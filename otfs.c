/*
 * ostreefs
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * Copyright (C) 2021 Giuseppe Scrivano
 * Copyright (C) 2022 Alexander Larsson
 *
 * This file is released under the GPL.
 */

#include <asm/unaligned.h>
#include <crypto/sha2.h>
#include <linux/backing-dev.h>
#include <linux/fs.h>
#include <linux/fs_parser.h>
#include <linux/init.h>
#include <linux/kernel_read_file.h>
#include <linux/pagemap.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/xattr.h>

#include "ostree.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Larsson <alexl@redhat.com>");

#define OTFS_MAGIC 0x055245638

struct otfs_info {
	struct vfsmount *root_mnt;

	char *object_dir_path;
	char *commit_id;
	struct file *object_dir;

	atomic64_t inode_counter;
};

struct otfs_inode_info {
	char object_id[OSTREE_SHA256_STRING_LEN+1];
	OtTreeMetaRef dirtree;
	OtDirMetaRef dirmeta;
	u64 inode_base;
};

static const struct super_operations otfs_ops;
static const struct file_operations otfs_file_operations;
static const struct file_operations otfs_dir_operations;
static const struct inode_operations otfs_dir_inode_operations;
static const struct inode_operations otfs_file_inode_operations;
static const struct address_space_operations otfs_aops = {
	.direct_IO = noop_direct_IO,
};

static void ot_ref_kvfree(OtRef ref)
{
	if (ref.base)
		kvfree(ref.base);
}

static int otfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct otfs_info *fsi = root->d_sb->s_fs_info;

	seq_printf(m, ",object_dir=%s", fsi->object_dir_path);
	seq_printf(m, ",commit=%s", fsi->commit_id);
	return 0;
}

static int otfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct otfs_info *fsi = dentry->d_sb->s_fs_info;
	int err;

	err = vfs_statfs(&(fsi->object_dir->f_path), buf);
	if (!err) {
		buf->f_namelen = NAME_MAX;
		buf->f_type = OTFS_MAGIC;
	}

	return err;
}

static void otfs_free_inode(struct inode *inode)
{
	struct otfs_inode_info *ino_info;

	ino_info = inode->i_private;
	
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);

	ot_ref_kvfree(ino_info->dirtree);
	ot_ref_kvfree(ino_info->dirmeta);
	kfree(ino_info);

	free_inode_nonrcu(inode);
}

static const struct super_operations otfs_ops = {
	.statfs = otfs_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = otfs_show_options,
	.free_inode = otfs_free_inode,
};


enum otfs_param {
	Opt_object_dir,
	Opt_commit,
};

const struct fs_parameter_spec otfs_parameters[] = {
	fsparam_string("objectdir", Opt_object_dir),
	fsparam_string("commit", Opt_commit),
	{}
};

static int otfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct otfs_info *fsi = fc->s_fs_info;
	int opt;

	opt = fs_parse(fc, otfs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_object_dir:
		kfree(fsi->object_dir_path);
		/* Take ownership.  */
		fsi->object_dir_path = param->string;
		param->string = NULL;
		break;
	case Opt_commit:
		kfree(fsi->commit_id);
		/* Take ownership.  */
		fsi->commit_id = param->string;
		param->string = NULL;
		break;
	}

	return 0;
}

static int otfs_setxattr(const struct xattr_handler *handler,
			struct user_namespace *mnt_userns,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value, size_t size,
			int flags)
{
	return -EROFS;
}

static int otfs_getxattr(const struct xattr_handler *handler,
			struct dentry *unused2, struct inode *inode,
			const char *name, void *value, size_t size)
{
	struct otfs_inode_info *ino_info = inode->i_private;
	size_t name_len = strlen(name);
	size_t i;

	printk(KERN_ERR "getxattr %s\n", name);
	
	if (S_ISDIR(inode->i_mode)) {
		OtArrayofXattrRef xattrs;
		size_t n_xattrs = 0;

		if (ot_dir_meta_get_xattrs(ino_info->dirmeta, &xattrs))
			n_xattrs = ot_arrayof_xattr_get_length(xattrs);

		for (i = 0; i < n_xattrs; i++) {
			OtXattrRef xattr;
			if (ot_arrayof_xattr_get_at(xattrs, i, &xattr)) {
				size_t this_name_len, this_value_len;
				const u8 *this_name, *this_value;

				this_name = ot_xattr_get_name (xattr, &this_name_len);
				if (name_len != this_name_len ||
				    memcmp(this_name, name, name_len) != 0)
					continue;

				printk(KERN_ERR "match xattr %*s: %*s\n", (int)this_name_len, this_name, (int)this_value_len, this_value);
				
				this_value = ot_xattr_get_value (xattr, &this_value_len);
				if (size == 0)
					return this_value_len;
				if (size  < this_value_len + 1)
					return -E2BIG;
				memcpy(value, this_value, this_value_len);
				printk(KERN_ERR "xattr return len %d\n", (int)this_value_len);
				return this_value_len;
			}
		}
	} else {
		/* TODO: Implement xattrs for regular files and symlinks */
	}
	
	return -ENODATA;
}

static const struct xattr_handler otfs_xattr_handler = {
	.prefix = "", /* catch all */
	.get = otfs_getxattr,
	.set = otfs_setxattr,
};

static const struct xattr_handler *otfs_xattr_handlers[] = {
	&otfs_xattr_handler,
	NULL,
};

static struct file *otfs_open_object (struct file *object_dir, const char *object_id, const char *type, int flags)
{
	char relpath[OSTREE_SHA256_STRING_LEN + 12]; /* Fits slash and longest extenssion (.dirtree) */

	if (strlen(object_id) != OSTREE_SHA256_STRING_LEN)
		return ERR_PTR(-ENOENT);

	relpath[0] = object_id[0];
	relpath[1] = object_id[1];
	relpath[2] = '/';
	relpath[3] = 0;
	strcat (relpath, object_id + 2);
	strcat (relpath, type);

	return file_open_root(&(object_dir->f_path), relpath, flags, 0);
}

static int otfs_read_object (struct file *object_dir, const char *object_id, const char *type,
			     u8 **data_out)
{
	struct file *f = NULL;
	void *buf = NULL;
	size_t file_size;
	int ret;
	int read_bytes;
	uint8_t digest[SHA256_DIGEST_SIZE];
	char digest_string[OSTREE_SHA256_STRING_LEN + 1]; /* Fits slash and longest extenssion (.dirtree) */

	f = otfs_open_object(object_dir, object_id, type, O_RDONLY);
	if (IS_ERR(f))
		return PTR_ERR(f);
	
	read_bytes = kernel_read_file(f, 0, &buf, INT_MAX, &file_size, READING_UNKNOWN);
	if (read_bytes < 0) {
		ret = read_bytes;
		goto fail;
	}

        sha256(buf, read_bytes, digest);
	sha256_digest_to_string (digest, digest_string);

	if (strcmp(digest_string, object_id) != 0) {
		printk(KERN_ERR "Invalid digest %s for ostree object %s of type %s\n", digest_string, object_id, type);
		ret = -EIO;
		goto fail;
	}

	fput(f);

	*data_out = buf;
	return read_bytes;

 fail:
	if (buf)
		kvfree(buf);
		
	if (f)
		fput(f);
	return ret;
}

static int otfs_read_objectv (struct file *object_dir, OtChecksumRef checksum, const char *type,
			      u8 **data_out)
{
	char object_id[OSTREE_SHA256_STRING_LEN+1];
	ot_checksum_to_string (checksum, object_id);

	return otfs_read_object (object_dir, object_id, type, data_out);
}

static int otfs_read_dirtree_object (struct file *object_dir, OtChecksumRef commit,
				     OtTreeMetaRef *treemetav_out)
{
	OtTreeMetaRef treemetav;
	int res;
	u8 *data;

	res = otfs_read_objectv (object_dir, commit, ".dirtree", &data);
	if (res < 0)
		return res;

	if (!ot_tree_meta_from_data (data, res, &treemetav)) {
		kvfree(data);
		return -EIO;
	}

	*treemetav_out = treemetav;
	return 0;
}

static int otfs_read_dirmeta_object (struct file *object_dir, OtChecksumRef commit,
				     OtDirMetaRef *dirmetav_out)
{
	OtDirMetaRef dirmetav;
	int res;
	u8 *data;

	res = otfs_read_objectv (object_dir, commit, ".dirmeta", &data);
	if (res < 0)
		return res;

	if (!ot_dir_meta_from_data (data, res, &dirmetav)) {
		kvfree(data);
		return -EIO;
	}

	*dirmetav_out = dirmetav;
	return 0;
}

static struct inode *otfs_make_file_inode(struct super_block *sb,
					 const struct inode *dir,
					 ino_t ino_num,
					 OtChecksumRef file_csum)
{
	struct otfs_info *fsi = sb->s_fs_info;
	struct otfs_inode_info *inode_info = NULL;
	struct file *object_file = NULL;
	int err;
	int ret;
	struct kstat stat;
	struct inode *inode;
	char *target_link = NULL;
	DEFINE_DELAYED_CALL(done);
	struct timespec64 ostree_time = {0, 0};
	char object_id[OSTREE_SHA256_STRING_LEN+1];

	ot_checksum_to_string (file_csum, object_id);
	
	object_file = otfs_open_object (fsi->object_dir, object_id, ".file", O_PATH|O_NOFOLLOW);
	if (IS_ERR(object_file))
		return ERR_CAST(object_file);

	err = vfs_getattr(&object_file->f_path, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	if (err < 0) {
		ret = err;
		goto fail;
	}

	/* We support only regular and symlink file objects */
	if (!S_ISLNK(stat.mode) && !S_ISREG(stat.mode)) {
		ret = -EIO;
		goto fail;
	}
	
	if (S_ISLNK(stat.mode)) {
		const char *link;
		link = vfs_get_link(object_file->f_path.dentry, &done);
                if (IS_ERR(link)) {
			ret = PTR_ERR(link);
			goto fail;
		}

		target_link = kstrdup(link, GFP_KERNEL);
		do_delayed_call(&done);
	}

	inode_info = kzalloc(sizeof(*inode_info), GFP_KERNEL);
	if (inode_info == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	inode = new_inode(sb);
	if (inode == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	inode_init_owner(&init_user_ns, inode, dir, stat.mode);
	inode->i_mapping->a_ops = &otfs_aops;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	inode->i_private = inode_info;

	memcpy (inode_info->object_id, object_id, sizeof(object_id));
	
	inode->i_ino = ino_num;
	set_nlink(inode, 1);
	inode->i_rdev = 0;
	inode->i_uid = stat.uid;
	inode->i_gid = stat.gid;
	inode->i_mode = stat.mode;
	inode->i_atime = ostree_time;
	inode->i_mtime = ostree_time;
	inode->i_ctime = ostree_time;
	if (S_ISLNK(stat.mode)) {
		inode->i_link = target_link; /* transfer ownership */
		inode->i_op = &simple_symlink_inode_operations;
		inode->i_fop = &otfs_file_operations;
	} else {
		inode->i_size = stat.size;
		inode->i_op = &otfs_file_inode_operations;
		inode->i_fop = &otfs_file_operations;
	}

	return inode;
	

	
 fail:
	if (object_file)
		fput(object_file);
	if (target_link)
		kfree(target_link);
	
	return ERR_PTR(ret);
}



static struct inode *otfs_make_dir_inode(struct super_block *sb,
					 const struct inode *dir,
					 ino_t ino_num,
					 struct file *object_dir,
					 OtChecksumRef dirtree_csum,
					 OtChecksumRef dirmeta_csum)
{
	struct otfs_info *fsi = sb->s_fs_info;
	struct inode *inode;
	struct otfs_inode_info *inode_info = NULL;
	int ret;
	OtTreeMetaRef dirtree = { NULL, 0 };
	OtDirMetaRef dirmeta = { NULL, 0 };
	u32 uid, gid, mode;
	int res;
	struct timespec64 ostree_time = {0, 0};
	u64 n_inos;
	OtArrayofTreeFileRef files;
	OtArrayofTreeDirRef dirs;

	res = otfs_read_dirmeta_object (object_dir, dirmeta_csum, &dirmeta);
	if (res < 0) {
		ret = res;
		goto fail;
	}

	uid = ot_dir_meta_get_uid(dirmeta);
	gid = ot_dir_meta_get_gid(dirmeta);
	mode = ot_dir_meta_get_mode(dirmeta);

	/* Ensure its actually a directory */
	if ((mode & S_IFMT) != S_IFDIR) {
		ret = -EIO;
		goto fail;
	}
	
	/* TODO: Should we validate mode mode? */

	res = otfs_read_dirtree_object (object_dir, dirtree_csum,
					&dirtree);
	if (res < 0) {
		ret = res;
		goto fail;
	}

	inode_info = kzalloc(sizeof(*inode_info), GFP_KERNEL);
	if (inode_info == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	/* Allocate inodes for all children */
	n_inos = 0;
	if (ot_tree_meta_get_files (dirtree, &files))
		n_inos += ot_arrayof_tree_file_get_length (files);
	if (ot_tree_meta_get_dirs (dirtree, &dirs))
		n_inos += ot_arrayof_tree_dir_get_length (dirs);
	inode_info->inode_base = atomic64_add_return (n_inos, &fsi->inode_counter) - n_inos;
	
	inode = new_inode(sb);
	if (inode == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	inode_init_owner(&init_user_ns, inode, dir, mode);
	inode->i_mapping->a_ops = &otfs_aops;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	inode->i_private = inode_info;

	inode->i_ino = ino_num;
	set_nlink(inode, 1);
	inode->i_rdev = 0;
	inode->i_uid = make_kuid(current_user_ns(), uid);
	inode->i_gid = make_kgid(current_user_ns(), gid);
	inode->i_mode = mode;
	inode->i_atime = ostree_time;
	inode->i_mtime = ostree_time;
	inode->i_ctime = ostree_time;
	inode->i_op = &otfs_dir_inode_operations;
	inode->i_fop = &otfs_dir_operations;
	inode->i_size = 4096;

	inode_info->dirtree = dirtree; /* Transfer ownership */
	inode_info->dirmeta = dirmeta; /* Transfer ownership */
	
	return inode;
 fail:
	if (inode_info)
		kfree(inode_info);
	ot_ref_kvfree(dirtree);
	ot_ref_kvfree(dirmeta);

	return ERR_PTR(ret);
}

static int otfs_rmdir(struct inode *ino, struct dentry *dir)
{
	return -EROFS;
}

static int otfs_rename(struct user_namespace *userns, struct inode *source_ino,
		      struct dentry *src_dir, struct inode *target_ino,
		      struct dentry *target, unsigned int flags)
{
	return -EROFS;
}

static int otfs_link(struct dentry *src, struct inode *i, struct dentry *target)
{
	return -EROFS;
}

static int otfs_unlink(struct inode *inode, struct dentry *dir)
{
	return -EROFS;
}

static int otfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
		     struct dentry *dentry, umode_t mode, dev_t dev)
{
	return -EROFS;
}

static int otfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	return -EROFS;
}

static int otfs_create(struct user_namespace *mnt_userns, struct inode *dir,
		      struct dentry *dentry, umode_t mode, bool excl)
{
	return -EROFS;
}

static int otfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, const char *symname)
{
	return -EROFS;
}

static int otfs_tmpfile(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	return -EROFS;
}

static int otfs_dir_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int otfs_dir_open(struct inode *inode, struct file *file)
{
	return 0;
}

struct dentry *otfs_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags)
{
	struct otfs_inode_info *dir_ino_info;
	struct otfs_info *fsi;
	OtArrayofTreeFileRef files;
	OtArrayofTreeDirRef dirs;
	size_t i, n_files, n_dirs;
	struct inode *inode;
	
	fsi = dir->i_sb->s_fs_info;
	dir_ino_info = dir->i_private;

	if (!ot_tree_meta_get_files (dir_ino_info->dirtree, &files))
		return ERR_PTR(-EIO);
	n_files = ot_arrayof_tree_file_get_length (files);
	
	if (!ot_tree_meta_get_dirs (dir_ino_info->dirtree, &dirs))
		return ERR_PTR(-EIO);
	n_dirs = ot_arrayof_tree_dir_get_length (dirs);

	if (!dentry->d_sb->s_d_op)
		d_set_d_op(dentry, &simple_dentry_operations);

	for (i = 0; i < n_files; i++) {
		OtTreeFileRef treefile;
		size_t name_len;
		const char *name;
		
		if (!ot_arrayof_tree_file_get_at (files, i, &treefile))
			continue;

		name = ot_tree_file_get_name (treefile, &name_len);
		if (name == NULL)
			continue;

		if (dentry->d_name.len == name_len &&
		    memcmp(dentry->d_name.name,name, name_len) == 0) {
			OtChecksumRef file_csum;
			if (!ot_tree_file_get_checksum (treefile, &file_csum))
				return ERR_PTR(-EIO);

			inode = otfs_make_file_inode(dir->i_sb, dir, dir_ino_info->inode_base + i,
						     file_csum);
			if (IS_ERR(inode))
				return ERR_CAST(inode);

			return d_splice_alias(inode, dentry);
		}
	}
	
	for (i = 0; i < n_dirs; i++) {
		OtTreeDirRef treedir;
		size_t name_len;
		const char *name;
		
		if (!ot_arrayof_tree_dir_get_at (dirs, i, &treedir))
			continue;

		name = ot_tree_dir_get_name (treedir, &name_len);
		if (name == NULL)
			continue;

		if (dentry->d_name.len == name_len &&
		    memcmp(dentry->d_name.name,name, name_len) == 0) {
			OtChecksumRef tree_csum, meta_csum;
			if (!ot_tree_dir_get_tree_checksum (treedir, &tree_csum) ||
			    !ot_tree_dir_get_meta_checksum (treedir, &meta_csum))
				return ERR_PTR(-EIO);

			inode = otfs_make_dir_inode(dir->i_sb, dir, dir_ino_info->inode_base + n_files + i, fsi->object_dir,
						    tree_csum, meta_csum);
			if (IS_ERR(inode))
				return ERR_CAST(inode);

			return d_splice_alias(inode, dentry);
		}
	}
	
	d_add(dentry, NULL);
	return NULL;
}

static int otfs_iterate(struct file *file, struct dir_context *ctx)
{
	struct otfs_inode_info *ino_info;
	struct otfs_info *fsi;
	bool done = false;
	size_t pos;
	OtArrayofTreeFileRef files;
	OtArrayofTreeDirRef dirs;
	size_t i, n_files, n_dirs;
	
	fsi = file->f_inode->i_sb->s_fs_info;
	ino_info = file->f_inode->i_private;

	if (!ot_tree_meta_get_files (ino_info->dirtree, &files))
		return -EIO;
	n_files = ot_arrayof_tree_file_get_length (files);
	
	if (!ot_tree_meta_get_dirs (ino_info->dirtree, &dirs))
		return -EIO;
	n_dirs = ot_arrayof_tree_dir_get_length (dirs);

	/* Early exit if guaranteed past end */
	if (ctx->pos >= 2 + n_files + n_dirs)
		return 0;
	
	if (!dir_emit_dots(file, ctx))
		return 0;

	/* pos 0 and 1 is dots, our entries start at 2 */
	pos = 2;

	/* First list files */
	for (i = 0; !done && i < n_files; i++) {
		OtTreeFileRef treefile;
		size_t name_len;
		const char *name;

		if (!ot_arrayof_tree_file_get_at (files, i, &treefile))
			continue;
		
		name = ot_tree_file_get_name (treefile, &name_len);
		if (name == NULL)
			continue;

		if (pos++ == ctx->pos) {
			if (dir_emit(ctx, name, name_len, ino_info->inode_base + i, DT_UNKNOWN)) {
				ctx->pos++;
			} else {
				done = true; /* no more */
			}
		}
	}

	/* Then dirs */
	for (i = 0; !done && i < n_dirs; i++) {
		OtTreeDirRef treedir;
		size_t name_len;
		const char *name;
		
		if (!ot_arrayof_tree_dir_get_at (dirs, i, &treedir))
			continue;

		name = ot_tree_dir_get_name (treedir, &name_len);
		if (name == NULL)
			continue;

		if (pos++ == ctx->pos) {
			if (dir_emit(ctx, name, name_len, ino_info->inode_base + n_files + i, DT_DIR)) {
				ctx->pos++;
			} else {
				done = true; /* no more */
			}
		}
	}

	return 0;
}

static loff_t otfs_dir_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t res = -EINVAL;

	switch (origin) {
	case SEEK_CUR:
		offset += file->f_pos;
		break;
	case SEEK_SET:
		break;
	default:
		return res;
	}
	if (offset < 0)
		return res;

	file->f_pos = offset;

	return offset;
}

static ssize_t otfs_listxattr(struct dentry *dentry, char *names, size_t size)
{
	/* TODO */
	return -EIO;
}

static ssize_t otfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct file *realfile = file->private_data;
	int ret;

	if (!realfile->f_op->read_iter)
		return -ENODEV;

	iocb->ki_filp = realfile;
	ret = call_read_iter(realfile, iocb, iter);
	iocb->ki_filp = file;

	return ret;
}

static int otfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *realfile = file->private_data;
	int ret;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma_set_file(vma, realfile);

	ret = call_mmap(vma->vm_file, vma);

	return ret;
}

static int otfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct file *realfile = file->private_data;

	return vfs_fadvise(realfile, offset, len, advice);
}

static unsigned long otfs_mmu_get_unmapped_area(struct file *file,
					       unsigned long addr,
					       unsigned long len,
					       unsigned long pgoff,
					       unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static int otfs_release_file(struct inode *inode, struct file *file)
{
	struct file *realfile = file->private_data;

	if (WARN_ON(realfile == NULL))
		return -EIO;

	fput(file->private_data);
	file->private_data = NULL;

	return 0;
}

static int otfs_open_file(struct inode *inode, struct file *file)
{
	struct otfs_info *fsi = inode->i_sb->s_fs_info;
	struct otfs_inode_info *ino_info = inode->i_private;
	struct file *real_file;

	if (WARN_ON(file == NULL))
		return -EIO;

	if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC))
		return -EROFS;

	real_file = otfs_open_object (fsi->object_dir, ino_info->object_id, ".file", file->f_flags);
	if (IS_ERR(real_file)) {
		return PTR_ERR(real_file);
	}

	file->private_data = real_file;
	return 0;
}

static const struct file_operations otfs_dir_operations = {
	.open = otfs_dir_open,
	.iterate = otfs_iterate,
	.release = otfs_dir_release,
	.llseek = otfs_dir_llseek,
};

static const struct inode_operations otfs_dir_inode_operations = {
	.create = otfs_create,
	.lookup = otfs_lookup,
	.link = otfs_link,
	.unlink = otfs_unlink,
	.symlink = otfs_symlink,
	.mkdir = otfs_mkdir,
	.rmdir = otfs_rmdir,
	.mknod = otfs_mknod,
	.rename = otfs_rename,
	.tmpfile = otfs_tmpfile,
};

static const struct inode_operations otfs_file_inode_operations = {
	.setattr = simple_setattr,
	.getattr = simple_getattr,

	.listxattr = otfs_listxattr,
};

static const struct file_operations otfs_file_operations = {
	.read_iter = otfs_read_iter,
	.mmap = otfs_mmap,
	.fadvise = otfs_fadvise,
	.fsync = noop_fsync,
	.splice_read = generic_file_splice_read,
	.llseek = generic_file_llseek,
	.get_unmapped_area = otfs_mmu_get_unmapped_area,
	.release = otfs_release_file,
	.open = otfs_open_file,
};


static int otfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct otfs_info *fsi = sb->s_fs_info;
	struct file *object_dir = NULL;
	struct file *f;
	int ret;
	int res;
	u8 *commit_data = NULL;
	u8 *dirtree_data = NULL;
	u8 *dirmeta_data = NULL;
	struct inode *inode;
	OtCommitRef commit;
	OtChecksumRef root_contents;
	OtChecksumRef root_metadata;

	if (sb->s_root)
		return -EINVAL;

	/* These are required options */
	if (fsi->object_dir_path == NULL ||
	    fsi->commit_id == NULL)
		return -EINVAL;


	f = filp_open(fsi->object_dir_path, O_PATH, 0);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto fail;
	}
	object_dir = f;

	res = otfs_read_object (object_dir, fsi->commit_id, ".commit", &commit_data);
	if (res < 0) {
		ret = res;
		goto fail;
	}

	if (!ot_commit_from_data (commit_data, res, &commit) ||
	    !ot_commit_get_root_contents (commit, &root_contents) ||
	    !ot_commit_get_root_metadata (commit, &root_metadata)) {
		ret = -EINVAL;
		goto fail;
	}

	/* 0 is root, so start at 1 */
	atomic64_set (&fsi->inode_counter, 1);
	inode = otfs_make_dir_inode(sb, NULL, 0, object_dir, 
				    root_contents, root_metadata);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}
	sb->s_root = d_make_root(inode); /* Takes ownership */

	ret = -ENOMEM;
	if (!sb->s_root)
		goto fail;
	
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = OTFS_MAGIC;
	sb->s_xattr = otfs_xattr_handlers;

	sb->s_op = &otfs_ops;
	sb->s_time_gran = 1;

	fsi->object_dir = object_dir;
	return 0;
fail:
	if (dirmeta_data)
		kvfree(dirmeta_data);
	if (dirtree_data)
		kvfree(dirtree_data);
	if (commit_data)
		kvfree(commit_data);
	if (object_dir)
		fput(object_dir);
	return ret;
}

static int otfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, otfs_fill_super);
}

static const struct fs_context_operations otfs_context_ops = {
	.parse_param = otfs_parse_param,
	.get_tree = otfs_get_tree,
};

static int otfs_init_fs_context(struct fs_context *fc)
{
	struct otfs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fc->s_fs_info = fsi;
	fc->ops = &otfs_context_ops;
	return 0;
}

static void otfs_kill_sb(struct super_block *sb)
{
	struct otfs_info *fsi = sb->s_fs_info;

	if (fsi->root_mnt)
		kern_unmount(fsi->root_mnt);
	if (fsi->object_dir_path)
		kfree(fsi->object_dir_path);
	if (fsi->object_dir)
		fput(fsi->object_dir);
	if (fsi->commit_id)
		kfree(fsi->commit_id);

	kfree(fsi);
	kill_litter_super(sb);
}

static struct file_system_type otfs_type = {
	.name = "ostreefs",
	.init_fs_context = otfs_init_fs_context,
	.parameters = otfs_parameters,
	.kill_sb = otfs_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

static int __init init_otfs(void)
{
	return register_filesystem(&otfs_type);
}

static void __exit exit_otfs(void)
{
	unregister_filesystem(&otfs_type);
}

module_init(init_otfs);
module_exit(exit_otfs);

