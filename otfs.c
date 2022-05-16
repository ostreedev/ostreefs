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
#include <linux/sort.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/xattr.h>

#include "ostree.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Larsson <alexl@redhat.com>");

#define OTFS_MAGIC 0x055245638

struct otfs_info {
	char *object_dir_path;
	char *commit_id;
	struct file *object_dir;

	atomic64_t inode_counter;
};

struct otfs_inode {
	struct inode vfs_inode;
	char object_id[OSTREE_SHA256_STRING_LEN+1];
	OtTreeMetaRef dirtree;
	OtDirMetaRef dirmeta;
	u64 inode_base;
};

static inline struct otfs_inode *OTFS_I(struct inode *inode)
{
	return container_of(inode, struct otfs_inode, vfs_inode);
}

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
	if (ref.base) {
		kvfree(ref.base);
		ref.base = NULL;
	}
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

static struct kmem_cache *otfs_inode_cachep;

static struct inode *otfs_alloc_inode(struct super_block *sb)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0))
	struct otfs_inode *oti = kmem_cache_alloc(otfs_inode_cachep, GFP_KERNEL);
#else
	struct otfs_inode *oti = alloc_inode_sb(sb, otfs_inode_cachep, GFP_KERNEL);
#endif

	if (!oti)
		return NULL;

        oti->vfs_inode.i_link = NULL;
	oti->dirtree.base =  NULL;
	oti->dirtree.size =  0;
	oti->dirmeta.base = NULL;
	oti->dirmeta.size = 0;

	return &oti->vfs_inode;
}

static void otfs_destroy_inode(struct inode *inode)
{
	struct otfs_inode *oti = OTFS_I(inode);

	if (S_ISLNK(inode->i_mode) && inode->i_link)
		kfree(inode->i_link);

	ot_ref_kvfree(oti->dirtree);
	ot_ref_kvfree(oti->dirmeta);
}

static void otfs_free_inode(struct inode *inode)
{
	struct otfs_inode *oti = OTFS_I(inode);

	kmem_cache_free(otfs_inode_cachep, oti);
}

static void otfs_put_super(struct super_block *sb)
{
	struct otfs_info *fsi = sb->s_fs_info;

	if (fsi->object_dir_path)
		kfree(fsi->object_dir_path);
	if (fsi->object_dir)
		fput(fsi->object_dir);
	if (fsi->commit_id)
		kfree(fsi->commit_id);

	kfree(fsi);
	sb->s_fs_info = NULL;
}

static const struct super_operations otfs_ops = {
	.put_super = otfs_put_super,
	.statfs = otfs_statfs,
	.drop_inode = generic_delete_inode,
	.show_options = otfs_show_options,
	.alloc_inode = otfs_alloc_inode,
	.destroy_inode = otfs_destroy_inode,
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
		vfree(buf);

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
		vfree(data);
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
		vfree(data);
		return -EIO;
	}

	*dirmetav_out = dirmetav;
	return 0;
}

static ssize_t listxattr(struct dentry *dentry, char **bufp)
{
	ssize_t len;
	ssize_t ret;
	char *buf;
	struct inode *inode;

	inode = d_inode(dentry);
	len = 0;

	inode_lock_shared(inode);

	len = vfs_listxattr(dentry, NULL, 0);
	if (len <= 0) {
		ret = len;
		goto out;
	}

	if (len > XATTR_LIST_MAX) {
		ret = -E2BIG;
		goto out;
	}

	/* We're holding i_rwsem - use GFP_NOFS. */
	buf = kvmalloc(len, GFP_KERNEL | GFP_NOFS);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	len = vfs_listxattr(dentry, buf, len);
	if (len <= 0) {
		kvfree(buf);
		ret = len;
		goto out;
	}

	*bufp = buf;
	ret = len;

 out:
	inode_unlock_shared(inode);
	return ret;
}

static int
xattr_data_cmp(const struct OtXAttrData *a, const struct OtXAttrData *b)
{
	return strcmp(a->name, b->name);
}

static void
xattrs_data_free(struct OtXAttrData *data, size_t num_xattr, char *names)
{
	size_t i;
	if (data) {
		for (i = 0; i < num_xattr; i++)
			kvfree(data[i].value);
		kvfree(data);
	}
	if (names)
		kvfree(names);
}

static ssize_t get_xattrs(struct dentry *dentry, char **names_out, struct OtXAttrData **data_out)
{
	char *names = NULL;
	const char *name;
	ssize_t names_len;
	ssize_t remaining;
	ssize_t ret;
	size_t slen;
	ssize_t size, value_size;
	char *value = NULL;
	size_t num_xattrs, i = 0;
	struct OtXAttrData *data = NULL;

	names_len = listxattr(dentry, &names);
	if (names_len < 0)
		return (int)names_len;

	if (names_len == 0) {
		*names_out = NULL;
		*data_out = NULL;
		return 0;
	}

	num_xattrs = 0;
	for (name = names, remaining = names_len; remaining; name += slen) {
		slen = strnlen(name, remaining) + 1;
		/* underlying fs providing us with an broken xattr list? */
		if (WARN_ON(slen > remaining)) {
			ret = -EIO;
			goto fail;
		}
		num_xattrs++;
		remaining -= slen;
	}

	data = kvmalloc_array(num_xattrs, sizeof(struct OtXAttrData), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto fail;
	}

	for (name = names, remaining = names_len; remaining; name += slen) {
		slen = strnlen(name, remaining) + 1;
		remaining -= slen;

		size = vfs_getxattr(&init_user_ns, dentry, name, NULL, 0);
		if (size < 0) {
			ret = size;
			goto fail;
		}

		value_size = size;
		value = kvmalloc(value_size, GFP_KERNEL);

		size = vfs_getxattr(&init_user_ns, dentry, name, value, value_size);
		if (size < 0) {
			kvfree(value);
			ret = size;
			goto fail;
		}

		data[i].name = name;
		data[i].value = value;
		data[i].size = size;
		i++;
	}

	sort(data, num_xattrs, sizeof(struct OtXAttrData), (cmp_func_t)xattr_data_cmp, NULL);

	*names_out = names;
	*data_out = data;
	return num_xattrs;

 fail:
	while (i > 0) {
		kvfree(data[i].value);
		i--;
	}

	if (data)
		kvfree(data);
	if (names)
		kvfree(names);
	return ret;
}

static struct inode *otfs_new_inode(struct super_block *sb,
				    const struct inode *dir,
				    ino_t ino_num,
				    mode_t mode)
{
	struct inode *inode;
	struct timespec64 ostree_time = {0, 0};

	inode = new_inode(sb);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);

	inode->i_ino = ino_num;

	inode_init_owner(&init_user_ns, inode, dir, mode);
	inode->i_mapping->a_ops = &otfs_aops;
	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	set_nlink(inode, 1);
	inode->i_mode = mode;
	inode->i_rdev = 0;
	inode->i_atime = ostree_time;
	inode->i_mtime = ostree_time;
	inode->i_ctime = ostree_time;

	return inode;
}

static struct inode *otfs_make_file_inode(struct super_block *sb,
					 const struct inode *dir,
					 ino_t ino_num,
					 OtChecksumRef file_csum)
{
	struct otfs_info *fsi = sb->s_fs_info;
	struct otfs_inode *oti = NULL;
	struct file *object_file = NULL;
	int err;
	int ret;
	struct kstat stat;
	struct inode *inode;
	char *target_link = NULL;
	DEFINE_DELAYED_CALL(done);
	char object_id[OSTREE_SHA256_STRING_LEN+1];
	char *xattr_names = NULL;
	struct OtXAttrData *xattr_data = NULL;
	OtDirMetaRef filemeta = { NULL, 0};
	ssize_t num_xattr = 0;

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

	num_xattr = get_xattrs(object_file->f_path.dentry, &xattr_names, &xattr_data);
	if (num_xattr < 0) {
		ret = num_xattr;
		goto fail;
	}

	err = ot_dir_meta_serialize(from_kuid(&init_user_ns, stat.uid),
				    from_kgid(&init_user_ns, stat.gid),
				    stat.mode,
				    xattr_data, num_xattr, &filemeta);
	xattrs_data_free(xattr_data, num_xattr, xattr_names);
	if (err < 0) {
		ret = err;
		goto fail;
	}

	inode = otfs_new_inode(sb, dir, ino_num, stat.mode);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}

	oti = OTFS_I(inode);

	memcpy (oti->object_id, object_id, sizeof(object_id));
	oti->dirmeta = filemeta;

	inode->i_uid = stat.uid;
	inode->i_gid = stat.gid;

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
	ot_ref_kvfree(filemeta);

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
	struct otfs_inode *oti = NULL;
	int ret;
	OtTreeMetaRef dirtree = { NULL, 0 };
	OtDirMetaRef dirmeta = { NULL, 0 };
	u32 uid, gid, mode;
	int res;
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

	inode = otfs_new_inode(sb, dir, ino_num, mode);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}

	oti = OTFS_I(inode);

	/* Allocate inodes for all children */
	n_inos = 0;
	if (ot_tree_meta_get_files (dirtree, &files))
		n_inos += ot_arrayof_tree_file_get_length (files);
	if (ot_tree_meta_get_dirs (dirtree, &dirs))
		n_inos += ot_arrayof_tree_dir_get_length (dirs);
	oti->inode_base = atomic64_add_return (n_inos, &fsi->inode_counter) - n_inos;
	inode->i_uid = make_kuid(current_user_ns(), uid);
	inode->i_gid = make_kgid(current_user_ns(), gid);

	inode->i_op = &otfs_dir_inode_operations;
	inode->i_fop = &otfs_dir_operations;
	inode->i_size = 4096;

	oti->dirtree = dirtree; /* Transfer ownership */
	oti->dirmeta = dirmeta; /* Transfer ownership */

	return inode;
 fail:
	ot_ref_kvfree(dirtree);
	ot_ref_kvfree(dirmeta);

	return ERR_PTR(ret);
}

static int otfs_getxattr(const struct xattr_handler *handler,
			struct dentry *unused2, struct inode *inode,
			const char *name, void *value, size_t size)
{
	struct otfs_inode *oti = OTFS_I(inode);
	size_t name_len = strlen(name) + 1; /* Include the terminating zero */
	size_t i;
	OtArrayofXattrRef xattrs;
	size_t n_xattrs = 0;

	if (ot_dir_meta_get_xattrs(oti->dirmeta, &xattrs))
		n_xattrs = ot_arrayof_xattr_get_length(xattrs);

	for (i = 0; i < n_xattrs; i++) {
		OtXattrRef xattr;
		if (ot_arrayof_xattr_get_at(xattrs, i, &xattr)) {
			size_t this_name_len, this_value_len;
			const u8 *this_name, *this_value;

			this_name = ot_xattr_get_name (xattr, &this_name_len);
			if (name == NULL || name_len != this_name_len ||
			    memcmp(this_name, name, name_len) != 0)
				continue;

			this_value = ot_xattr_get_value (xattr, &this_value_len);
			if (this_value == NULL)
				continue;

			if (size == 0)
				return this_value_len;
			if (size  < this_value_len)
				return -E2BIG;
			memcpy(value, this_value, this_value_len);
			return this_value_len;
		}
	}

	return -ENODATA;
}

static const struct xattr_handler otfs_xattr_handler = {
	.prefix = "", /* catch all */
	.get = otfs_getxattr,
};

static const struct xattr_handler *otfs_xattr_handlers[] = {
	&otfs_xattr_handler,
	NULL,
};

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
	struct otfs_inode *dir_oti;
	struct otfs_info *fsi;
	OtArrayofTreeFileRef files;
	OtArrayofTreeDirRef dirs;
	size_t i, n_files, n_dirs;
	struct inode *inode;

	fsi = dir->i_sb->s_fs_info;
	dir_oti = OTFS_I(dir);

	if (!ot_tree_meta_get_files (dir_oti->dirtree, &files))
		return ERR_PTR(-EIO);
	n_files = ot_arrayof_tree_file_get_length (files);

	if (!ot_tree_meta_get_dirs (dir_oti->dirtree, &dirs))
		return ERR_PTR(-EIO);
	n_dirs = ot_arrayof_tree_dir_get_length (dirs);

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

			inode = otfs_make_file_inode(dir->i_sb, dir, dir_oti->inode_base + i,
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

			inode = otfs_make_dir_inode(dir->i_sb, dir, dir_oti->inode_base + n_files + i, fsi->object_dir,
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
	struct otfs_inode *oti;
	struct otfs_info *fsi;
	bool done = false;
	size_t pos;
	OtArrayofTreeFileRef files;
	OtArrayofTreeDirRef dirs;
	size_t i, n_files, n_dirs;

	fsi = file->f_inode->i_sb->s_fs_info;
	oti = OTFS_I(file->f_inode);

	if (!ot_tree_meta_get_files (oti->dirtree, &files))
		return -EIO;
	n_files = ot_arrayof_tree_file_get_length (files);

	if (!ot_tree_meta_get_dirs (oti->dirtree, &dirs))
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
			if (dir_emit(ctx, name, name_len, oti->inode_base + i, DT_UNKNOWN)) {
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
			if (dir_emit(ctx, name, name_len, oti->inode_base + n_files + i, DT_DIR)) {
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
	struct inode *inode = d_inode(dentry);
	struct otfs_inode *oti = OTFS_I(inode);
	OtArrayofXattrRef xattrs;
	size_t n_xattrs = 0;
	size_t required_size = 0;
	char *dest;
	size_t i;

	if (ot_dir_meta_get_xattrs(oti->dirmeta, &xattrs))
		n_xattrs = ot_arrayof_xattr_get_length(xattrs);

	for (i = 0; i < n_xattrs; i++) {
		OtXattrRef xattr;
		if (ot_arrayof_xattr_get_at(xattrs, i, &xattr)) {
			size_t name_len;
			const u8 *name;
			name = ot_xattr_get_name (xattr, &name_len);
			if (name != NULL)
				required_size += name_len;
		}
	}
	if (size < required_size)
		return -ERANGE;
	dest = names;
	for (i = 0; i < n_xattrs; i++) {
		OtXattrRef xattr;
		if (ot_arrayof_xattr_get_at(xattrs, i, &xattr)) {
			size_t name_len;
			const u8 *name;
			name = ot_xattr_get_name (xattr, &name_len);
			if (name != NULL) {
				memcpy(dest, name, name_len);
				dest += name_len;
			}
		}
	}

	return required_size;
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
	struct otfs_inode *oti = OTFS_I(inode);
	struct file *real_file;

	if (WARN_ON(file == NULL))
		return -EIO;

	if (file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC))
		return -EROFS;

	real_file = otfs_open_object (fsi->object_dir, oti->object_id, ".file", file->f_flags);
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
	.lookup = otfs_lookup,
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

	/* Set up the inode allocator early */
	sb->s_op = &otfs_ops;
	sb->s_xattr = otfs_xattr_handlers;
	sb->s_flags |= SB_RDONLY;
	sb->s_magic = OTFS_MAGIC;

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

	sb->s_time_gran = 1;

	vfree(commit_data);
	fsi->object_dir = object_dir;
	return 0;
fail:
	if (commit_data)
		vfree(commit_data);
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

static struct file_system_type otfs_type = {
	.name = "ostreefs",
	.init_fs_context = otfs_init_fs_context,
	.parameters = otfs_parameters,
	.kill_sb = kill_anon_super,
	.fs_flags = FS_USERNS_MOUNT,
};

static void otfs_inode_init_once(void *foo)
{
	struct otfs_inode *oti = foo;

	inode_init_once(&oti->vfs_inode);
}

static int __init init_otfs(void)
{
	otfs_inode_cachep = kmem_cache_create("otfs_inode",
					      sizeof(struct otfs_inode), 0,
					      (SLAB_RECLAIM_ACCOUNT|
					       SLAB_MEM_SPREAD|SLAB_ACCOUNT),
					      otfs_inode_init_once);
	if (otfs_inode_cachep == NULL)
		return -ENOMEM;

	return register_filesystem(&otfs_type);
}

static void __exit exit_otfs(void)
{
	unregister_filesystem(&otfs_type);

	/* Ensure all RCU free inodes are safe to be destroyed. */
	rcu_barrier();

	kmem_cache_destroy(otfs_inode_cachep);
}

module_init(init_otfs);
module_exit(exit_otfs);
