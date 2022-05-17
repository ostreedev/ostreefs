#define ALIGN_TO(_offset, _align_to) ((_offset + _align_to - 1) & ~(size_t)(_align_to - 1))
#define STRUCT_MEMBER_P(struct_p, struct_offset)  ((void *) ((u8*) (struct_p) + (size_t) (struct_offset)))
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) (*(member_type*) STRUCT_MEMBER_P ((struct_p), (struct_offset)))

#define OSTREE_SHA256_DIGEST_LEN 32
#define OSTREE_SHA256_STRING_LEN 64

struct OtXAttrData {
	const char *name;
	size_t size;
	char *value;
};

typedef struct {
	const u8 *base;
	size_t size;
} OtRef;

__pure static inline u64 ot_ref_read_unaligned_le(const u8 *bytes, u32 size)
{
	if (size >= 4) {
		if (size == 8)
			return get_unaligned_le64(bytes);
		else
			return (u64)get_unaligned_le32(bytes);
	} else  {
		if (size == 2)
			return (u64)get_unaligned_le16(bytes);
		else
			return (u64)bytes[0];
	}
}

static inline void ot_ref_write_unaligned_le(u8 *bytes, u32 size, u64 value)
{
	if (size >= 4) {
		if (size == 8)
			put_unaligned_le64(value, bytes);
		else
			put_unaligned_le32((u32)value, bytes);
	} else  {
		if (size == 2)
			put_unaligned_le16((u16)value, bytes);
		else
			bytes[0] = (u8)value;
	}
}

__attribute_const__ static inline u32 ot_ref_get_offset_size(size_t size)
{
	if (size > U16_MAX) {
		if (size > U32_MAX)
			return 8;
		else
			return 4;
	} else {
		if (size > U8_MAX)
			return 2;
		else
			return 1;
	}
}

static inline size_t ot_variant_total_size(size_t body_size, size_t num_offsets)
{
	if (body_size + 1 * num_offsets <= U8_MAX)
		return body_size + 1 * num_offsets;

	if (body_size + 2 * num_offsets <= U16_MAX)
		return body_size + 2 * num_offsets;

	if (body_size + 4 * num_offsets <= U32_MAX)
		return body_size + 4 * num_offsets;

	return body_size + 8 * num_offsets;
}

__pure static inline u64
ot_ref_read_frame_offset(OtRef ref, u32 offset_size, u32 index)
{
	size_t offset_from_end = offset_size * (index + 1);
	return ot_ref_read_unaligned_le(ref.base + ref.size - offset_from_end, offset_size);
}

static inline size_t ot_arrayof_nonfixed_get_length(OtRef v)
{
	if (v.size == 0) {
		return 0;
	} else {
		u32 offset_size = ot_ref_get_offset_size(v.size);
		size_t last_end = ot_ref_read_frame_offset(v, offset_size, 0);
		size_t offsets_array_size;
		if (last_end > v.size)
			return 0;
		offsets_array_size = v.size - last_end;
		if (offsets_array_size % offset_size != 0)
			return 0;
		return offsets_array_size / offset_size;
	}
}

static inline bool ot_arrayof_nonfixed_get_at(OtRef v, size_t index, size_t *start_out, size_t *end_out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t last_end = ot_ref_read_frame_offset(v, offset_size, 0);
	size_t len = (v.size - last_end) / offset_size;
	size_t start = (index > 0) ? ALIGN_TO(ot_ref_read_frame_offset(v, offset_size, len - index), 1) : 0;
	size_t end = ot_ref_read_frame_offset(v, offset_size, len - index - 1);

	if (start > end || end > last_end)
		return false;

	*start_out = start;
	*end_out = end;
	return true;
}


/************** OtChecksum *******************/
#define OT_CHECKSUM_TYPESTRING "ay"

typedef OtRef OtChecksumRef;

static inline bool ot_checksum_from_data(const u8 * data, size_t size, bool allow_empty, OtChecksumRef *out)
{
	if (size != OSTREE_SHA256_DIGEST_LEN &&
	    (size != 0 || !allow_empty))
		return false;

	*out = (OtChecksumRef) { data, size };
	return true;
}

static inline const u8 *ot_checksum_peek(OtChecksumRef v)
{
	return (const u8 *)v.base;
}

static inline void sha256_digest_to_string(const u8 *csum, char *buf)
{
	static const char hexchars[] = "0123456789abcdef";
	u32 i, j;

	for (i = 0, j = 0; i < OSTREE_SHA256_DIGEST_LEN; i++, j += 2) {
		u8 byte = csum[i];
		buf[j] = hexchars[byte >> 4];
		buf[j+1] = hexchars[byte & 0xF];
	}
  buf[j] = '\0';
}

static inline void ot_checksum_to_string(OtChecksumRef v, char *buf)
{
	sha256_digest_to_string(ot_checksum_peek(v), buf);
}


/************** OtCommit *******************/
#define OT_COMMIT_TYPESTRING "(a{sv}aya(say)sstayay)"

typedef OtRef OtCommitRef;

static inline bool ot_commit_from_data(const u8 *data, size_t size, OtCommitRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(size);

	if (size < 8 + offset_size * 6)
		return false;

	*out = (OtCommitRef) { data, size };
	return true;
}

static inline bool ot_commit_get_root_contents(OtCommitRef v, OtChecksumRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t last_end = ot_ref_read_frame_offset(v, offset_size, 4);
	size_t start = ALIGN_TO(last_end, 8) + 8;
	size_t end = ot_ref_read_frame_offset(v, offset_size, 5);

	if (start > end || end > v.size)
		return false;

	return ot_checksum_from_data(STRUCT_MEMBER_P(v.base, start), end - start, false, out);
}

static inline bool ot_commit_get_root_metadata(OtCommitRef v, OtChecksumRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t start = ot_ref_read_frame_offset(v, offset_size, 5);
	size_t end = v.size - offset_size * 6;

	if (start > end || end > v.size)
		return false;

	return ot_checksum_from_data(STRUCT_MEMBER_P(v.base, start), end - start, false, out);
}

/************** OtXattr *******************/
#define OT_XATTR_TYPESTRING "(ayay)"

typedef OtRef OtXattrRef;

static inline bool ot_xattr_from_data(const u8 *data, size_t size, OtXattrRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(size);

	if (size < offset_size * 1)
		return false;

	*out = (OtXattrRef) { data, size };
	return true;
}

static inline const u8 *ot_xattr_get_name(OtXattrRef v, size_t *len_out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t start = 0;
	size_t end = ot_ref_read_frame_offset(v, offset_size, 0);

	if (start > end || end > v.size)
		return NULL;

	*len_out = end - start;
	return STRUCT_MEMBER_P(v.base, start);
}

static inline const u8 *ot_xattr_get_value(OtXattrRef v, size_t *len)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t last_end = ot_ref_read_frame_offset(v, offset_size, 0);
	size_t start = last_end;
	size_t end = v.size - offset_size * 1;

	if (start > end || end > v.size)
		return NULL;

	*len = end - start;
	return STRUCT_MEMBER_P(v.base, start);
}

static inline size_t ot_xattr_compute_size(const char *name, size_t data_size)
{
	size_t name_len = strlen(name) + 1;
	return ot_variant_total_size(name_len + data_size, 1);
}

static inline size_t ot_xattr_serialize(u8 *buf, const char *name, const u8 *data, size_t data_size)
{
	size_t name_len = strlen(name) + 1;
	size_t size = ot_xattr_compute_size(name, data_size);
	u32 offset_size = ot_ref_get_offset_size(size);

	memcpy(buf, name, name_len);
	memcpy(buf + name_len, data, data_size);
	ot_ref_write_unaligned_le(buf + name_len + data_size, offset_size, name_len);

	return size;
}

/************** OtArrayofXattr *******************/
#define OT_ARRAYOF_XATTR_TYPESTRING "a(ayay)"

typedef OtRef OtArrayofXattrRef;

static inline bool ot_arrayof_xattr_from_data(const u8 *data, size_t size, OtArrayofXattrRef *out)
{
	*out = (OtArrayofXattrRef) { data, size };
	return true;
}

static inline size_t ot_arrayof_xattr_get_length(OtArrayofXattrRef v)
{
	return ot_arrayof_nonfixed_get_length(v);
}

static inline bool ot_arrayof_xattr_get_at(OtArrayofXattrRef v, size_t index, OtXattrRef *out)
{
	size_t start, end;

	if (!ot_arrayof_nonfixed_get_at(v, index, &start, &end))
		return false;

	return ot_xattr_from_data(((const u8 *)v.base) + start, end - start, out);
}

/************** OtDirMeta *******************/
#define OT_DIR_META_TYPESTRING "(uuua(ayay))"

/* Note: This is also used for the header of file content. */

typedef OtRef OtDirMetaRef;

static inline bool ot_dir_meta_from_data(const u8 *data, size_t size, OtDirMetaRef *out)
{
	if (size < 12)
		return false;

	*out = (OtDirMetaRef) { data, size };
	return true;
}

static inline u32 ot_dir_meta_get_uid(OtDirMetaRef v)
{
	return be32_to_cpu(STRUCT_MEMBER(u32, v.base, 0));
}

static inline u32 ot_dir_meta_get_gid(OtDirMetaRef v)
{
	return be32_to_cpu(STRUCT_MEMBER(u32, v.base, 4));
}

static inline u32 ot_dir_meta_get_mode(OtDirMetaRef v)
{
	return be32_to_cpu(STRUCT_MEMBER(u32, v.base, 8));
}

static inline bool ot_dir_meta_get_xattrs(OtDirMetaRef v, OtArrayofXattrRef *out)
{
	size_t start = 12;
	size_t end = v.size;

	if (start > end || end > v.size)
		return false;

	return ot_arrayof_xattr_from_data(STRUCT_MEMBER_P(v.base, start), end - start, out);
}

static inline int ot_dir_meta_serialize(u32 uid, u32 gid, u32 mode, struct OtXAttrData *xattrs, size_t num_xattr, OtDirMetaRef *out)
{
	size_t size, i;
	u8 *data;
	size_t array_body_size;
	size_t array_size;

	array_body_size = 0;
	array_size = 0;
	if (num_xattr > 0) {
		for (i = 0; i < num_xattr; i++)
			array_body_size += ot_xattr_compute_size(xattrs[i].name, xattrs[i].size);
		array_size = ot_variant_total_size(array_body_size, num_xattr);
	}

	size = 12 + array_size;

	data = kvmalloc(size, GFP_KERNEL);
	if (data == NULL) {
		return -ENOMEM;
	}

	STRUCT_MEMBER(u32, data, 0) = cpu_to_be32(uid);
	STRUCT_MEMBER(u32, data, 4) = cpu_to_be32(gid);
	STRUCT_MEMBER(u32, data, 8) = cpu_to_be32(mode);

	if (num_xattr > 0) {
		u32 array_offset_size = ot_ref_get_offset_size(array_size);
		u8 *xattrs_data_start = data + 12;
		u8 *xattrs_data;

		for (xattrs_data = xattrs_data_start, i = 0; i < num_xattr; i++) {
			xattrs_data += ot_xattr_serialize(xattrs_data, xattrs[i].name, xattrs[i].value, xattrs[i].size);
			ot_ref_write_unaligned_le(xattrs_data_start + array_body_size + i * array_offset_size, array_offset_size, xattrs_data - xattrs_data_start);
		}
	}

	out->base = data;
	out->size = size;
	return 0;
}

/************** OtFileHeader *******************/
#define OT_FILE_HEADER_TYPESTRING "(uuuusa(ayay))"

static inline int ot_file_header_checksum(OtDirMetaRef dir_meta, const char *target_link, struct sha256_state *sha256_ctx)
{
	size_t body_size, variant_size, target_link_len, size;
	u32 offset_size;
	OtArrayofXattrRef xattrs;
	u8 data[8 + 16];

	if (!ot_dir_meta_get_xattrs(dir_meta, &xattrs)) {
		return -EIO;
	}

	target_link_len = strlen(target_link) + 1;
	body_size =
		16  /* uid, gid, mode, pad */ +
		target_link_len +
		xattrs.size;
	variant_size = ot_variant_total_size(body_size, 1);
	offset_size = ot_ref_get_offset_size(variant_size);
	size = 8 /* lenprefix header */ + variant_size;

	/* length-prefix */
	STRUCT_MEMBER(u32, data, 0) = cpu_to_be32(variant_size);
	STRUCT_MEMBER(u32, data, 4) = 0; /* padding */

	/* variant */
	STRUCT_MEMBER(u32, data + 8, 0) = cpu_to_be32(ot_dir_meta_get_uid (dir_meta));
	STRUCT_MEMBER(u32, data + 8, 4) = cpu_to_be32(ot_dir_meta_get_gid (dir_meta));
	STRUCT_MEMBER(u32, data + 8, 8) = cpu_to_be32(ot_dir_meta_get_mode (dir_meta));
	STRUCT_MEMBER(u32, data + 8, 12) = 0;

	sha256_update(sha256_ctx, data, 8 + 16);

	sha256_update(sha256_ctx, target_link, target_link_len);
	sha256_update(sha256_ctx, xattrs.base, xattrs.size);

	ot_ref_write_unaligned_le(data, offset_size, 16 + target_link_len);
	sha256_update(sha256_ctx, data, offset_size);

	return 0;

}

/************** OtTreeFile *******************/
#define OT_TREE_FILE_TYPESTRING "(say)"

typedef OtRef OtTreeFileRef;

static inline bool ot_tree_file_from_data(const u8 * data, size_t size, OtTreeFileRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(size);

	if (size < offset_size * 1)
		return false;

	*out = (OtTreeFileRef) { data, size };
	return true;
}

static inline const char *ot_tree_file_get_name(OtTreeFileRef v, size_t *len_out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	const char *base = (const char *)v.base;
	size_t start = 0;
	size_t end = ot_ref_read_frame_offset(v, offset_size, 0);

	if (start > end || end > v.size || base[end-1] != 0)
		return NULL;

	if (len_out)
		*len_out = end - start - 1; /* Not including terminating zero */

	return &STRUCT_MEMBER(const char, v.base, start);
}

static inline bool ot_tree_file_get_checksum(OtTreeFileRef v, OtChecksumRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t last_end = ot_ref_read_frame_offset(v, offset_size, 0);
	size_t start = last_end;
	size_t end = v.size - offset_size * 1;

	if (start > end || end > v.size)
		return false;

	return ot_checksum_from_data(STRUCT_MEMBER_P(v.base, start), end - start, false, out);
}

/************** OtTreeDir *******************/
#define OT_TREE_DIR_TYPESTRING "(sayay)"

typedef OtRef OtTreeDirRef;

static inline bool ot_tree_dir_from_data(const u8 * data, size_t size, OtTreeDirRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(size);

	if (size < offset_size * 2)
		return false;

	*out = (OtTreeDirRef) { data, size };
	return true;
}

static inline const char *ot_tree_dir_get_name(OtTreeDirRef v, size_t *len_out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	const char *base = (const char *)v.base;
	size_t start = 0;
	size_t end = ot_ref_read_frame_offset(v, offset_size, 0);

	if (start > end || end > v.size || base[end-1] != 0)
		return NULL;

	if (len_out)
		*len_out = end - start - 1; /* Not including terminating zero */

	return &STRUCT_MEMBER(const char, v.base, start);
}

static inline bool ot_tree_dir_get_tree_checksum(OtTreeDirRef v, OtChecksumRef *out)
{
	u32 offset_size = ot_ref_get_offset_size (v.size);
	size_t start = ot_ref_read_frame_offset(v, offset_size, 0);
	size_t end = ot_ref_read_frame_offset(v, offset_size, 1);

	if (start > end || end > v.size)
		return false;

	return ot_checksum_from_data(STRUCT_MEMBER_P(v.base, start), end - start, false, out);
}

static inline bool ot_tree_dir_get_meta_checksum(OtTreeDirRef v, OtChecksumRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t start = ot_ref_read_frame_offset(v, offset_size, 1);
	size_t end = v.size - offset_size * 2;

	if (start > end || end > v.size)
		return false;

	return ot_checksum_from_data(STRUCT_MEMBER_P(v.base, start), end - start, false, out);
}

/************** OtArrayofTreeFile *******************/
#define OT_ARRAYOF_TREE_FILE_TYPESTRING "a(say)"

typedef OtRef OtArrayofTreeFileRef;

static inline bool ot_arrayof_tree_file_from_data(const u8 * data, size_t size, OtArrayofTreeFileRef *out)
{
	*out = (OtArrayofTreeFileRef) { data, size };
	return true;
}

static inline size_t ot_arrayof_tree_file_get_length(OtArrayofTreeFileRef v)
{
	return ot_arrayof_nonfixed_get_length(v);
}

static inline bool ot_arrayof_tree_file_get_at(OtArrayofTreeFileRef v, size_t index, OtTreeFileRef *out)
{
	size_t start, end;

	if (!ot_arrayof_nonfixed_get_at(v, index, &start, &end))
		return false;

	return ot_tree_file_from_data(((const u8 *)v.base) + start, end - start, out);
}

/************** OtArrayofTreeDir *******************/
#define OT_ARRAYOF_TREE_DIR_TYPESTRING "a(say)"

typedef OtRef OtArrayofTreeDirRef;

static inline bool ot_arrayof_tree_dir_from_data(const u8 * data, size_t size, OtArrayofTreeDirRef *out)
{
	*out = (OtArrayofTreeDirRef) { data, size };
	return true;
}

static inline size_t ot_arrayof_tree_dir_get_length(OtArrayofTreeDirRef v)
{
	return ot_arrayof_nonfixed_get_length(v);
}

static inline bool ot_arrayof_tree_dir_get_at(OtArrayofTreeDirRef v, size_t index, OtTreeDirRef *out)
{
	size_t start, end;

  if (!ot_arrayof_nonfixed_get_at(v, index, &start, &end))
    return false;

  return ot_tree_dir_from_data(((const u8 *)v.base) + start, end - start, out);
}

/************** OtTreeMeta *******************/
#define OT_TREE_META_TYPESTRING "(a(say)a(sayay))"

typedef OtRef OtTreeMetaRef;

static inline bool ot_tree_meta_from_data(const u8 * data, size_t size, OtTreeMetaRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(size);

	if (size < offset_size * 1)
		return false;

	*out = (OtTreeMetaRef) { data, size };
	return true;
}

static inline bool ot_tree_meta_get_files(OtTreeMetaRef v, OtArrayofTreeFileRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t start = 0;
	size_t end = ot_ref_read_frame_offset(v, offset_size, 0);

	if (start > end || end > v.size)
		return false;

	return ot_arrayof_tree_file_from_data(STRUCT_MEMBER_P(v.base, start), end - start, out);
}

static inline bool ot_tree_meta_get_dirs(OtTreeMetaRef v, OtArrayofTreeDirRef *out)
{
	u32 offset_size = ot_ref_get_offset_size(v.size);
	size_t start = ot_ref_read_frame_offset(v, offset_size, 0);
	size_t end = v.size - offset_size * 1;

	if (start > end || end > v.size)
		return false;

	return ot_arrayof_tree_dir_from_data(STRUCT_MEMBER_P(v.base, start), end - start, out);
}
