// SPDX-License-Identifier: GPL-2.0
/*
 * famfs - dax file system for shared fabric-attached memory
 *
 * Copyright 2023-2024 Micron Technology, Inc.
 *
 * This file system, originally based on ramfs the dax support from xfs,
 * is intended to allow multiple host systems to mount a common file system
 * view of dax files that map to shared memory.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/dax.h>
#include <linux/uio.h>
#include <linux/iomap.h>
#include <uapi/linux/famfs_ioctl.h>
#include "famfs_internal.h"

/**
 * famfs_map_meta_alloc() - Allocate famfs file metadata
 * @mapp:       Pointer to an mcache_map_meta pointer
 * @ext_count:  The number of extents needed
 */
static int
famfs_meta_alloc(
	struct famfs_file_meta  **metap,
	size_t                    ext_count)
{
	struct famfs_file_meta *meta;
	size_t                  metasz;

	*metap = NULL;

	metasz = sizeof(*meta) + sizeof(*(meta->tfs_extents)) * ext_count;

	meta = kzalloc(metasz, GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->tfs_extent_ct = ext_count;
	*metap = meta;

	return 0;
}

static void
famfs_meta_free(
	struct famfs_file_meta *map)
{
	kfree(map);
}

/**
 * famfs_file_init_dax() - FAMFSIOC_MAP_CREATE ioctl handler
 * @file:
 * @arg:        ptr to struct mcioc_map in user space
 *
 * Setup the dax mapping for a file. Files are created empty, and then function is called
 * (by famfs_file_ioctl()) to setup the mapping and set the file size.
 */
static int
famfs_file_init_dax(
	struct file    *file,
	void __user    *arg)
{
	struct famfs_extent    *tfs_extents = NULL;
	struct famfs_file_meta *meta = NULL;
	struct inode           *inode;
	struct famfs_ioc_map    imap;
	struct famfs_fs_info   *fsi;
	struct super_block     *sb;
	int    alignment_errs = 0;
	size_t extent_total = 0;
	size_t ext_count;
	int    rc = 0;
	int    i;

	rc = copy_from_user(&imap, arg, sizeof(imap));
	if (rc)
		return -EFAULT;

	ext_count = imap.ext_list_count;
	if (ext_count < 1) {
		rc = -ENOSPC;
		goto errout;
	}

	if (ext_count > FAMFS_MAX_EXTENTS) {
		rc = -E2BIG;
		goto errout;
	}

	inode = file_inode(file);
	if (!inode) {
		rc = -EBADF;
		goto errout;
	}
	sb  = inode->i_sb;
	fsi = inode->i_sb->s_fs_info;

	tfs_extents = &imap.ext_list[0];

	rc = famfs_meta_alloc(&meta, ext_count);
	if (rc)
		goto errout;

	meta->file_type = imap.file_type;
	meta->file_size = imap.file_size;

	/* Fill in the internal file metadata structure */
	for (i = 0; i < imap.ext_list_count; i++) {
		size_t len;
		off_t  offset;

		offset = imap.ext_list[i].offset;
		len    = imap.ext_list[i].len;

		extent_total += len;

		if (WARN_ON(offset == 0 && meta->file_type != FAMFS_SUPERBLOCK)) {
			rc = -EINVAL;
			goto errout;
		}

		meta->tfs_extents[i].offset = offset;
		meta->tfs_extents[i].len    = len;

		/* All extent addresses/offsets must be 2MiB aligned,
		 * and all but the last length must be a 2MiB multiple.
		 */
		if (!IS_ALIGNED(offset, PMD_SIZE)) {
			pr_err("%s: error ext %d hpa %lx not aligned\n",
			       __func__, i, offset);
			alignment_errs++;
		}
		if (i < (imap.ext_list_count - 1) && !IS_ALIGNED(len, PMD_SIZE)) {
			pr_err("%s: error ext %d length %ld not aligned\n",
			       __func__, i, len);
			alignment_errs++;
		}
	}

	/*
	 * File size can be <= ext list size, since extent sizes are constrained
	 * to PMD multiples
	 */
	if (imap.file_size > extent_total) {
		pr_err("%s: file size %lld larger than ext list size %lld\n",
		       __func__, (u64)imap.file_size, (u64)extent_total);
		rc = -EINVAL;
		goto errout;
	}

	if (alignment_errs > 0) {
		pr_err("%s: there were %d alignment errors in the extent list\n",
		       __func__, alignment_errs);
		rc = -EINVAL;
		goto errout;
	}

	/* Publish the famfs metadata on inode->i_private */
	inode_lock(inode);
	if (inode->i_private) {
		rc = -EEXIST; /* file already has famfs metadata */
	} else {
		inode->i_private = meta;
		i_size_write(inode, imap.file_size);
		inode->i_flags |= S_DAX;
	}
	inode_unlock(inode);

 errout:
	if (rc)
		famfs_meta_free(meta);

	return rc;
}

/**
 * famfs_file_ioctl() -  top-level famfs file ioctl handler
 * @file:
 * @cmd:
 * @arg:
 */
static
long
famfs_file_ioctl(
	struct file    *file,
	unsigned int    cmd,
	unsigned long   arg)
{
	long rc;

	switch (cmd) {
	case FAMFSIOC_NOP:
		rc = 0;
		break;

	case FAMFSIOC_MAP_CREATE:
		rc = famfs_file_init_dax(file, (void *)arg);
		break;

	case FAMFSIOC_MAP_GET: {
		struct inode *inode = file_inode(file);
		struct famfs_file_meta *meta = inode->i_private;
		struct famfs_ioc_map umeta;

		memset(&umeta, 0, sizeof(umeta));

		if (meta) {
			/* TODO: do more to harmonize these structures */
			umeta.extent_type    = meta->tfs_extent_type;
			umeta.file_size      = i_size_read(inode);
			umeta.ext_list_count = meta->tfs_extent_ct;

			rc = copy_to_user((void __user *)arg, &umeta, sizeof(umeta));
			if (rc)
				pr_err("%s: copy_to_user returned %ld\n", __func__, rc);

		} else {
			rc = -EINVAL;
		}
	}
		break;
	case FAMFSIOC_MAP_GETEXT: {
		struct inode *inode = file_inode(file);
		struct famfs_file_meta *meta = inode->i_private;

		if (meta)
			rc = copy_to_user((void __user *)arg, meta->tfs_extents,
					  meta->tfs_extent_ct * sizeof(struct famfs_extent));
		else
			rc = -EINVAL;
	}
		break;
	default:
		rc = -ENOTTY;
		break;
	}

	return rc;
}

/*********************************************************************
 * file_operations
 */

/* Reject I/O to files that aren't in a valid state */
static ssize_t
famfs_file_invalid(struct inode *inode)
{
	size_t i_size       = i_size_read(inode);
	struct famfs_file_meta *meta = inode->i_private;

	if (!meta) {
		pr_err("%s: un-initialized famfs file\n", __func__);
		return -EIO;
	}
	if (i_size != meta->file_size) {
		pr_err("%s: something changed the size from  %ld to %ld\n",
		       __func__, meta->file_size, i_size);
		meta->error = 1;
		return -ENXIO;
	}
	if (!IS_DAX(inode)) {
		pr_err("%s: inode %llx IS_DAX is false\n", __func__, (u64)inode);
		meta->error = 1;
		return -ENXIO;
	}
	if (meta->error) {
		pr_err("%s: previously detected metadata errors\n", __func__);
		meta->error = 1;
		return -EIO;
	}
	return 0;
}

static ssize_t
famfs_dax_read_iter(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	size_t i_size       = i_size_read(inode);
	size_t count        = iov_iter_count(to);
	size_t max_count;
	ssize_t rc;

	rc = famfs_file_invalid(inode);
	if (rc)
		return rc;

	max_count = max_t(size_t, 0, i_size - iocb->ki_pos);

	if (count > max_count)
		iov_iter_truncate(to, max_count);

	if (!iov_iter_count(to))
		return 0;

	rc = dax_iomap_rw(iocb, to, &famfs_iomap_ops);

	file_accessed(iocb->ki_filp);
	return rc;
}

/**
 * famfs_write_iter()
 *
 * We need our own write-iter in order to prevent append
 */
static ssize_t
famfs_dax_write_iter(
	struct kiocb    *iocb,
	struct iov_iter *from)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	size_t i_size       = i_size_read(inode);
	size_t count        = iov_iter_count(from);
	size_t max_count;
	ssize_t rc;

	rc = famfs_file_invalid(inode);
	if (rc)
		return rc;

	/* Starting offset of write is: iocb->ki_pos
	 * length is iov_iter_count(from)
	 */
	max_count = max_t(size_t, 0, i_size - iocb->ki_pos);

	/* If write would go past EOF, truncate it to end at EOF since famfs does not
	 * alloc-on-write
	 */
	if (count > max_count)
		iov_iter_truncate(from, max_count);

	if (!iov_iter_count(from))
		return 0;

	return dax_iomap_rw(iocb, from, &famfs_iomap_ops);
}

static int
famfs_file_mmap(
	struct file		*file,
	struct vm_area_struct	*vma)
{
	struct inode		*inode = file_inode(file);
	ssize_t rc;

	rc = famfs_file_invalid(inode);
	if (rc)
		return (int)rc;

	file_accessed(file);
	vma->vm_ops = &famfs_file_vm_ops;
	vm_flags_set(vma, VM_HUGEPAGE);
	return 0;
}

const struct file_operations famfs_file_operations = {
	.owner             = THIS_MODULE,

	/* Custom famfs operations */
	.write_iter	   = famfs_dax_write_iter,
	.read_iter	   = famfs_dax_read_iter,
	.unlocked_ioctl    = famfs_file_ioctl,
	.mmap		   = famfs_file_mmap,

	/* Force PMD alignment for mmap */
	.get_unmapped_area = thp_get_unmapped_area,

	/* Generic Operations */
	.fsync		   = noop_fsync,
	.splice_read	   = filemap_splice_read,
	.splice_write	   = iter_file_splice_write,
	.llseek		   = generic_file_llseek,
};

/*********************************************************************
 * iomap_operations
 *
 * This stuff uses the iomap (dax-related) helpers to resolve file offsets to
 * offsets within a dax device.
 */

/**
 * famfs_meta_to_dax_offset()
 *
 * This function is called by famfs_iomap_begin() to resolve an offset in a file to
 * an offset in a dax device. This is upcalled from dax from calls to both
 * dax_iomap_fault() and dax_iomap_rw(). Dax finishes the job resolving a fault to
 * a specific physical page (the fault case) or doing a memcpy variant (the rw case)
 *
 * Pages can be PTE (4k), PMD (2MiB) or (theoretically) PuD (1GiB)
 * (these sizes are for X86; may vary on other cpu architectures
 *
 * @inode  - the file where the fault occurred
 * @iomap  - struct iomap to be filled in to indicate where to find the right memory, relative
 *           to a dax device.
 * @offset - the offset within the file where the fault occurred (will be page boundary)
 * @len    - the length of the faulted mapping (will be a page multiple)
 *           (will be trimmed in *iomap if it's disjoint in the extent list)
 * @flags
 */
static int
famfs_meta_to_dax_offset(
	struct inode *inode,
	struct iomap *iomap,
	loff_t        offset,
	loff_t        len,
	unsigned int  flags)
{
	struct famfs_file_meta *meta = (struct famfs_file_meta *)inode->i_private;
	int i;
	loff_t local_offset = offset;
	struct famfs_fs_info  *fsi = inode->i_sb->s_fs_info;

	iomap->offset = offset; /* file offset */

	for (i = 0; i < meta->tfs_extent_ct; i++) {
		loff_t dax_ext_offset = meta->tfs_extents[i].offset;
		loff_t dax_ext_len    = meta->tfs_extents[i].len;

		if ((dax_ext_offset == 0) && (meta->file_type != FAMFS_SUPERBLOCK))
			pr_err("%s: zero offset on non-superblock file!!\n", __func__);

		/* local_offset is the offset minus the size of extents skipped so far;
		 * If local_offset < dax_ext_len, the data of interest starts in this extent
		 */
		if (local_offset < dax_ext_len) {
			loff_t ext_len_remainder = dax_ext_len - local_offset;

			/*+
			 * OK, we found the file metadata extent where this data begins
			 * @local_offset      - The offset within the current extent
			 * @ext_len_remainder - Remaining length of ext after skipping local_offset
			 *
			 * iomap->addr is the offset within the dax device where that data
			 * starts
			 */
			iomap->addr    = dax_ext_offset + local_offset; /* dax dev offset */
			iomap->offset  = offset; /* file offset */
			iomap->length  = min_t(loff_t, len, ext_len_remainder);
			iomap->dax_dev = fsi->dax_devp;
			iomap->type    = IOMAP_MAPPED;
			iomap->flags   = flags;

			return 0;
		}
		local_offset -= dax_ext_len; /* Get ready for the next extent */
	}

	/* Set iomap to zero length in this case, and return 0
	 * This just means that the r/w is past EOF
	 */
	iomap->addr    = offset;
	iomap->offset  = offset; /* file offset */
	iomap->length  = 0; /* this had better result in no access to dax mem */
	iomap->dax_dev = fsi->dax_devp;
	iomap->type    = IOMAP_MAPPED;
	iomap->flags   = flags;

	return 0;
}

/**
 * famfs_iomap_begin()
 *
 * This function is pretty simple because files are
 * * never partially allocated
 * * never have holes (never sparse)
 * * never "allocate on write"
 */
static int
famfs_iomap_begin(
	struct inode	       *inode,
	loff_t			offset,
	loff_t			length,
	unsigned int		flags,
	struct iomap	       *iomap,
	struct iomap	       *srcmap)
{
	struct famfs_file_meta *meta = inode->i_private;
	size_t size;
	int rc;

	size = i_size_read(inode);

	WARN_ON(size != meta->file_size);

	rc = famfs_meta_to_dax_offset(inode, iomap, offset, length, flags);

	return rc;
}

/* Note: We never need a special set of write_iomap_ops because famfs never
 * performs allocation on write.
 */
const struct iomap_ops famfs_iomap_ops = {
	.iomap_begin		= famfs_iomap_begin,
};

/*********************************************************************
 * vm_operations
 */
static vm_fault_t
__famfs_filemap_fault(
	struct vm_fault		*vmf,
	unsigned int		pe_size,
	bool			write_fault)
{
	struct inode		*inode = file_inode(vmf->vma->vm_file);
	vm_fault_t		ret;

	if (write_fault) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	if (IS_DAX(inode)) {
		pfn_t pfn;

		ret = dax_iomap_fault(vmf, pe_size, &pfn, NULL, &famfs_iomap_ops);
		if (ret & VM_FAULT_NEEDDSYNC)
			ret = dax_finish_sync_fault(vmf, pe_size, pfn);
	} else {
		/* All famfs faults will be dax... */
		pr_err("%s: oops, non-dax fault\n", __func__);
		ret = VM_FAULT_SIGBUS;
	}

	if (write_fault)
		sb_end_pagefault(inode->i_sb);

	return ret;
}

static inline bool
famfs_is_write_fault(
	struct vm_fault		*vmf)
{
	return (vmf->flags & FAULT_FLAG_WRITE) &&
	       (vmf->vma->vm_flags & VM_SHARED);
}

static vm_fault_t
famfs_filemap_fault(
	struct vm_fault		*vmf)
{
	/* DAX can shortcut the normal fault path on write faults! */
	return __famfs_filemap_fault(vmf, 0,
			IS_DAX(file_inode(vmf->vma->vm_file)) && famfs_is_write_fault(vmf));
}

static vm_fault_t
famfs_filemap_huge_fault(
	struct vm_fault	*vmf,
	unsigned int	 pe_size)
{
	if (!IS_DAX(file_inode(vmf->vma->vm_file))) {
		pr_err("%s: file not marked IS_DAX!!\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	/* DAX can shortcut the normal fault path on write faults! */
	return __famfs_filemap_fault(vmf, pe_size, famfs_is_write_fault(vmf));
}

static vm_fault_t
famfs_filemap_page_mkwrite(
	struct vm_fault		*vmf)
{
	return __famfs_filemap_fault(vmf, 0, true);
}

static vm_fault_t
famfs_filemap_pfn_mkwrite(
	struct vm_fault		*vmf)
{
	return __famfs_filemap_fault(vmf, 0, true);
}

static vm_fault_t
famfs_filemap_map_pages(
	struct vm_fault	       *vmf,
	pgoff_t			start_pgoff,
	pgoff_t			end_pgoff)
{
	vm_fault_t ret;

	ret = filemap_map_pages(vmf, start_pgoff, end_pgoff);
	return ret;
}

const struct vm_operations_struct famfs_file_vm_ops = {
	.fault		= famfs_filemap_fault,
	.huge_fault	= famfs_filemap_huge_fault,
	.map_pages	= famfs_filemap_map_pages,
	.page_mkwrite	= famfs_filemap_page_mkwrite,
	.pfn_mkwrite	= famfs_filemap_pfn_mkwrite,
};

