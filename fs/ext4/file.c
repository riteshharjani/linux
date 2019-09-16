// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include <linux/backing-dev.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "truncate.h"

static bool ext4_dio_checks(struct inode *inode)
{
#if IS_ENABLED(CONFIG_FS_ENCRYPTION)
	if (IS_ENCRYPTED(inode))
		return false;
#endif
	if (ext4_should_journal_data(inode))
		return false;
	if (ext4_has_inline_data(inode))
		return false;
	return true;
}

static ssize_t ext4_dio_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	/*
	 * Get exclusion from truncate and other inode operations.
	 */
	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!ext4_ilock_nowait(inode, EXT4_IOLOCK_SHARED))
			return -EAGAIN;
	} else {
		ext4_ilock(inode, EXT4_IOLOCK_SHARED);
	}

	if (!ext4_dio_checks(inode)) {
		ext4_iunlock(inode, EXT4_IOLOCK_SHARED);
		/*
		 * Fallback to buffered IO if the operation being
		 * performed on the inode is not supported by direct
		 * IO. The IOCB_DIRECT flag flags needs to be cleared
		 * here to ensure that the direct IO code path within
		 * generic_file_read_iter() is not taken again.
		 */
		iocb->ki_flags &= ~IOCB_DIRECT;
		return generic_file_read_iter(iocb, to);
	}

	ret = iomap_dio_rw(iocb, to, &ext4_iomap_ops, NULL);
	ext4_iunlock(inode, EXT4_IOLOCK_SHARED);

	file_accessed(iocb->ki_filp);
	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t ext4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!ext4_ilock_nowait(inode, EXT4_IOLOCK_SHARED))
			return -EAGAIN;
	} else {
		ext4_ilock(inode, EXT4_IOLOCK_SHARED);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		ext4_iunlock(inode, EXT4_IOLOCK_SHARED);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_read_iter(iocb, to);
	}
	ret = dax_iomap_rw(iocb, to, &ext4_iomap_ops);
	ext4_iunlock(inode, EXT4_IOLOCK_SHARED);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

	if (IS_DAX(inode))
		return ext4_dax_read_iter(iocb, to);

	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_read_iter(iocb, to);
	return generic_file_read_iter(iocb, to);
}

/*
 * Called when an inode is released. Note that this is different
 * from ext4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext4_release_file(struct inode *inode, struct file *filp)
{
	if (ext4_test_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE)) {
		ext4_alloc_da_blocks(inode);
		ext4_clear_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1) &&
		        !EXT4_I(inode)->i_reserved_data_blocks)
	{
		down_write(&EXT4_I(inode)->i_data_sem);
		ext4_discard_preallocations(inode);
		up_write(&EXT4_I(inode)->i_data_sem);
	}
	if (is_dx(inode) && filp->private_data)
		ext4_htree_free_dir_info(filp->private_data);

	return 0;
}

/*
 * This tests whether the IO in question is block-aligned or not.
 * Ext4 utilizes unwritten extents when hole-filling during direct IO, and they
 * are converted to written only after the IO is complete.  Until they are
 * mapped, these blocks appear as holes, so dio_zero_block() will assume that
 * it needs to zero out portions of the start and/or end block.  If 2 AIO
 * threads are at work on the same unwritten block, they must be synchronized
 * or one thread will zero the other's data, causing corruption.
 */
static int
ext4_unaligned_aio(struct inode *inode, struct iov_iter *from, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	int blockmask = sb->s_blocksize - 1;

	if (pos >= ALIGN(i_size_read(inode), sb->s_blocksize))
		return 0;

	if ((pos | iov_iter_alignment(from)) & blockmask)
		return 1;

	return 0;
}

/* Is IO overwriting allocated and initialized blocks? */
static bool ext4_overwrite_io(struct inode *inode, loff_t pos, loff_t len)
{
	struct ext4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = EXT4_MAX_BLOCKS(len, pos, blkbits);
	blklen = map.m_len;

	err = ext4_map_blocks(NULL, inode, &map, 0);
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. To exclude
	 * unwritten extents, we need to check m_flags.
	 */
	return err == blklen && (map.m_flags & EXT4_MAP_MAPPED);
}

static ssize_t ext4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	ret = file_modified(iocb->ki_filp);
	if (ret)
		return 0;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}
	return iov_iter_count(from);
}

static ssize_t ext4_buffered_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	ext4_ilock(inode, EXT4_IOLOCK_EXCL);
	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	current->backing_dev_info = inode_to_bdi(inode);
	ret = generic_perform_write(iocb->ki_filp, from, iocb->ki_pos);
	current->backing_dev_info = NULL;
out:
	ext4_iunlock(inode, EXT4_IOLOCK_EXCL);
	if (likely(ret > 0)) {
		iocb->ki_pos += ret;
		ret = generic_write_sync(iocb, ret);
	}
	return ret;
}

static int ext4_handle_inode_extension(struct inode *inode, loff_t offset,
				       ssize_t len, size_t count)
{
	handle_t *handle;
	bool truncate = false;
	ext4_lblk_t written_blk, end_blk;
	int ret = 0, blkbits = inode->i_blkbits;

	handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto orphan_del;
	}

	if (ext4_update_inode_size(inode, offset + len))
		ext4_mark_inode_dirty(handle, inode);

	/*
	 * We may need truncate allocated but not written blocks
	 * beyond EOF.
	 */
	written_blk = ALIGN(offset + len, 1 << blkbits);
	end_blk = ALIGN(offset + count, 1 << blkbits);
	if (written_blk < end_blk && ext4_can_truncate(inode))
		truncate = true;

	/*
	 * Remove the inode from the orphan list if it has been
	 * extended and everything went OK.
	 */
	if (!truncate && inode->i_nlink)
		ext4_orphan_del(handle, inode);
	ext4_journal_stop(handle);

	if (truncate) {
		ext4_truncate_failed_write(inode);
orphan_del:
		/*
		 * If the truncate operation failed early the inode
		 * may still be on the orphan list. In that case, we
		 * need try remove the inode from the linked list in
		 * memory.
		 */
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}
	return ret;
}

/*
 * The inode may have been placed onto the orphan list or has had
 * blocks allocated beyond EOF as a result of an extension. We need to
 * ensure that any necessary cleanup routines are performed if the
 * error path has been taken for a write.
 */
static int ext4_handle_failed_inode_extension(struct inode *inode, loff_t size)
{
	handle_t *handle;

	if (size > i_size_read(inode))
		ext4_truncate_failed_write(inode);

	if (!list_empty(&EXT4_I(inode)->i_orphan)) {
		handle = ext4_journal_start(inode, EXT4_HT_INODE, 2);
		if (IS_ERR(handle)) {
			if (inode->i_nlink)
				ext4_orphan_del(NULL, inode);
			return PTR_ERR(handle);
		}
		if (inode->i_nlink)
			ext4_orphan_del(handle, inode);
		ext4_journal_stop(handle);
	}
	return 0;
}

/*
 * For a write that extends the inode size, ext4_dio_write_iter() will
 * wait for the write to complete. Consequently, operations performed
 * within this function are still covered by the inode_lock(). On
 * success, this function returns 0.
 */
static int ext4_dio_write_end_io(struct kiocb *iocb, ssize_t size, int error,
				 unsigned int flags)
{
	int ret;
	loff_t offset = iocb->ki_pos;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (error) {
		ret = ext4_handle_failed_inode_extension(inode, offset + size);
		return ret ? ret : error;
	}

	if (flags & IOMAP_DIO_UNWRITTEN) {
		ret = ext4_convert_unwritten_extents(NULL, inode,
						     offset, size);
		if (ret)
			return ret;
	}

	if (offset + size > i_size_read(inode)) {
		ret = ext4_handle_inode_extension(inode, offset, size, 0);
		if (ret)
			return ret;
	}
	return 0;
}

static ssize_t ext4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	size_t count;
	loff_t offset = iocb->ki_pos;
	struct inode *inode = file_inode(iocb->ki_filp);
	bool extend = false, overwrite = false, unaligned_aio = false;
	unsigned int iolock = EXT4_IOLOCK_EXCL;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!ext4_ilock_nowait(inode, iolock))
			return -EAGAIN;
	} else {
		ext4_ilock(inode, iolock);
	}

	if (!ext4_dio_checks(inode)) {
		ext4_iunlock(inode, iolock);
		/*
		 * Fallback to buffered IO if the operation on the
		 * inode is not supported by direct IO.
		 */
		return ext4_buffered_write_iter(iocb, from);
	}

	ret = ext4_write_checks(iocb, from);
	if (ret <= 0) {
		ext4_iunlock(inode, iolock);
		return ret;
	}

	/*
	 * Unaligned direct AIO must be serialized among each other as
	 * the zeroing of partial blocks of two competing unaligned
	 * AIOs can result in data corruption.
	 */
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS) &&
	    !is_sync_kiocb(iocb) && ext4_unaligned_aio(inode, from, offset)) {
		unaligned_aio = true;
		inode_dio_wait(inode);
	}

	/*
	 * Determine whether the IO operation will overwrite allocated
	 * and initialized blocks. If so, check to see whether it is
	 * possible to take the dioread_nolock path.
	 */
	count = iov_iter_count(from);
	if (!unaligned_aio && ext4_overwrite_io(inode, offset, count) &&
	    ext4_should_dioread_nolock(inode)) {
		overwrite = true;
		ext4_ilock_demote(inode, iolock);
		iolock = EXT4_IOLOCK_SHARED;
	}

	if (offset + count > i_size_read(inode) ||
	    offset + count > EXT4_I(inode)->i_disksize) {
		ext4_update_i_disksize(inode, inode->i_size);
		extend = true;
	}

	ret = iomap_dio_rw(iocb, from, &ext4_iomap_ops, ext4_dio_write_end_io);

	/*
	 * Unaligned direct AIO must be the only IO in flight or else
	 * any overlapping aligned IO after unaligned IO might result
	 * in data corruption. We also need to wait here in the case
	 * where the inode is being extended so that inode extension
	 * routines in ext4_dio_write_end_io() are covered by the
	 * inode_lock().
	 */
	if (ret == -EIOCBQUEUED && (unaligned_aio || extend))
		inode_dio_wait(inode);

	ext4_iunlock(inode, iolock);

	if (ret >= 0 && iov_iter_count(from))
		return ext4_buffered_write_iter(iocb, from);
	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t
ext4_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	int error = 0;
	loff_t offset;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!ext4_ilock_nowait(inode, EXT4_IOLOCK_EXCL))
			return -EAGAIN;
	} else {
		ext4_ilock(inode, EXT4_IOLOCK_EXCL);
	}

	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	ret = dax_iomap_rw(iocb, from, &ext4_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode))
		error = ext4_handle_inode_extension(inode, offset, ret,
						    iov_iter_count(from));

	if (ret < 0)
		error = ext4_handle_failed_inode_extension(inode,
							   iocb->ki_pos);

	if (error)
		ret = error;
out:
	ext4_iunlock(inode, EXT4_IOLOCK_EXCL);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
#endif

static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	if (IS_DAX(inode))
		return ext4_dax_write_iter(iocb, from);

	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_write_iter(iocb, from);
	return ext4_buffered_write_iter(iocb, from);
}

#ifdef CONFIG_FS_DAX
static vm_fault_t ext4_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	int error = 0;
	vm_fault_t result;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for pe_size != PE_SIZE_PTE (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		down_read(&EXT4_I(inode)->i_mmap_sem);
retry:
		handle = ext4_journal_start_sb(sb, EXT4_HT_WRITE_PAGE,
					       EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			up_read(&EXT4_I(inode)->i_mmap_sem);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		down_read(&EXT4_I(inode)->i_mmap_sem);
	}
	result = dax_iomap_fault(vmf, pe_size, &pfn, &error, &ext4_iomap_ops);
	if (write) {
		ext4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    ext4_should_retry_alloc(sb, &retries))
			goto retry;
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, pe_size, pfn);
		up_read(&EXT4_I(inode)->i_mmap_sem);
		sb_end_pagefault(sb);
	} else {
		up_read(&EXT4_I(inode)->i_mmap_sem);
	}

	return result;
}

static vm_fault_t ext4_dax_fault(struct vm_fault *vmf)
{
	return ext4_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct ext4_dax_vm_ops = {
	.fault		= ext4_dax_fault,
	.huge_fault	= ext4_dax_huge_fault,
	.page_mkwrite	= ext4_dax_fault,
	.pfn_mkwrite	= ext4_dax_fault,
};
#else
#define ext4_dax_vm_ops	ext4_file_vm_ops
#endif

static const struct vm_operations_struct ext4_file_vm_ops = {
	.fault		= ext4_filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = ext4_page_mkwrite,
};

static int ext4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct dax_device *dax_dev = sbi->s_daxdev;

	if (unlikely(ext4_forced_shutdown(sbi)))
		return -EIO;

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, dax_dev))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &ext4_dax_vm_ops;
		vma->vm_flags |= VM_HUGEPAGE;
	} else {
		vma->vm_ops = &ext4_file_vm_ops;
	}
	return 0;
}

static int ext4_sample_last_mounted(struct super_block *sb,
				    struct vfsmount *mnt)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct path path;
	char buf[64], *cp;
	handle_t *handle;
	int err;

	if (likely(sbi->s_mount_flags & EXT4_MF_MNTDIR_SAMPLED))
		return 0;

	if (sb_rdonly(sb) || !sb_start_intwrite_trylock(sb))
		return 0;

	sbi->s_mount_flags |= EXT4_MF_MNTDIR_SAMPLED;
	/*
	 * Sample where the filesystem has been mounted and
	 * store it in the superblock for sysadmin convenience
	 * when trying to sort through large numbers of block
	 * devices or filesystem images.
	 */
	memset(buf, 0, sizeof(buf));
	path.mnt = mnt;
	path.dentry = mnt->mnt_root;
	cp = d_path(&path, buf, sizeof(buf));
	err = 0;
	if (IS_ERR(cp))
		goto out;

	handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
	err = PTR_ERR(handle);
	if (IS_ERR(handle))
		goto out;
	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = ext4_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto out_journal;
	strlcpy(sbi->s_es->s_last_mounted, cp,
		sizeof(sbi->s_es->s_last_mounted));
	ext4_handle_dirty_super(handle, sb);
out_journal:
	ext4_journal_stop(handle);
out:
	sb_end_intwrite(sb);
	return err;
}

static int ext4_file_open(struct inode * inode, struct file * filp)
{
	int ret;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	ret = ext4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	ret = fscrypt_file_open(inode, filp);
	if (ret)
		return ret;

	/*
	 * Set up the jbd2_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	filp->f_mode |= FMODE_NOWAIT;
	return dquot_file_open(inode, filp);
}

/*
 * ext4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t ext4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		maxbytes = EXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	default:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_HOLE:
		ext4_ilock(inode, EXT4_IOLOCK_SHARED);
		offset = iomap_seek_hole(inode, offset, &ext4_iomap_ops);
		ext4_iunlock(inode, EXT4_IOLOCK_SHARED);
		break;
	case SEEK_DATA:
		ext4_ilock(inode, EXT4_IOLOCK_SHARED);
		offset = iomap_seek_data(inode, offset, &ext4_iomap_ops);
		ext4_iunlock(inode, EXT4_IOLOCK_SHARED);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, maxbytes);
}

const struct file_operations ext4_file_operations = {
	.llseek		= ext4_llseek,
	.read_iter	= ext4_file_read_iter,
	.write_iter	= ext4_file_write_iter,
	.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext4_compat_ioctl,
#endif
	.mmap		= ext4_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= ext4_file_open,
	.release	= ext4_release_file,
	.fsync		= ext4_sync_file,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= ext4_fallocate,
};

const struct inode_operations ext4_file_inode_operations = {
	.setattr	= ext4_setattr,
	.getattr	= ext4_file_getattr,
	.listxattr	= ext4_listxattr,
	.get_acl	= ext4_get_acl,
	.set_acl	= ext4_set_acl,
	.fiemap		= ext4_fiemap,
};

