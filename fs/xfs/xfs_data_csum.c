// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022-2025 Christoph Hellwig.
 */
#include "xfs.h"
#include "xfs_format.h"
#include "xfs_shared.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_cksum.h"
#include "xfs_data_csum.h"
#include <linux/iomap.h>
#include <linux/blk-integrity.h>
#include <linux/bio-integrity.h>

static inline void *xfs_csum_buf(struct bio *bio)
{
	return bvec_virt(bio_integrity(bio)->bip_vec);
}

static inline __le32
xfs_data_csum(
	void			*data,
	unsigned int		len)
{
	return xfs_end_cksum(crc32c(XFS_CRC_SEED, data, len));
}

static void
__xfs_data_csum_generate(
	struct bio		*bio)
{
	unsigned int		ssize = bdev_logical_block_size(bio->bi_bdev);
	__le32			*csum_buf = xfs_csum_buf(bio);
	struct bvec_iter_all	iter;
	struct bio_vec		*bv;
	int			c = 0;

	bio_for_each_segment_all(bv, bio, iter) {
		void		*p;
		unsigned int	off;

		p = bvec_kmap_local(bv);
		for (off = 0; off < bv->bv_len; off += ssize)
			csum_buf[c++] = xfs_data_csum(p + off, ssize);
		kunmap_local(p);
	}
}

static int
__xfs_data_csum_verify(
	struct bio		*bio,
	struct xfs_inode	*ip,
	xfs_off_t		file_offset)
{
	unsigned int		ssize = bdev_logical_block_size(bio->bi_bdev);
	__le32			*csum_buf = xfs_csum_buf(bio);
	int			c = 0;
	struct bvec_iter_all	iter;
	struct bio_vec		*bv;

	bio_for_each_segment_all(bv, bio, iter) {
		void		*p;
		unsigned int	off;

		p = bvec_kmap_local(bv);
		for (off = 0; off < bv->bv_len; off += ssize) {
			if (xfs_data_csum(p + off, ssize) != csum_buf[c++]) {
				kunmap_local(p);
				xfs_warn(ip->i_mount,
"checksum mismatch at inode 0x%llx offset %lld",
					ip->i_ino, file_offset);
				return -EFSBADCRC;
			}
			file_offset += ssize;
		}
		kunmap_local(p);
	}

	return 0;
}

void *
xfs_data_csum_alloc(
	struct bio		*bio)
{
	struct blk_integrity	*bi = blk_get_integrity(bio->bi_bdev->bd_disk);
	struct bio_integrity_payload *bip;
	unsigned int		buf_size;
	void			*buf;

	if (!bi)
		return NULL;

	buf_size = bio_integrity_bytes(bi, bio_sectors(bio));
	/* XXX: this needs proper mempools */
	/* XXX: needs (partial) zeroing if tuple_size > csum_size */
	buf = kmalloc(buf_size, GFP_NOFS | __GFP_NOFAIL);
	bip = bio_integrity_alloc(bio, GFP_NOFS | __GFP_NOFAIL, 1);
	if (!bio_integrity_add_page(bio, virt_to_page(buf), buf_size,
			offset_in_page(buf)))
		WARN_ON_ONCE(1);

	if (bi->csum_type) {
		if (bi->csum_type == BLK_INTEGRITY_CSUM_IP)
			bip->bip_flags |= BIP_IP_CHECKSUM;
		bip->bip_flags |= BIP_CHECK_GUARD;
	}
	if (bi->flags & BLK_INTEGRITY_REF_TAG)
		bip->bip_flags |= BIP_CHECK_REFTAG;
	bip_set_seed(bip, bio->bi_iter.bi_sector);

	return buf;
}

void
xfs_data_csum_generate(
	struct bio		*bio)
{
	struct blk_integrity	*bi = blk_get_integrity(bio->bi_bdev->bd_disk);

	if (!bi)
		return;

	xfs_data_csum_alloc(bio);
	if (!bi->csum_type)
		__xfs_data_csum_generate(bio);
	else
		blk_integrity_generate(bio);
}

int
xfs_data_csum_verify(
	struct iomap_ioend	*ioend)
{
	struct bio		*bio = &ioend->io_bio;
	struct blk_integrity	*bi = blk_get_integrity(bio->bi_bdev->bd_disk);

	if (!bi)
		return 0;
	if (!bi->csum_type)
		return __xfs_data_csum_verify(&ioend->io_bio,
				XFS_I(ioend->io_inode), ioend->io_offset);
	return blk_integrity_verify_all(bio, ioend->io_sector);
}
