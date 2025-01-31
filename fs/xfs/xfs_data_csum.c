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

	if (!bi || !bi->csum_type)
		return;

	xfs_data_csum_alloc(bio);
	blk_integrity_generate(bio);
}

int
xfs_data_csum_verify(
	struct iomap_ioend	*ioend)
{
	struct bio		*bio = &ioend->io_bio;
	struct blk_integrity	*bi = blk_get_integrity(bio->bi_bdev->bd_disk);

	if (!bi || !bi->csum_type)
		return 0;
	return blk_integrity_verify_all(bio, ioend->io_sector);
}
