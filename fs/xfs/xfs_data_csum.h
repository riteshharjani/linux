/* SPDX-License-Identifier: GPL-2.0 */

struct iomap_ioend;

void *xfs_data_csum_alloc(struct bio *bio);
void xfs_data_csum_generate(struct bio *bio);
int xfs_data_csum_verify(struct iomap_ioend *ioend);
