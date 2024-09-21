/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 IBM Corporation.
 */
#ifndef _ASM_POWERPC_TLBBATCH_H
#define _ASM_POWERPC_TLBBATCH_H

#include <linux/cpumask.h>

struct arch_tlbflush_unmap_batch {
	struct cpumask cpumask;
};

#endif /* _ASM_POWERPC_TLBBATCH_H */
