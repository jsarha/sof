/* 
 * BSD 3 Clause - See LICENCE file for details.
 *
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 */

#ifndef __INCLUDE_ALLOC__
#define __INCLUDE_ALLOC__

#include <string.h>

/* Heap Memory Zones */
/* device zone - never freed, always suceeds */
#define RZONE_DEV	0
/* module zone - freed on module removal, can fail */
#define RZONE_MODULE	1

/* Modules */
#define RMOD_SYS	0	/* system module */
#define RMOD(m)		(m + 16)	/* all other modules */

void *rmalloc(int zone, int module, size_t bytes);

/* allocates buffer on 4k boundary */
void *rballoc(int zone, int module, size_t bytes);

void rfree(int zone, int module, void *ptr);

void init_heap(void);

#endif
