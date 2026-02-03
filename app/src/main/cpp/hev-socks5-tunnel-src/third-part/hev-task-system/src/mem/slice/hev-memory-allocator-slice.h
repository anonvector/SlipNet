/*
 ============================================================================
 Name        : hev-memory-allocator-slice.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description : Memory allocator sliced
 ============================================================================
 */

#ifndef __HEV_MEMORY_ALLOCATOR_SLICE_H__
#define __HEV_MEMORY_ALLOCATOR_SLICE_H__

#include "mem/base/hev-memory-allocator.h"

typedef struct _HevMemoryAllocatorSlice HevMemoryAllocatorSlice;

HevMemoryAllocator *hev_memory_allocator_slice_new (void);

#endif /* __HEV_MEMORY_ALLOCATOR_SLICE_H__ */
