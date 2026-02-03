/*
 ============================================================================
 Name        : hev-memory-allocator-simple.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Memory allocator simple
 ============================================================================
 */

#ifndef __HEV_MEMORY_ALLOCATOR_SIMPLE_H__
#define __HEV_MEMORY_ALLOCATOR_SIMPLE_H__

#include "mem/base/hev-memory-allocator.h"

/**
 * hev_memory_allocator_simple_new:
 *
 * Creates a new simple memory allocator.
 *
 * Returns: a new #HevMemoryAllocator
 *
 * Since: 3.2
 */
HevMemoryAllocator *hev_memory_allocator_simple_new (void);

#endif /* __HEV_MEMORY_ALLOCATOR_SIMPLE_H__ */
