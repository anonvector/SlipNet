/*
 ============================================================================
 Name        : hev-memory-allocator.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description : Memory allocator
 ============================================================================
 */

#ifndef __HEV_MEMORY_ALLOCATOR_H__
#define __HEV_MEMORY_ALLOCATOR_H__

#include <stddef.h>

typedef struct _HevMemoryAllocator HevMemoryAllocator;

typedef void *(*HevMemoryAllocatorAlloc) (HevMemoryAllocator *self,
                                          size_t size);
typedef void *(*HevMemoryAllocatorRealloc) (HevMemoryAllocator *self, void *ptr,
                                            size_t size);
typedef void (*HevMemoryAllocatorFree) (HevMemoryAllocator *self, void *ptr);
typedef void (*HevMemoryAllocatorDestroy) (HevMemoryAllocator *self);

struct _HevMemoryAllocator
{
    HevMemoryAllocatorAlloc alloc;
    HevMemoryAllocatorRealloc realloc;
    HevMemoryAllocatorFree free;
    HevMemoryAllocatorDestroy destroy;

    unsigned int ref_count;
};

/**
 * hev_memory_allocator_default:
 *
 * Get the default memory allocator.
 *
 * Returns: a #HevMemoryAllocator
 *
 * Since: 1.0
 */
HevMemoryAllocator *hev_memory_allocator_default (void);

/**
 * hev_memory_allocator_set_default:
 * @allocator: a #HevMemoryAllocator
 *
 * Set the default memory allocator.
 *
 * Returns: The old #HevMemoryAllocator
 *
 * Since: 1.0
 */
HevMemoryAllocator *
hev_memory_allocator_set_default (HevMemoryAllocator *allocator);

/**
 * hev_memory_allocator_ref:
 * @self: a #HevMemoryAllocator
 *
 * Increases the reference count of the @self by one.
 *
 * Returns: a #HevMemoryAllocator
 *
 * Since: 1.0
 */
HevMemoryAllocator *hev_memory_allocator_ref (HevMemoryAllocator *self);

/**
 * hev_memory_allocator_unref:
 * @self: a #HevMemoryAllocator
 *
 * Decreases the reference count of @self. When its reference count
 * drops to 0, the object is finalized (i.e. its memory is freed).
 *
 * Since: 1.0
 */
void hev_memory_allocator_unref (HevMemoryAllocator *self);

/**
 * hev_memory_allocator_alloc:
 * @self: a #HevMemoryAllocator
 * @size: bytes
 *
 * Allocate @size bytes memory from the default memory allocator.
 *
 * Returns: memory address
 *
 * Since: 1.0
 */
void *hev_memory_allocator_alloc (HevMemoryAllocator *self, size_t size);

/**
 * hev_memory_allocator_realloc:
 * @self: a #HevMemoryAllocator
 * @ptr: memory address
 * @size: bytes
 *
 * Changes the size of the memory block pointed to by @ptr to @size bytes.
 *
 * Returns: memory address
 *
 * Since: 3.2
 */
void *hev_memory_allocator_realloc (HevMemoryAllocator *self, void *ptr,
                                    size_t size);

/**
 * hev_memory_allocator_free:
 * @self: a #HevMemoryAllocator
 * @ptr: memory address
 *
 * Free the memory from memory allocator.
 *
 * Since: 1.0
 */
void hev_memory_allocator_free (HevMemoryAllocator *self, void *ptr);

#endif /* __HEV_MEMORY_ALLOCATOR_H__ */
