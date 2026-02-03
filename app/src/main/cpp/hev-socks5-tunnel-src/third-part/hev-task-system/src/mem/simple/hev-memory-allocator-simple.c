/*
 ============================================================================
 Name        : hev-memory-allocator-simple.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Memory allocator simple
 ============================================================================
 */

#include <stdlib.h>

#include "hev-memory-allocator-simple.h"

static void *_hev_memory_allocator_alloc (HevMemoryAllocator *self,
                                          size_t size);
static void *_hev_memory_allocator_realloc (HevMemoryAllocator *self, void *ptr,
                                            size_t size);
static void _hev_memory_allocator_free (HevMemoryAllocator *self, void *ptr);

HevMemoryAllocator *
hev_memory_allocator_simple_new (void)
{
    HevMemoryAllocator *self = NULL;

    self = malloc (sizeof (HevMemoryAllocator));
    if (!self)
        return NULL;

    self->ref_count = 1;
    self->alloc = _hev_memory_allocator_alloc;
    self->realloc = _hev_memory_allocator_realloc;
    self->free = _hev_memory_allocator_free;
    self->destroy = NULL;

    return self;
}

static void *
_hev_memory_allocator_alloc (HevMemoryAllocator *self, size_t size)
{
    return malloc (size);
}

static void *
_hev_memory_allocator_realloc (HevMemoryAllocator *self, void *ptr, size_t size)
{
    return realloc (ptr, size);
}

static void
_hev_memory_allocator_free (HevMemoryAllocator *self, void *ptr)
{
    free (ptr);
}
