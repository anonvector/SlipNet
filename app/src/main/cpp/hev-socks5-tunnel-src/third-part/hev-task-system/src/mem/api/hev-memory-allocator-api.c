/*
 ============================================================================
 Name        : hev-memory-allocator-api.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Memory allocator APIs
 ============================================================================
 */

#include <string.h>

#include "lib/misc/hev-compiler.h"
#include "mem/base/hev-memory-allocator.h"

#include "hev-memory-allocator-api.h"

EXPORT_SYMBOL void *
hev_malloc (size_t size)
{
    HevMemoryAllocator *allocator;

    allocator = hev_memory_allocator_default ();
    return hev_memory_allocator_alloc (allocator, size);
}

EXPORT_SYMBOL void *
hev_malloc0 (size_t size)
{
    HevMemoryAllocator *allocator;
    void *data;

    allocator = hev_memory_allocator_default ();
    data = hev_memory_allocator_alloc (allocator, size);
    if (data)
        memset (data, 0, size);
    return data;
}

EXPORT_SYMBOL void *
hev_calloc (size_t nmemb, size_t size)
{
    HevMemoryAllocator *allocator;
    void *data;

    if (!nmemb || !size)
        return NULL;

    size *= nmemb;
    allocator = hev_memory_allocator_default ();
    data = hev_memory_allocator_alloc (allocator, size);
    if (data)
        memset (data, 0, size);
    return data;
}

EXPORT_SYMBOL void *
hev_realloc (void *ptr, size_t size)
{
    HevMemoryAllocator *allocator;

    allocator = hev_memory_allocator_default ();
    return hev_memory_allocator_realloc (allocator, ptr, size);
}

EXPORT_SYMBOL void
hev_free (void *ptr)
{
    HevMemoryAllocator *allocator;

    allocator = hev_memory_allocator_default ();
    hev_memory_allocator_free (allocator, ptr);
}
