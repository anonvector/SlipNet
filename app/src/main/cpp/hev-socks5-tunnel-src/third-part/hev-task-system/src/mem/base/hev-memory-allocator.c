/*
 ============================================================================
 Name        : hev-memory-allocator.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2013 - 2024 everyone.
 Description : Memory allocator
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "lib/misc/hev-compiler.h"
#include "mem/simple/hev-memory-allocator-simple.h"

#include "hev-memory-allocator.h"

static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void
pthread_key_creator (void)
{
    pthread_key_create (&key, NULL);
}

EXPORT_SYMBOL HevMemoryAllocator *
hev_memory_allocator_default (void)
{
    HevMemoryAllocator *allocator;

    pthread_once (&key_once, pthread_key_creator);

    allocator = pthread_getspecific (key);
    if (!allocator) {
        allocator = hev_memory_allocator_simple_new ();
        pthread_setspecific (key, allocator);
    }

    return allocator;
}

EXPORT_SYMBOL HevMemoryAllocator *
hev_memory_allocator_set_default (HevMemoryAllocator *allocator)
{
    HevMemoryAllocator *old_allocator;

    pthread_once (&key_once, pthread_key_creator);

    old_allocator = pthread_getspecific (key);
    pthread_setspecific (key, allocator);

    return old_allocator;
}

EXPORT_SYMBOL HevMemoryAllocator *
hev_memory_allocator_ref (HevMemoryAllocator *self)
{
    self->ref_count++;
    return self;
}

EXPORT_SYMBOL void
hev_memory_allocator_unref (HevMemoryAllocator *self)
{
    self->ref_count--;
    if (0 < self->ref_count)
        return;

    if (self->destroy)
        self->destroy (self);
    free (self);
}

EXPORT_SYMBOL void *
hev_memory_allocator_alloc (HevMemoryAllocator *self, size_t size)
{
    return self->alloc (self, size);
}

EXPORT_SYMBOL void *
hev_memory_allocator_realloc (HevMemoryAllocator *self, void *ptr, size_t size)
{
    return self->realloc (self, ptr, size);
}

EXPORT_SYMBOL void
hev_memory_allocator_free (HevMemoryAllocator *self, void *ptr)
{
    return self->free (self, ptr);
}
