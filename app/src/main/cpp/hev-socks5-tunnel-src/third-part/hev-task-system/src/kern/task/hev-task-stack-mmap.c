/*
 ============================================================================
 Name        : hev-task-stack-mmap.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 everyone.
 Description :
 ============================================================================
 */

#include <unistd.h>
#include <sys/mman.h>

#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-stack.h"

#if CONFIG_STACK_BACKEND == STACK_MMAP

#ifndef MAP_STACK
#define MAP_STACK (0)
#endif

struct _HevTaskStack
{
    int size;
    void *stack;
};

HevTaskStack *
hev_task_stack_new (int size)
{
    HevTaskStack *self;
    static int page_size;

    if (!page_size)
        page_size = getpagesize ();

    size = ALIGN_UP (size, page_size);
#ifdef ENABLE_STACK_OVERFLOW_DETECTION
    size += page_size;
#endif

    self = hev_malloc (sizeof (HevTaskStack));
    if (!self)
        return NULL;

    self->stack = mmap (NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON | MAP_STACK, -1, 0);
    if (self->stack == MAP_FAILED) {
        hev_free (self);
        return NULL;
    }

#ifdef ENABLE_STACK_OVERFLOW_DETECTION
    if (mprotect (self->stack, page_size, PROT_NONE) < 0) {
        munmap (self->stack, size);
        hev_free (self);
        return NULL;
    }
#endif

    self->size = size;

    return self;
}

void
hev_task_stack_destroy (HevTaskStack *self)
{
    munmap (self->stack, self->size);
    hev_free (self);
}

void *
hev_task_stack_get_base (HevTaskStack *self)
{
    return self->stack;
}

void *
hev_task_stack_get_bottom (HevTaskStack *self)
{
    return self->stack + self->size;
}

#endif /* CONFIG_STACK_BACKEND == STACK_MMAP */
