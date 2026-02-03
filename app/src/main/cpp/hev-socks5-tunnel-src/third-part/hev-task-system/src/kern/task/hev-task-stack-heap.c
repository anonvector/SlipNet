/*
 ============================================================================
 Name        : hev-task-stack-heap.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description :
 ============================================================================
 */

#include <assert.h>
#include <stdint.h>

#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-stack.h"

#if CONFIG_STACK_BACKEND == STACK_HEAP

#ifdef ENABLE_STACK_OVERFLOW_DETECTION
#if CONFIG_STACK_OVERFLOW_DETECTION == 1
#define STACK_OVERFLOW_DETECTION_SIZE (4)
#elif CONFIG_STACK_OVERFLOW_DETECTION == 2
#define STACK_OVERFLOW_DETECTION_SIZE (4096)
#else
#define STACK_OVERFLOW_DETECTION_SIZE (8192)
#endif
#define STACK_OVERFLOW_DETECTION_TAG (0xdeadbeefu)
#else
#define STACK_OVERFLOW_DETECTION_SIZE (0)
#endif

struct _HevTaskStack
{
    int size;
};

static inline void
hev_task_stack_detection_mark (HevTaskStack *self)
{
#ifdef ENABLE_STACK_OVERFLOW_DETECTION
    const unsigned int tag = STACK_OVERFLOW_DETECTION_TAG;
    const unsigned int tags = STACK_OVERFLOW_DETECTION_SIZE / sizeof (tag);
    unsigned int *tagp = (unsigned int *)(self + 1);
    int i;

    for (i = 0; i < tags; i++)
        tagp[i] = tag;
#endif
}

static inline void
hev_task_stack_detection_check (HevTaskStack *self)
{
#ifdef ENABLE_STACK_OVERFLOW_DETECTION
    const unsigned int tag = STACK_OVERFLOW_DETECTION_TAG;
    const unsigned int tags = STACK_OVERFLOW_DETECTION_SIZE / sizeof (tag);
    unsigned int *tagp = (unsigned int *)(self + 1);
    int i;

    for (i = 0; i < tags; i++)
        assert (tagp[i] == tag);
#endif
}

HevTaskStack *
hev_task_stack_new (int size)
{
    HevTaskStack *self;

    size += STACK_OVERFLOW_DETECTION_SIZE;
    self = hev_malloc (sizeof (HevTaskStack) + size);
    if (self)
        self->size = size;

    hev_task_stack_detection_mark (self);
    return self;
}

void
hev_task_stack_destroy (HevTaskStack *self)
{
    hev_task_stack_detection_check (self);
    hev_free (self);
}

void *
hev_task_stack_get_base (HevTaskStack *self)
{
    return (void *)(self + 1);
}

void *
hev_task_stack_get_bottom (HevTaskStack *self)
{
    return (void *)ALIGN_DOWN ((intptr_t)self + self->size, 16);
}

#endif /* CONFIG_STACK_BACKEND == STACK_HEAP */
