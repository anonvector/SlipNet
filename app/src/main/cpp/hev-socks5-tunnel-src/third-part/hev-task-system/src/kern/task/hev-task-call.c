/*
 ============================================================================
 Name        : hev-task-call.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : Task call
 ============================================================================
 */

#include <stdint.h>

#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-call.h"

extern void hev_task_execute (HevTaskCall *self, HevTaskCallEntry entry);

EXPORT_SYMBOL HevTaskCall *
hev_task_call_new (int base_size, int stack_size)
{
    HevTaskCall *self;

    self = hev_malloc (base_size + stack_size);
    if (self) {
        uintptr_t stack_addr;
        stack_addr = (uintptr_t)((void *)self + base_size + stack_size);
        self->stack_top = (void *)ALIGN_DOWN (stack_addr, 16);
    }

    return self;
}

EXPORT_SYMBOL void
hev_task_call_destroy (HevTaskCall *self)
{
    hev_free (self);
}

EXPORT_SYMBOL void *
hev_task_call_jump (HevTaskCall *self, HevTaskCallEntry entry)
{
    hev_task_execute (self, entry);
    return self->retval;
}
