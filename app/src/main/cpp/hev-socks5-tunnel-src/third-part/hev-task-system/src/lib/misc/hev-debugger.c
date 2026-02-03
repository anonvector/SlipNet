/*
 ============================================================================
 Name        : hev-debugger.c
 Authors     : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : Debugger
 ============================================================================
 */

#include <stdio.h>
#include <inttypes.h>

#include "kern/core/hev-task-system-private.h"
#include "kern/task/hev-task-private.h"
#include "kern/task/hev-task-stack.h"
#include "lib/misc/hev-compiler.h"

#include "hev-debugger.h"

#ifdef ENABLE_DEBUG

EXPORT_SYMBOL HevTaskSystemContext *
_hev_task_system_get_context (void)
{
    return hev_task_system_get_context ();
}

EXPORT_SYMBOL unsigned int
_hev_task_system_get_total_task_count (void)
{
    return hev_task_system_get_context ()->total_task_count;
}

EXPORT_SYMBOL unsigned int
_hev_task_system_get_running_task_count (void)
{
    return hev_task_system_get_context ()->running_task_count;
}

EXPORT_SYMBOL HevTask *
_hev_task_system_get_current_task (void)
{
    return hev_task_system_get_context ()->current_task;
}

EXPORT_SYMBOL void
_hev_task_system_dump_all_tasks (void)
{
    HevTaskSystemContext *context = hev_task_system_get_context ();
    HevListNode *node = hev_list_first (&context->all_tasks);

    printf ("===========================================\n");
    for (; node; node = hev_list_node_next (node)) {
        HevTask *task = container_of (node, HevTask, list_node);
        const void *stack_base, *stack_bottom;
        const char *state;

        switch (task->state) {
        case HEV_TASK_RUNNING:
            state = "RUNNING";
            break;
        case HEV_TASK_WAITING:
            state = "WAITING";
            break;
        default:
            state = "STOPPED";
        }

        stack_base = hev_task_stack_get_base (task->stack);
        stack_bottom = hev_task_stack_get_bottom (task->stack);

        printf ("Task: %p\n", task);
        printf ("  State   : %s\n", state);
        printf ("  Entry   : %p [%p]\n", task->entry, task->data);
        printf ("  Stack   : %p - %p\n", stack_base, stack_bottom);
        printf ("  Priority: %d -> %d\n", task->priority, task->next_priority);
        printf ("  RefCount: %d\n", task->ref_count);
        printf ("  SchedKey: %" PRIx64 "\n", task->sched_key);
    }
    printf ("===========================================\n");
}

#endif /* ENABLE_DEBUG */
