/*
 ============================================================================
 Name        : hev-task-system-schedule.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2025 everyone.
 Description :
 ============================================================================
 */

/* Disable signal stack check in longjmp */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif

#include <stdlib.h>

#include "hev-task-system.h"
#include "hev-task-system-private.h"
#include "kern/task/hev-task-private.h"
#include "kern/task/hev-task-executer.h"
#include "kern/io/hev-task-io-reactor.h"
#include "lib/misc/hev-compiler.h"

static inline void
hev_task_system_get_clock_time (struct timespec *ts)
{
#if CONFIG_SCHED_CLOCK != CLOCK_NONE
    if (-1 == clock_gettime (CONFIG_SCHED_CLOCK, ts))
        abort ();
#endif
}

static inline void
hev_task_system_update_sched_key (HevTaskSystemContext *ctx)
{
    HevTask *curr_task = ctx->current_task;
    uint64_t runtime = 1;

#if CONFIG_SCHED_CLOCK != CLOCK_NONE
    struct timespec curr_time;
    time_t sec;
    long nsec;

    hev_task_system_get_clock_time (&curr_time);

    sec = curr_time.tv_sec - ctx->sched_time.tv_sec;
    nsec = curr_time.tv_nsec - ctx->sched_time.tv_nsec;
    if (nsec < 0) {
        sec--;
        nsec += 1000000000L;
    }

    runtime += (uint64_t)sec * 1000000000UL + nsec;
#endif

    curr_task->sched_key += runtime * curr_task->priority;
}

static inline void
hev_task_system_update_sched_time (HevTaskSystemContext *ctx)
{
    hev_task_system_get_clock_time (&ctx->sched_time);
}

static inline uint64_t
hev_task_system_get_min_sched_key (HevTaskSystemContext *ctx)
{
    HevRBTreeNode *sched_node;

    sched_node = hev_rbtree_cached_first (&ctx->running_tasks);
    if (sched_node) {
        HevTask *task = container_of (sched_node, HevTask, sched_node);
        return task->sched_key;
    }

    return 0;
}

static inline void
_hev_task_system_insert_task (HevRBTreeCached *tree, HevTask *task)
{
    HevRBTreeNode **new = &tree->base.root, *parent = NULL;
    int leftmost = 1;

    while (*new) {
        HevTask *this = container_of (*new, HevTask, sched_node);

        parent = *new;
        if (task->sched_key < this->sched_key) {
            new = &((*new)->left);
        } else {
            new = &((*new)->right);
            leftmost = 0;
        }
    }

    hev_rbtree_node_link (&task->sched_node, parent, new);
    hev_rbtree_cached_insert_color (tree, &task->sched_node, leftmost);
}

static inline void
hev_task_system_insert_task (HevTaskSystemContext *ctx, HevTask *task)
{
    task->state = HEV_TASK_RUNNING;
    task->priority = task->next_priority;

    _hev_task_system_insert_task (&ctx->running_tasks, task);

    ctx->running_task_count++;
}

static inline void
hev_task_system_reinsert_current_task (HevTaskSystemContext *ctx)
{
    HevTask *task = ctx->current_task;

    task->priority = task->next_priority;

    hev_rbtree_cached_erase (&ctx->running_tasks, &task->sched_node);
    _hev_task_system_insert_task (&ctx->running_tasks, task);
}

static inline void
hev_task_system_remove_current_task (HevTaskSystemContext *ctx,
                                     HevTaskState state)
{
    HevTask *task = ctx->current_task;

    task->state = state;

    hev_rbtree_cached_erase (&ctx->running_tasks, &task->sched_node);

    ctx->running_task_count--;

    if (HEV_TASK_STOPPED == state) {
        ctx->total_task_count--;
        hev_task_unref (task);
    } else {
        task->sched_key = task->next_priority;
    }
}

void
hev_task_system_wakeup_task_with_context (HevTaskSystemContext *ctx,
                                          HevTask *task)
{
    /* skip to wake up this task that is already in running */
    if (task->state == HEV_TASK_RUNNING)
        return;

    if (task->state == HEV_TASK_STOPPED)
        abort ();

    task->sched_key += hev_task_system_get_min_sched_key (ctx);

    hev_task_system_insert_task (ctx, task);
}

static inline void
hev_task_system_io_poll (HevTaskSystemContext *ctx, int timeout)
{
    int i, count;
    HevTaskIOReactorWaitEvent events[1024];

    if (timeout < 0)
        timeout = hev_task_timer_get_timeout (ctx->timer);

    count = hev_task_io_reactor_wait (ctx->reactor, events, 1024, timeout);
    for (i = 0; i < count; i++) {
        HevTaskSchedEntity *sched_entity;

        sched_entity = hev_task_io_reactor_wait_event_get_data (&events[i]);
        hev_task_system_wakeup_task_with_context (ctx, sched_entity->task);
    }

    hev_task_timer_wake (ctx->timer);
}

static inline void
hev_task_system_pick_current_task (HevTaskSystemContext *ctx)
{
    HevRBTreeNode *sched_node;

    if (ctx->running_task_count < ctx->total_task_count) {
        if (ctx->running_task_count) {
            hev_task_system_io_poll (ctx, 0);
        } else {
            do {
                hev_task_system_io_poll (ctx, -1);
            } while (!ctx->running_task_count);
        }
    }

    sched_node = hev_rbtree_cached_first (&ctx->running_tasks);
    ctx->current_task = container_of (sched_node, HevTask, sched_node);
}

void
hev_task_system_schedule (HevTaskYieldType type)
{
    HevTaskSystemContext *ctx = hev_task_system_get_context ();

    if (ctx->current_task) {
        /*
         * NOTE: in task context
         * save current task context
         */
        if (_setjmp (ctx->current_task->context))
            return; /* resume to task context */

        /* resume to kernel context */
        _longjmp (ctx->kernel_context, type);
    }

    /* NOTE: in kernel context */
    if (type == HEV_TASK_RUN_SCHEDULER) {
        switch (_setjmp (ctx->kernel_context)) {
        case HEV_TASK_SCHED_SWITCH:
            hev_task_system_update_sched_key (ctx);
            hev_task_system_reinsert_current_task (ctx);
            break;
        case HEV_TASK_SCHED_WAITIO:
            hev_task_system_update_sched_key (ctx);
            hev_task_system_remove_current_task (ctx, HEV_TASK_WAITING);
            break;
        case HEV_TASK_SCHED_REMOVE:
            hev_task_system_remove_current_task (ctx, HEV_TASK_STOPPED);
            break;
        }
    }

    /* All tasks exited, Bye! */
    if (ctx->total_task_count == 0) {
        ctx->current_task = NULL;
        return;
    }

    /* pick a task */
    hev_task_system_pick_current_task (ctx);

    /* update schedule time */
    hev_task_system_update_sched_time (ctx);

    /* switch to task */
    _longjmp (ctx->current_task->context, 1);
}

void
hev_task_system_wakeup_task (HevTask *task)
{
    HevTaskSystemContext *ctx;

    ctx = hev_task_system_get_context ();
    hev_task_system_wakeup_task_with_context (ctx, task);
}

void
hev_task_system_run_new_task (HevTask *task)
{
    HevTaskSystemContext *ctx = hev_task_system_get_context ();

    hev_task_execute (task, hev_task_executer);

    if (ctx->current_task)
        task->sched_key += hev_task_system_get_min_sched_key (ctx);

    hev_task_system_insert_task (ctx, task);
    ctx->total_task_count++;
}

void
hev_task_system_kill_current_task (void)
{
    HevTaskSystemContext *ctx = hev_task_system_get_context ();

    /*
     * NOTE: remove current task in kernel context, because current
     * task stack may be freed.
     */
    _longjmp (ctx->kernel_context, HEV_TASK_SCHED_REMOVE);
}
