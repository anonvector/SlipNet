/*
 ============================================================================
 Name        : hev-task-cond.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Condition
 ============================================================================
 */

#include <stddef.h>

#include "kern/task/hev-task.h"
#include "lib/misc/hev-compiler.h"

#include "hev-task-cond.h"

struct _HevTaskCondNode
{
    HevTaskCondNode *prev;
    HevTaskCondNode *next;

    HevTask *task;
};

EXPORT_SYMBOL int
hev_task_cond_init (HevTaskCond *self)
{
    self->waiters = NULL;

    return 0;
}

EXPORT_SYMBOL int
hev_task_cond_wait (HevTaskCond *self, HevTaskMutex *mutex)
{
    HevTaskCondNode node;

    node.prev = NULL;
    node.next = self->waiters;
    node.task = hev_task_self ();

    if (self->waiters)
        self->waiters->prev = &node;
    self->waiters = &node;

    hev_task_mutex_unlock (mutex);
    do {
        hev_task_yield (HEV_TASK_WAITIO);
    } while (READ_ONCE (node.task));
    hev_task_mutex_lock (mutex);

    return 0;
}

EXPORT_SYMBOL int
hev_task_cond_timedwait (HevTaskCond *self, HevTaskMutex *mutex,
                         unsigned int milliseconds)
{
    HevTaskCondNode node;

    node.prev = NULL;
    node.next = self->waiters;
    node.task = hev_task_self ();

    if (self->waiters)
        self->waiters->prev = &node;
    self->waiters = &node;

    hev_task_mutex_unlock (mutex);
    while (milliseconds && READ_ONCE (node.task))
        milliseconds = hev_task_sleep (milliseconds);
    hev_task_mutex_lock (mutex);

    if (READ_ONCE (node.task)) {
        if (node.prev)
            node.prev->next = node.next;
        if (node.next)
            node.next->prev = node.prev;
        if (self->waiters == &node)
            self->waiters = NULL;
        return -1;
    }

    return 0;
}

EXPORT_SYMBOL int
hev_task_cond_signal (HevTaskCond *self)
{
    if (self->waiters) {
        hev_task_wakeup (self->waiters->task);

        self->waiters->task = NULL;
        self->waiters = self->waiters->next;
        if (self->waiters)
            self->waiters->prev = NULL;
    }

    return 0;
}

EXPORT_SYMBOL int
hev_task_cond_broadcast (HevTaskCond *self)
{
    while (self->waiters) {
        hev_task_wakeup (self->waiters->task);

        self->waiters->task = NULL;
        self->waiters = self->waiters->next;
    }

    return 0;
}
