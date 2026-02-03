/*
 ============================================================================
 Name        : hev-task-cond.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Condition
 ============================================================================
 */

#ifndef __HEV_TASK_COND_H__
#define __HEV_TASK_COND_H__

#include "hev-task-mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevTaskCond HevTaskCond;
typedef struct _HevTaskCondNode HevTaskCondNode;

struct _HevTaskCond
{
    HevTaskCondNode *waiters;
};

/**
 * hev_task_cond_init:
 * @self: a #HevTaskCond
 *
 * Initialize the task condition.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.4
 */
int hev_task_cond_init (HevTaskCond *self);

/**
 * hev_task_cond_wait:
 * @self: a #HevTaskCond
 * @mutex: a #HevTaskMutex
 *
 * Wait on the task condition.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.4
 */
int hev_task_cond_wait (HevTaskCond *self, HevTaskMutex *mutex);

/**
 * hev_task_cond_wait:
 * @self: a #HevTaskCond
 * @mutex: a #HevTaskMutex
 * @milliseconds: wait time
 *
 * The timedwait function shall be equivalent to condition wait, except that an
 * error is returned if the time specified by @milliseconds passes.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.4
 */
int hev_task_cond_timedwait (HevTaskCond *self, HevTaskMutex *mutex,
                             unsigned int milliseconds);

/**
 * hev_task_cond_signal:
 * @self: a #HevTaskCond
 *
 * Wake one task that wait on condition.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.4
 */
int hev_task_cond_signal (HevTaskCond *self);

/**
 * hev_task_cond_broadcast:
 * @self: a #HevTaskCond
 *
 * Wake all task that wait on condition.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.4
 */
int hev_task_cond_broadcast (HevTaskCond *self);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_MUTEX_H__ */
