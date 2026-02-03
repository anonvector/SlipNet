/*
 ============================================================================
 Name        : hev-task-mutex.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Mutex
 ============================================================================
 */

#ifndef __HEV_TASK_MUTEX_H__
#define __HEV_TASK_MUTEX_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevTaskMutex HevTaskMutex;
typedef struct _HevTaskMutexNode HevTaskMutexNode;

struct _HevTaskMutex
{
    unsigned int locker;

    HevTaskMutexNode *waiters;
};

/**
 * hev_task_mutex_init:
 * @self: a #HevTaskMutex
 *
 * Initialize the task mutex.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.3
 */
int hev_task_mutex_init (HevTaskMutex *self);

/**
 * hev_task_mutex_lock:
 * @self: a #HevTaskMutex
 *
 * Lock the task mutex.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.3
 */
int hev_task_mutex_lock (HevTaskMutex *self);

/**
 * hev_task_mutex_trylock:
 * @self: a #HevTaskMutex
 *
 * Try lock the task mutex.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.3
 */
int hev_task_mutex_trylock (HevTaskMutex *self);

/**
 * hev_task_mutex_unlock:
 * @self: a #HevTaskMutex
 *
 * Unlock the task mutex.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 4.3
 */
int hev_task_mutex_unlock (HevTaskMutex *self);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_MUTEX_H__ */
