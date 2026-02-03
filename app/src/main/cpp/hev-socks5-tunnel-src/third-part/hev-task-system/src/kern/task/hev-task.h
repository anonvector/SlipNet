/*
 ============================================================================
 Name        : hev-task.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2025 everyone.
 Description :
 ============================================================================
 */

#ifndef __HEV_TASK_H__
#define __HEV_TASK_H__

#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_TASK_PRIORITY_MIN (0)
#define HEV_TASK_PRIORITY_MAX (15)

#define HEV_TASK_PRIORITY_HIGH HEV_TASK_PRIORITY_MIN
#define HEV_TASK_PRIORITY_LOW HEV_TASK_PRIORITY_MAX

#define HEV_TASK_PRIORITY_DEFAULT (8)
#define HEV_TASK_PRIORITY_REALTIME (0)

typedef struct _HevTask HevTask;
typedef void (*HevTaskEntry) (void *data);

/**
 * HevTaskState:
 * @HEV_TASK_STOPPED: The task is not in any task system.
 * @HEV_TASK_RUNNING: The task is in a task system's running tree.
 * @HEV_TASK_WAITING: The task is in a task system's waiting poll.
 *
 * Since: 1.0
 */
typedef enum
{
    HEV_TASK_STOPPED,
    HEV_TASK_RUNNING,
    HEV_TASK_WAITING,
} HevTaskState;

/**
 * HevTaskYieldType:
 * @HEV_TASK_YIELD: Move task to yield waiting state.
 * @HEV_TASK_WAITIO: Move task to I/O waiting state.
 * @HEV_TASK_YIELD_COUNT: Maximum yield type count.
 *
 * Since: 1.0
 */
typedef enum
{
    HEV_TASK_YIELD = 1,
    HEV_TASK_WAITIO,
    HEV_TASK_YIELD_COUNT,
} HevTaskYieldType;

/**
 * hev_task_new:
 * @stack_size: stack size for task
 *
 * Creates a new task. If @stack_size = -1, the default stack size
 * will be used.
 *
 * Returns: a new #HevTask.
 *
 * Since: 1.0
 */
HevTask *hev_task_new (int stack_size);

/**
 * hev_task_ref:
 * @self: a #HevTask
 *
 * Increases the reference count of the @self by one.
 *
 * Returns: a #HevTask
 *
 * Since: 1.0
 */
HevTask *hev_task_ref (HevTask *self);

/**
 * hev_task_unref:
 * @self: a #HevTask
 *
 * Decreases the reference count of @self. When its reference count
 * drops to 0, the object is finalized (i.e. its memory is freed).
 *
 * Since: 1.0
 */
void hev_task_unref (HevTask *self);

/**
 * hev_task_self:
 *
 * Get the current task.
 *
 * Returns: a #HevTask
 *
 * Since: 1.0
 */
HevTask *hev_task_self (void);

/**
 * hev_task_get_state:
 * @self: a #HevTask
 *
 * Get the state of a task.
 *
 * Returns: a #HevTaskState
 *
 * Since: 1.0
 */
HevTaskState hev_task_get_state (HevTask *self);

/**
 * hev_task_set_priority:
 * @self: a #HevTask
 * @priority: priority
 *
 * Set the priority of a task. The value range of priority are [0-1],
 * with smaller values representing higher priorities.
 *
 * Since: 1.0
 */
void hev_task_set_priority (HevTask *self, int priority);

/**
 * hev_task_get_priority:
 * @self: a #HevTask
 *
 * Get the priority of a task.
 *
 * Returns: current priority of task
 *
 * Since: 1.0
 */
int hev_task_get_priority (HevTask *self);

/**
 * hev_task_add_fd:
 * @self: a #HevTask
 * @fd: a file descriptor
 * @events: a poll events. (e.g. POLLIN, POLLOUT)
 *
 * Add a file descriptor to I/O reactor of task system. The task system will
 * wake up the task when I/O events ready.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 1.0
 */
int hev_task_add_fd (HevTask *self, int fd, unsigned int events);

/**
 * hev_task_mod_fd:
 * @self: a #HevTask
 * @fd: a file descriptor
 * @events: a poll events.
 *
 * Modify events of a file descriptor that added into I/O reactor of task
 * system.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 1.0
 */
int hev_task_mod_fd (HevTask *self, int fd, unsigned int events);

/**
 * hev_task_del_fd:
 * @self: a #HevTask
 * @fd: a file descriptor
 *
 * Remove a file descriptor from I/O reactor of task system.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 1.0
 */
int hev_task_del_fd (HevTask *self, int fd);

/**
 * hev_task_add_whandle:
 * @self: a #HevTask
 * @handle: a waitable handle
 *
 * Add a waitable handle to I/O reactor of task system. The task system will
 * wake up the task when signaled.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 5.8
 */
int hev_task_add_whandle (HevTask *self, void *handle);

/**
 * hev_task_del_whandle:
 * @self: a #HevTask
 * @handle: a waitable handle
 *
 * Remove a waitable handle from I/O reactor of task system.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 5.8
 */
int hev_task_del_whandle (HevTask *self, void *handle);

/**
 * hev_task_wakeup:
 * @self: a #HevTask
 *
 * Wake up a task. Don't switch tasks immediately.
 *
 * Since: 1.0
 */
void hev_task_wakeup (HevTask *task);

/**
 * hev_task_yield:
 * @type: type of #HevTaskYieldType
 *
 * Save current task context, pick a new task and switch to.
 *
 * Since: 1.0
 */
void hev_task_yield (HevTaskYieldType type);

/**
 * hev_task_sleep:
 * @milliseconds: time to sleep
 *
 * Like yield. The task will be waked up by two condition:
 * 1. Timer. time has elapsed.
 * 2. I/O events. The task will be waked up by file descriptors events.
 *
 * Returns: Zero if the requested time has elapsed, or
 * the number of milliseconds left to sleep.
 *
 * Since: 1.0
 */
unsigned int hev_task_sleep (unsigned int milliseconds);

/**
 * hev_task_usleep:
 * @microseconds: time to sleep
 *
 * Like yield. The task will be waked up by two condition:
 * 1. Timer. time has elapsed.
 * 2. I/O events. The task will be waked up by file descriptors events.
 *
 * Returns: Zero if the requested time has elapsed, or
 * the number of microseconds left to sleep.
 *
 * Deprecated: 5.4.0
 */
unsigned int hev_task_usleep (unsigned int microseconds);

/**
 * hev_task_run:
 * @self (transfer full): a #HevTask
 * @entry: A #HevTaskEntry
 * @data (nullable): a user data to passed to @entry
 *
 * Set the entry and data to the task, and add to running tree of task system.
 * The task will be really run after task system run or current task yield.
 *
 * Since: 1.0
 */
void hev_task_run (HevTask *self, HevTaskEntry entry, void *data);

/**
 * hev_task_exit:
 *
 * The function terminates the calling process immediately.
 *
 * Since: 1.4
 */
void hev_task_exit (void);

/**
 * hev_task_join:
 * @task: a #HevTask
 *
 * Join with a terminated task.
 *
 * Returns: When successful, returns zero. When an error occurs, returns -1.
 *
 * Since: 5.2.6
 */
int hev_task_join (HevTask *task);

/**
 * hev_task_get_data:
 * @self: a #HevTask
 *
 * Get the user data of a task that set by run.
 *
 * Returns: current data of task.
 *
 * Since: 3.3.4
 */
void *hev_task_get_data (HevTask *self);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_H__ */
