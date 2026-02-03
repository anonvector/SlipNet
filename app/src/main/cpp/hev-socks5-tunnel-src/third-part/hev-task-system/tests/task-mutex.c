/*
 ============================================================================
 Name        : task-mutex.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Task Mutex Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-mutex.h>
#include <hev-task-system.h>

static int count;
static HevTaskMutex mutex;

static void
task1_entry (void *data)
{
    assert (hev_task_mutex_trylock (&mutex) == 0);
    assert (hev_task_mutex_trylock (&mutex) == -1);
    assert (hev_task_mutex_unlock (&mutex) == 0);

    assert (hev_task_mutex_lock (&mutex) == 0);
    hev_task_yield (HEV_TASK_YIELD);
    assert (count == 0);
    assert (hev_task_mutex_unlock (&mutex) == 0);
}

static void
task2_entry (void *data)
{
    assert (hev_task_mutex_lock (&mutex) == 0);
    count++;
    assert (hev_task_mutex_unlock (&mutex) == 0);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    assert (hev_task_mutex_init (&mutex) == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task1_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task2_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
