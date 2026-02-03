/*
 ============================================================================
 Name        : task-cond.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Task Condition Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-cond.h>
#include <hev-task-system.h>

static int count;
static HevTaskMutex mutex;
static HevTaskCond cond;

static void
task_producer_entry (void *data)
{
    assert (hev_task_mutex_lock (&mutex) == 0);
    if (count == 0)
        assert (hev_task_cond_signal (&cond) == 0);
    count++;
    assert (hev_task_mutex_unlock (&mutex) == 0);

    hev_task_sleep (50);

    assert (hev_task_mutex_lock (&mutex) == 0);
    if (count == 0)
        assert (hev_task_cond_broadcast (&cond) == 0);
    count += 10;
    assert (hev_task_mutex_unlock (&mutex) == 0);
}

static void
task_consumer1_entry (void *data)
{
    hev_task_yield (HEV_TASK_YIELD);

    assert (hev_task_mutex_lock (&mutex) == 0);
    while (count == 0)
        assert (hev_task_cond_wait (&cond, &mutex) == 0);
    count--;
    assert (hev_task_mutex_unlock (&mutex) == 0);
}

static void
task_consumer2_entry (void *data)
{
    int i;

    assert (hev_task_mutex_lock (&mutex) == 0);
    while (count == 0)
        assert (hev_task_cond_wait (&cond, &mutex) == 0);
    count--;
    assert (hev_task_mutex_unlock (&mutex) == 0);

    assert (hev_task_mutex_lock (&mutex) == 0);
    assert (count == 0);
    assert (hev_task_cond_timedwait (&cond, &mutex, 0) == -1);
    assert (hev_task_cond_timedwait (&cond, &mutex, 1) == -1);
    assert (hev_task_mutex_unlock (&mutex) == 0);

    for (i = 0; i < 10; i++) {
        HevTask *task = hev_task_new (-1);
        assert (task);
        hev_task_set_priority (task, 1);
        hev_task_run (task, task_consumer1_entry, NULL);
    }
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    assert (hev_task_mutex_init (&mutex) == 0);
    assert (hev_task_cond_init (&cond) == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_producer_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_consumer2_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
