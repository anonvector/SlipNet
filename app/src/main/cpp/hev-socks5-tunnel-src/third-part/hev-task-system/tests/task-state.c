/*
 ============================================================================
 Name        : task-state.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task State Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>

static void
task1_entry (void *data)
{
    HevTask *task = hev_task_self ();

    assert (hev_task_get_state (task) == HEV_TASK_RUNNING);

    hev_task_sleep (1);
}

static void
task2_entry (void *data)
{
    HevTask *task = data;

    assert (hev_task_get_state (task) == HEV_TASK_WAITING);
    hev_task_unref (task);
}

int
main (int argc, char *argv[])
{
    HevTask *task1, *task2;

    assert (hev_task_system_init () == 0);

    task1 = hev_task_new (-1);
    assert (task1);
    hev_task_ref (task1);
    hev_task_set_priority (task1, 1);
    assert (hev_task_get_state (task1) == HEV_TASK_STOPPED);
    hev_task_run (task1, task1_entry, NULL);
    assert (hev_task_get_state (task1) == HEV_TASK_RUNNING);

    task2 = hev_task_new (-1);
    assert (task2);
    hev_task_set_priority (task2, 2);
    hev_task_run (task2, task2_entry, hev_task_ref (task1));

    hev_task_system_run ();

    assert (hev_task_get_state (task1) == HEV_TASK_STOPPED);
    hev_task_unref (task1);

    hev_task_system_fini ();

    return 0;
}
