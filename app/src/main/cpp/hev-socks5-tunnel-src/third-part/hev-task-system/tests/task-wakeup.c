/*
 ============================================================================
 Name        : task-wakeup.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task Wakeup Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>

static void
task1_entry (void *data)
{
    hev_task_yield (HEV_TASK_WAITIO);
}

static void
task2_entry (void *data)
{
    HevTask *task = data;

    while (hev_task_get_state (task) != HEV_TASK_WAITING)
        hev_task_yield (HEV_TASK_YIELD);

    hev_task_wakeup (task);
    hev_task_unref (task);
}

int
main (int argc, char *argv[])
{
    HevTask *task1, *task2;

    assert (hev_task_system_init () == 0);

    task1 = hev_task_new (-1);
    assert (task1);
    hev_task_run (task1, task1_entry, NULL);

    task2 = hev_task_new (-1);
    assert (task2);
    hev_task_run (task2, task2_entry, hev_task_ref (task1));

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
