/*
 ============================================================================
 Name        : task-yield.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task Yield Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>

static int count;

static void
task1_entry (void *data)
{
    count++;
    hev_task_yield (HEV_TASK_YIELD);
    assert ((count & 1) == 0);
}

static void
task2_entry (void *data)
{
    count++;
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task1_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task2_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
