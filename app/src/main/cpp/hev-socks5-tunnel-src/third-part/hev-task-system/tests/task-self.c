/*
 ============================================================================
 Name        : task-self.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task Self Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>

static HevTask *task;

static void
task_entry (void *data)
{
    assert (hev_task_self () == task);
}

int
main (int argc, char *argv[])
{
    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
