/*
 ============================================================================
 Name        : task-data.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task Data Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>

static int tag;

static void
task_entry (void *data)
{
    assert (data == &tag);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task_entry, &tag);

    assert (hev_task_get_data (task) == &tag);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
