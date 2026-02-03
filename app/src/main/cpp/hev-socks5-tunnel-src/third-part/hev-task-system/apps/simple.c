/*
 ============================================================================
 Name        : simple.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

#include <stdio.h>

#include <hev-task.h>
#include <hev-task-system.h>

static void
task_entry1 (void *data)
{
    int i;

    for (i = 0; i < 2; i++) {
        printf ("hello 1\n");
        hev_task_yield (HEV_TASK_YIELD);
    }
}

static void
task_entry2 (void *data)
{
    int i;

    for (i = 0; i < 2; i++) {
        printf ("hello 2\n");
        hev_task_yield (HEV_TASK_YIELD);
    }
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    hev_task_system_init ();

    task = hev_task_new (-1);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_entry1, NULL);

    task = hev_task_new (-1);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_entry2, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
