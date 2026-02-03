/*
 ============================================================================
 Name        : timeout.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

#include <stdio.h>

#include <hev-task.h>
#include <hev-task-system.h>

static void
task_entry (void *data)
{
    const unsigned int interval = 1000;

    printf ("waiting for timeout %ums ...\n", interval);
    hev_task_sleep (interval);
    printf ("timeout\n");
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    hev_task_system_init ();

    task = hev_task_new (-1);
    hev_task_run (task, task_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
