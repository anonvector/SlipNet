/*
 ============================================================================
 Name        : wakeup.c
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
    const unsigned int interval = 5000;
    unsigned int left_ms;

    printf ("task1: waiting for timeout %ums ...\n", interval);
    left_ms = hev_task_sleep (interval);
    if (left_ms == 0)
        printf ("task1: timeout\n");
    else
        printf ("task1: awake now, left: %ums\n", left_ms);
}

static void
task_entry2 (void *data)
{
    HevTask *task1 = data;
    const unsigned int interval = 1000;

    printf ("task2: wakeup task1 after %dms...\n", interval);
    hev_task_sleep (interval);
    printf ("task2: wakeup task1 ...\n");
    hev_task_wakeup (task1);
}

int
main (int argc, char *argv[])
{
    HevTask *task1, *task2;

    hev_task_system_init ();

    task1 = hev_task_new (-1);
    hev_task_run (task1, task_entry1, NULL);

    task2 = hev_task_new (-1);
    hev_task_set_priority (task2, 1);
    hev_task_run (task2, task_entry2, task1);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
