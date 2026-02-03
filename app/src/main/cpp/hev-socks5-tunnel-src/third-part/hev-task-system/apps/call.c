/*
 ============================================================================
 Name        : call.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description :
 ============================================================================
 */

#include <stdio.h>

#include <hev-task.h>
#include <hev-task-call.h>
#include <hev-task-system.h>

static void
call_entry (HevTaskCall *call)
{
    void *ptr;

    printf ("call %p on stack %p\n", call, &ptr);
    hev_task_call_set_retval (call, &ptr);
}

static void
task_entry (void *data)
{
    HevTaskCall *call;

    call = hev_task_call_new (sizeof (HevTaskCall), 8192);
    hev_task_call_jump (call, call_entry);
    hev_task_call_destroy (call);
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
