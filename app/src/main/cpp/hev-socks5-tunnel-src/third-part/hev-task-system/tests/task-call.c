/*
 ============================================================================
 Name        : task-call.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : Task Call Test
 ============================================================================
 */

#include <assert.h>
#include <stdlib.h>

#include <hev-task.h>
#include <hev-task-call.h>
#include <hev-task-system.h>

static void
call_entry1 (HevTaskCall *call)
{
    void *ptr;

    ptr = alloca (1);
    hev_task_call_set_retval (call, ptr);
}

static void
call_entry2 (HevTaskCall *call)
{
    hev_task_call_set_retval (call, call_entry1);
}

static void
task_entry (void *data)
{
    HevTaskCall *call;
    void *retval;

    call = hev_task_call_new (sizeof (HevTaskCall), 8192);

    retval = hev_task_call_jump (call, call_entry1);
    assert (retval > (void *)call + sizeof (HevTaskCall));
    assert (retval < (void *)call + sizeof (HevTaskCall) + 8192);

    retval = hev_task_call_jump (call, call_entry2);
    assert (retval == call_entry1);

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
