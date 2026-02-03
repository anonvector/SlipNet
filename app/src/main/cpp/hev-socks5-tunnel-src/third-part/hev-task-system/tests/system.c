/*
 ============================================================================
 Name        : system.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : System Test
 ============================================================================
 */

#include <assert.h>

#include <hev-task-system.h>

int
main (int argc, char *argv[])
{
    assert (hev_task_system_init () == 0);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
