/*
 ============================================================================
 Name        : hev-task-executer.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

#include "hev-task-executer.h"
#include "kern/core/hev-task-system-private.h"

void
hev_task_executer (HevTask *task)
{
    if (_setjmp (task->context) == 0)
        return;

    task->entry (task->data);

    if (task->joiner)
        hev_task_wakeup (task->joiner);

    hev_task_system_kill_current_task ();
}
