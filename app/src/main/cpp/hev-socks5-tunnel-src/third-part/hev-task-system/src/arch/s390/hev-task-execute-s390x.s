/*
 ============================================================================
 Name        : hev-task-execute-s390x.s
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    lg   %r4, 0(%r2)
    aghi %r4, -256
    stmg %r14, %r15, 0(%r4)
    lgr  %r15, %r4

    basr %r14, %r3

    lmg  %r14, %r15, 0(%r15)
    br   %r14

    .size hev_task_execute, . - hev_task_execute
