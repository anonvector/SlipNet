/*
 ============================================================================
 Name        : hev-task-execute-microblaze.s
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    lwi   r3, r5, 0
    swi   r1, r3, -4
    swi   r15, r3, -8

    brald r15, r6
    addi  r1, r3, -32

    lwi   r15, r1, 24
    rtsd  r15, 8
    lwi   r1, r1, 28

    .size hev_task_execute, . - hev_task_execute
