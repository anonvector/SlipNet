/*
 ============================================================================
 Name        : hev-task-execute-sh.s
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    mov.l @r4, r3
    mov.l r15, @-r3
    sts.l pr, @-r3

    jsr   @r5
    mov   r3, r15

    lds.l @r15+, pr
    rts
    mov.l @r15, r15

    .end hev_task_execute
    .size hev_task_execute, . - hev_task_execute
