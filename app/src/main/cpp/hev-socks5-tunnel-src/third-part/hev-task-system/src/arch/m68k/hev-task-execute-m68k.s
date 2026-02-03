/*
 ============================================================================
 Name        : hev-task-execute-m68k.s
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    movel  %sp, %d0
    moveal %sp@(4), %a0
    moveal %sp@(8), %a1
    moveal %a0@, %sp

    moveml %d0, %sp@-
    moveml %a0, %sp@-
    jsr    %a1@

    moveal %sp@(4), %sp
    rts

    .end hev_task_execute
    .size hev_task_execute, . - hev_task_execute
