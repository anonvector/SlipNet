/*
 ============================================================================
 Name        : hev-task-execute-or1k.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2025 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    l.lwz  r11, 0(r3)
    l.sw   -4(r11), r1
    l.sw   -8(r11), r9
    l.addi r1, r11, -8

    l.jalr r4
     l.nop

    l.lwz  r9, 0(r1)
    l.lwz  r1, 4(r1)
    l.jr   r9
     l.nop

    .end hev_task_execute
    .size hev_task_execute, . - hev_task_execute
