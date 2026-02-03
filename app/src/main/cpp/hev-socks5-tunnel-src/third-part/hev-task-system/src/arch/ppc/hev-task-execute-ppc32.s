/*
 ============================================================================
 Name        : hev-task-execute-ppc32.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2022 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    lwz   5, 0(3)
    mflr  0
    stw   1, -0x04(5)
    stw   0, -0x08(5)
    addi  1, 5, -0x10

    mtctr 4
    bctrl

    lwz   0, 0x08(1)
    lwz   1, 0x0c(1)
    mtlr  0
    blr

    .size hev_task_execute, . - hev_task_execute
