/*
 ============================================================================
 Name        : hev-task-execute-riscv32.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    lw  t0, (a0)
    sw  sp, -0x0c(t0)
    sw  ra, -0x10(t0)
    addi  sp, t0, -0x10

    jalr  a1

    lw  ra, (sp)
    lw  sp, 0x0c(sp)
    jr  ra

    .size hev_task_execute, . - hev_task_execute
