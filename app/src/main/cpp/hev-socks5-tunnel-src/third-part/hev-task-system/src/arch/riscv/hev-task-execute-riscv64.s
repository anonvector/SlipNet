/*
 ============================================================================
 Name        : hev-task-execute-riscv64.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    ld  t0, (a0)
    sd  sp, -0x08(t0)
    sd  ra, -0x10(t0)
    addi  sp, t0, -0x10

    jalr  a1

    ld  ra, (sp)
    ld  sp, 0x08(sp)
    jr  ra

    .size hev_task_execute, . - hev_task_execute
