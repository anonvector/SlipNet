/*
 ============================================================================
 Name        : hev-task-execute-mips64.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .ent hev_task_execute, 0
    .type hev_task_execute, @function

hev_task_execute:
    ld  $t0, ($a0)
    sd  $sp, -0x08($t0)
    sd  $ra, -0x10($t0)
    daddiu  $sp, $t0, -0x10

    move  $t9, $a1
    jalr  $a1

    ld  $ra, ($sp)
    ld  $sp, 0x08($sp)
    jr  $ra

    .end hev_task_execute
    .size hev_task_execute, . - hev_task_execute
