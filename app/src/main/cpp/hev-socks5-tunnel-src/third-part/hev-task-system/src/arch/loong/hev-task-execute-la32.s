/*
 ============================================================================
 Name        : hev-task-execute-la32.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description :
 ============================================================================
 */

    .globl hev_task_execute
    .type hev_task_execute, @function

hev_task_execute:
    ld.w  $t0, $a0, 0
    st.w  $sp, $t0, -4
    st.w  $ra, $t0, -8
    addi.w  $sp, $t0, -8

    jirl  $ra, $a1, 0

    ld.w  $ra, $sp, 0
    ld.w  $sp, $sp, 4
    jirl  $zero, $ra, 0

    .size hev_task_execute, . - hev_task_execute
