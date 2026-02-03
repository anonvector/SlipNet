/*
 ============================================================================
 Name        : hev-task-execute-sw64.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description :
 ============================================================================
 */

#include <asm/regdef.h>

    .globl hev_task_execute
    .ent hev_task_execute, 0
    .type hev_task_execute, @function

hev_task_execute:
    ldl  t0, 0(a0)
    stl  sp, -0x08(t0)
    stl  ra, -0x10(t0)
    subl  t0, 0x10, sp

    mov  a1, pv
    call  ra, (pv)

    ldl  ra, 0(sp)
    ldl  sp, 8(sp)
    ret  zero, (ra)

    .end hev_task_execute
    .size hev_task_execute, . - hev_task_execute
