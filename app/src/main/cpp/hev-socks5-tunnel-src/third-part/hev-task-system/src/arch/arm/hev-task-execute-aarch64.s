/*
 ============================================================================
 Name        : hev-task-execute-aarch64.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 everyone.
 Description :
 ============================================================================
 */

#include "asm.h"

NESTED(hev_task_execute)
    ldr  x3, [x0]
    mov  x4, sp
    stp  x4, x30, [x3, -0x10]
    sub  sp, x3, 0x10

    blr  x1

    ldp  x4, x30, [sp]
    mov  sp, x4
    ret
END(hev_task_execute)
