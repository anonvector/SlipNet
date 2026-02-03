/*
 ============================================================================
 Name        : hev-task-execute-arm.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2021 everyone.
 Description :
 ============================================================================
 */

#include "asm.h"

NESTED(hev_task_execute)
    ldr  r3, [r0]
    str  sp, [r3, #-0x4]
    str  lr, [r3, #-0x8]
    sub  sp, r3, #0x8

    blx  r1

    ldr  lr, [sp]
    ldr  sp, [sp, #0x4]
    bx   lr
END(hev_task_execute)
