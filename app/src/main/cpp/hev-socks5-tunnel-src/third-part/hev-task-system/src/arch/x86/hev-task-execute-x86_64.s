/*
 ============================================================================
 Name        : hev-task-execute-x86_64.s
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2025 everyone.
 Description :
 ============================================================================
 */

#include "asm.h"

#if defined(__MSYS__)
#define REG_ARG0  %rcx
#define REG_ARG1  %rdx
#define STACK_PAD 0x28
#else
#define REG_ARG0  %rdi
#define REG_ARG1  %rsi
#define STACK_PAD 0x08
#endif

NESTED(hev_task_execute)
    movq  %rsp, %rax
    movq  (REG_ARG0), %rsp
    pushq %rax
    subq  $STACK_PAD, %rsp

    callq *REG_ARG1

    movq  STACK_PAD(%rsp), %rsp
    retq
END(hev_task_execute)
