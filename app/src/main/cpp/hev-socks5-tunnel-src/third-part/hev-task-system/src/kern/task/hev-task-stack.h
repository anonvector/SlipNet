/*
 ============================================================================
 Name        : hev-task-stack.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description :
 ============================================================================
 */

#ifndef __HEV_TASK_STACK_H__
#define __HEV_TASK_STACK_H__

#define STACK_HEAP (0)
#define STACK_MMAP (1)

typedef struct _HevTaskStack HevTaskStack;

HevTaskStack *hev_task_stack_new (int size);
void hev_task_stack_destroy (HevTaskStack *self);

void *hev_task_stack_get_base (HevTaskStack *self);
void *hev_task_stack_get_bottom (HevTaskStack *self);

#endif /* __HEV_TASK_STACK_H__ */
