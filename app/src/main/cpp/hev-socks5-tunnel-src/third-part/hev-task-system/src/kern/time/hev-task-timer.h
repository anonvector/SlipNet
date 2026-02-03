/*
 ============================================================================
 Name        : hev-task-timer.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : Timer
 ============================================================================
 */

#ifndef __HEV_TASK_TIMER_H__
#define __HEV_TASK_TIMER_H__

#include <time.h>

#include "kern/task/hev-task.h"
#include "lib/rbtree/hev-rbtree-cached.h"

typedef struct _HevTaskTimer HevTaskTimer;

HevTaskTimer *hev_task_timer_new (void *ctx);
void hev_task_timer_destroy (HevTaskTimer *self);

int hev_task_timer_get_timeout (HevTaskTimer *self);
void hev_task_timer_wake (HevTaskTimer *self);

unsigned int hev_task_timer_wait (HevTaskTimer *self, unsigned int milliseconds,
                                  HevTask *task);

#endif /* __HEV_TASK_TIMER_H__ */
