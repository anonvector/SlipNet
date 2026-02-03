/*
 ============================================================================
 Name        : hev-task-stack-detector.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev.
 Description : Task Stack Overflow Detector
 ============================================================================
 */

#ifndef __HEV_TASK_STACK_DETECTOR_H__
#define __HEV_TASK_STACK_DETECTOR_H__

typedef struct _HevTaskStackDetector HevTaskStackDetector;

HevTaskStackDetector *hev_task_stack_detector_new (void);
void hev_task_stack_detector_destroy (HevTaskStackDetector *self);

#endif /* __HEV_TASK_STACK_DETECTOR_H__ */
