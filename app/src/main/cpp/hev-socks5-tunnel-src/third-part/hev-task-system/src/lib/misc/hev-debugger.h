/*
 ============================================================================
 Name        : hev-debugger.h
 Authors     : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : Debugger
 ============================================================================
 */

#ifndef __HEV_DEBUGGER_H__
#define __HEV_DEBUGGER_H__

#ifdef __cplusplus
extern "C" {
#endif

HevTaskSystemContext *_hev_task_system_get_context (void);
unsigned int _hev_task_system_get_total_task_count (void);
unsigned int _hev_task_system_get_running_task_count (void);
HevTask *_hev_task_system_get_current_task (void);
void _hev_task_system_dump_all_tasks (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_DEBUGGER_H__ */
