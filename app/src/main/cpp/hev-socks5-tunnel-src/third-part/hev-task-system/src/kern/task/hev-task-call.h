/*
 ============================================================================
 Name        : hev-task-call.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2020 everyone.
 Description : Task call
 ============================================================================
 */

#ifndef __HEV_TASK_CALL_H__
#define __HEV_TASK_CALL_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevTaskCall HevTaskCall;
typedef void (*HevTaskCallEntry) (HevTaskCall *call);

struct _HevTaskCall
{
    void *stack_top;
    void *retval;
};

/**
 * hev_task_call_new:
 * @base_size: base size
 * @stack_size: stack size
 *
 * Creates a new task call.
 *
 * Returns: a new #HevTaskCall.
 *
 * Since: 4.8.0
 */
HevTaskCall *hev_task_call_new (int base_size, int stack_size);

/**
 * hev_task_call_destroy:
 * @self: a #HevTaskCall
 *
 * Destroy the task call.
 *
 * Since: 4.8.0
 */
void hev_task_call_destroy (HevTaskCall *self);

/**
 * hev_task_call_jump:
 * @self: a #HevTaskCall
 * @entry: task call entry
 *
 * Call @entry on new stack.
 *
 * Returns: value from @entry (see set_retval).
 *
 * Since: 4.8.0
 */
void *hev_task_call_jump (HevTaskCall *self, HevTaskCallEntry entry);

/**
 * hev_task_call_set_retval:
 * @self: a #HevTaskCall
 * @value: return value
 *
 * Set return value of task call.
 *
 * Since: 4.8.0
 */
static inline void
hev_task_call_set_retval (HevTaskCall *self, void *value)
{
    self->retval = value;
}

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_CALL_H__ */
