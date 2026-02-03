/*
 ============================================================================
 Name        : hev-task-channel-select.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Channel Selector
 ============================================================================
 */

#ifndef __HEV_TASK_CHANNEL_SELECT_H__
#define __HEV_TASK_CHANNEL_SELECT_H__

#include <sys/types.h>

#include "hev-task-channel.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevTaskChannelSelect HevTaskChannelSelect;

/**
 * hev_task_channel_select_new:
 *
 * Creates A task channel selector.
 *
 * Returns: A #HevTaskChannelSelect
 *
 * Since: 4.6.9
 */
HevTaskChannelSelect *hev_task_channel_select_new (void);

/**
 * hev_task_channel_select_destroy:
 * @self: A #HevTaskChannelSelect
 *
 * Destroy the task channel selector.
 *
 * Since: 4.6.9
 */
void hev_task_channel_select_destroy (HevTaskChannelSelect *self);

/**
 * hev_task_channel_select_add:
 * @self: A #HevTaskChannelSelect
 * @chan: A #HevTaskChannel
 *
 * Add the task channel @chan to selector @self.
 *
 * Since: 4.6.9
 */
void hev_task_channel_select_add (HevTaskChannelSelect *self,
                                  HevTaskChannel *chan);

/**
 * hev_task_channel_select_del:
 * @self: A #HevTaskChannelSelect
 * @chan: A #HevTaskChannel
 *
 * Remove the task channel @chan to selector @self.
 *
 * Since: 4.6.9
 */
void hev_task_channel_select_del (HevTaskChannelSelect *self,
                                  HevTaskChannel *chan);

/**
 * hev_task_channel_select_read:
 * @self: A #HevTaskChannelSelect
 * @timeout: (milliseconds): wait timeout
 *
 * The select read function shall attempt to select a readable channel.
 * The function will wait until at least one channel is ready or timeout.
 *
 * Returns: A #HevTaskChannel
 *
 * Since: 4.6.9
 */
HevTaskChannel *hev_task_channel_select_read (HevTaskChannelSelect *self,
                                              int timeout);

/**
 * hev_task_channel_select_write:
 * @self: A #HevTaskChannelSelect
 * @timeout: (milliseconds): wait timeout
 *
 * The select write function shall attempt to select a writable channel.
 * The function will wait until at least one channel is ready or timeout.
 *
 * Returns: A #HevTaskChannel
 *
 * Since: 5.1.0
 */
HevTaskChannel *hev_task_channel_select_write (HevTaskChannelSelect *self,
                                               int timeout);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_CHANNEL_SELECT_H__ */
