/*
 ============================================================================
 Name        : hev-task-channel-select-private.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Channel Selector
 ============================================================================
 */

#ifndef __HEV_TASK_CHANNEL_SELECT_PRIVATE_H__
#define __HEV_TASK_CHANNEL_SELECT_PRIVATE_H__

#include "lib/list/hev-list.h"
#include "kern/task/hev-task.h"

#include "hev-task-channel.h"
#include "hev-task-channel-private.h"

#include "hev-task-channel-select.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HevTaskChannelSelect
{
    HevTask *task;
    HevList chan_list;
    HevList read_list;
    HevList write_list;
};

static inline void
hev_task_channel_select_add_read (HevTaskChannelSelect *self,
                                  HevTaskChannel *chan)
{
    if (chan->read.used)
        return;

    chan->read.used = 1;
    hev_list_add_tail (&self->read_list, &chan->read.node);
}

static inline void
hev_task_channel_select_del_read (HevTaskChannelSelect *self,
                                  HevTaskChannel *chan)
{
    if (!chan->read.used)
        return;

    chan->read.used = 0;
    hev_list_del (&self->read_list, &chan->read.node);
}

static inline void
hev_task_channel_select_add_write (HevTaskChannelSelect *self,
                                   HevTaskChannel *chan)
{
    if (chan->write.used)
        return;

    chan->write.used = 1;
    hev_list_add_tail (&self->write_list, &chan->write.node);
}

static inline void
hev_task_channel_select_del_write (HevTaskChannelSelect *self,
                                   HevTaskChannel *chan)
{
    if (!chan->write.used)
        return;

    chan->write.used = 0;
    hev_list_del (&self->write_list, &chan->write.node);
}

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_CHANNEL_SELECT_PRIVATE_H__ */
