/*
 ============================================================================
 Name        : hev-task-channel-select.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Channel Selector
 ============================================================================
 */

#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-channel-select.h"
#include "hev-task-channel-select-private.h"

EXPORT_SYMBOL HevTaskChannelSelect *
hev_task_channel_select_new (void)
{
    HevTaskChannelSelect *self;

    self = hev_malloc0 (sizeof (HevTaskChannelSelect));

    return self;
}

EXPORT_SYMBOL void
hev_task_channel_select_destroy (HevTaskChannelSelect *self)
{
    hev_free (self);
}

EXPORT_SYMBOL void
hev_task_channel_select_add (HevTaskChannelSelect *self, HevTaskChannel *chan)
{
    chan->select = self;
    chan->task = hev_task_self ();

    hev_list_add_tail (&self->chan_list, &chan->chan_node);
    if (hev_task_channel_is_readable (chan))
        hev_task_channel_select_add_read (self, chan);
    if (chan->peer && hev_task_channel_is_select_writable (chan->peer))
        hev_task_channel_select_add_write (self, chan);
}

EXPORT_SYMBOL void
hev_task_channel_select_del (HevTaskChannelSelect *self, HevTaskChannel *chan)
{
    hev_task_channel_select_del_read (self, chan);
    hev_task_channel_select_del_write (self, chan);
    hev_list_del (&self->chan_list, &chan->chan_node);

    chan->task = NULL;
    chan->select = NULL;
}

static HevListNode *
hev_task_channel_select (HevTaskChannelSelect *self, HevList *list, int timeout)
{
    HevListNode *node;
    unsigned int milliseconds = timeout;

    if (!hev_list_first (&self->chan_list))
        return NULL;

    while (!(node = hev_list_first (list)) && milliseconds) {
        barrier ();
        if (timeout < 0)
            hev_task_yield (HEV_TASK_WAITIO);
        else
            milliseconds = hev_task_sleep (milliseconds);
        barrier ();
    }

    return node;
}

EXPORT_SYMBOL HevTaskChannel *
hev_task_channel_select_read (HevTaskChannelSelect *self, int timeout)
{
    HevListNode *node;

    node = hev_task_channel_select (self, &self->read_list, timeout);
    if (!node)
        return NULL;

    return container_of (node, HevTaskChannel, read.node);
}

EXPORT_SYMBOL HevTaskChannel *
hev_task_channel_select_write (HevTaskChannelSelect *self, int timeout)
{
    HevListNode *node;

    node = hev_task_channel_select (self, &self->write_list, timeout);
    if (!node)
        return NULL;

    return container_of (node, HevTaskChannel, write.node);
}
