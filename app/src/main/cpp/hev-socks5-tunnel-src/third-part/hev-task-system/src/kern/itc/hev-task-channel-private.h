/*
 ============================================================================
 Name        : hev-task-channel-private.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Channel
 ============================================================================
 */

#ifndef __HEV_TASK_CHANNEL_PRIVATE_H__
#define __HEV_TASK_CHANNEL_PRIVATE_H__

#include "lib/list/hev-list.h"
#include "kern/task/hev-task.h"

#include "hev-task-channel-select.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union _HevTaskChannelData HevTaskChannelData;
typedef struct _HevTaskChannelBuffer HevTaskChannelBuffer;

union _HevTaskChannelData
{
    char b[0];
    short h[0];
    int w[0];
    long long d[0];
};

struct _HevTaskChannelBuffer
{
    size_t size;
    HevTaskChannelData *data;
};

struct _HevTaskChannel
{
    HevTaskChannel *peer;

    struct
    {
        HevListNode node;
        int used;
    } read;
    struct
    {
        HevListNode node;
        int used;
    } write;
    HevListNode chan_node;

    HevTask *task;
    HevTaskChannelSelect *select;

    unsigned int rd_idx;
    unsigned int wr_idx;
    unsigned int max_size;
    unsigned int use_count;
    unsigned int max_count;
    unsigned int ref_count;

    HevTaskChannelBuffer buffers[0];
};

static inline int
hev_task_channel_is_active (HevTaskChannel *self)
{
    return READ_ONCE (self->peer) != NULL;
}

static inline int
hev_task_channel_is_readable (HevTaskChannel *self)
{
    return READ_ONCE (self->use_count) != 0;
}

static inline int
hev_task_channel_is_writable (HevTaskChannel *peer)
{
    return READ_ONCE (peer->use_count) < READ_ONCE (peer->max_count);
}

static inline int
hev_task_channel_is_select_writable (HevTaskChannel *peer)
{
    return READ_ONCE (peer->use_count) < (READ_ONCE (peer->max_count) - 1);
}

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_CHANNEL_PRIVATE_H__ */
