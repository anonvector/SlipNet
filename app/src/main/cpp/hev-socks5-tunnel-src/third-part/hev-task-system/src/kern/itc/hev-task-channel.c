/*
 ============================================================================
 Name        : hev-task-channel.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Channel
 ============================================================================
 */

#include "kern/task/hev-task.h"
#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-channel-select-private.h"

#include "hev-task-channel.h"
#include "hev-task-channel-private.h"

EXPORT_SYMBOL int
hev_task_channel_new (HevTaskChannel **chan1, HevTaskChannel **chan2)
{
    return hev_task_channel_new_with_buffers (chan1, chan2, 0, 0);
}

EXPORT_SYMBOL int
hev_task_channel_new_with_buffers (HevTaskChannel **chan1,
                                   HevTaskChannel **chan2, unsigned int size,
                                   unsigned int buffers)
{
    HevTaskChannel *c1, *c2;
    unsigned int buffers_size;
    unsigned int data_size = 0;

    buffers += 1;
    if (buffers > 1)
        data_size = size * buffers;
    buffers_size = sizeof (HevTaskChannelBuffer) * buffers;

    c1 = hev_malloc (sizeof (HevTaskChannel) + buffers_size + data_size);
    if (!c1)
        goto err0;

    c2 = hev_malloc (sizeof (HevTaskChannel) + buffers_size + data_size);
    if (!c2)
        goto err1;

    __builtin_bzero (c1, sizeof (HevTaskChannel));
    c1->peer = c2;
    c1->max_size = size;
    c1->max_count = buffers;
    c1->ref_count = 1;

    __builtin_bzero (c2, sizeof (HevTaskChannel));
    c2->peer = c1;
    c2->max_size = size;
    c2->max_count = buffers;
    c2->ref_count = 1;

    if (buffers > 1) {
        unsigned int i;

        for (i = 0; i < buffers; i++) {
            c1->buffers[i].data = (void *)c1->buffers + buffers_size + size * i;
            c2->buffers[i].data = (void *)c2->buffers + buffers_size + size * i;
        }
    }

    *chan1 = c1;
    *chan2 = c2;

    return 0;

    hev_free (c2);
err1:
    hev_free (c1);
err0:

    return -1;
}

static void
hev_task_channel_ref (HevTaskChannel *self)
{
    self->ref_count++;
}

static void
hev_task_channel_unref (HevTaskChannel *self)
{
    self->ref_count--;
    if (self->ref_count)
        return;

    hev_free (self);
}

EXPORT_SYMBOL void
hev_task_channel_destroy (HevTaskChannel *self)
{
    if (self->peer) {
        self->peer->peer = NULL;
        if (self->peer->task)
            hev_task_wakeup (self->peer->task);
    }
    if (self->task)
        hev_task_wakeup (self->task);

    hev_task_channel_unref (self);
}

static ssize_t
hev_task_channel_data_copy (void *dst, const void *src, size_t size)
{
    HevTaskChannelData *d = dst;
    const HevTaskChannelData *s = src;

    switch (size) {
    case 0:
        break;
    case sizeof (char):
        d->b[0] = s->b[0];
        break;
    case sizeof (short):
        d->h[0] = s->h[0];
        break;
    case sizeof (int):
        d->w[0] = s->w[0];
        break;
    case sizeof (long long):
        d->d[0] = s->d[0];
        break;
    default:
        __builtin_memcpy (dst, src, size);
    }

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_channel_read (HevTaskChannel *self, void *buffer, size_t count)
{
    HevTaskChannelBuffer *cbuf;
    ssize_t size = -1;

    /* wait on empty */
    while (!hev_task_channel_is_readable (self)) {
        /* check is peer alive because cond wait may yield */
        if (!hev_task_channel_is_active (self))
            goto out;

        WRITE_ONCE (self->task, hev_task_self ());
        hev_task_yield (HEV_TASK_WAITIO);
    }

    barrier ();
    cbuf = &self->buffers[self->rd_idx];
    self->rd_idx = (self->rd_idx + 1) % self->max_count;

    size = count;
    if (cbuf->size < count)
        size = cbuf->size;
    size = hev_task_channel_data_copy (buffer, cbuf->data, size);

    if (self->use_count == self->max_count) {
        HevTaskChannel *peer = self->peer;

        if (peer) {
            if (peer->select)
                hev_task_channel_select_add_write (peer->select, peer);
            if (peer->task)
                hev_task_wakeup (peer->task);
        }
    }

    self->use_count--;
    if (self->select && !hev_task_channel_is_readable (self))
        hev_task_channel_select_del_read (self->select, self);

out:
    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_channel_write (HevTaskChannel *self, const void *buffer, size_t count)
{
    HevTaskChannel *peer = self->peer;
    HevTaskChannelBuffer *cbuf;
    ssize_t size = -1;

    if (!peer)
        goto out0;

    hev_task_channel_ref (peer);

    /* wait on full */
    while (!hev_task_channel_is_writable (peer)) {
        /* check is peer alive because cond wait may yield */
        if (!hev_task_channel_is_active (self))
            goto out1;

        WRITE_ONCE (self->task, hev_task_self ());
        hev_task_yield (HEV_TASK_WAITIO);
    }

    barrier ();
    cbuf = &peer->buffers[peer->wr_idx];
    peer->wr_idx = (peer->wr_idx + 1) % peer->max_count;

    size = count;
    if (peer->max_count == 1) {
        cbuf->data = (HevTaskChannelData *)buffer;
    } else {
        if (size > self->max_size)
            size = self->max_size;
        size = hev_task_channel_data_copy (cbuf->data, buffer, size);
    }
    cbuf->size = size;

    if (peer->use_count == 0) {
        if (peer->select)
            hev_task_channel_select_add_read (peer->select, peer);
        if (peer->task)
            hev_task_wakeup (peer->task);
    }

    peer->use_count++;
    if (self->select && !hev_task_channel_is_select_writable (peer))
        hev_task_channel_select_del_write (self->select, self);

    /* sync */
    while (!hev_task_channel_is_writable (peer)) {
        /* check is peer alive because cond wait may yield */
        if (!hev_task_channel_is_active (self)) {
            size = -1;
            break;
        }

        WRITE_ONCE (self->task, hev_task_self ());
        hev_task_yield (HEV_TASK_WAITIO);
    }

    barrier ();
out1:
    hev_task_channel_unref (peer);
out0:

    return size;
}
