/*
 ============================================================================
 Name        : task-channel-select.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Task Channel Select Test
 ============================================================================
 */

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-channel.h>
#include <hev-task-channel-select.h>

#define MAX_CHANNELS (1024)

typedef struct _ChannelData ChannelData;

typedef enum
{
    CHANNEL_DATA_U8,
    CHANNEL_DATA_U16,
    CHANNEL_DATA_U32,
    CHANNEL_DATA_U64,
    CHANNEL_DATA_CHAN,
} ChannelDataType;

struct _ChannelData
{
    uint32_t type;

    union
    {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        HevTaskChannel *chan;
    };
};

static void
task_read_entry (void *data)
{
    HevTaskChannelSelect *sel;
    HevTaskChannel *chan = data;
    HevTaskChannel *chans[MAX_CHANNELS];
    size_t i, chan_count = 0;

    sel = hev_task_channel_select_new ();
    assert (sel != NULL);

    hev_task_channel_select_add (sel, chan);

    for (;;) {
        HevTaskChannel *c;
        ChannelData d = { 0 };
        const size_t ds = sizeof (d);

        c = hev_task_channel_select_read (sel, 100);
        if (!c)
            break;

        assert (hev_task_channel_read (c, &d, ds) == ds);

        switch (d.type) {
        case CHANNEL_DATA_U8:
            assert (d.u8 == 123);
            break;
        case CHANNEL_DATA_U16:
            assert (d.u16 == 32767);
            break;
        case CHANNEL_DATA_U32:
            assert (d.u32 == 387563847);
            break;
        case CHANNEL_DATA_U64:
            assert (d.u64 == 3784597313707128903);
            break;
        case CHANNEL_DATA_CHAN:
            hev_task_channel_select_add (sel, d.chan);
            chans[chan_count] = d.chan;
            chan_count++;
            break;
        }
    }

    assert (hev_task_channel_select_read (sel, 0) == NULL);
    assert (hev_task_channel_select_read (sel, 1) == NULL);

    for (i = 0; i < chan_count; i++) {
        hev_task_channel_select_del (sel, chans[i]);
        hev_task_channel_destroy (chans[i]);
    }
    hev_task_channel_select_del (sel, chan);
    hev_task_channel_destroy (chan);
    hev_task_channel_select_destroy (sel);
}

static void
task_write_u8_entry (void *data)
{
    HevTaskChannel *chan = data;
    int i;

    for (i = 0; i < 8; i++) {
        ChannelData d;
        const size_t ds = sizeof (d);

        d.type = CHANNEL_DATA_U8;
        d.u8 = 123;
        assert (hev_task_channel_write (chan, &d, ds) == ds);
    }

    hev_task_channel_destroy (chan);
}

static void
task_write_u16_entry (void *data)
{
    HevTaskChannel *chan = data;
    int i;

    for (i = 0; i < 16; i++) {
        ChannelData d;
        const size_t ds = sizeof (d);

        d.type = CHANNEL_DATA_U16;
        d.u16 = 32767;
        assert (hev_task_channel_write (chan, &d, ds) == ds);
    }

    hev_task_channel_destroy (chan);
}

static void
task_write_u32_entry (void *data)
{
    HevTaskChannel *chan = data;
    int i;

    for (i = 0; i < 32; i++) {
        ChannelData d;
        const size_t ds = sizeof (d);

        d.type = CHANNEL_DATA_U32;
        d.u32 = 387563847;
        assert (hev_task_channel_write (chan, &d, ds) == ds);
    }

    hev_task_channel_destroy (chan);
}

static void
task_write_u64_entry (void *data)
{
    HevTaskChannel *chan = data;
    int i;

    for (i = 0; i < 64; i++) {
        ChannelData d;
        const size_t ds = sizeof (d);

        d.type = CHANNEL_DATA_U64;
        d.u64 = 3784597313707128903;
        assert (hev_task_channel_write (chan, &d, ds) == ds);
    }

    hev_task_channel_destroy (chan);
}

static void
task_fork_entry (void *data)
{
    HevTaskChannel *chan = data;
    int i;

    for (i = 0; i < MAX_CHANNELS; i++) {
        HevTaskChannel *chan1, *chan2;
        HevTask *task;
        ChannelData d;
        const size_t ds = sizeof (d);
        static const HevTaskEntry entries[] = {
            task_write_u8_entry,
            task_write_u16_entry,
            task_write_u32_entry,
            task_write_u64_entry,
        };

        assert (hev_task_channel_new (&chan1, &chan2) == 0);

        task = hev_task_new (-1);
        assert (task);
        hev_task_set_priority (task, i % (HEV_TASK_PRIORITY_MAX + 1));
        hev_task_run (task, entries[i % 4], chan1);

        d.type = CHANNEL_DATA_CHAN;
        d.chan = chan2;
        assert (hev_task_channel_write (chan, &d, ds) == ds);
    }

    hev_task_channel_destroy (chan);
}

static void
task_select_entry (void *data)
{
    HevTaskChannel *chans[MAX_CHANNELS];
    HevTaskChannel *chan = data;
    HevTaskChannelSelect *sel;
    int i;

    sel = hev_task_channel_select_new ();
    assert (sel != NULL);

    for (i = 0; i < MAX_CHANNELS; i++) {
        HevTask *task;

        assert (hev_task_channel_new (&chan, &chans[i]) == 0);
        hev_task_channel_select_add (sel, chans[i]);

        task = hev_task_new (-1);
        assert (task);
        hev_task_set_priority (task, 1);
        hev_task_run (task, task_read_entry, chan);
    }

    for (i = 0; i < MAX_CHANNELS; i++) {
        HevTaskChannel *c;
        ChannelData d;
        const size_t ds = sizeof (d);

        c = hev_task_channel_select_write (sel, 100);
        if (!c)
            break;

        d.type = CHANNEL_DATA_U64;
        d.u64 = 3784597313707128903;
        assert (hev_task_channel_write (c, &d, ds) == ds);
    }

    assert (hev_task_channel_select_write (sel, 0) == NULL);
    assert (hev_task_channel_select_write (sel, 1) == NULL);

    for (i = 0; i < MAX_CHANNELS; i++) {
        hev_task_channel_select_del (sel, chans[i]);
        hev_task_channel_destroy (chans[i]);
    }
    hev_task_channel_select_destroy (sel);
}

int
main (int argc, char *argv[])
{
    HevTaskChannel *chan1, *chan2;
    HevTask *task;

    assert (hev_task_system_init () == 0);

    assert (hev_task_channel_new (&chan1, &chan2) == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_read_entry, chan1);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_fork_entry, chan2);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_select_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
