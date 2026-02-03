/*
 ============================================================================
 Name        : channel.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description :
 ============================================================================
 */

#include <stdio.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-channel.h>

typedef struct _TaskArgs TaskArgs;

struct _TaskArgs
{
    int type;
    char *command;
};

static void
task_entry1 (void *data)
{
    HevTaskChannel *chan = data;
    TaskArgs args;

    hev_task_channel_read (chan, &args, sizeof (args));
    printf ("type: %d command: %s\n", args.type, args.command);

    args.type = 2;
    args.command = "world";
    hev_task_channel_write (chan, &args, sizeof (args));

    hev_task_channel_destroy (chan);
}

static void
task_entry2 (void *data)
{
    HevTaskChannel *chan = data;
    TaskArgs args = {
        .type = 1,
        .command = "hello",
    };

    hev_task_channel_write (chan, &args, sizeof (args));
    hev_task_channel_read (chan, &args, sizeof (args));
    printf ("type: %d command: %s\n", args.type, args.command);

    hev_task_channel_destroy (chan);
}

int
main (int argc, char *argv[])
{
    HevTask *task;
    HevTaskChannel *chan1, *chan2;

    hev_task_system_init ();

    hev_task_channel_new (&chan1, &chan2);

    task = hev_task_new (-1);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_entry1, chan1);

    task = hev_task_new (-1);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_entry2, chan2);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
