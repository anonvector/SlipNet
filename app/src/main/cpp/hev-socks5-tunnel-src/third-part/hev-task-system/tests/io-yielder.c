/*
 ============================================================================
 Name        : io-yielder.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : IO Yielder Test
 ============================================================================
 */

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    assert (type == HEV_TASK_WAITIO);

    return -1;
}

static void
task_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int fds[2];
    char buf[16];
    ssize_t size;

    assert (hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds) == 0);
    assert (fds[0] >= 0);
    assert (fds[1] >= 0);

    assert (hev_task_add_fd (task, fds[0], POLLIN) == 0);

    size = hev_task_io_read (fds[0], buf, 16, task_io_yielder, NULL);
    assert (size == -2);

    assert (hev_task_del_fd (task, fds[0]) == 0);
    close (fds[0]);
    close (fds[1]);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
