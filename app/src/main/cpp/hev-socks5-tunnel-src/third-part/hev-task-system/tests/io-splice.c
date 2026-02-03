/*
 ============================================================================
 Name        : io-splice.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : IO Splice Test
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

static int fds1[2];
static int fds2[2];

static void
task_splice_entry (void *data)
{
    HevTask *task = hev_task_self ();

    assert (hev_task_add_fd (task, fds1[1], POLLIN | POLLOUT) == 0);
    assert (hev_task_add_fd (task, fds2[0], POLLIN | POLLOUT) == 0);

    hev_task_io_splice (fds1[1], fds1[1], fds2[0], fds2[0], 2048, NULL, NULL);

    assert (hev_task_del_fd (task, fds1[1]) == 0);
    assert (hev_task_del_fd (task, fds2[0]) == 0);

    close (fds1[1]);
    close (fds2[0]);
}

static void
task_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int result;
    char buf1[64], buf2[64];
    ssize_t size;

    result = hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds1);
    assert (result == 0);
    result = hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds2);
    assert (result == 0);

    assert (hev_task_add_fd (task, fds1[0], POLLOUT) == 0);
    assert (hev_task_add_fd (task, fds2[1], POLLIN) == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task_splice_entry, NULL);

    size = hev_task_io_socket_send (fds1[0], buf1, 64, MSG_WAITALL, NULL, NULL);
    assert (size == 64);
    size = hev_task_io_socket_recv (fds2[1], buf2, 64, MSG_WAITALL, NULL, NULL);
    assert (size == 64);

    assert (memcmp (buf1, buf2, 64) == 0);

    assert (hev_task_del_fd (task, fds1[0]) == 0);
    assert (hev_task_del_fd (task, fds2[1]) == 0);

    close (fds1[0]);
    close (fds2[1]);
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
