/*
 ============================================================================
 Name        : io-writev.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : IO WriteV Test
 ============================================================================
 */

#include <assert.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

static void
task_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int fds[2];
    char buf1[2], buf2[2];
    ssize_t size;
    struct iovec iov[2];

    assert (hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds) == 0);

    assert (hev_task_add_fd (task, fds[1], POLLOUT) == 0);

    iov[0].iov_base = buf1;
    iov[0].iov_len = 2;
    iov[1].iov_base = buf2;
    iov[1].iov_len = 2;
    size = hev_task_io_writev (fds[1], iov, 2, NULL, NULL);
    assert (size == 4);

    assert (hev_task_del_fd (task, fds[1]) == 0);
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
