/*
 ============================================================================
 Name        : io-poll.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : IO Poll Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-poll.h>
#include <hev-task-io-socket.h>

static int fds[2];

static void
task1_entry (void *data)
{
    int val;
    HevTaskIOPollFD pfds[1];

    pfds[0].fd = fds[0];
    pfds[0].events = POLLIN;

    val = hev_task_io_poll (pfds, 1, -1);
    assert (val == 1);
    assert (pfds[0].revents & POLLIN);

    close (fds[0]);
}

static void
task2_entry (void *data)
{
    int val;
    HevTaskIOPollFD pfds[1];

    hev_task_sleep (50);

    pfds[0].fd = fds[1];
    pfds[0].events = POLLOUT;

    val = hev_task_io_poll (pfds, 1, -1);
    assert (val == 1);
    assert (pfds[0].revents & POLLOUT);

    assert (write (fds[1], &val, sizeof (val)) == sizeof (val));

    close (fds[1]);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

#if defined(__MSYS__)
    return 0;
#endif

    assert (hev_task_system_init () == 0);

    assert (hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds) == 0);
    assert (fds[0] >= 0);
    assert (fds[1] >= 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task1_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, task2_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
