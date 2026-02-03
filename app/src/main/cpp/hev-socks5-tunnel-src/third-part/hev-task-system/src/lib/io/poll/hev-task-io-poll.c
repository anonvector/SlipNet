/*
 ============================================================================
 Name        : hev-task-io-poll.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2019 everyone.
 Description :
 ============================================================================
 */

#include "kern/task/hev-task.h"
#include "lib/misc/hev-compiler.h"

#include "hev-task-io-poll.h"

EXPORT_SYMBOL int
hev_task_io_poll (HevTaskIOPollFD fds[], unsigned int nfds, int timeout)
{
    int res;

    if (timeout == 0) {
        res = poll (fds, nfds, 0);
    } else {
        HevTask *task = hev_task_self ();
        unsigned int i;

        for (i = 0; i < nfds; i++) {
            if (hev_task_mod_fd (task, fds[i].fd, fds[i].events) < 0)
                hev_task_add_fd (task, fds[i].fd, fds[i].events);
        }

        if (timeout > 0) {
            do {
                timeout = hev_task_sleep (timeout);
                res = poll (fds, nfds, 0);
            } while (timeout > 0 && res == 0);
        } else {
            do {
                hev_task_yield (HEV_TASK_WAITIO);
                res = poll (fds, nfds, 0);
            } while (res == 0);
        }
    }

    return res;
}
