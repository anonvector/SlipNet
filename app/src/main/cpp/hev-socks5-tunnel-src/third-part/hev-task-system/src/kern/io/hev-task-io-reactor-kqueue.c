/*
 ============================================================================
 Name        : hev-task-io-reactor-kqueue.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : I/O Reactor KQueue
 ============================================================================
 */

#if !defined(__linux__) && !defined(__MSYS__)

#include <fcntl.h>
#include <unistd.h>

#include "mem/api/hev-memory-allocator-api.h"

#include "kern/io/hev-task-io-reactor.h"

HevTaskIOReactor *
hev_task_io_reactor_new (void)
{
    HevTaskIOReactor *self;
    int flags;

    self = hev_malloc0 (sizeof (HevTaskIOReactor));
    if (!self)
        return NULL;

    self->fd = kqueue ();
    if (self->fd < 0) {
        hev_free (self);
        return NULL;
    }

    flags = fcntl (self->fd, F_GETFD);
    if (flags < 0) {
        hev_free (self);
        return NULL;
    }

    flags |= FD_CLOEXEC;
    if (fcntl (self->fd, F_SETFD, flags) < 0) {
        hev_free (self);
        return NULL;
    }

    return self;
}

void
hev_task_io_reactor_destroy (HevTaskIOReactor *self)
{
    close (self->fd);
    hev_free (self);
}

int
hev_task_io_reactor_setup (HevTaskIOReactor *self,
                           HevTaskIOReactorSetupEvent *events, int count)
{
    int i, res = -1;

    for (i = 0; i < count; i++) {
        if (!(events[i].flags & EV_DELETE)) {
            res = kevent (self->fd, &events[i], count - i, NULL, 0, NULL);
            break;
        }
        res &= kevent (self->fd, &events[i], 1, NULL, 0, NULL);
    }

    return res;
}

#endif /* !defined(__linux__) && !defined(__MSYS__) */
