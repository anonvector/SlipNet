/*
 ============================================================================
 Name        : hev-task-io-reactor-iocp.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 hev
 Description : I/O Reactor IOCP
 ============================================================================
 */

#ifndef __HEV_TASK_IO_REACTOR_IOCP_H__
#define __HEV_TASK_IO_REACTOR_IOCP_H__

#include <io.h>
#include <poll.h>
#include <pthread.h>

#include "lib/rbtree/hev-rbtree.h"
#include "lib/misc/hev-windows-api.h"

#define HEV_TASK_IO_REACTOR_EVENT_GEN_MAX (1)

typedef struct _HevTaskIOReactorIOCP HevTaskIOReactorIOCP;
typedef struct _HevTaskIOReactorSetupEvent HevTaskIOReactorSetupEvent;
typedef struct _HevTaskIOReactorWaitEvent HevTaskIOReactorWaitEvent;

struct _HevTaskIOReactorIOCP
{
    HevTaskIOReactor base;

    HevRBTree tree;
    pthread_mutex_t mutex;
};

enum _HevTaskIOReactorEvents
{
    HEV_TASK_IO_REACTOR_EV_RO = FD_READ | FD_ACCEPT,
    HEV_TASK_IO_REACTOR_EV_WO = FD_WRITE | FD_CONNECT,
    HEV_TASK_IO_REACTOR_EV_ER = FD_CLOSE,
};

enum _HevTaskIOReactorOperation
{
    HEV_TASK_IO_REACTOR_OP_ADD,
    HEV_TASK_IO_REACTOR_OP_MOD,
    HEV_TASK_IO_REACTOR_OP_DEL,
};

struct _HevTaskIOReactorSetupEvent
{
    HevTaskIOReactorOperation op;

    long handle;
    int events;
    void *data;
};

struct _HevTaskIOReactorWaitEvent
{
    int events;
    void *data;
};

int hev_task_io_reactor_wait (HevTaskIOReactor *self,
                              HevTaskIOReactorWaitEvent *events, int count,
                              int timeout);

static inline void
hev_task_io_reactor_setup_event_set (HevTaskIOReactorSetupEvent *event,
                                     long handle, HevTaskIOReactorOperation op,
                                     unsigned int events, void *data)
{
    event->op = op;
    event->handle = handle;
    event->events = events;
    event->data = data;
}

static inline int
hev_task_io_reactor_setup_event_fd_gen (HevTaskIOReactorSetupEvent *events,
                                        long fd, HevTaskIOReactorOperation op,
                                        unsigned int poll_events, void *data)
{
    HevTaskIOReactorEvents reactor_events = 0;

    if (poll_events & POLLIN)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_RO;
    if (poll_events & POLLOUT)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_WO;
    if (poll_events & POLLERR)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_ER;

    hev_task_io_reactor_setup_event_set (events, get_osfhandle (fd), op,
                                         reactor_events, data);

    return 1;
}

static inline int
hev_task_io_reactor_setup_event_whandle_gen (HevTaskIOReactorSetupEvent *events,
                                             void *handle,
                                             HevTaskIOReactorOperation op,
                                             void *data)
{
    hev_task_io_reactor_setup_event_set (events, (long)handle, op, 0, data);

    return 1;
}

static inline unsigned int
hev_task_io_reactor_wait_event_get_events (HevTaskIOReactorWaitEvent *event)
{
    unsigned int events = 0;

    if (event->events & HEV_TASK_IO_REACTOR_EV_RO)
        events |= POLLIN;
    if (event->events & HEV_TASK_IO_REACTOR_EV_WO)
        events |= POLLOUT;
    if (event->events & HEV_TASK_IO_REACTOR_EV_ER)
        events |= POLLERR;

    return events;
}

static inline void *
hev_task_io_reactor_wait_event_get_data (HevTaskIOReactorWaitEvent *event)
{
    return event->data;
}

#endif /* __HEV_TASK_IO_REACTOR_IOCP_H__ */
