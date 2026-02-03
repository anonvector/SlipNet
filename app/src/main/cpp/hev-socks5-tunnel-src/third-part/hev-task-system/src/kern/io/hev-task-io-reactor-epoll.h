/*
 ============================================================================
 Name        : hev-task-io-reactor-epoll.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2022 everyone.
 Description : I/O Reactor EPoll
 ============================================================================
 */

#ifndef __HEV_TASK_IO_REACTOR_EPOLL_H__
#define __HEV_TASK_IO_REACTOR_EPOLL_H__

#include <poll.h>
#include <sys/epoll.h>

#define HEV_TASK_IO_REACTOR_EVENT_GEN_MAX (1)

typedef struct _HevTaskIOReactorSetupEvent HevTaskIOReactorSetupEvent;
typedef struct epoll_event HevTaskIOReactorWaitEvent;

enum _HevTaskIOReactorEvents
{
    HEV_TASK_IO_REACTOR_EV_RO = EPOLLIN,
    HEV_TASK_IO_REACTOR_EV_WO = EPOLLOUT,
    HEV_TASK_IO_REACTOR_EV_ER = EPOLLERR,
};

enum _HevTaskIOReactorOperation
{
    HEV_TASK_IO_REACTOR_OP_ADD = EPOLL_CTL_ADD,
    HEV_TASK_IO_REACTOR_OP_MOD = EPOLL_CTL_MOD,
    HEV_TASK_IO_REACTOR_OP_DEL = EPOLL_CTL_DEL,
};

struct _HevTaskIOReactorSetupEvent
{
    HevTaskIOReactorOperation op;

    int fd;
    struct epoll_event event;
};

static inline int
hev_task_io_reactor_wait (HevTaskIOReactor *self,
                          HevTaskIOReactorWaitEvent *events, int count,
                          int timeout)
{
    return epoll_wait (self->fd, events, count, timeout);
}

static inline void
hev_task_io_reactor_setup_event_set (HevTaskIOReactorSetupEvent *event, int fd,
                                     HevTaskIOReactorOperation op,
                                     unsigned int events, void *data)
{
    event->op = op;
    event->fd = fd;
    event->event.events = events | EPOLLET;
    event->event.data.ptr = data;
}

static inline int
hev_task_io_reactor_setup_event_fd_gen (HevTaskIOReactorSetupEvent *events,
                                        int fd, HevTaskIOReactorOperation op,
                                        unsigned int poll_events, void *data)
{
    HevTaskIOReactorEvents reactor_events = 0;

    if (poll_events & POLLIN)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_RO;
    if (poll_events & POLLOUT)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_WO;
    if (poll_events & POLLERR)
        reactor_events |= HEV_TASK_IO_REACTOR_EV_ER;

    hev_task_io_reactor_setup_event_set (events, fd, op, reactor_events, data);

    return 1;
}

static inline int
hev_task_io_reactor_setup_event_whandle_gen (HevTaskIOReactorSetupEvent *events,
                                             void *handle,
                                             HevTaskIOReactorOperation op,
                                             void *data)
{
    return -1;
}

static inline unsigned int
hev_task_io_reactor_wait_event_get_events (HevTaskIOReactorWaitEvent *event)
{
    return event->events;
}

static inline void *
hev_task_io_reactor_wait_event_get_data (HevTaskIOReactorWaitEvent *event)
{
    return event->data.ptr;
}

#endif /* __HEV_TASK_IO_REACTOR_EPOLL_H__ */
