/*
 ============================================================================
 Name        : hev-task-io-reactor-kqueue.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : I/O Reactor KQueue
 ============================================================================
 */

#ifndef __HEV_TASK_IO_REACTOR_KQUEUE_H__
#define __HEV_TASK_IO_REACTOR_KQUEUE_H__

#include <poll.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#ifndef EVFILT_EXCEPT
#define EVFILT_EXCEPT (0)
#endif

#define HEV_TASK_IO_REACTOR_EVENT_GEN_MAX (6)

typedef struct kevent HevTaskIOReactorSetupEvent;
typedef struct kevent HevTaskIOReactorWaitEvent;

enum _HevTaskIOReactorEvents
{
    HEV_TASK_IO_REACTOR_EV_RO = EVFILT_READ,
    HEV_TASK_IO_REACTOR_EV_WO = EVFILT_WRITE,
    HEV_TASK_IO_REACTOR_EV_ER = EVFILT_EXCEPT,
};

enum _HevTaskIOReactorOperation
{
    HEV_TASK_IO_REACTOR_OP_ADD,
    HEV_TASK_IO_REACTOR_OP_MOD,
    HEV_TASK_IO_REACTOR_OP_DEL,
};

static inline int
hev_task_io_reactor_wait (HevTaskIOReactor *self,
                          HevTaskIOReactorWaitEvent *events, int count,
                          int timeout)
{
    struct timespec *tsp = NULL;
    struct timespec ts;

    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tsp = &ts;
    }

    return kevent (self->fd, NULL, 0, events, count, tsp);
}

static inline void
hev_task_io_reactor_setup_event_set (HevTaskIOReactorSetupEvent *event, int fd,
                                     HevTaskIOReactorOperation op,
                                     unsigned int events, void *data)
{
    int action;

    switch (op) {
    case HEV_TASK_IO_REACTOR_OP_ADD:
    case HEV_TASK_IO_REACTOR_OP_MOD:
        action = EV_ADD;
        break;
    case HEV_TASK_IO_REACTOR_OP_DEL:
        action = EV_DELETE;
    }

    EV_SET (event, fd, events, action | EV_CLEAR, 0, 0, data);
}

static inline int
hev_task_io_reactor_setup_event_fd_gen (HevTaskIOReactorSetupEvent *events,
                                        int fd, HevTaskIOReactorOperation op,
                                        unsigned int poll_events, void *data)
{
    int count = 0;

    if (op > HEV_TASK_IO_REACTOR_OP_ADD) {
        if (!(poll_events & POLLIN))
            hev_task_io_reactor_setup_event_set (&events[count++], fd,
                                                 HEV_TASK_IO_REACTOR_OP_DEL,
                                                 HEV_TASK_IO_REACTOR_EV_RO,
                                                 data);
        if (!(poll_events & POLLOUT))
            hev_task_io_reactor_setup_event_set (&events[count++], fd,
                                                 HEV_TASK_IO_REACTOR_OP_DEL,
                                                 HEV_TASK_IO_REACTOR_EV_WO,
                                                 data);
        if (!(poll_events & POLLERR))
            hev_task_io_reactor_setup_event_set (&events[count++], fd,
                                                 HEV_TASK_IO_REACTOR_OP_DEL,
                                                 HEV_TASK_IO_REACTOR_EV_ER,
                                                 data);
        if (op == HEV_TASK_IO_REACTOR_OP_DEL)
            return count;
    }

    if (poll_events & POLLIN)
        hev_task_io_reactor_setup_event_set (&events[count++], fd, op,
                                             HEV_TASK_IO_REACTOR_EV_RO, data);
    if (poll_events & POLLOUT)
        hev_task_io_reactor_setup_event_set (&events[count++], fd, op,
                                             HEV_TASK_IO_REACTOR_EV_WO, data);
    if (poll_events & POLLERR)
        hev_task_io_reactor_setup_event_set (&events[count++], fd, op,
                                             HEV_TASK_IO_REACTOR_EV_ER, data);

    return count;
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
    switch (event->filter) {
    case HEV_TASK_IO_REACTOR_EV_RO:
        return POLLIN;
    case HEV_TASK_IO_REACTOR_EV_WO:
        return POLLOUT;
    default:
        return POLLERR;
    }
}

static inline void *
hev_task_io_reactor_wait_event_get_data (HevTaskIOReactorWaitEvent *event)
{
    return event->udata;
}

#endif /* __HEV_TASK_IO_REACTOR_KQUEUE_H__ */
