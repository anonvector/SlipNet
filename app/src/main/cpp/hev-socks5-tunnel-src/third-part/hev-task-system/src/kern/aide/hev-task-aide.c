/*
 ============================================================================
 Name        : hev-task-aide.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2022 - 2024 everyone.
 Description : Aide
 ============================================================================
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "kern/task/hev-task-private.h"
#include "kern/io/hev-task-io-reactor.h"
#include "lib/io/basic/hev-task-io.h"

#include "hev-task-aide.h"

static pthread_t thread;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static HevTaskIOReactor *reactor;

static void *
hev_task_aide_entry (void *data)
{
    for (;;) {
        HevTaskIOReactorWaitEvent events[256];
        int i, count;

        count = hev_task_io_reactor_wait (reactor, events, 256, -1);

        for (i = 0; i < count; i++) {
            HevTaskAideWork *work;
            unsigned int revents;

            work = hev_task_io_reactor_wait_event_get_data (&events[i]);
            revents = hev_task_io_reactor_wait_event_get_events (&events[i]);

            work->handler (revents, work->data);
        }
    }

    return NULL;
}

int
hev_task_aide_init (void)
{
    int res = 0;

    if (reactor)
        return 0;

    pthread_mutex_lock (&mutex);
    if (!reactor) {
        reactor = hev_task_io_reactor_new ();
        if (!reactor) {
            res = -1;
        } else {
            res = pthread_create (&thread, NULL, hev_task_aide_entry, NULL);
            if (res != 0)
                res = -1;
        }
    }
    pthread_mutex_unlock (&mutex);

    return res;
}

int
hev_task_aide_add (HevTaskAideWork *work)
{
    HevTaskIOReactorSetupEvent revents[HEV_TASK_IO_REACTOR_EVENT_GEN_MAX];
    int count;

    count = hev_task_io_reactor_setup_event_fd_gen (
        revents, work->fd, HEV_TASK_IO_REACTOR_OP_ADD, work->events, work);

    return hev_task_io_reactor_setup (reactor, revents, count);
}

int
hev_task_aide_del (HevTaskAideWork *work)
{
    HevTaskIOReactorSetupEvent revents[HEV_TASK_IO_REACTOR_EVENT_GEN_MAX];
    int count;

    count = hev_task_io_reactor_setup_event_fd_gen (
        revents, work->fd, HEV_TASK_IO_REACTOR_OP_DEL, 0, NULL);

    return hev_task_io_reactor_setup (reactor, revents, count);
}
