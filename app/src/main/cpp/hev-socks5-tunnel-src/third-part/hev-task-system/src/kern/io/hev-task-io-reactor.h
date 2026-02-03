/*
 ============================================================================
 Name        : hev-task-io-reactor.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : I/O Reactor
 ============================================================================
 */

#ifndef __HEV_TASK_IO_REACTOR_H__
#define __HEV_TASK_IO_REACTOR_H__

typedef struct _HevTaskIOReactor HevTaskIOReactor;
typedef enum _HevTaskIOReactorEvents HevTaskIOReactorEvents;
typedef enum _HevTaskIOReactorOperation HevTaskIOReactorOperation;

struct _HevTaskIOReactor
{
    union
    {
        int fd;
        void *handle;
    };
};

#if defined(__MSYS__)
#include "kern/io/hev-task-io-reactor-iocp.h"
#elif defined(__linux__)
#include "kern/io/hev-task-io-reactor-epoll.h"
#else
#include "kern/io/hev-task-io-reactor-kqueue.h"
#endif

HevTaskIOReactor *hev_task_io_reactor_new (void);
void hev_task_io_reactor_destroy (HevTaskIOReactor *self);

int hev_task_io_reactor_setup (HevTaskIOReactor *self,
                               HevTaskIOReactorSetupEvent *events, int count);

#endif /* __HEV_TASK_IO_REACTOR_H__ */
