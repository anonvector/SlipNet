/*
 ============================================================================
 Name        : hev-socks5-tcp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 hev
 Description : Socks5 TCP
 ============================================================================
 */

#include "hev-socks5.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-tcp.h"

#define task_io_yielder hev_socks5_task_io_yielder

static int
hev_socks5_tcp_splicer (HevSocks5TCP *self, int fd)
{
    HevTask *task = hev_task_self ();
    int cfd;
    int res;

    LOG_D ("%p socks5 tcp splicer", self);

    cfd = HEV_SOCKS5 (self)->fd;
    if (cfd < 0)
        return -1;

    res = hev_task_add_fd (task, fd, POLLIN | POLLOUT);
    if (res < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    hev_task_io_splice (cfd, cfd, fd, fd, 8192, task_io_yielder, self);

    return 0;
}

int
hev_socks5_tcp_splice (HevSocks5TCP *self, int fd)
{
    HevSocks5TCPIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_TCP_TYPE);
    return iface->splicer (self, fd);
}

void *
hev_socks5_tcp_iface (void)
{
    static HevSocks5TCPIface type = {
        .splicer = hev_socks5_tcp_splicer,
    };

    return &type;
}
