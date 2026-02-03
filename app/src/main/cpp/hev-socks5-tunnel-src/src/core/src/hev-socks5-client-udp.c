/*
 ============================================================================
 Name        : hev-socks5-client-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Client UDP
 ============================================================================
 */

#include <string.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-client-udp.h"

#define task_io_yielder hev_socks5_task_io_yielder

HevSocks5ClientUDP *
hev_socks5_client_udp_new (HevSocks5Type type)
{
    HevSocks5ClientUDP *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientUDP));
    if (!self)
        return NULL;

    res = hev_socks5_client_udp_construct (self, type);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client udp new", self);

    return self;
}

static HevSocks5Addr *
hev_socks5_client_udp_get_upstream_addr (HevSocks5Client *base)
{
    HevSocks5AddrFamily family;
    HevSocks5Addr *addr;

    family = hev_socks5_get_addr_family (HEV_SOCKS5 (base));

    switch (family) {
    case HEV_SOCKS5_ADDR_FAMILY_IPV4:
        addr = hev_malloc0 (7);
        if (addr)
            addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV4;
        break;
    case HEV_SOCKS5_ADDR_FAMILY_IPV6:
        addr = hev_malloc0 (19);
        if (addr)
            addr->atype = HEV_SOCKS5_ADDR_TYPE_IPV6;
        break;
    default:
        addr = NULL;
    }

    return addr;
}

static int
hev_socks5_client_udp_set_upstream_addr (HevSocks5Client *base,
                                         HevSocks5Addr *addr)
{
    HevSocks5ClientUDP *self = HEV_SOCKS5_CLIENT_UDP (base);
    struct sockaddr_in6 saddr;
    struct sockaddr *sadp;
    HevSocks5Class *klass;
    int addr_family;
    int res;
    int fd;

    if (HEV_SOCKS5 (base)->type != HEV_SOCKS5_TYPE_UDP_IN_UDP)
        return 0;

    addr_family = hev_socks5_get_addr_family (HEV_SOCKS5 (self));
    res = hev_socks5_addr_into_sockaddr6 (addr, &saddr, &addr_family);
    if (res < 0) {
        LOG_W ("%p socks5 client udp addr", self);
        return -1;
    }

    fd = hev_socks5_socket (SOCK_DGRAM);
    if (fd < 0) {
        LOG_E ("%p socks5 client udp socket", self);
        return -1;
    }

    sadp = (struct sockaddr *)&saddr;
    klass = HEV_OBJECT_GET_CLASS (self);
    res = klass->binder (HEV_SOCKS5 (self), fd, sadp);
    if (res < 0) {
        LOG_W ("%p socks5 client udp bind", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    res = hev_task_io_socket_connect (fd, sadp, sizeof (saddr), task_io_yielder,
                                      self);
    if (res < 0) {
        LOG_I ("%p socks5 client udp connect", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    HEV_SOCKS5 (self)->udp_associated = 1;
    self->fd = fd;

    return 0;
}

static int
hev_socks5_client_udp_get_fd (HevSocks5UDP *self)
{
    int fd;

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        fd = HEV_SOCKS5 (self)->fd;
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        fd = HEV_SOCKS5_CLIENT_UDP (self)->fd;
        break;
    default:
        return -1;
    }

    return fd;
}

int
hev_socks5_client_udp_construct (HevSocks5ClientUDP *self, HevSocks5Type type)
{
    int res;

    res = hev_socks5_client_construct (&self->base, type);
    if (res < 0)
        return res;

    LOG_I ("%p socks5 client udp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_CLIENT_UDP_TYPE;

    self->fd = -1;

    return 0;
}

static void
hev_socks5_client_udp_destruct (HevObject *base)
{
    HevSocks5ClientUDP *self = HEV_SOCKS5_CLIENT_UDP (base);

    LOG_D ("%p socks5 client udp destruct", self);

    if (self->fd >= 0) {
        hev_task_del_fd (hev_task_self (), self->fd);
        close (self->fd);
    }

    HEV_SOCKS5_CLIENT_TYPE->destruct (base);
}

static void *
hev_socks5_client_udp_iface (HevObject *base, void *type)
{
    HevSocks5ClientUDPClass *klass = HEV_OBJECT_GET_CLASS (base);

    return &klass->udp;
}

HevObjectClass *
hev_socks5_client_udp_class (void)
{
    static HevSocks5ClientUDPClass klass;
    HevSocks5ClientUDPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5ClientClass *ckptr;
        HevSocks5UDPIface *uiptr;

        memcpy (kptr, HEV_SOCKS5_CLIENT_TYPE, sizeof (HevSocks5ClientClass));

        okptr->name = "HevSocks5ClientUDP";
        okptr->destruct = hev_socks5_client_udp_destruct;
        okptr->iface = hev_socks5_client_udp_iface;

        ckptr = HEV_SOCKS5_CLIENT_CLASS (kptr);
        ckptr->get_upstream_addr = hev_socks5_client_udp_get_upstream_addr;
        ckptr->set_upstream_addr = hev_socks5_client_udp_set_upstream_addr;

        uiptr = &kptr->udp;
        memcpy (uiptr, HEV_SOCKS5_UDP_TYPE, sizeof (HevSocks5UDPIface));
        uiptr->get_fd = hev_socks5_client_udp_get_fd;
    }

    return okptr;
}
