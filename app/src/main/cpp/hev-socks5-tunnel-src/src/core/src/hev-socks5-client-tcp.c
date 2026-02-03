/*
 ============================================================================
 Name        : hev-socks5-client-tcp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Client TCP
 ============================================================================
 */

#include <string.h>

#include <hev-memory-allocator.h>

#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-client-tcp.h"

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_name (const char *name, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_name (&addr, name, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new name", self);

    return self;
}

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_ipv4 (const void *ipv4, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_ipv4 (&addr, ipv4, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new ipv4", self);

    return self;
}

HevSocks5ClientTCP *
hev_socks5_client_tcp_new_ipv6 (const void *ipv6, int port)
{
    HevSocks5ClientTCP *self;
    HevSocks5Addr addr;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5ClientTCP));
    if (!self)
        return NULL;

    hev_socks5_addr_from_ipv6 (&addr, ipv6, port);
    res = hev_socks5_client_tcp_construct (self, &addr);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 client tcp new ipv6", self);

    return self;
}

static HevSocks5Addr *
hev_socks5_client_tcp_get_upstream_addr (HevSocks5Client *base)
{
    HevSocks5ClientTCP *self = HEV_SOCKS5_CLIENT_TCP (base);
    HevSocks5Addr *addr;

    addr = self->addr;
    self->addr = NULL;

    return addr;
}

static int
hev_socks5_client_tcp_set_upstream_addr (HevSocks5Client *base,
                                         HevSocks5Addr *addr)
{
    return 0;
}

int
hev_socks5_client_tcp_construct (HevSocks5ClientTCP *self,
                                 const HevSocks5Addr *addr)
{
    int res;

    res = hev_socks5_client_construct (&self->base, HEV_SOCKS5_TYPE_TCP);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 client tcp construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_CLIENT_TCP_TYPE;

    res = hev_socks5_addr_len (addr);
    self->addr = hev_malloc (res);
    if (!self->addr)
        return -1;
    memcpy (self->addr, addr, res);

    if (LOG_ON ()) {
        const char *str;
        char buf[272];

        str = hev_socks5_addr_into_str (self->addr, buf, sizeof (buf));
        LOG_I ("%p socks5 client tcp -> %s", self, str);
    }

    return 0;
}

static void
hev_socks5_client_tcp_destruct (HevObject *base)
{
    HevSocks5ClientTCP *self = HEV_SOCKS5_CLIENT_TCP (base);

    LOG_D ("%p socks5 client tcp destruct", self);

    if (self->addr)
        hev_free (self->addr);

    HEV_SOCKS5_CLIENT_TYPE->destruct (base);
}

static void *
hev_socks5_client_tcp_iface (HevObject *base, void *type)
{
    HevSocks5ClientTCPClass *klass = HEV_OBJECT_GET_CLASS (base);

    return &klass->tcp;
}

HevObjectClass *
hev_socks5_client_tcp_class (void)
{
    static HevSocks5ClientTCPClass klass;
    HevSocks5ClientTCPClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5ClientClass *ckptr;
        HevSocks5TCPIface *tiptr;

        memcpy (kptr, HEV_SOCKS5_CLIENT_TYPE, sizeof (HevSocks5ClientClass));

        okptr->name = "HevSocks5ClientTCP";
        okptr->destruct = hev_socks5_client_tcp_destruct;
        okptr->iface = hev_socks5_client_tcp_iface;

        ckptr = HEV_SOCKS5_CLIENT_CLASS (kptr);
        ckptr->get_upstream_addr = hev_socks5_client_tcp_get_upstream_addr;
        ckptr->set_upstream_addr = hev_socks5_client_tcp_set_upstream_addr;

        tiptr = &kptr->tcp;
        memcpy (tiptr, HEV_SOCKS5_TCP_TYPE, sizeof (HevSocks5TCPIface));
    }

    return okptr;
}
