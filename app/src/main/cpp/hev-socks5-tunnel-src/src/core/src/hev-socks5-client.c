/*
 ============================================================================
 Name        : hev-socks5-client.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Client
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

#include "hev-socks5-client.h"

#define task_io_yielder hev_socks5_task_io_yielder

static int
hev_socks5_client_write_auth_methods (HevSocks5Client *self)
{
    HevSocks5Auth auth;
    int res;

    LOG_D ("%p socks5 client write auth methods", self);

    auth.ver = HEV_SOCKS5_VERSION_5;
    auth.method_len = 1;
    if (!self->auth.user || !self->auth.pass)
        auth.methods[0] = HEV_SOCKS5_AUTH_METHOD_NONE;
    else
        auth.methods[0] = HEV_SOCKS5_AUTH_METHOD_USER;

    res = hev_task_io_socket_send (HEV_SOCKS5 (self)->fd, &auth, 3, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res <= 0) {
        LOG_I ("%p socks5 client write auth methods", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_client_write_auth_creds (HevSocks5Client *self)
{
    struct msghdr mh = { 0 };
    struct iovec iov[4];
    unsigned char ub[3];
    int res;

    LOG_D ("%p socks5 client write auth creds", self);

    if (!self->auth.user || !self->auth.pass)
        return 0;

    ub[0] = HEV_SOCKS5_AUTH_VERSION_1;
    ub[1] = strlen (self->auth.user);
    ub[2] = strlen (self->auth.pass);
    iov[0].iov_base = &ub[0];
    iov[0].iov_len = 2;
    iov[1].iov_base = (void *)self->auth.user;
    iov[1].iov_len = ub[1];
    iov[2].iov_base = &ub[2];
    iov[2].iov_len = 1;
    iov[3].iov_base = (void *)self->auth.pass;
    iov[3].iov_len = ub[2];

    mh.msg_iov = iov;
    mh.msg_iovlen = 4;
    res = hev_task_io_socket_sendmsg (HEV_SOCKS5 (self)->fd, &mh, MSG_WAITALL,
                                      task_io_yielder, self);
    if (res <= 0) {
        LOG_I ("%p socks5 client write auth creds", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_client_write_request (HevSocks5Client *self)
{
    HevSocks5ClientClass *klass;
    struct msghdr mh = { 0 };
    struct iovec iov[2];
    HevSocks5Addr *addr;
    HevSocks5ReqRes req;
    int addrlen;
    int ret;

    LOG_D ("%p socks5 client write request", self);

    req.ver = HEV_SOCKS5_VERSION_5;
    req.rsv = 0;

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_TCP:
        req.cmd = HEV_SOCKS5_REQ_CMD_CONNECT;
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        req.cmd = HEV_SOCKS5_REQ_CMD_FWD_UDP;
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        req.cmd = HEV_SOCKS5_REQ_CMD_UDP_ASC;
        break;
    default:
        return -1;
    }

    iov[0].iov_base = &req;
    iov[0].iov_len = 3;

    klass = HEV_OBJECT_GET_CLASS (self);
    addr = klass->get_upstream_addr (self);

    switch (addr->atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        addrlen = 7;
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        addrlen = 19;
        break;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        addrlen = 4 + addr->domain.len;
        break;
    default:
        LOG_I ("%p socks5 client req.atype %u", self, addr->atype);
        return -1;
    }

    iov[1].iov_base = addr;
    iov[1].iov_len = addrlen;

    mh.msg_iov = iov;
    mh.msg_iovlen = 2;
    ret = hev_task_io_socket_sendmsg (HEV_SOCKS5 (self)->fd, &mh, MSG_WAITALL,
                                      task_io_yielder, self);
    if (ret <= 0) {
        LOG_I ("%p socks5 client write request", self);
        return -1;
    }

    hev_free (addr);

    return 0;
}

static int
hev_socks5_client_read_auth_method (HevSocks5Client *self)
{
    HevSocks5Auth auth;
    int res;

    LOG_D ("%p socks5 client read auth method", self);

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &auth, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res != 2) {
        LOG_I ("%p socks5 client read auth", self);
        return -1;
    }

    if (auth.ver != HEV_SOCKS5_VERSION_5) {
        LOG_I ("%p socks5 client auth.ver %u", self, auth.ver);
        return -1;
    }

    return auth.method;
}

static int
hev_socks5_client_read_auth_creds (HevSocks5Client *self)
{
    HevSocks5ReqRes res;
    int ret;

    LOG_D ("%p socks5 client read auth creds", self);

    ret = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &res, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (ret != 2) {
        LOG_I ("%p socks5 client read auth creds", self);
        return -1;
    }

    if (res.ver != HEV_SOCKS5_AUTH_VERSION_1) {
        LOG_I ("%p socks5 client auth.res.ver %u", self, res.ver);
        return -1;
    }

    if (res.rep != HEV_SOCKS5_RES_REP_SUCC) {
        LOG_I ("%p socks5 client auth.res.rep %u", self, res.rep);
        return -1;
    }

    LOG_D ("%p socks5 client auth done", self);

    return 0;
}

static int
hev_socks5_client_read_response (HevSocks5Client *self)
{
    HevSocks5ClientClass *klass;
    HevSocks5ReqRes res;
    int addrlen;
    int ret;

    LOG_D ("%p socks5 client read response", self);

    ret = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &res, 4, MSG_WAITALL,
                                   task_io_yielder, self);
    if (ret != 4) {
        LOG_I ("%p socks5 client read response", self);
        return -1;
    }

    if (res.ver != HEV_SOCKS5_VERSION_5) {
        LOG_I ("%p socks5 client res.ver %u", self, res.ver);
        return -1;
    }

    if (res.rep != HEV_SOCKS5_RES_REP_SUCC) {
        LOG_I ("%p socks5 client res.rep %u", self, res.rep);
        return -1;
    }

    switch (res.addr.atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        addrlen = 6;
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        addrlen = 18;
        break;
    default:
        LOG_I ("%p socks5 client res.atype %u", self, res.addr.atype);
        return -1;
    }

    ret = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &res.addr.ipv4,
                                   addrlen, MSG_WAITALL, task_io_yielder, self);
    if (ret != addrlen) {
        LOG_I ("%p socks5 client read addr", self);
        return -1;
    }

    klass = HEV_OBJECT_GET_CLASS (self);
    ret = klass->set_upstream_addr (self, &res.addr);
    if (ret < 0) {
        LOG_W ("%p socks5 client set upstream addr", self);
        return -1;
    }

    return 0;
}

int
hev_socks5_client_connect (HevSocks5Client *self, const char *addr, int port)
{
    HevSocks5Class *klass;
    struct sockaddr_in6 saddr;
    struct sockaddr *sap;
    int addr_family;
    int timeout;
    int fd, res;

    LOG_D ("%p socks5 client connect [%s]:%d", self, addr, port);

    timeout = hev_socks5_get_connect_timeout ();
    hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);

    addr_family = hev_socks5_get_addr_family (HEV_SOCKS5 (self));
    res = hev_socks5_name_into_sockaddr6 (addr, port, &saddr, &addr_family);
    if (res < 0) {
        LOG_I ("%p socks5 client resolve [%s]:%d", self, addr, port);
        return -1;
    }

    fd = hev_socks5_socket (SOCK_STREAM);
    if (fd < 0) {
        LOG_E ("%p socks5 client socket", self);
        return -1;
    }

    sap = (struct sockaddr *)&saddr;
    klass = HEV_OBJECT_GET_CLASS (self);
    res = klass->binder (HEV_SOCKS5 (self), fd, sap);
    if (res < 0) {
        LOG_W ("%p socks5 client bind", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    res = hev_task_io_socket_connect (fd, sap, sizeof (saddr), task_io_yielder,
                                      self);
    if (res < 0) {
        LOG_I ("%p socks5 client connect", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    HEV_SOCKS5 (self)->fd = fd;
    hev_socks5_set_addr_family (HEV_SOCKS5 (self), addr_family);
    LOG_D ("%p socks5 client connect server fd %d", self, fd);

    return 0;
}

static int
hev_socks5_client_handshake_standard (HevSocks5Client *self)
{
    int res;

    LOG_D ("%p socks5 client handshake standard", self);

    res = hev_socks5_client_write_auth_methods (self);
    if (res < 0)
        return -1;

    res = hev_socks5_client_read_auth_method (self);
    if (res < 0)
        return -1;

    if (res == HEV_SOCKS5_AUTH_METHOD_USER) {
        res = hev_socks5_client_write_auth_creds (self);
        if (res < 0)
            return -1;

        res = hev_socks5_client_read_auth_creds (self);
        if (res < 0)
            return -1;
    } else if (res != HEV_SOCKS5_AUTH_METHOD_NONE) {
        LOG_I ("%p socks5 client auth method %d", self, res);
        return -1;
    }

    res = hev_socks5_client_write_request (self);
    if (res < 0)
        return -1;

    res = hev_socks5_client_read_response (self);
    if (res < 0)
        return -1;

    return 0;
}

static int
hev_socks5_client_handshake_pipeline (HevSocks5Client *self)
{
    int res;

    LOG_D ("%p socks5 client handshake pipeline", self);

    res = hev_socks5_client_write_auth_methods (self);
    if (res < 0)
        return -1;

    res = hev_socks5_client_write_auth_creds (self);
    if (res < 0)
        return -1;

    res = hev_socks5_client_write_request (self);
    if (res < 0)
        return -1;

    res = hev_socks5_client_read_auth_method (self);
    if (res < 0)
        return -1;

    if (res == HEV_SOCKS5_AUTH_METHOD_USER) {
        res = hev_socks5_client_read_auth_creds (self);
        if (res < 0)
            return -1;
    } else if (res != HEV_SOCKS5_AUTH_METHOD_NONE) {
        LOG_I ("%p socks5 client auth method %d", self, res);
        return -1;
    }

    res = hev_socks5_client_read_response (self);
    if (res < 0)
        return -1;

    return 0;
}

int
hev_socks5_client_handshake (HevSocks5Client *self, int pipeline)
{
    int timeout;
    int res;

    timeout = hev_socks5_get_tcp_timeout ();
    hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);

    if (pipeline)
        res = hev_socks5_client_handshake_pipeline (self);
    else
        res = hev_socks5_client_handshake_standard (self);

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        timeout = hev_socks5_get_udp_timeout ();
        hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);
        break;
    default:
        break;
    }

    return res;
}

void
hev_socks5_client_set_auth (HevSocks5Client *self, const char *user,
                            const char *pass)
{
    LOG_D ("%p socks5 client set auth", self);

    self->auth.user = user;
    self->auth.pass = pass;
}

int
hev_socks5_client_construct (HevSocks5Client *self, HevSocks5Type type)
{
    int res;

    res = hev_socks5_construct (&self->base, type);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 client construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_CLIENT_TYPE;

    return 0;
}

static void
hev_socks5_client_destruct (HevObject *base)
{
    HevSocks5Client *self = HEV_SOCKS5_CLIENT (base);

    LOG_D ("%p socks5 client destruct", self);

    HEV_SOCKS5_TYPE->destruct (base);
}

HevObjectClass *
hev_socks5_client_class (void)
{
    static HevSocks5ClientClass klass;
    HevSocks5ClientClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_SOCKS5_TYPE, sizeof (HevSocks5Class));

        okptr->name = "HevSocks5Client";
        okptr->destruct = hev_socks5_client_destruct;
    }

    return okptr;
}
