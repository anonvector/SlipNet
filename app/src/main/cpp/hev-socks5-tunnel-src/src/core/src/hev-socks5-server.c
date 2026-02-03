/*
 ============================================================================
 Name        : hev-socks5-server.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Server
 ============================================================================
 */

#include <string.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-socks5-proto.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-server.h"

#define task_io_yielder hev_socks5_task_io_yielder

HevSocks5Server *
hev_socks5_server_new (int fd)
{
    HevSocks5Server *self;
    int res;

    self = hev_malloc0 (sizeof (HevSocks5Server));
    if (!self)
        return NULL;

    res = hev_socks5_server_construct (self, fd);
    if (res < 0) {
        hev_free (self);
        return NULL;
    }

    LOG_D ("%p socks5 server new", self);

    return self;
}

void
hev_socks5_server_set_auth (HevSocks5Server *self, HevSocks5Authenticator *auth)
{
    if (self->auth)
        hev_object_unref (HEV_OBJECT (self->auth));

    hev_object_ref (HEV_OBJECT (auth));
    self->auth = auth;
}

static int
hev_socks5_server_read_auth_method (HevSocks5Server *self)
{
    HevSocks5Auth auth;
    HevSocks5AuthMethod method;
    int res;
    int i;

    LOG_D ("%p socks5 server read auth method", self);

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &auth, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res != 2) {
        LOG_I ("%p socks5 server read auth method", self);
        return -1;
    }

    if (auth.ver != HEV_SOCKS5_VERSION_5) {
        LOG_I ("%p socks5 server auth.ver %u", self, auth.ver);
        return -1;
    }

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &auth.methods,
                                   auth.method_len, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res != auth.method_len) {
        LOG_I ("%p socks5 server read auth methods", self);
        return -1;
    }

    if (self->auth)
        method = HEV_SOCKS5_AUTH_METHOD_USER;
    else
        method = HEV_SOCKS5_AUTH_METHOD_NONE;

    res = -1;
    for (i = 0; i < auth.method_len; i++) {
        if (auth.methods[i] == method) {
            res = method;
            break;
        }
    }

    return res;
}

static int
hev_socks5_server_write_auth_method (HevSocks5Server *self, int auth_method)
{
    HevSocks5Auth auth;
    int res;

    LOG_D ("%p socks5 server write auth method", self);

    auth.ver = HEV_SOCKS5_VERSION_5;
    auth.method = auth_method;

    res = hev_task_io_socket_send (HEV_SOCKS5 (self)->fd, &auth, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res <= 0) {
        LOG_I ("%p socks5 server write auth method", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_server_read_auth_user (HevSocks5Server *self)
{
    HevSocks5User *user;
    uint8_t nlen, plen;
    uint8_t name[257];
    uint8_t pass[257];
    uint8_t head[2];
    int res;

    LOG_D ("%p socks5 server read auth user", self);

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, head, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res != 2) {
        LOG_I ("%p socks5 server read auth user.ver", self);
        return -1;
    }

    if (head[0] != 1) {
        LOG_I ("%p socks5 server auth user.ver %u", self, head[0]);
        return -1;
    }

    nlen = head[1];
    if (nlen == 0) {
        LOG_I ("%p socks5 server auth user.nlen %u", self, nlen);
        return -1;
    }

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, name, nlen + 1,
                                   MSG_WAITALL, task_io_yielder, self);
    if (res != (nlen + 1)) {
        LOG_I ("%p socks5 server read auth user.name", self);
        return -1;
    }

    plen = name[nlen];
    if (plen == 0) {
        LOG_I ("%p socks5 server auth user.plen %u", self, plen);
        return -1;
    }

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, pass, plen,
                                   MSG_WAITALL, task_io_yielder, self);
    if (res != plen) {
        LOG_I ("%p socks5 server read auth user.pass", self);
        return -1;
    }

    user = hev_socks5_authenticator_get (self->auth, (char *)name, nlen);
    if (!user) {
        LOG_I ("%p socks5 server auth user: %s pass: %s", self, name, pass);
        return -1;
    }

    res = hev_socks5_user_check (user, (char *)pass, plen);
    if (res < 0) {
        LOG_I ("%p socks5 server auth user: %s pass: %s", self, name, pass);
        return -1;
    }

    hev_object_ref (HEV_OBJECT (user));
    hev_object_unref (HEV_OBJECT (self->auth));
    self->user = user;

    return 0;
}

static int
hev_socks5_server_write_auth_user (HevSocks5Server *self, int auth_res)
{
    uint8_t buf[2];
    int res;

    LOG_D ("%p socks5 server write auth user", self);

    buf[0] = 1;
    buf[1] = auth_res;

    res = hev_task_io_socket_send (HEV_SOCKS5 (self)->fd, buf, 2, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res <= 0) {
        LOG_I ("%p socks5 server write auth user", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_server_auth (HevSocks5Server *self)
{
    int method;
    int res;

    method = hev_socks5_server_read_auth_method (self);
    res = hev_socks5_server_write_auth_method (self, method);
    if (res < 0)
        return -1;

    switch (method) {
    case HEV_SOCKS5_AUTH_METHOD_NONE:
        break;
    case HEV_SOCKS5_AUTH_METHOD_USER:
        res = hev_socks5_server_read_auth_user (self);
        res |= hev_socks5_server_write_auth_user (self, res);
        if (res < 0)
            return -1;
        break;
    default:
        return -1;
    }

    return 0;
}

static int
hev_socks5_server_read_request (HevSocks5Server *self, int *cmd, int *rep,
                                struct sockaddr_in6 *addr)
{
    HevSocks5ReqRes req;
    int addr_family;
    int addrlen;
    int res;

    LOG_D ("%p socks5 server read request", self);

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, &req, 5, MSG_WAITALL,
                                   task_io_yielder, self);
    if (res != 5) {
        LOG_I ("%p socks5 server read request", self);
        return -1;
    }

    if (req.ver != HEV_SOCKS5_VERSION_5) {
        *rep = HEV_SOCKS5_RES_REP_FAIL;
        LOG_I ("%p socks5 server req.ver %u", self, req.ver);
        return 0;
    }

    switch (req.addr.atype) {
    case HEV_SOCKS5_ADDR_TYPE_IPV4:
        addrlen = 5;
        break;
    case HEV_SOCKS5_ADDR_TYPE_IPV6:
        addrlen = 17;
        break;
    case HEV_SOCKS5_ADDR_TYPE_NAME:
        addrlen = 2 + req.addr.domain.len;
        break;
    default:
        *rep = HEV_SOCKS5_RES_REP_ADDR;
        LOG_I ("%p socks5 server req.atype %u", self, req.addr.atype);
        return 0;
    }

    res = hev_task_io_socket_recv (HEV_SOCKS5 (self)->fd, req.addr.domain.addr,
                                   addrlen, MSG_WAITALL, task_io_yielder, self);
    if (res != addrlen) {
        *rep = HEV_SOCKS5_RES_REP_ADDR;
        LOG_I ("%p socks5 server read addr", self);
        return 0;
    }

    addr_family = hev_socks5_get_addr_family (HEV_SOCKS5 (self));
    res = hev_socks5_addr_into_sockaddr6 (&req.addr, addr, &addr_family);
    if (res < 0) {
        *rep = HEV_SOCKS5_RES_REP_ADDR;
        LOG_I ("%p socks5 server resolve addr", self);
        return 0;
    }
    hev_socks5_set_addr_family (HEV_SOCKS5 (self), addr_family);

    if (LOG_ON ()) {
        const char *type;
        const char *str;
        char buf[272];

        switch (req.cmd) {
        case HEV_SOCKS5_REQ_CMD_CONNECT:
            type = "tcp";
            break;
        case HEV_SOCKS5_REQ_CMD_UDP_ASC:
        case HEV_SOCKS5_REQ_CMD_FWD_UDP:
            type = "udp";
            break;
        default:
            type = "unknown";
            break;
        }

        str = hev_socks5_addr_into_str (&req.addr, buf, sizeof (buf));
        LOG_I ("%p socks5 server %s %s", self, type, str);
    }

    *cmd = req.cmd;

    return 0;
}

static int
hev_socks5_server_write_response (HevSocks5Server *self, int rep,
                                  struct sockaddr_in6 *addr)
{
    HevSocks5ReqRes res;
    int ret;

    LOG_D ("%p socks5 server write response", self);

    res.ver = HEV_SOCKS5_VERSION_5;
    res.rep = rep;
    res.rsv = 0;

    ret = hev_socks5_addr_from_sockaddr6 (&res.addr, addr);
    ret = hev_task_io_socket_send (HEV_SOCKS5 (self)->fd, &res, 3 + ret,
                                   MSG_WAITALL, task_io_yielder, self);
    if (ret <= 0) {
        LOG_I ("%p socks5 server write response", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_server_connect (HevSocks5Server *self, struct sockaddr_in6 *addr)
{
    HevSocks5Class *klass;
    int timeout;
    int res;
    int fd;

    LOG_D ("%p socks5 server connect", self);

    fd = hev_socks5_socket (SOCK_STREAM);
    if (fd < 0) {
        LOG_E ("%p socks5 server socket stream", self);
        return -1;
    }

    klass = HEV_OBJECT_GET_CLASS (self);
    res = klass->binder (HEV_SOCKS5 (self), fd, (struct sockaddr *)addr);
    if (res < 0) {
        LOG_W ("%p socks5 server bind", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    timeout = hev_socks5_get_connect_timeout ();
    hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);

    res = hev_task_io_socket_connect (fd, (struct sockaddr *)addr,
                                      sizeof (*addr), task_io_yielder, self);
    if (res < 0) {
        LOG_I ("%p socks5 server connect", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    timeout = hev_socks5_get_tcp_timeout ();
    hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);

    self->fds[0] = fd;

    return 0;
}

static int
hev_socks5_server_bind (HevSocks5Server *self, struct sockaddr_in6 *addr)
{
    HevSocks5ServerClass *sskptr = HEV_OBJECT_GET_CLASS (self);
    int one = 1;
    int res;
    int fd;

    LOG_D ("%p socks5 server bind", self);

    fd = hev_socks5_socket (SOCK_DGRAM);
    if (fd < 0) {
        LOG_E ("%p socks5 server socket dgram", self);
        return -1;
    }

    self->fds[0] = fd;

    if (!addr)
        return 0;

    fd = hev_socks5_socket (SOCK_DGRAM);
    if (fd < 0) {
        LOG_E ("%p socks5 server socket dgram", self);
        return -1;
    }

    res = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
    if (res < 0) {
        LOG_W ("%p socks5 server socket reuse", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    res = sskptr->binder (self, fd, addr);
    if (res < 0) {
        LOG_W ("%p socks5 server bind", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    self->fds[1] = fd;

    return 0;
}

static int
hev_socks5_server_udp_bind (HevSocks5Server *self, int sock,
                            struct sockaddr_in6 *src)
{
    socklen_t alen;
    int res;

    LOG_D ("%p socks5 server udp bind", self);

    alen = sizeof (struct sockaddr_in6);
    res = getsockname (HEV_SOCKS5 (self)->fd, (struct sockaddr *)src, &alen);
    if (res < 0) {
        LOG_W ("%p socks5 server tcp socket name", self);
        return -1;
    }

    src->sin6_port = 0;
    res = bind (sock, (struct sockaddr *)src, alen);
    if (res < 0) {
        LOG_W ("%p socks5 server socket bind", self);
        return -1;
    }

    res = getsockname (sock, (struct sockaddr *)src, &alen);
    if (res < 0) {
        LOG_W ("%p socks5 server udp socket name", self);
        return -1;
    }

    return 0;
}

static int
hev_socks5_server_handshake (HevSocks5Server *self)
{
    struct sockaddr_in6 addr;
    int timeout;
    int cmd;
    int rep;
    int res;

    LOG_D ("%p socks5 server handshake", self);

    timeout = hev_socks5_get_tcp_timeout ();
    hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);

    res = hev_socks5_server_auth (self);
    if (res < 0)
        return -1;

    rep = HEV_SOCKS5_RES_REP_SUCC;
    res = hev_socks5_server_read_request (self, &cmd, &rep, &addr);
    if (res < 0)
        return -1;

    if (rep == HEV_SOCKS5_RES_REP_SUCC) {
        switch (cmd) {
        case HEV_SOCKS5_REQ_CMD_CONNECT:
            res = hev_socks5_server_connect (self, &addr);
            if (res < 0)
                rep = HEV_SOCKS5_RES_REP_HOST;
            HEV_SOCKS5 (self)->type = HEV_SOCKS5_TYPE_TCP;
            break;
        case HEV_SOCKS5_REQ_CMD_UDP_ASC:
            res = hev_socks5_server_bind (self, &addr);
            if (res < 0)
                rep = HEV_SOCKS5_RES_REP_FAIL;
            HEV_SOCKS5 (self)->type = HEV_SOCKS5_TYPE_UDP_IN_UDP;
            break;
        case HEV_SOCKS5_REQ_CMD_FWD_UDP:
            res = hev_socks5_server_bind (self, NULL);
            if (res < 0)
                rep = HEV_SOCKS5_RES_REP_FAIL;
            HEV_SOCKS5 (self)->type = HEV_SOCKS5_TYPE_UDP_IN_TCP;
            break;
        default:
            rep = HEV_SOCKS5_RES_REP_IMPL;
            break;
        }
    }

    res = hev_socks5_server_write_response (self, rep, &addr);
    if ((res < 0) || (rep != HEV_SOCKS5_RES_REP_SUCC))
        return -1;

    return 0;
}

static int
hev_socks5_server_service (HevSocks5Server *self)
{
    int timeout;

    LOG_D ("%p socks5 server service", self);

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_TCP:
        hev_socks5_tcp_splice (HEV_SOCKS5_TCP (self), self->fds[0]);
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        timeout = hev_socks5_get_udp_timeout ();
        hev_socks5_set_timeout (HEV_SOCKS5 (self), timeout);
        hev_socks5_udp_splice (HEV_SOCKS5_UDP (self), self->fds[0]);
        break;
    default:
        return -1;
    }

    return 0;
}

int
hev_socks5_server_run (HevSocks5Server *self)
{
    HevTask *task = hev_task_self ();
    int res;
    int fd;

    LOG_D ("%p socks5 server run", self);

    fd = HEV_SOCKS5 (self)->fd;
    res = hev_task_add_fd (task, fd, POLLIN | POLLOUT);
    if (res < 0)
        hev_task_mod_fd (task, fd, POLLIN | POLLOUT);

    res = hev_socks5_server_handshake (self);
    if (res < 0)
        return -1;

    res = hev_socks5_server_service (self);
    if (res < 0)
        return -1;

    return 0;
}

static int
hev_socks5_server_get_fd (HevSocks5UDP *self)
{
    int fd;

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        fd = HEV_SOCKS5 (self)->fd;
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        fd = HEV_SOCKS5_SERVER (self)->fds[1];
        break;
    default:
        return -1;
    }

    return fd;
}

int
hev_socks5_server_construct (HevSocks5Server *self, int fd)
{
    int res;

    res = hev_socks5_construct (&self->base, HEV_SOCKS5_TYPE_NONE);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 server construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_SERVER_TYPE;

    HEV_SOCKS5 (self)->fd = fd;

    self->fds[0] = -1;
    self->fds[1] = -1;

    return 0;
}

static void
hev_socks5_server_destruct (HevObject *base)
{
    HevSocks5Server *self = HEV_SOCKS5_SERVER (base);
    HevTask *task = hev_task_self ();

    LOG_D ("%p socks5 server destruct", self);

    if (self->fds[0] >= 0) {
        hev_task_del_fd (task, self->fds[0]);
        close (self->fds[0]);
    }
    if (self->fds[1] >= 0) {
        hev_task_del_fd (task, self->fds[1]);
        close (self->fds[1]);
    }

    if (self->obj)
        hev_object_unref (self->obj);

    HEV_SOCKS5_TYPE->destruct (base);
}

static void *
hev_socks5_server_iface (HevObject *base, void *type)
{
    HevSocks5ServerClass *klass = HEV_OBJECT_GET_CLASS (base);

    if (type == HEV_SOCKS5_TCP_TYPE)
        return &klass->tcp;

    if (type == HEV_SOCKS5_UDP_TYPE)
        return &klass->udp;

    return NULL;
}

HevObjectClass *
hev_socks5_server_class (void)
{
    static HevSocks5ServerClass klass;
    HevSocks5ServerClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5TCPIface *tiptr;
        HevSocks5UDPIface *uiptr;

        memcpy (kptr, HEV_SOCKS5_TYPE, sizeof (HevSocks5Class));

        okptr->name = "HevSocks5Server";
        okptr->destruct = hev_socks5_server_destruct;
        okptr->iface = hev_socks5_server_iface;

        kptr->binder = hev_socks5_server_udp_bind;

        tiptr = &kptr->tcp;
        memcpy (tiptr, HEV_SOCKS5_TCP_TYPE, sizeof (HevSocks5TCPIface));

        uiptr = &kptr->udp;
        memcpy (uiptr, HEV_SOCKS5_UDP_TYPE, sizeof (HevSocks5UDPIface));
        uiptr->get_fd = hev_socks5_server_get_fd;
    }

    return okptr;
}
