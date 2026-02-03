/*
 ============================================================================
 Name        : hev-task-dns-proxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2022 everyone.
 Description : DNS Proxy
 ============================================================================
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>

#include "kern/aide/hev-task-aide.h"
#include "kern/sync/hev-task-mutex.h"
#include "kern/core/hev-task-system-private.h"
#include "lib/io/basic/hev-task-io.h"
#include "lib/io/socket/hev-task-io-socket.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-task-dns-proxy.h"

typedef enum _HevTaskDNSCallType HevTaskDNSCallType;
typedef struct _HevTaskDNSCall HevTaskDNSCall;
typedef struct _HevTaskDNSCallGetAddrInfo HevTaskDNSCallGetAddrInfo;
typedef struct _HevTaskDNSCallGetNameInfo HevTaskDNSCallGetNameInfo;

enum _HevTaskDNSCallType
{
    HEV_TASK_DNS_CALL_GETADDRINFO,
    HEV_TASK_DNS_CALL_GETNAMEINFO,
};

struct _HevTaskDNSProxy
{
    int fd;
    HevTaskMutex mutex;
    HevTaskAideWork work;
    HevTaskDNSCall *call;
    HevTaskSchedEntity sched_entity;
};

struct _HevTaskDNSCall
{
    int type;
};

struct _HevTaskDNSCallGetAddrInfo
{
    HevTaskDNSCall base;
    const char *node;
    const char *service;
    const struct addrinfo *hints;
    struct addrinfo **res;
    int err;
    int ret;
};

struct _HevTaskDNSCallGetNameInfo
{
    HevTaskDNSCall base;
    const struct sockaddr *addr;
    char *node;
    char *service;
    socklen_t addrlen;
    socklen_t nodelen;
    socklen_t servicelen;
    int flags;
    int err;
    int ret;
};

static HevTask dummy_task = { .state = HEV_TASK_RUNNING };

static void
hev_task_dns_server_getaddrinfo (HevTaskDNSCall *call)
{
    HevTaskDNSCallGetAddrInfo *gai = (HevTaskDNSCallGetAddrInfo *)call;

    gai->ret = getaddrinfo (gai->node, gai->service, gai->hints, gai->res);
    gai->err = errno;
}

static void
hev_task_dns_server_getnameinfo (HevTaskDNSCall *call)
{
    HevTaskDNSCallGetNameInfo *gni = (HevTaskDNSCallGetNameInfo *)call;

    gni->ret = getnameinfo (gni->addr, gni->addrlen, gni->node, gni->nodelen,
                            gni->service, gni->servicelen, gni->flags);
    gni->err = errno;
}

static void
hev_task_dns_server_handler (unsigned int revents, void *data)
{
    HevTaskDNSProxy *proxy = data;

    for (;;) {
        char sync = 's';
        int res;

        res = read (proxy->work.fd, &sync, sizeof (sync));
        if (0 >= res)
            break;

        switch (proxy->call->type) {
        case HEV_TASK_DNS_CALL_GETADDRINFO:
            hev_task_dns_server_getaddrinfo (proxy->call);
            break;
        case HEV_TASK_DNS_CALL_GETNAMEINFO:
            hev_task_dns_server_getnameinfo (proxy->call);
            break;
        }

        for (;;) {
            struct pollfd pfd;

            res = write (proxy->work.fd, &sync, sizeof (sync));
            if ((0 <= res) || (EAGAIN != errno))
                break;

            pfd.fd = proxy->work.fd;
            pfd.events = POLLOUT;
            poll (&pfd, 1, -1);
        }
    }
}

HevTaskDNSProxy *
hev_task_dns_proxy_new (void)
{
    HevTaskDNSProxy *self;
    HevTaskIOReactor *reactor;
    HevTaskIOReactorSetupEvent revents[HEV_TASK_IO_REACTOR_EVENT_GEN_MAX];
    int fds[2];
    int count;
    int res;

    res = hev_task_aide_init ();
    if (0 > res)
        return NULL;

    self = hev_malloc0 (sizeof (HevTaskDNSProxy));
    if (!self)
        goto exit;

    res = hev_task_io_socket_socketpair (PF_LOCAL, SOCK_STREAM, 0, fds);
    if (0 > res)
        goto free;

    reactor = hev_task_system_get_context ()->reactor;
    count = hev_task_io_reactor_setup_event_fd_gen (revents, fds[0],
                                                    HEV_TASK_IO_REACTOR_OP_ADD,
                                                    POLLIN | POLLOUT,
                                                    &self->sched_entity);
    res = hev_task_io_reactor_setup (reactor, revents, count);
    if (0 > res)
        goto close;

    self->fd = fds[0];
    self->work.fd = fds[1];
    self->work.events = POLLIN;
    self->work.handler = hev_task_dns_server_handler;
    self->work.data = self;
    res = hev_task_aide_add (&self->work);
    if (0 > res)
        goto close;

    return self;

close:
    close (fds[0]);
    close (fds[1]);
free:
    hev_free (self);
exit:
    return NULL;
}

void
hev_task_dns_proxy_destroy (HevTaskDNSProxy *self)
{
    hev_task_aide_del (&self->work);
    close (self->work.fd);
    close (self->fd);
    hev_free (self);
}

static void
hev_task_dns_proxy_call (HevTaskDNSProxy *self, HevTaskDNSCall *call)
{
    hev_task_mutex_lock (&self->mutex);

    self->call = call;
    self->sched_entity.task = hev_task_self ();

    for (;;) {
        char sync = 's';
        int res = write (self->fd, &sync, sizeof (sync));
        if ((0 <= res) || (EAGAIN != errno))
            break;

        hev_task_yield (HEV_TASK_WAITIO);
    }

    for (;;) {
        char sync;
        int res = read (self->fd, &sync, sizeof (sync));
        if ((0 <= res) || (EAGAIN != errno))
            break;

        hev_task_yield (HEV_TASK_WAITIO);
    }

    self->sched_entity.task = &dummy_task;

    hev_task_mutex_unlock (&self->mutex);
}

int
hev_task_dns_proxy_getaddrinfo (HevTaskDNSProxy *self, const char *node,
                                const char *service,
                                const struct addrinfo *hints,
                                struct addrinfo **res)
{
    HevTaskDNSCallGetAddrInfo gai;

    gai.base.type = HEV_TASK_DNS_CALL_GETADDRINFO;
    gai.node = node;
    gai.service = service;
    gai.hints = hints;
    gai.res = res;
    gai.ret = -1;

    hev_task_dns_proxy_call (self, &gai.base);

    errno = gai.err;
    return gai.ret;
}

int
hev_task_dns_proxy_getnameinfo (HevTaskDNSProxy *self,
                                const struct sockaddr *addr, socklen_t addrlen,
                                char *node, socklen_t nodelen, char *service,
                                socklen_t servicelen, int flags)
{
    HevTaskDNSCallGetNameInfo gni;

    gni.base.type = HEV_TASK_DNS_CALL_GETNAMEINFO;
    gni.addr = addr;
    gni.addrlen = addrlen;
    gni.node = node;
    gni.nodelen = nodelen;
    gni.service = service;
    gni.servicelen = servicelen;
    gni.flags = flags;
    gni.ret = -1;

    hev_task_dns_proxy_call (self, &gni.base);

    errno = gni.err;
    return gni.ret;
}
