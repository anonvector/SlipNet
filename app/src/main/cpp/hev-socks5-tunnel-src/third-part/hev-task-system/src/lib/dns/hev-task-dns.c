/*
 ============================================================================
 Name        : hev-task-dns.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 everyone.
 Description : DNS
 ============================================================================
 */

#include <errno.h>

#include "lib/misc/hev-compiler.h"
#include "lib/dns/hev-task-dns-proxy.h"
#include "kern/core/hev-task-system-private.h"

#include "hev-task-dns.h"

static HevTaskDNSProxy *
hev_task_dns_proxy_get (void)
{
    HevTaskSystemContext *context;

    context = hev_task_system_get_context ();

    if (!context->dns_proxy)
        context->dns_proxy = hev_task_dns_proxy_new ();

    return context->dns_proxy;
}

EXPORT_SYMBOL int
hev_task_dns_getaddrinfo (const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res)
{
    HevTaskDNSProxy *proxy = hev_task_dns_proxy_get ();

    if (!proxy) {
        errno = EIO;
        return EAI_SYSTEM;
    }

    return hev_task_dns_proxy_getaddrinfo (proxy, node, service, hints, res);
}

EXPORT_SYMBOL int
hev_task_dns_getnameinfo (const struct sockaddr *addr, socklen_t addrlen,
                          char *node, socklen_t nodelen, char *service,
                          socklen_t servicelen, int flags)
{
    HevTaskDNSProxy *proxy = hev_task_dns_proxy_get ();

    if (!proxy) {
        errno = EIO;
        return EAI_SYSTEM;
    }

    return hev_task_dns_proxy_getnameinfo (proxy, addr, addrlen, node, nodelen,
                                           service, servicelen, flags);
}
