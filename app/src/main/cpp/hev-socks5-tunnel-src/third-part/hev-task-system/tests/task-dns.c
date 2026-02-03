/*
 ============================================================================
 Name        : task-dns.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 everyone.
 Description : Task DNS Test
 ============================================================================
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <hev-task.h>
#include <hev-task-dns.h>
#include <hev-task-system.h>

static void
getaddrinfo_entry (void *data)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    assert (hev_task_dns_getaddrinfo (NULL, "80", &hints, &result) == 0);
    assert (result != NULL);
    freeaddrinfo (result);
}

static void
getnameinfo_entry (void *data)
{
    struct sockaddr *addr;
    struct sockaddr_in addr4 = { 0 };
    struct sockaddr_in6 addr6 = { 0 };
    char node[NI_MAXHOST];
    char service[NI_MAXSERV];

    addr4.sin_family = AF_INET;
    addr4.sin_port = htons (80);
    assert (inet_pton (AF_INET, "127.0.0.1", &addr4.sin_addr) == 1);
    addr = (struct sockaddr *)&addr4;
    assert (hev_task_dns_getnameinfo (addr, sizeof (addr4), node, NI_MAXHOST,
                                      service, NI_MAXSERV, 0) == 0);
    assert (strlen (node) > 0);
    assert (strcmp (service, "http") == 0);

    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons (80);
    assert (inet_pton (AF_INET6, "::1", &addr6.sin6_addr) == 1);
    addr = (struct sockaddr *)&addr6;
    assert (hev_task_dns_getnameinfo (addr, sizeof (addr6), node, NI_MAXHOST,
                                      service, NI_MAXSERV, 0) == 0);
    assert (strlen (node) > 0);
    assert (strcmp (service, "http") == 0);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, getaddrinfo_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_run (task, getnameinfo_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
