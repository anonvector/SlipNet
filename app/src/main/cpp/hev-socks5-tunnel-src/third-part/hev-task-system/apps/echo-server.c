/*
 ============================================================================
 Name        : echo-server.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2018 everyone.
 Description :
 ============================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

static void
task_client_entry (void *data)
{
    int fd = (intptr_t)data;
    char buf[2048];
    ssize_t size;

    size = hev_task_io_socket_recv (fd, buf, 2048, 0, NULL, NULL);
    if (size == -1) {
        printf ("Receive failed!\n");
        goto quit;
    }

    size = hev_task_io_socket_send (fd, buf, size, MSG_WAITALL, NULL, NULL);
    if (size == -1) {
        printf ("Send failed!\n");
        goto quit;
    }

quit:
    close (fd);
}

static void
task_listener_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int fd, ret, reuseaddr = 1;
    struct sockaddr_in addr;

    fd = hev_task_io_socket_socket (AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf (stderr, "Create socket failed!\n");
        return;
    }

    ret = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                      sizeof (reuseaddr));
    if (ret == -1) {
        fprintf (stderr, "Set reuse address failed!\n");
        close (fd);
        return;
    }

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons (8000);
    ret = bind (fd, (struct sockaddr *)&addr, (socklen_t)sizeof (addr));
    if (ret == -1) {
        fprintf (stderr, "Bind address failed!\n");
        close (fd);
        return;
    }
    ret = listen (fd, 100);
    if (ret == -1) {
        fprintf (stderr, "Listen failed!\n");
        close (fd);
        return;
    }

    hev_task_add_fd (task, fd, POLLIN);

    while (1) {
        int client_fd;
        struct sockaddr *in_addr = (struct sockaddr *)&addr;
        socklen_t addr_len = sizeof (addr);

        for (;;) {
            client_fd =
                hev_task_io_socket_accept (fd, in_addr, &addr_len, NULL, NULL);
            if (-1 != client_fd)
                break;
            printf ("Accept failed!\n");
        }

        printf ("New client %d enter from %s:%u\n", client_fd,
                inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));

        task = hev_task_new (-1);
        hev_task_set_priority (task, 1);
        hev_task_add_fd (task, client_fd, POLLIN | POLLOUT);
        hev_task_run (task, task_client_entry, (void *)(intptr_t)client_fd);
    }

    close (fd);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    hev_task_system_init ();

    task = hev_task_new (-1);
    hev_task_run (task, task_listener_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
