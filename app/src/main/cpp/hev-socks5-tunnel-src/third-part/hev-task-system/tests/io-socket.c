/*
 ============================================================================
 Name        : io-socket.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : IO Socket Test
 ============================================================================
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

static int port;
static int fds[2];
static const char *msg = "Hello!";

static void
task_tcp_server_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int fd, cfd;
    struct sockaddr_in addr;
    char buf[16];
    struct msghdr mh;
    struct iovec iov[1];
    ssize_t size;

    /* socket */
    fd = hev_task_io_socket_socket (AF_INET, SOCK_STREAM, 0);
    assert (fd >= 0);
    assert ((fcntl (fd, F_GETFL) & O_NONBLOCK) == O_NONBLOCK);

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    for (port = 1024; port < 65536; port++) {
        addr.sin_port = htons (port);
        if (bind (fd, (struct sockaddr *)&addr, sizeof (addr)) == 0)
            break;
    }
    assert (listen (fd, 5) == 0);

    assert (hev_task_add_fd (task, fd, POLLIN) == 0);

    /* accept */
    cfd = hev_task_io_socket_accept (fd, NULL, NULL, NULL, NULL);
    assert (cfd >= 0);
    assert ((fcntl (cfd, F_GETFL) & O_NONBLOCK) == O_NONBLOCK);

    assert (hev_task_add_fd (task, cfd, POLLIN | POLLOUT) == 0);

    /* send */
    size = hev_task_io_socket_send (cfd, msg, strlen (msg), MSG_WAITALL, NULL,
                                    NULL);
    assert (size == strlen (msg));

    /* sendto */
    size = hev_task_io_socket_sendto (cfd, msg, strlen (msg), MSG_WAITALL, NULL,
                                      0, NULL, NULL);
    assert (size == strlen (msg));

    /* sendmsg */
    memset (&mh, 0, sizeof (mh));
    iov[0].iov_base = (void *)msg;
    iov[0].iov_len = strlen (msg);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    size = hev_task_io_socket_sendmsg (cfd, &mh, MSG_WAITALL, NULL, NULL);
    assert (size == strlen (msg));

    /* recv */
    hev_task_io_socket_recv (cfd, buf, strlen (msg), 0, NULL, NULL);

    assert (hev_task_del_fd (task, cfd) == 0);
    assert (hev_task_del_fd (task, fd) == 0);

    close (cfd);
    close (fd);
}

static void
task_tcp_client_entry (void *data)
{
    HevTask *task = hev_task_self ();
    int fd;
    struct sockaddr_in addr;
    char buf[16];
    struct msghdr mh;
    struct iovec iov[1];
    ssize_t size;

    /* socket */
    fd = hev_task_io_socket_socket (AF_INET, SOCK_STREAM, 0);
    assert (fd >= 0);
    assert ((fcntl (fd, F_GETFL) & O_NONBLOCK) == O_NONBLOCK);

    assert (hev_task_add_fd (task, fd, POLLIN | POLLOUT) == 0);

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
    addr.sin_port = htons (port);
    /* connect */
    assert (hev_task_io_socket_connect (fd, (struct sockaddr *)&addr,
                                        sizeof (addr), NULL, NULL) == 0);

    /* recv */
    size = hev_task_io_socket_recv (fd, buf, strlen (msg), MSG_WAITALL, NULL,
                                    NULL);
    assert (size == strlen (msg));

    /* recvfrom */
    size = hev_task_io_socket_recvfrom (fd, buf, strlen (msg), MSG_WAITALL,
                                        NULL, NULL, NULL, NULL);
    assert (size == strlen (msg));

    /* recvmsg */
    memset (&mh, 0, sizeof (mh));
    iov[0].iov_base = buf;
    iov[0].iov_len = strlen (msg);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    size = hev_task_io_socket_recvmsg (fd, &mh, MSG_WAITALL, NULL, NULL);
    assert (size == strlen (msg));

    /* send */
    hev_task_io_socket_send (fd, msg, strlen (msg), 0, NULL, NULL);

    assert (hev_task_del_fd (task, fd) == 0);

    close (fd);
}

static void
task_udp_server_entry (void *data)
{
    HevTask *task = hev_task_self ();
    struct mmsghdr msgv[10];
    struct iovec iov[10];
    char bufs[128][10];
    int i;

    for (i = 0; i < 10; i++) {
        msgv[i].msg_hdr.msg_name = NULL;
        msgv[i].msg_hdr.msg_namelen = 0;
        msgv[i].msg_hdr.msg_control = NULL;
        msgv[i].msg_hdr.msg_controllen = 0;
        msgv[i].msg_hdr.msg_flags = 0;
        msgv[i].msg_hdr.msg_iov = &iov[i];
        msgv[i].msg_hdr.msg_iovlen = 1;
        msgv[i].msg_len = 0;

        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 128;
    }

    assert (hev_task_add_fd (task, fds[0], POLLIN) == 0);

    i = hev_task_io_socket_recvmmsg (fds[0], msgv, 10, MSG_WAITALL, NULL, NULL);
    assert (i == 10);

    for (i = 0; i < 10; i++) {
        int res;

        assert (msgv[i].msg_len == strlen (msg));
        res = memcmp (msgv[i].msg_hdr.msg_iov[0].iov_base, msg, strlen (msg));
        assert (res == 0);
    }

    assert (hev_task_del_fd (task, fds[0]) == 0);
    close (fds[0]);
}

static void
task_udp_client_entry (void *data)
{
    HevTask *task = hev_task_self ();
    struct mmsghdr msgv[10];
    struct iovec iov[10];
    int i;

    for (i = 0; i < 10; i++) {
        msgv[i].msg_hdr.msg_name = NULL;
        msgv[i].msg_hdr.msg_namelen = 0;
        msgv[i].msg_hdr.msg_control = NULL;
        msgv[i].msg_hdr.msg_controllen = 0;
        msgv[i].msg_hdr.msg_flags = 0;
        msgv[i].msg_hdr.msg_iov = &iov[i];
        msgv[i].msg_hdr.msg_iovlen = 1;
        msgv[i].msg_len = 0;

        iov[i].iov_base = (void *)msg;
        iov[i].iov_len = strlen (msg);
    }

    assert (hev_task_add_fd (task, fds[1], POLLOUT) == 0);

    i = hev_task_io_socket_sendmmsg (fds[1], msgv, 10, MSG_WAITALL, NULL, NULL);
    assert (i == 10);

    for (i = 0; i < 10; i++)
        assert (msgv[i].msg_len == strlen (msg));

    assert (hev_task_del_fd (task, fds[1]) == 0);
    close (fds[1]);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    assert (hev_task_system_init () == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_tcp_server_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_tcp_client_entry, NULL);

    assert (hev_task_io_socket_socketpair (PF_LOCAL, SOCK_DGRAM, 0, fds) == 0);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 1);
    hev_task_run (task, task_udp_server_entry, NULL);

    task = hev_task_new (-1);
    assert (task);
    hev_task_set_priority (task, 2);
    hev_task_run (task, task_udp_client_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
