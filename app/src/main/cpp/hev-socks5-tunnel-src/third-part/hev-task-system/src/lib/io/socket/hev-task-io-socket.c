/*
 ============================================================================
 Name        : hev-task-io-socket.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task socket I/O operations
 ============================================================================
 */

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "kern/task/hev-task.h"
#include "lib/io/basic/hev-task-io.h"
#include "lib/misc/hev-compiler.h"

#include "hev-task-io-socket.h"

EXPORT_SYMBOL int
hev_task_io_socket_socket (int domain, int type, int protocol)
{
    int fd;

#ifdef SOCK_NONBLOCK
    type |= SOCK_NONBLOCK;
#endif

    fd = socket (domain, type, protocol);

#ifndef SOCK_NONBLOCK
    if (fd >= 0) {
        int nonblock = 1;

        if (ioctl (fd, FIONBIO, (char *)&nonblock) < 0) {
            close (fd);
            return -2;
        }
    }
#endif

    return fd;
}

EXPORT_SYMBOL int
hev_task_io_socket_socketpair (int domain, int type, int protocol,
                               int socket_vector[2])
{
    int res;

#ifdef SOCK_NONBLOCK
    type |= SOCK_NONBLOCK;
#endif

    res = socketpair (domain, type, protocol, socket_vector);

#ifndef SOCK_NONBLOCK
    if (res >= 0) {
        int nonblock = 1;

        if (ioctl (socket_vector[0], FIONBIO, (char *)&nonblock) < 0) {
            close (socket_vector[0]);
            close (socket_vector[1]);
            return -2;
        }

        if (ioctl (socket_vector[1], FIONBIO, (char *)&nonblock) < 0) {
            close (socket_vector[0]);
            close (socket_vector[1]);
            return -3;
        }
    }
#endif

    return res;
}

EXPORT_SYMBOL int
hev_task_io_socket_connect (int fd, const struct sockaddr *addr,
                            socklen_t addr_len, HevTaskIOYielder yielder,
                            void *yielder_data)
{
    int res;

retry:
    res = connect (fd, addr, addr_len);
    if (res < 0) {
        if (errno == EINPROGRESS || errno == EALREADY) {
            if (yielder) {
                if (yielder (HEV_TASK_WAITIO, yielder_data))
                    return -2;
            } else {
                hev_task_yield (HEV_TASK_WAITIO);
            }
            goto retry;
        } else if (errno == EISCONN) {
            res = 0;
        }
    }

    return res;
}

EXPORT_SYMBOL int
hev_task_io_socket_accept (int fd, struct sockaddr *addr, socklen_t *addr_len,
                           HevTaskIOYielder yielder, void *yielder_data)
{
    int new_fd;

retry:
#ifndef SOCK_NONBLOCK
    new_fd = accept (fd, addr, addr_len);
#else
    new_fd = accept4 (fd, addr, addr_len, SOCK_NONBLOCK);
#endif
    if (new_fd < 0 && errno == EAGAIN) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

#ifndef SOCK_NONBLOCK
    if (new_fd >= 0) {
        int nonblock = 1;

        if (ioctl (new_fd, FIONBIO, (char *)&nonblock) < 0) {
            close (new_fd);
            return -3;
        }
    }
#endif

    return new_fd;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_recv (int fd, void *buf, size_t len, int flags,
                         HevTaskIOYielder yielder, void *yielder_data)
{
    size_t size = 0;
    ssize_t s;

retry:
    s = recv (fd, buf + size, len - size, flags & ~MSG_WAITALL);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len)
        goto retry;

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_send (int fd, const void *buf, size_t len, int flags,
                         HevTaskIOYielder yielder, void *yielder_data)
{
    size_t size = 0;
    ssize_t s;

retry:
    s = send (fd, buf + size, len - size, flags & ~MSG_WAITALL);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len)
        goto retry;

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_recvfrom (int fd, void *buf, size_t len, int flags,
                             struct sockaddr *addr, socklen_t *addr_len,
                             HevTaskIOYielder yielder, void *yielder_data)
{
    size_t size = 0;
    ssize_t s;

retry:
    s = recvfrom (fd, buf + size, len - size, flags & ~MSG_WAITALL, addr,
                  addr_len);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len)
        goto retry;

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_sendto (int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *addr, socklen_t addr_len,
                           HevTaskIOYielder yielder, void *yielder_data)
{
    size_t size = 0;
    ssize_t s;

retry:
    s = sendto (fd, buf + size, len - size, flags & ~MSG_WAITALL, addr,
                addr_len);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len)
        goto retry;

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_recvmsg (int fd, struct msghdr *msg, int flags,
                            HevTaskIOYielder yielder, void *yielder_data)
{
    struct iovec iov[msg->msg_iovlen];
    size_t i, size = 0, len = 0;
    struct msghdr mh;
    ssize_t s;

    mh.msg_name = msg->msg_name;
    mh.msg_namelen = msg->msg_namelen;
    mh.msg_control = msg->msg_control;
    mh.msg_controllen = msg->msg_controllen;
    mh.msg_flags = msg->msg_flags;
    mh.msg_iov = iov;
    mh.msg_iovlen = msg->msg_iovlen;

    for (i = 0; i < msg->msg_iovlen; i++) {
        iov[i] = msg->msg_iov[i];
        len += iov[i].iov_len;
    }

retry:
    s = recvmsg (fd, &mh, flags & ~MSG_WAITALL);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len) {
        for (i = 0; i < mh.msg_iovlen; i++) {
            if (s < mh.msg_iov[i].iov_len) {
                mh.msg_iov[i].iov_base += s;
                mh.msg_iov[i].iov_len -= s;
                break;
            }

            s -= mh.msg_iov[i].iov_len;
        }

        mh.msg_iov += i;
        mh.msg_iovlen -= i;

        goto retry;
    }

    return size;
}

EXPORT_SYMBOL ssize_t
hev_task_io_socket_sendmsg (int fd, const struct msghdr *msg, int flags,
                            HevTaskIOYielder yielder, void *yielder_data)
{
    struct iovec iov[msg->msg_iovlen];
    size_t i, size = 0, len = 0;
    struct msghdr mh;
    ssize_t s;

    mh.msg_name = msg->msg_name;
    mh.msg_namelen = msg->msg_namelen;
    mh.msg_control = msg->msg_control;
    mh.msg_controllen = msg->msg_controllen;
    mh.msg_flags = msg->msg_flags;
    mh.msg_iov = iov;
    mh.msg_iovlen = msg->msg_iovlen;

    for (i = 0; i < msg->msg_iovlen; i++) {
        iov[i] = msg->msg_iov[i];
        len += iov[i].iov_len;
    }

retry:
    s = sendmsg (fd, &mh, flags & ~MSG_WAITALL);
    if (s < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return size ? size : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return s;

    if (s <= 0)
        return size ? size : s;

    size += s;
    if (size < len) {
        for (i = 0; i < mh.msg_iovlen; i++) {
            if (s < mh.msg_iov[i].iov_len) {
                mh.msg_iov[i].iov_base += s;
                mh.msg_iov[i].iov_len -= s;
                break;
            }

            s -= mh.msg_iov[i].iov_len;
        }

        mh.msg_iov += i;
        mh.msg_iovlen -= i;

        goto retry;
    }

    return size;
}

EXPORT_SYMBOL int
hev_task_io_socket_recvmmsg (int fd, void *_msgv, unsigned int n, int flags,
                             HevTaskIOYielder yielder, void *yielder_data)
{
    struct mmsghdr *msgv = _msgv;
    int r, c = 0;

retry:
#ifdef MSG_WAITFORONE
    r = recvmmsg (fd, &msgv[c], n - c, flags & ~MSG_WAITALL, NULL);
#else
    r = recvmsg (fd, &msgv[c].msg_hdr, flags & ~MSG_WAITALL);
    if (r >= 0) {
        msgv[c].msg_len = r;
        r = 1;
    }
#endif
    if (r < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return c ? c : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return r;

    if (r <= 0)
        return c ? c : r;

    c += r;
    if (c < n)
        goto retry;

    return c;
}

EXPORT_SYMBOL int
hev_task_io_socket_sendmmsg (int fd, void *_msgv, unsigned int n, int flags,
                             HevTaskIOYielder yielder, void *yielder_data)
{
    struct mmsghdr *msgv = _msgv;
    int r, c = 0;

retry:
#ifdef MSG_WAITFORONE
    r = sendmmsg (fd, &msgv[c], n - c, flags & ~MSG_WAITALL);
#else
    r = sendmsg (fd, &msgv[c].msg_hdr, flags & ~MSG_WAITALL);
    if (r >= 0) {
        msgv[c].msg_len = r;
        r = 1;
    }
#endif
    if (r < 0 && errno == EAGAIN && !(flags & MSG_DONTWAIT)) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return c ? c : -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    if (!(flags & MSG_WAITALL))
        return r;

    if (r <= 0)
        return c ? c : r;

    c += r;
    if (c < n)
        goto retry;

    return c;
}
