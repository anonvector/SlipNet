/*
 ============================================================================
 Name        : hev-task-io.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task I/O operations
 ============================================================================
 */

#if !defined(__linux__) && defined(ENABLE_IO_SPLICE_SYSCALL)
#undef ENABLE_IO_SPLICE_SYSCALL
#endif /* !defined(__linux__) && ENABLE_IO_SPLICE_SYSCALL */

#ifdef ENABLE_IO_SPLICE_SYSCALL
#define _GNU_SOURCE
#endif /* ENABLE_IO_SPLICE_SYSCALL */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "kern/task/hev-task.h"
#include "lib/io/buffer/hev-circular-buffer.h"
#include "lib/misc/hev-compiler.h"

#include "hev-task-io.h"

typedef struct _HevTaskIOSplicer HevTaskIOSplicer;

struct _HevTaskIOSplicer
{
#ifdef ENABLE_IO_SPLICE_SYSCALL
    int fd[2];
    size_t wlen;
    size_t blen;
#else
    HevCircularBuffer *buf;
#endif /* !ENABLE_IO_SPLICE_SYSCALL */
};

EXPORT_SYMBOL int
hev_task_io_open (const char *pathname, int flags, ...)
{
    flags |= O_NONBLOCK;

    if (O_CREAT & flags) {
        int fd;
        va_list ap;

        va_start (ap, flags);
        fd = open (pathname, flags, va_arg (ap, int));
        va_end (ap);

        return fd;
    }

    return open (pathname, flags);
}

EXPORT_SYMBOL int
hev_task_io_creat (const char *pathname, mode_t mode)
{
    return hev_task_io_open (pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

EXPORT_SYMBOL int
hev_task_io_openat (int dirfd, const char *pathname, int flags, ...)
{
    flags |= O_NONBLOCK;

    if (O_CREAT & flags) {
        int fd;
        va_list ap;

        va_start (ap, flags);
        fd = openat (dirfd, pathname, flags, va_arg (ap, int));
        va_end (ap);

        return fd;
    }

    return openat (dirfd, pathname, flags);
}

EXPORT_SYMBOL int
hev_task_io_dup (int oldfd)
{
    int newfd;
    int nonblock = 1;

    newfd = dup (oldfd);
    if (0 > newfd)
        return -1;

    if (0 > ioctl (newfd, FIONBIO, (char *)&nonblock)) {
        close (newfd);
        return -2;
    }

    return newfd;
}

EXPORT_SYMBOL int
hev_task_io_dup2 (int oldfd, int newfd)
{
    int nonblock = 1;

    newfd = dup2 (oldfd, newfd);
    if (0 > newfd)
        return -1;

    if (0 > ioctl (newfd, FIONBIO, (char *)&nonblock)) {
        close (newfd);
        return -2;
    }

    return newfd;
}

EXPORT_SYMBOL ssize_t
hev_task_io_read (int fd, void *buf, size_t count, HevTaskIOYielder yielder,
                  void *yielder_data)
{
    ssize_t s;

retry:
    s = read (fd, buf, count);
    if (s < 0 && errno == EAGAIN) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    return s;
}

EXPORT_SYMBOL ssize_t
hev_task_io_readv (int fd, const struct iovec *iov, int iovcnt,
                   HevTaskIOYielder yielder, void *yielder_data)
{
    ssize_t s;

retry:
    s = readv (fd, iov, iovcnt);
    if (s < 0 && errno == EAGAIN) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    return s;
}

EXPORT_SYMBOL ssize_t
hev_task_io_write (int fd, const void *buf, size_t count,
                   HevTaskIOYielder yielder, void *yielder_data)
{
    ssize_t s;

retry:
    s = write (fd, buf, count);
    if (s < 0 && errno == EAGAIN) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    return s;
}

EXPORT_SYMBOL ssize_t
hev_task_io_writev (int fd, const struct iovec *iov, int iovcnt,
                    HevTaskIOYielder yielder, void *yielder_data)
{
    ssize_t s;

retry:
    s = writev (fd, iov, iovcnt);
    if (s < 0 && errno == EAGAIN) {
        if (yielder) {
            if (yielder (HEV_TASK_WAITIO, yielder_data))
                return -2;
        } else {
            hev_task_yield (HEV_TASK_WAITIO);
        }
        goto retry;
    }

    return s;
}

#ifdef ENABLE_IO_SPLICE_SYSCALL

static int
task_io_splicer_init (HevTaskIOSplicer *self, size_t buf_size)
{
    HevTask *task = hev_task_self ();
    int res;

    res = pipe2 (self->fd, O_NONBLOCK);
    if (res < 0)
        goto exit;

    res = hev_task_add_fd (task, self->fd[0], POLLIN);
    if (res < 0)
        goto exit_close;

    res = hev_task_add_fd (task, self->fd[1], POLLOUT);
    if (res < 0)
        goto exit_close;

#ifdef F_GETPIPE_SZ
    buf_size = fcntl (self->fd[0], F_GETPIPE_SZ);
#endif

    self->wlen = 0;
    self->blen = buf_size;

    return 0;

exit_close:
    close (self->fd[0]);
    close (self->fd[1]);
exit:
    return res;
}

static void
task_io_splicer_fini (HevTaskIOSplicer *self)
{
    close (self->fd[0]);
    close (self->fd[1]);
}

static int
task_io_splice (HevTaskIOSplicer *self, int fd_in, int fd_out)
{
    int res;
    ssize_t s;

    s = splice (fd_in, NULL, self->fd[1], NULL, self->blen,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (0 >= s) {
        if ((0 > s) && (EAGAIN == errno))
            res = 0;
        else
            res = -1;
    } else {
        res = 1;
        self->wlen += s;
    }

    if (self->wlen) {
        s = splice (self->fd[0], NULL, fd_out, NULL, self->blen,
                    SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            res = 1;
            self->wlen -= s;
        }
    } else if (res < 0) {
        shutdown (fd_out, SHUT_WR);
    }

    return res;
}

#else

static int
task_io_splicer_init (HevTaskIOSplicer *self, size_t buf_size)
{
    self->buf = hev_circular_buffer_new (buf_size);
    if (!self->buf)
        return -1;

    return 0;
}

static void
task_io_splicer_fini (HevTaskIOSplicer *self)
{
    if (self->buf)
        hev_circular_buffer_unref (self->buf);
}

static int
task_io_splice (HevTaskIOSplicer *self, int fd_in, int fd_out)
{
    struct iovec iov[2];
    int res = 1, iovc;

    iovc = hev_circular_buffer_writing (self->buf, iov);
    if (iovc) {
        ssize_t s = readv (fd_in, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            hev_circular_buffer_write_finish (self->buf, s);
        }
    }

    iovc = hev_circular_buffer_reading (self->buf, iov);
    if (iovc) {
        ssize_t s = writev (fd_out, iov, iovc);
        if (0 >= s) {
            if ((0 > s) && (EAGAIN == errno))
                res = 0;
            else
                res = -1;
        } else {
            res = 1;
            hev_circular_buffer_read_finish (self->buf, s);
        }
    } else if (res < 0) {
        shutdown (fd_out, SHUT_WR);
    }

    return res;
}

#endif /* !ENABLE_IO_SPLICE_SYSCALL */

EXPORT_SYMBOL void
hev_task_io_splice (int fd_a_i, int fd_a_o, int fd_b_i, int fd_b_o,
                    size_t buf_size, HevTaskIOYielder yielder,
                    void *yielder_data)
{
    HevTaskIOSplicer splicer_f;
    HevTaskIOSplicer splicer_b;
    int res_f = 1;
    int res_b = 1;

    if (task_io_splicer_init (&splicer_f, buf_size) < 0)
        return;
    if (task_io_splicer_init (&splicer_b, buf_size) < 0)
        goto exit;

    for (;;) {
        HevTaskYieldType type;

        if (res_f >= 0)
            res_f = task_io_splice (&splicer_f, fd_a_i, fd_b_o);
        if (res_b >= 0)
            res_b = task_io_splice (&splicer_b, fd_b_i, fd_a_o);

        if (res_f > 0 || res_b > 0)
            type = HEV_TASK_YIELD;
        else if ((res_f & res_b) == 0)
            type = HEV_TASK_WAITIO;
        else
            break;

        if (yielder) {
            if (yielder (type, yielder_data))
                break;
        } else {
            hev_task_yield (type);
        }
    }

    task_io_splicer_fini (&splicer_b);
exit:
    task_io_splicer_fini (&splicer_f);
}
