/*
 ============================================================================
 Name        : hev-task-io-poll.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2018 everyone.
 Description : I/O Poll
 ============================================================================
 */

#ifndef __HEV_TASK_IO_POLL_H__
#define __HEV_TASK_IO_POLL_H__

#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pollfd HevTaskIOPollFD;

/**
 * hev_task_io_poll:
 * @fds: file descriptors to poll
 * @nfds: the number of file descriptors in @fds
 * @timeout: amount of time to wait, in milliseconds, or -1 to wait forever
 *
 * Polls @fds, as with the poll() system call, but not block current thread.
 *
 * Returns: the number of entries in @fds whose %revents fields
 * were filled in, or 0 if the operation timed out, or -1 on error or
 * if the call was interrupted.
 *
 * Since: 1.2
 */
int hev_task_io_poll (HevTaskIOPollFD fds[], unsigned int nfds, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_IO_POLL_H__ */
