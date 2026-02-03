/*
 ============================================================================
 Name        : hev-task-io-pipe.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task pipe I/O operations
 ============================================================================
 */

#ifndef __HEV_TASK_IO_PIPE_H__
#define __HEV_TASK_IO_PIPE_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * hev_task_io_pipe_pipe:
 * @pipefd: two file descriptors
 *
 * The pipe function creates a pipe, a unidirectional data channel that can be
 * used for interprocess communication.
 *
 * Returns: the status of create.
 *
 * Since: 3.3.5
 */
int hev_task_io_pipe_pipe (int pipefd[2]);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_IO_PIPE_H__ */
