/*
 ============================================================================
 Name        : hev-circular-buffer.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Circular buffer
 ============================================================================
 */

#ifndef __HEV_CIRCULAR_BUFFER_H__
#define __HEV_CIRCULAR_BUFFER_H__

#include <sys/uio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HevCircularBuffer HevCircularBuffer;

/**
 * hev_circular_buffer_new:
 * @max_size: max buffer size
 *
 * Creates a new circular buffer. The max buffer size is specified by @max_size.
 *
 * Returns: a new #HevCircularBuffer.
 *
 * Since: 4.6.1
 */
HevCircularBuffer *hev_circular_buffer_new (size_t max_size);

/**
 * hev_circular_buffer_ref:
 * @self: a #HevCircularBuffer
 *
 * Increases the reference count of the @self by one.
 *
 * Returns: a #HevCircularBuffer
 *
 * Since: 4.6.1
 */
HevCircularBuffer *hev_circular_buffer_ref (HevCircularBuffer *self);

/**
 * hev_circular_buffer_unref:
 * @self: a #HevCircularBuffer
 *
 * Decreases the reference count of @self. When its reference count
 * drops to 0, the object is finalized (i.e. its memory is freed).
 *
 * Since: 4.6.1
 */
void hev_circular_buffer_unref (HevCircularBuffer *self);

/**
 * hev_circular_buffer_get_max_size:
 * @self: a #HevCircularBuffer
 *
 * Get the max size of buffer.
 *
 * Returns: the number of bytes actually allocated
 *
 * Since: 4.6.1
 */
size_t hev_circular_buffer_get_max_size (HevCircularBuffer *self);

/**
 * hev_circular_buffer_get_use_size:
 * @self: a #HevCircularBuffer
 *
 * Get the use size of buffer.
 *
 * Returns: the number of bytes actually used
 *
 * Since: 4.6.1
 */
size_t hev_circular_buffer_get_use_size (HevCircularBuffer *self);

/**
 * hev_circular_buffer_reading:
 * @self: a #HevCircularBuffer
 * @iov: a io vector contain two elements
 *
 * The reading function start a buffer reading and update the @iov to point to
 * data in buffer.
 *
 * Returns: the number of iov actually used
 *
 * Since: 4.6.1
 */
int hev_circular_buffer_reading (HevCircularBuffer *self, struct iovec *iov);

/**
 * hev_circular_buffer_read_finish:
 * @self: a #hevcircularbuffer
 * @size: the number of bytes actually read
 *
 * the read_finish function stop buffer reading and increase read pointer by
 * @size.
 *
 * returns: the number of iov actually used
 *
 * since: 4.6.1
 */
void hev_circular_buffer_read_finish (HevCircularBuffer *self, size_t size);

/**
 * hev_circular_buffer_writing:
 * @self: a #HevCircularBuffer
 * @iov: a io vector contain two elements
 *
 * The writing function start a buffer writing and update the @iov to point to
 * data in buffer.
 *
 * Returns: the number of iov actually used
 *
 * Since: 4.6.1
 */
int hev_circular_buffer_writing (HevCircularBuffer *self, struct iovec *iov);

/**
 * hev_circular_buffer_write_finish:
 * @self: a #hevcircularbuffer
 * @size: the number of bytes actually write
 *
 * the write_finish function stop buffer writing and increase write pointer by
 * @size.
 *
 * returns: the number of iov actually used
 *
 * since: 4.6.1
 */
void hev_circular_buffer_write_finish (HevCircularBuffer *self, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_CIRCULAR_BUFFER_H__ */
