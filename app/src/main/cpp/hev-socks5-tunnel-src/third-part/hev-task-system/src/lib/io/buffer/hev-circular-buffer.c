/*
 ============================================================================
 Name        : hev-circular-buffer.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : Circular buffer
 ============================================================================
 */

#include "lib/misc/hev-compiler.h"
#include "mem/api/hev-memory-allocator-api.h"

#include "hev-circular-buffer.h"

struct _HevCircularBuffer
{
    size_t rp;
    size_t use_size;
    size_t max_size;
    unsigned int ref_count;

    unsigned char data[0];
};

EXPORT_SYMBOL HevCircularBuffer *
hev_circular_buffer_new (size_t max_size)
{
    HevCircularBuffer *self;

    self = hev_malloc (sizeof (HevCircularBuffer) + max_size);
    if (!self)
        return NULL;

    self->rp = 0;
    self->use_size = 0;
    self->max_size = max_size;
    self->ref_count = 1;

    return self;
}

EXPORT_SYMBOL HevCircularBuffer *
hev_circular_buffer_ref (HevCircularBuffer *self)
{
    self->ref_count++;

    return self;
}

EXPORT_SYMBOL void
hev_circular_buffer_unref (HevCircularBuffer *self)
{
    self->ref_count--;
    if (self->ref_count)
        return;

    hev_free (self);
}

EXPORT_SYMBOL size_t
hev_circular_buffer_get_max_size (HevCircularBuffer *self)
{
    return self->max_size;
}

EXPORT_SYMBOL size_t
hev_circular_buffer_get_use_size (HevCircularBuffer *self)
{
    return self->use_size;
}

EXPORT_SYMBOL int
hev_circular_buffer_reading (HevCircularBuffer *self, struct iovec *iov)
{
    size_t upper_size = self->max_size - self->rp;

    if (0 == self->use_size)
        return 0;

    iov[0].iov_base = self->data + self->rp;
    if (self->use_size <= upper_size) {
        iov[0].iov_len = self->use_size;
        return 1;
    }

    iov[0].iov_len = upper_size;
    iov[1].iov_base = self->data;
    iov[1].iov_len = self->use_size - upper_size;
    return 2;
}

EXPORT_SYMBOL void
hev_circular_buffer_read_finish (HevCircularBuffer *self, size_t size)
{
    self->rp = (self->rp + size) % self->max_size;
    self->use_size -= size;
}

EXPORT_SYMBOL int
hev_circular_buffer_writing (HevCircularBuffer *self, struct iovec *iov)
{
    size_t wp = (self->rp + self->use_size) % self->max_size;
    size_t upper_size = self->max_size - wp;
    size_t spc_size = self->max_size - self->use_size;

    if (self->use_size == self->max_size)
        return 0;

    iov[0].iov_base = self->data + wp;
    if (spc_size <= upper_size) {
        iov[0].iov_len = spc_size;
        return 1;
    }

    iov[0].iov_len = upper_size;
    iov[1].iov_base = self->data;
    iov[1].iov_len = spc_size - upper_size;
    return 2;
}

EXPORT_SYMBOL void
hev_circular_buffer_write_finish (HevCircularBuffer *self, size_t size)
{
    self->use_size += size;
}
