/*
 ============================================================================
 Name        : io-circular-buffer.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2019 everyone.
 Description : IO Circular Buffer Test
 ============================================================================
 */

#include <assert.h>

#include <hev-circular-buffer.h>

int
main (int argc, char *argv[])
{
    HevCircularBuffer *buffer;
    struct iovec iov[2];
    void *rb1, *rb2, *rb3;
    void *wb1, *wb2, *wb3;

    buffer = hev_circular_buffer_new (128);
    assert (buffer);

    assert (buffer == hev_circular_buffer_ref (buffer));
    hev_circular_buffer_unref (buffer);

    assert (128 == hev_circular_buffer_get_max_size (buffer));

    /* |------------------------------|
     *  ^
     */
    assert (0 == hev_circular_buffer_get_use_size (buffer));
    assert (0 == hev_circular_buffer_reading (buffer, iov));
    assert (1 == hev_circular_buffer_writing (buffer, iov));
    wb1 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 128);
    hev_circular_buffer_write_finish (buffer, 32);

    /* |xxxxxxxxxx--------------------|
     *  ^
     */
    assert (32 == hev_circular_buffer_get_use_size (buffer));
    assert (1 == hev_circular_buffer_reading (buffer, iov));
    rb1 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 32);
    assert (1 == hev_circular_buffer_writing (buffer, iov));
    wb2 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == (128 - 32));
    assert (32 == (wb2 - wb1));
    hev_circular_buffer_write_finish (buffer, 128 - 32);

    /* |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
     *  ^
     */
    assert (128 == hev_circular_buffer_get_use_size (buffer));
    assert (0 == hev_circular_buffer_writing (buffer, iov));
    assert (1 == hev_circular_buffer_reading (buffer, iov));
    rb2 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 128);
    assert (rb1 == rb2);
    hev_circular_buffer_read_finish (buffer, 16);

    /* |----xxxxxxxxxxxxxxxxxxxxxxxxxx|
     *      ^
     */
    assert ((128 - 16) == hev_circular_buffer_get_use_size (buffer));
    assert (1 == hev_circular_buffer_writing (buffer, iov));
    wb3 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 16);
    assert (wb3 == wb1);
    assert (1 == hev_circular_buffer_reading (buffer, iov));
    rb3 = iov[0].iov_base;
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == (128 - 16));
    assert (rb3 == (rb1 + 16));
    hev_circular_buffer_read_finish (buffer, (128 - 16));

    /* |------------------------------|
     *  ^
     */
    assert (0 == hev_circular_buffer_get_use_size (buffer));
    assert (1 == hev_circular_buffer_writing (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 128);
    hev_circular_buffer_write_finish (buffer, (128 - 16));
    assert (1 == hev_circular_buffer_reading (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == (128 - 16));
    hev_circular_buffer_read_finish (buffer, 16);

    /* |----xxxxxxxxxxxxxxxxxxxxxx----|
     *      ^
     */
    assert ((128 - 16 - 16) == hev_circular_buffer_get_use_size (buffer));
    assert (2 == hev_circular_buffer_writing (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 16);
    assert (iov[1].iov_base);
    assert (iov[1].iov_len == 16);
    assert (1 == hev_circular_buffer_reading (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == (128 - 16 - 16));
    hev_circular_buffer_read_finish (buffer, (128 - 16 - 16));

    /* |------------------------------|
     *                            ^
     */
    assert (0 == hev_circular_buffer_get_use_size (buffer));
    assert (2 == hev_circular_buffer_writing (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 16);
    assert (iov[1].iov_base);
    assert (iov[1].iov_len == (128 - 16));
    hev_circular_buffer_write_finish (buffer, 32);

    /* |xxxx----------------------xxxx|
     *                            ^
     */
    assert (32 == hev_circular_buffer_get_use_size (buffer));
    assert (2 == hev_circular_buffer_reading (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == 16);
    assert (iov[1].iov_base);
    assert (iov[1].iov_len == 16);
    assert (1 == hev_circular_buffer_writing (buffer, iov));
    assert (iov[0].iov_base);
    assert (iov[0].iov_len == (128 - 16 - 16));

    hev_circular_buffer_unref (buffer);

    return 0;
}
