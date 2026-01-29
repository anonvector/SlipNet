/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>

#include "bytestream.h"
#include "picoquic_internal.h"

static int bytestream_error(bytestream * s);

bytestream * bytestream_ref_init(bytestream * s, const void * bytes, size_t nb_bytes)
{
    s->data = (uint8_t*)bytes;
    s->size = nb_bytes;
    s->ptr = 0;

    return s;
}

bytestream * bytestream_buf_init(bytestream_buf * s, size_t nb_bytes)
{
    if (nb_bytes > BYTESTREAM_MAX_BUFFER_SIZE) {
        return NULL;
    }

    s->s.data = s->buf;
    s->s.size = nb_bytes;
    s->s.ptr = 0;

    return &s->s;
}

bytestream * bytestream_alloc(bytestream * s, size_t nb_bytes)
{
    s->data = (uint8_t*)malloc(nb_bytes);
    if (s->data == NULL) {
        free(s);
        return NULL;
    }
    s->size = nb_bytes;
    s->ptr = 0;

    return s;
}

void bytestream_delete(bytestream * s)
{
    if (s->data != NULL) {
        free(s->data);
        s->data = NULL;
    }
}

const uint8_t * bytestream_data(bytestream * s)
{
    return s->data;
}

const uint8_t * bytestream_ptr(bytestream * s)
{
    return s->data + s->ptr;
}

size_t bytestream_size(bytestream * s)
{
    return s->size;
}

size_t bytestream_length(bytestream * s)
{
    return s->ptr;
}

size_t bytestream_remain(bytestream * s)
{
    return s->size - s->ptr;
}

void bytestream_reset(bytestream * s)
{
    s->ptr = 0;
}

void bytestream_clear(bytestream * s)
{
    s->ptr = 0;
    memset(s->data, 0, s->size);
}

int bytestream_finished(bytestream * s)
{
    return s->ptr >= s->size;
}

int bytestream_skip(bytestream * s, size_t nb_bytes)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < nb_bytes) {
        return bytestream_error(s);
    } else {
        s->ptr += nb_bytes;
        return 0;
    }
}

int byteread_skip_vint(bytestream * s)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    }

    size_t len = picoquic_decode_varint_length(s->data[s->ptr]);
    return bytestream_skip(s, len);
}

int bytewrite_vint(bytestream * s, uint64_t value)
{
    size_t len = picoquic_varint_encode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        return bytestream_error(s);
    } else {
        s->ptr += len;
        return 0;
    }
}

int byteread_vint(bytestream * s, uint64_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    }

    size_t len = picoquic_varint_decode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        return bytestream_error(s);
    } else {
        s->ptr += len;
        return 0;
    }
}

size_t bytestream_vint_len(uint64_t value)
{
    return picoquic_encode_varint_length(value);
}

int byteread_vlen(bytestream * s, size_t * value)
{
    uint64_t val_read = 0;
    int ret = byteread_vint(s, &val_read);

    *value = (size_t)val_read;
    return *value != val_read ? -1 : ret;
}

int bytewrite_int8(bytestream * s, uint8_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    } else {
        s->data[s->ptr++] = value;
        return 0;
    }
}

int byteread_int8(bytestream * s, uint8_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    } else {
        *value = s->data[s->ptr++];
        return 0;
    }
}

int byteshow_int8(bytestream * s, uint8_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return -1;
    } else {
        *value = s->data[s->ptr];
        return 0;
    }
}

int bytewrite_int16(bytestream * s, uint16_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 2) {
        return bytestream_error(s);
    } else {
        picoformat_16(s->data + s->ptr, value);
        s->ptr += 2;
        return 0;
    }
}

int byteread_int16(bytestream * s, uint16_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 2) {
        return bytestream_error(s);
    }
    else {
        const uint8_t * ptr = s->data + s->ptr;
        *value = (ptr[0] << 8) | ptr[1];
        s->ptr += 2;
        return 0;
    }
}

int bytewrite_int32(bytestream * s, uint32_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        return bytestream_error(s);
    } else {
        picoformat_32(s->data + s->ptr, value);
        s->ptr += 4;
        return 0;
    }
}

int byteread_int32(bytestream * s, uint32_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        return bytestream_error(s);
    }
    else {
        const uint8_t * ptr = s->data + s->ptr;
        *value = (((uint32_t)ptr[0]) << 24) | (((uint32_t)ptr[1]) << 16) | (((uint32_t)ptr[2]) << 8) | ptr[3];
        s->ptr += 4;
        return 0;
    }
}

int bytewrite_int64(bytestream * s, uint64_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 8) {
        return bytestream_error(s);
    } else {
        picoformat_64(s->data + s->ptr, value);
        s->ptr += 8;
        return 0;
    }
}

int byteread_int64(bytestream * s, uint64_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 8) {
        return bytestream_error(s);
    }
    else {
        uint64_t v = 0;
        for (size_t i = 0; i < 8; i++) {
            v <<= 8;
            v += s->data[s->ptr++];
        }
        *value = v;
        return 0;
    }
}

int bytewrite_buffer(bytestream * s, const void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return bytestream_error(s);
    }

    memcpy(s->data + s->ptr, buffer, length);
    s->ptr += length;
    return 0;
}

int byteread_buffer(bytestream * s, void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return bytestream_error(s);
    }

    memcpy(buffer, s->data + s->ptr, length);
    s->ptr += length;
    return 0;
}

/* supplementary byte stream I/O */

int bytewrite_cid(bytestream * s, const picoquic_connection_id_t * cid)
{
    int ret = bytewrite_int8(s, cid->id_len);
    ret |= bytewrite_buffer(s, cid->id, cid->id_len);
    return ret;
}

int byteread_cid(bytestream * s, picoquic_connection_id_t * cid)
{
    int ret = byteread_int8(s, &cid->id_len);

    if (cid->id_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        ret = -1;
    } else {
        memset(cid->id, 0, sizeof(cid->id));
        ret |= byteread_buffer(s, cid->id, cid->id_len);
    }

    return ret;
}

int byteskip_cid(bytestream * s)
{
    uint8_t id_len = 0;
    int ret = byteread_int8(s, &id_len);
    ret |= bytestream_skip(s, id_len);
    return ret;
}

int bytewrite_cstr(bytestream * s, const char * cstr)
{
    size_t l_cstr = strlen(cstr);
    int ret = bytewrite_vint(s, l_cstr);
    ret |= bytewrite_buffer(s, cstr, l_cstr);
    return ret;
}

int byteread_cstr(bytestream * s, char * cstr, size_t max_len)
{
    uint64_t l_read = 0;
    int ret = byteread_vint(s, &l_read);

    size_t l_cstr = (size_t)l_read;

    if (ret != 0 || l_cstr != l_read || l_cstr + 1 > max_len) {
        ret = -1;
    } else {
        ret |= byteread_buffer(s, cstr, l_cstr);
        cstr[l_cstr] = 0;
    }

    return ret;
}

int byteskip_cstr(bytestream * s)
{
    uint64_t l_read = 0;
    int ret = byteread_vint(s, &l_read);

    size_t l_cstr = (size_t)l_read;

    if (ret != 0 || l_cstr != l_read) {
        ret = -1;
    } else {
        ret = bytestream_skip(s, l_cstr);
    }
    return ret;
}

int bytewrite_addr(bytestream* s, const struct sockaddr* addr)
{
    int ret = bytewrite_vint(s, addr->sa_family);
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr;
        ret |= bytewrite_buffer(s, &s4->sin_addr, 4);
        ret |= bytewrite_int16(s, s4->sin_port);
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr;
        ret |= bytewrite_buffer(s, &s6->sin6_addr, 16);
        ret |= bytewrite_int16(s, s6->sin6_port);
    }
    return ret;
}

int byteread_addr(bytestream* s, struct sockaddr_storage * addr)
{
    uint64_t family = 0;
    int ret = byteread_vint(s, &family);

    if (ret == 0 && family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr;
        s4->sin_family = AF_INET;
        ret |= byteread_buffer(s, &s4->sin_addr, 4);
        ret |= byteread_int16(s, &s4->sin_port);
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr;
        s6->sin6_family = AF_INET6;
        ret |= byteread_buffer(s, &s6->sin6_addr, 16);
        ret |= byteread_int16(s, &s6->sin6_port);
    }
    return ret;
}

int byteskip_addr(bytestream* s)
{
    uint64_t family = 0;
    int ret = byteread_vint(s, &family);

    if (ret == 0 && family == AF_INET) {
        ret |= bytestream_skip(s, 4 + 2);
    } else {
        ret |= bytestream_skip(s, 16 + 2);
    }
    return ret;
}

static int bytestream_error(bytestream* s)
{
    s->ptr = s->size;
    return -1;
}
