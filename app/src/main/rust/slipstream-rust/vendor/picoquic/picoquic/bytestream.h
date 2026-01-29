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

#ifndef PICOQUIC_BYTESTREAM_H
#define PICOQUIC_BYTESTREAM_H

#include "picoquic_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BYTESTREAM_MAX_BUFFER_SIZE 2560

typedef struct {
    uint8_t * data;
    size_t size;
    size_t ptr;
} bytestream;

typedef struct {
    bytestream s;
    uint8_t buf[BYTESTREAM_MAX_BUFFER_SIZE];
} bytestream_buf;

bytestream * bytestream_ref_init(bytestream * s, const void * bytes, size_t nb_bytes);
bytestream * bytestream_buf_init(bytestream_buf * s, size_t nb_bytes);
bytestream * bytestream_alloc(bytestream * s, size_t nb_bytes);
void bytestream_delete(bytestream * s);
const uint8_t * bytestream_data(bytestream * s);
const uint8_t * bytestream_ptr(bytestream * s);
size_t bytestream_size(bytestream * s);
size_t bytestream_length(bytestream * s);
size_t bytestream_remain(bytestream * s);

void bytestream_reset(bytestream * s);
void bytestream_clear(bytestream * s);
int bytestream_finished(bytestream * s);

int bytestream_skip(bytestream * s, size_t nb_bytes);

int bytewrite_int8(bytestream * s, uint8_t value);
int byteread_int8(bytestream * s, uint8_t * value);
int byteshow_int8(bytestream * s, uint8_t * value);

int bytewrite_int16(bytestream * s, uint16_t value);
int byteread_int16(bytestream * s, uint16_t * value);

int bytewrite_int32(bytestream * s, uint32_t value);
int byteread_int32(bytestream * s, uint32_t * value);

int bytewrite_int64(bytestream * s, uint64_t value);
int byteread_int64(bytestream * s, uint64_t * value);

int bytewrite_vint(bytestream * s, uint64_t value);
int byteread_vint(bytestream * s, uint64_t * value);
int byteread_skip_vint(bytestream * s);
size_t bytestream_vint_len(uint64_t value);

int byteread_vlen(bytestream * s, size_t * value);

int bytewrite_buffer(bytestream * s, const void * buffer, size_t length);
int byteread_buffer(bytestream * s, void * buffer, size_t length);

int bytewrite_cid(bytestream * s, const picoquic_connection_id_t * cid);
int byteread_cid(bytestream * s, picoquic_connection_id_t * cid);
int byteskip_cid(bytestream * s);

int bytewrite_cstr(bytestream* s, const char* cstr);
int byteread_cstr(bytestream* s, char* cstr, size_t max_len);
int byteskip_cstr(bytestream* s);

int bytewrite_addr(bytestream * s, const struct sockaddr * addr);
int byteread_addr(bytestream * s, struct sockaddr_storage * addr);
int byteskip_addr(bytestream * s);


#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_BYTESTREAM_H */
