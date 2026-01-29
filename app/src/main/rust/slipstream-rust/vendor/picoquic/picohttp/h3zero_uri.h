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

#ifndef H3ZERO_URI_H
#define H3ZERO_URI_H
/* Set of simple functions for parsing URI.
*/
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t h3zero_pathabempty_length(const uint8_t* path, size_t path_length);

size_t h3zero_query_offset(const uint8_t* path, size_t path_length);

size_t h3zero_query_parameter_position(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length);

size_t h3zero_query_parameter_length(const uint8_t* parameter_value, size_t max_length);

size_t h3zero_query_parameter_pchar(const uint8_t* bytes, size_t length, size_t next_char_index, uint8_t* p, int* err);

int h3zero_query_bytes_to_string(const uint8_t* bytes, size_t length, uint8_t* buffer, size_t buffer_max, size_t* parsed_length);

int h3zero_query_bytes_to_uint64(const uint8_t* bytes, size_t length, uint64_t* number);

int h3zero_query_parameter_string(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length, uint8_t* buffer, size_t buffer_size, size_t* parsed_length);

int h3zero_query_parameter_number(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length, uint64_t* number, uint64_t default_number);

#ifdef __cplusplus
}
#endif
#endif /* H3ZERO_URI_H */
