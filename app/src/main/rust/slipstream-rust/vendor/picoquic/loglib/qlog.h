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
#ifndef PICOQUIC_QLOG_H
#define PICOQUIC_QLOG_H

#include "picoquic_internal.h"
#include "bytestream.h"

#ifdef __cplusplus
extern "C" {
#endif

int qlog_packet_start(uint64_t time, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr);
int qlog_packet_frame(bytestream * s, void * ptr);
int qlog_packet_end(void * ptr);
int qlog_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr);
int qlog_connection_end(uint64_t time, void * ptr);

int qlog_convert(const picoquic_connection_id_t* cid, FILE * f_binlog, const char * binlog_name, const char* txt_name, const char * out_dir, uint16_t flags);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_QLOG_H */
