/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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
#ifndef PICOQUIC_UNIFIED_LOG_H
#define PICOQUIC_UNIFIED_LOG_H

/*
* Unified logging API.
*
* The logging code may be a significant part of the total application code. 
* For a variety of reasons, the code supports three modes of logging:
* - logging to a text file
* - structured logging to a binary file
* - structured logging to a qlog file
* We don't want to link all applications with the code for all three forms of
* logging, because that would inflate the size of the binaries. Instead,
* each logging option is documented by a set of function pointers in an
* "unified logging" structure. If the logging code is used, the structure
* is documented in the QUIC context created by the application.
*
* The application may document all three contexts if it wants to keep
* three types of logs, but it does not have to do that. If a logging
* type is documented, all three functions for that type shall
* be documented as well.
*/
#include "picoquic.h"
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log an event that cannot be attached to a specific connection */
typedef void (*picoquic_log_quic_app_message_fn)(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, va_list vargs);

/* Log arrival or departure of an UDP datagram for an unknown connection */
typedef void (*picoquic_log_quic_pdu_fn)(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length);

/* Log an event relating to a specific connection */
typedef void (*picoquic_log_app_message_fn)(picoquic_cnx_t* cnx, const char* fmt, va_list vargs);

/* Log arrival or departure of an UDP datagram on a connection */
typedef void (*picoquic_log_pdu_fn)(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length);

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
typedef void (*picoquic_log_packet_fn)(picoquic_cnx_t* cnx, picoquic_path_t * path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t bytes_max);

/* Report that a packet was dropped due to some error */
typedef void (*picoquic_log_dropped_packet_fn)(picoquic_cnx_t* cnx, picoquic_path_t* path_x, struct st_picoquic_packet_header_t* ph, size_t packet_size, int err, uint8_t* raw_data, uint64_t current_time);

/* Report that packet was buffered waiting for decryption */
typedef void (*picoquic_log_buffered_packet_fn)(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_type_enum ptype, uint64_t current_time);

/* Log that a packet was formatted, ready to be sent. */
typedef void (*picoquic_log_outgoing_packet_fn)(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time);

/* Log packet lost events */
typedef void (*picoquic_log_packet_lost_fn)(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time);

/* log negotiated ALPN */
typedef void (*picoquic_log_negotiated_alpn_fn)(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count);

/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */
typedef void (*picoquic_log_transport_extension_fn)(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params);

/* log TLS ticket */
typedef void (*picoquic_log_tls_ticket_fn)(picoquic_cnx_t * cnx,
    uint8_t* ticket, uint16_t ticket_length);

/* log the start of a connection */
typedef void (*picoquic_log_new_connection_fn)(picoquic_cnx_t* cnx);
/* log the end of a connection */
typedef void (*picoquic_log_close_connection_fn)(picoquic_cnx_t* cnx);

/* log congestion control parameters */
typedef void (*picoquic_log_cc_dump_fn)(picoquic_cnx_t* cnx, uint64_t current_time);

/* close resource allocated for logging in QUIC context */
typedef void (*picoquic_log_quic_close)(picoquic_quic_t* quic);

typedef struct st_picoquic_unified_logging_t {
    /* Per context log function */
    picoquic_log_quic_app_message_fn log_quic_app_message;
    picoquic_log_quic_pdu_fn log_quic_pdu;
    picoquic_log_quic_close log_quic_close;
    /* Per connection functions */
    picoquic_log_app_message_fn log_app_message;
    picoquic_log_pdu_fn log_pdu;
    picoquic_log_packet_fn log_packet;
    picoquic_log_dropped_packet_fn log_dropped_packet;
    picoquic_log_buffered_packet_fn log_buffered_packet;
    picoquic_log_outgoing_packet_fn log_outgoing_packet;
    picoquic_log_packet_lost_fn log_packet_lost;
    picoquic_log_negotiated_alpn_fn log_negotiated_alpn;
    picoquic_log_transport_extension_fn log_transport_extension;
    picoquic_log_tls_ticket_fn log_picotls_ticket;
    picoquic_log_new_connection_fn log_new_connection;
    picoquic_log_close_connection_fn log_close_connection;
    picoquic_log_cc_dump_fn log_cc_dump;
} picoquic_unified_logging_t;

/* Log an event that cannot be attached to a specific connection */
void picoquic_log_context_free_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, ...);

/* Log arrival or departure of an UDP datagram for an unknown connection */
void picoquic_log_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length);

/* Close the resource allocated for logs in quic context */
void picoquic_log_close_logs(picoquic_quic_t* quic);

/* Log an event relating to a specific connection */
void picoquic_log_app_message(picoquic_cnx_t* cnx, const char* fmt, ...);

/* Log arrival or departure of an UDP datagram on a connection */
void picoquic_log_pdu(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length);

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
void picoquic_log_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t bytes_max);

/* Report that a packet was dropped due to some error */
void picoquic_log_dropped_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, struct st_picoquic_packet_header_t* ph, size_t packet_size, int err, uint8_t* raw_data, uint64_t current_time);

/* Report that packet was buffered waiting for decryption */
void picoquic_log_buffered_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_type_enum ptype, uint64_t current_time);

/* Log that a packet was formatted, ready to be sent. */
void picoquic_log_outgoing_packet(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time);

/* Log packet lost events */
void picoquic_log_packet_lost(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time);

/* log negotiated ALPN */
void picoquic_log_negotiated_alpn(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count);


/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */
void picoquic_log_transport_extension(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params);

/* log TLS ticket */
void picoquic_log_tls_ticket(picoquic_cnx_t* cnx, uint8_t* ticket, uint16_t ticket_length);

/* log the start of a connection */
void picoquic_log_new_connection(picoquic_cnx_t* cnx);
/* log the end of a connection */
void picoquic_log_close_connection(picoquic_cnx_t* cnx);

/* log congestion control parameters */
void picoquic_log_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time);


#ifdef __cplusplus
}
#endif



#endif /* PICOQUIC_UNIFIED_LOG_H */
