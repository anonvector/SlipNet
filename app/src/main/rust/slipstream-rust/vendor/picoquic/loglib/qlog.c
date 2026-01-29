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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "picoquic_internal.h"
#include "bytestream.h"
#include "logreader.h"
#include "logconvert.h"

typedef struct qlog_context_st {

    FILE * f_txtlog;      /*!< The file handle of the opened output file. */

    uint32_t version_number;
    const char * cid_name; /*!< Name of the connection, default = initial connection id */
    struct sockaddr_storage addr_peer;
    struct sockaddr_storage addr_local;

    uint64_t start_time;  /*!< Timestamp is very first log event reported. */
    int event_count;
    int packet_count;
    int frame_count;
    picoquic_packet_type_enum packet_type;

    uint64_t cwin;
    uint64_t rtt_sample;
    uint64_t SRTT;
    uint64_t RTT_min;
    uint64_t bytes_in_transit;
    uint64_t pacing_packet_time;

    unsigned int trace_flow_id : 1;
    unsigned int key_phase_sent_last : 1;
    unsigned int key_phase_sent : 1;
    unsigned int key_phase_received_last : 1;
    unsigned int key_phase_received : 1;
    unsigned int spin_bit_sent_last : 1;
    unsigned int spin_bit_sent : 1;
    unsigned int app_limited : 1;

    int state;
} qlog_context_t;

int qlog_string(FILE* f, bytestream* s, uint64_t l)
{
    uint64_t x;
    int error_found = (s->ptr + (size_t)l > s->size);

    fprintf(f, "\"");

    for (x = 0; x < l && s->ptr < s->size; x++) {
        fprintf(f, "%02x", s->data[s->ptr++]);
    }

    if (error_found) {
        fprintf(f, "... coding error!");
    }

    fprintf(f, "\"");
    return (error_found) ? -1 : 0;
}

int qlog_chars(FILE* f, bytestream* s, uint64_t l)
{
    uint64_t x;
    int error_found = (s->ptr + (size_t)l > s->size);

    fprintf(f, "\"");

    for (x = 0; x < l && s->ptr < s->size; x++) {
        int c = s->data[s->ptr++];
        if (c == '"' || c == '\\') {
            fprintf(f, "\\%c", c);
        }
        else if (c >= ' ' && c < 127) {
            fprintf(f, "%c", c);
        }
        else {
            fprintf(f, "\\%02x", c);
        }
    }

    if (error_found) {
        fprintf(f, "... coding error!");
    }

    fprintf(f, "\"");
    return (error_found) ? -1 : 0;
}

static void qlog_log_addr(FILE* f, struct sockaddr* addr_peer)
{
    if (addr_peer->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr_peer;
        uint8_t* addr = (uint8_t*)&s4->sin_addr;

        fprintf(f, "\"ip_v4\": \"%d.%d.%d.%d\", \"port_v4\":%d",
            addr[0], addr[1], addr[2], addr[3],
            ntohs(s4->sin_port));
    }
    else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr_peer;
        uint8_t* addr = (uint8_t*)&s6->sin6_addr;

        fprintf(f, " \"ip_v6\": \"");
        for (int i = 0; i < 8; i++) {
            if (i != 0) {
                fprintf(f, ":");
            }

            if (addr[2 * i] != 0) {
                fprintf(f, "%x%02x", addr[2 * i], addr[(2 * i) + 1]);
            }
            else {
                fprintf(f, "%x", addr[(2 * i) + 1]);
            }
        }
        fprintf(f, "\", \"port_v6\" :%d", ntohs(s6->sin6_port));
    }
}

void qlog_event_header(FILE * f, qlog_context_t* ctx, int64_t delta_time, uint64_t path_id, char const * event_class, char const * event_name)
{
    fprintf(f, "[%"PRId64", ", delta_time);
    if (ctx->trace_flow_id) {
        fprintf(f, "%"PRId64", ", path_id);
    }
    fprintf(f, "\"%s\", \"%s\", {", event_class, event_name);
}

void qlog_vint_transport_extension(FILE* f, char const* ext_name, bytestream* s, uint64_t len)
{
    uint64_t val;
    size_t current_ptr = s->ptr;
    int ret = byteread_vint(s, &val);

    fprintf(f, "\"%s\" : ", ext_name);
    if (ret != 0 || current_ptr + (size_t)len != s->ptr) {
        s->ptr = current_ptr;
        qlog_string(f, s, len);
    }
    else {
        fprintf(f, "%" PRIu64, val);
    }
}

void qlog_boolean_transport_extension(FILE* f, char const* ext_name, bytestream* s, uint64_t len)
{
    fprintf(f, "\"%s\" : ", ext_name);
    if (len != 0) {
        qlog_string(f, s, len);
    }
    else {
        fprintf(f, "\"\"");
    }
}

void qlog_preferred_address(FILE* f, bytestream* s, uint64_t len)
{
    uint16_t port4 =0;
    uint16_t port6 = 0;
    uint8_t cid_len;
    size_t old_size = s->size;

    s->size = s->ptr + (size_t) len;

    fprintf(f, "\"ip_v4\": \"");
    for (int i = 0; i < 4 && s->ptr < s->size; i++, s->ptr++) {
        fprintf(f, "%s%d", (i == 0) ? "" : ".", s->data[s->ptr]);
    }
    byteread_int16(s, &port4);
    fprintf(f, "\", \"port_v4\":%d", port4);
    fprintf(f, ", \"ip_v6\": \"");
    for (int i = 0; i < 8; i++) {
        uint16_t chunk = 0;
        byteread_int16(s, &chunk);
        fprintf(f, "%s%x", (i == 0) ? "" : ":", chunk);
    }
    byteread_int16(s, &port6);
    fprintf(f, "\", \"port_v6\" : %d", port6);
    byteread_int8(s, &cid_len);
    fprintf(f, ", \"connection_id\": ");
    qlog_string(f, s, cid_len);
    fprintf(f, ", \"stateless_reset_token\": ");
    qlog_string(f, s, 16);
    if (s->ptr < s->size) {
        fprintf(f, "\", \"extra_bytes\": ");
        qlog_string(f, s, bytestream_remain(s));
    }
    s->size = old_size;
}

void qlog_tp_version_negotiation(FILE* f, bytestream* s, uint64_t len)
{
    size_t old_size = s->size;

    s->size = s->ptr + (size_t)len;
    fprintf(f, "{ ");
    if ((len & 3) != 0 || len == 0) {
        fprintf(f, "\"bad_length\": \"%" PRIu64, len);
    } else {
        fprintf(f, "\"chosen\": \"");
        for (int i = 0; i < 4 && s->ptr < s->size; i++, s->ptr++) {
            fprintf(f, "%02x", s->data[s->ptr]);
        }
        fprintf(f, "\"");
        if (s->ptr < s->size) {
            int is_first = 1;
            fprintf(f, ", \"others\": [");
            do {
                fprintf(f, "%s", (is_first)?"\"":", \"");
                is_first = 0;
                for (int i = 0; i < 4 && s->ptr < s->size; i++, s->ptr++) {
                    fprintf(f, "%02x", s->data[s->ptr]);
                }
                fprintf(f, "\"");
            } while (s->ptr < s->size);
            fprintf(f, "]");
        }
    }
    fprintf(f, "}");
    s->size = old_size;
}


int qlog_transport_extensions(FILE* f, bytestream* s, size_t tp_length)
{
    int ret = 0;
    size_t ptr_max = s->ptr + tp_length;

    if (ptr_max < s->size) {
        fprintf(f, ",\n    \"transport_parameter_length\": %zu", tp_length);
        fprintf(f, ",\n    \"bytes_available\": %zu" PRIu64, s->size - s->ptr);
    } else {
        while (ret == 0 && s->ptr < ptr_max) {
            uint64_t extension_type = UINT64_MAX;
            uint64_t extension_length = 0;
            size_t current_ptr = s->ptr;


            ret |= byteread_vint(s, &extension_type);
            ret |= byteread_vint(s, &extension_length);

            fprintf(f, ",\n    ");

            if (ret != 0 || bytestream_remain(s) < extension_length) {
                size_t len = bytestream_remain(s);
                ret = -1;
                s->ptr = current_ptr;
                /* Print invalid parameter there */
                fprintf(f, "\"Parameter_coding_error\": ");
                qlog_string(f, s, len);
                break;
            }
            else {
                switch ((picoquic_tp_enum)extension_type) {
                case picoquic_tp_initial_max_stream_data_bidi_local:
                    qlog_vint_transport_extension(f, "initial_max_stream_data_bidi_local", s, extension_length);
                    break;
                case picoquic_tp_initial_max_stream_data_bidi_remote:
                    qlog_vint_transport_extension(f, "initial_max_stream_data_bidi_remote", s, extension_length);
                    break;
                case picoquic_tp_initial_max_stream_data_uni:
                    qlog_vint_transport_extension(f, "initial_max_stream_data_uni", s, extension_length);
                    break;
                case picoquic_tp_initial_max_data:
                    qlog_vint_transport_extension(f, "initial_max_data", s, extension_length);
                    break;
                case picoquic_tp_initial_max_streams_bidi:
                    qlog_vint_transport_extension(f, "initial_max_streams_bidi", s, extension_length);
                    break;
                case picoquic_tp_idle_timeout:
                    qlog_vint_transport_extension(f, "idle_timeout", s, extension_length);
                    break;
                case picoquic_tp_max_packet_size:
                    qlog_vint_transport_extension(f, "max_packet_size", s, extension_length);
                    break;
                case picoquic_tp_stateless_reset_token:
                    fprintf(f, "\"stateless_reset_token\": ");
                    qlog_string(f, s, extension_length);
                    break;
                case picoquic_tp_ack_delay_exponent:
                    qlog_vint_transport_extension(f, "ack_delay_exponent", s, extension_length);
                    break;
                case picoquic_tp_initial_max_streams_uni:
                    qlog_vint_transport_extension(f, "initial_max_streams_uni", s, extension_length);
                    break;
                case picoquic_tp_server_preferred_address: 
                    fprintf(f, "\"server_preferred_address\": {"); 
                    qlog_preferred_address(f, s, extension_length);
                    fprintf(f, "}");
                    break;
                case picoquic_tp_disable_migration:
                    qlog_boolean_transport_extension(f, "disable_migration", s, extension_length);
                    break;
                case picoquic_tp_max_ack_delay:
                    qlog_vint_transport_extension(f, "max_ack_delay", s, extension_length);
                    break;
                case picoquic_tp_original_connection_id:
                    fprintf(f, "\"original_connection_id\": ");
                    qlog_string(f, s, extension_length);
                    break;
                case picoquic_tp_retry_connection_id:
                    fprintf(f, "\"retry_connection_id\": ");
                    qlog_string(f, s, extension_length);
                    break;
                case picoquic_tp_handshake_connection_id:
                    fprintf(f, "\"handshake_connection_id\": ");
                    qlog_string(f, s, extension_length);
                    break;
                case picoquic_tp_active_connection_id_limit:
                    qlog_vint_transport_extension(f, "active_connection_id_limit", s, extension_length);
                    break;
                case picoquic_tp_max_datagram_frame_size:
                    qlog_vint_transport_extension(f, "max_datagram_frame_size", s, extension_length);
                    break;
                case picoquic_tp_enable_loss_bit:
                    qlog_vint_transport_extension(f, "enable_loss_bit", s, extension_length);
                    break;
                case picoquic_tp_min_ack_delay:
                    qlog_vint_transport_extension(f, "min_ack_delay", s, extension_length);
                    break;
                case picoquic_tp_enable_time_stamp:
                    qlog_boolean_transport_extension(f, "enable_time_stamp", s, extension_length);
                    break;
                case picoquic_tp_grease_quic_bit:
                    qlog_boolean_transport_extension(f, "grease_quic_bit", s, extension_length);
                    break;
                case picoquic_tp_version_negotiation:
                    fprintf(f, "\"version_negotiation\": ");
                    qlog_tp_version_negotiation(f, s, extension_length);
                    break;
                case picoquic_tp_enable_bdp_frame:
                    qlog_vint_transport_extension(f, "enable_bdp_frame", s, extension_length);
                    break;
                case picoquic_tp_initial_max_path_id:
                    qlog_vint_transport_extension(f, "initial_max_path_id", s, extension_length);
                    break;
                case picoquic_tp_address_discovery:
                    qlog_vint_transport_extension(f, "address_discovery", s, extension_length);
                    break;
                default:
                    /* dump unknown extensions */
                    fprintf(f, "\"%" PRIx64 "\": ", extension_type);
                    qlog_string(f, s, extension_length);
                    break;
                }
            }
        }
    }

    return ret;
}


int qlog_alpn_update(uint64_t time, bytestream* s, void* ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t owner = 0;
    uint64_t sni_length = 0;
    uint64_t alpn_length = 0;
    uint64_t alpn_count = 0;
    int ret = 0;

    ret |= byteread_vint(s, &owner);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    ret |= byteread_vint(s, &sni_length);
    qlog_event_header(f, ctx, delta_time, 0, "transport", "parameters_set");
    fprintf(f, "\n    \"owner\": \"%s\"", (owner) ? "local" : "remote");
    if (sni_length > 0) {
        fprintf(f, ",\n    \"sni\": ");
        ret |= qlog_chars(f, s, sni_length);
    }

    ret |= byteread_vint(s, &alpn_count);
    if (ret == 0 && alpn_count > 0) {
        fprintf(f, ",\n    \"proposed_alpn\": [");

        for (size_t i = 0; i < alpn_count; i++) {
            uint64_t len;
            if (i != 0) {
                fprintf(f, ", ");
            }
            ret |= byteread_vint(s, &len);
            ret |= qlog_chars(f, s, len);
        }
        fprintf(f, "]");
    }


    ret |= byteread_vint(s, &alpn_length);
    if (ret == 0 && alpn_length > 0) {
        fprintf(f, ",\n    \"alpn\": ");
        qlog_chars(f, s, alpn_length);
    }

    fprintf(f, "}]");

    ctx->event_count++;

    return 0;
}


int qlog_param_update(uint64_t time, bytestream* s, void* ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t owner = 0;
    uint64_t tp_length = 0;
    int ret = 0;

    ret |= byteread_vint(s, &owner);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, 0, "transport", "parameters_set");

    fprintf(f, "\n    \"owner\": \"%s\"", (owner)?"local":"remote");

    ret |= byteread_vint(s, &tp_length);

    if (ret == 0 && tp_length > 0) {
        qlog_transport_extensions(f, s, (size_t)tp_length);
    }
    
    fprintf(f, "}]");

    ctx->event_count++;

    return 0;
}

int qlog_packet_lost(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t sequence = 0;
    uint64_t trigger_length;
    uint64_t packet_size = 0;
    uint8_t cid_len = 0;
    int ret = 0;

    ret |= byteread_vint(s, &packet_type);
    ret |= byteread_vint(s, &sequence);
    ret |= byteread_vint(s, &trigger_length);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, path_id, "recovery", "packet_lost");
    fprintf(f, "\n    \"packet_type\" : \"%s\"", ptype2str((picoquic_packet_type_enum)packet_type));
    fprintf(f, ",\n    \"packet_number\" : %" PRIu64, sequence);
    if (trigger_length > 0) {
        fprintf(f, ",\n    \"trigger\": ");
        ret |= qlog_chars(f, s, trigger_length);
    }
    fprintf(f, ",\n    \"header\": {");
    fprintf(f, "\n        \"packet_type\" : \"%s\"", ptype2str((picoquic_packet_type_enum)packet_type));
    fprintf(f, ",\n        \"packet_number\" : %" PRIu64, sequence);
    ret |= byteread_int8(s, &cid_len);
    if (ret == 0 && cid_len > 0) {
        fprintf(f, ",\n        \"dcid\" : ");
        qlog_string(f, s, cid_len);
    }
    ret |= byteread_vint(s, &packet_size);
    if (ret == 0) {
        fprintf(f, ",\n        \"packet_size\" : %" PRIu64, packet_size);
    }
    fprintf(f, "}}]");

    ctx->event_count++;

    return 0;
}

int qlog_packet_dropped(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t err_code;
    uint64_t packet_size = 0;
    uint64_t raw_len = 0;
    char const* str;
    int ret = 0;

    ret |= byteread_vint(s, &packet_type);
    ret |= byteread_vint(s, &packet_size);
    ret |= byteread_vint(s, &err_code);
    ret |= byteread_vint(s, &raw_len);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, path_id, "transport", "packet_dropped");
    fprintf(f, "\n    \"packet_type\" : \"%s\"", ptype2str((picoquic_packet_type_enum)packet_type));
    fprintf(f, ",\n    \"packet_size\" : %" PRIu64, packet_size);
    switch (err_code) {
    case PICOQUIC_ERROR_DUPLICATE:
        str = "dos_prevention";
        break;
    case PICOQUIC_ERROR_AEAD_CHECK:
        str = "payload_decrypt_error";
        break;
    case PICOQUIC_ERROR_CNXID_CHECK:
        str = "unknown_connection_id";
        break;
    case PICOQUIC_ERROR_INITIAL_TOO_SHORT:
        str = "dos_prevention";
        break;
    case PICOQUIC_ERROR_CNXID_NOT_AVAILABLE:	
        str = "unknown_connection_id";
        break;
    case PICOQUIC_ERROR_KEY_ROTATION_NOT_READY:
        str = "key_unavailable";
        break;
    case PICOQUIC_ERROR_AEAD_NOT_READY:
        str = "key_unavailable";
        break;
    case PICOQUIC_ERROR_STATELESS_RESET:
        str = "stateless_reset";
        break;
    default:
        str = "protocol_violation";
        break;
    }
    fprintf(f, ",\n    \"trigger\": \"%s\"", str);

    if (ret == 0 && raw_len > 0) {
        fprintf(f, ",\n    \"raw\": ");
        qlog_string(f, s, raw_len);
    }
    fprintf(f, "}]");

    ctx->event_count++;

    return 0;
}

int qlog_packet_buffered(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t trigger_length = 0;
    int ret = 0;

    ret |= byteread_vint(s, &packet_type);
    ret |= byteread_vint(s, &trigger_length);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, path_id, "transport", "packet_buffered");


    fprintf(f, "\n    \"type\" : \"%s\"", ptype2str((picoquic_packet_type_enum)packet_type));
    fprintf(f, ",\n    \"trigger\": ");
    qlog_chars(f, s, trigger_length);
    fprintf(f, "}]");

    ctx->event_count++;

    return ret;
}

int qlog_pdu(uint64_t time, int rxtx, bytestream* s, void * ptr)
{
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    int64_t delta_time = time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    struct sockaddr_storage addr_peer = { 0 };
    struct sockaddr_storage addr_local = { 0 };
    uint64_t byte_length = 0;
    int ret_local;

    byteread_addr(s, &addr_peer);
    byteread_vint(s, &byte_length);
    ret_local = byteread_addr(s, &addr_local);

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, 0, "transport", (rxtx == 0) ? "datagram_sent" : "datagram_received");

    fprintf(f, " \"byte_length\": %" PRIu64, byte_length);

    if (addr_peer.ss_family != 0 &&
        picoquic_compare_addr((struct sockaddr*)&addr_peer, (struct sockaddr*) & ctx->addr_peer) != 0) {
        fprintf(f, ", \"%s\" : {", (rxtx == 0) ? "addr_to" : "addr_from");
        qlog_log_addr(f, (struct sockaddr*) & addr_peer);
        fprintf(f, "}");
        picoquic_store_addr(&ctx->addr_peer, (struct sockaddr*) & addr_peer);
    }

    if (ret_local == 0 && addr_local.ss_family != 0 &&
        picoquic_compare_addr((struct sockaddr*) & addr_local, (struct sockaddr*) & ctx->addr_local) != 0) {
        fprintf(f, ", \"%s\" : {", (rxtx != 0) ? "addr_to" : "addr_from");
        qlog_log_addr(f, (struct sockaddr*) & addr_local);
        fprintf(f, "}");
        picoquic_store_addr(&ctx->addr_local, (struct sockaddr*) & addr_local);
    }

    fprintf(f, "}]");
    ctx->event_count++;
    return 0;
}

int qlog_packet_start(uint64_t time, uint64_t path_id, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    int64_t delta_time = time - ctx->start_time;

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    } else {
        fprintf(f, "\n");
    }

    if (ph->ptype == picoquic_packet_1rtt_protected && rxtx == 0) {
        if (ctx->spin_bit_sent && (ctx->spin_bit_sent_last != ph->spin)) {
            qlog_event_header(f, ctx, delta_time, path_id, "transport", "spin_bit_updated");
            fprintf(f, " \"state\": %s }],\n", (ph->spin) ? "true" : "false");
        }
        ctx->spin_bit_sent = 1;
        ctx->spin_bit_sent_last = ph->spin;
    }

    qlog_event_header(f, ctx, delta_time, path_id, "transport", (rxtx == 0) ? "packet_sent" : "packet_received");
    fprintf(f, " \"packet_type\": \"%s\", \"header\": { \"packet_size\": %"PRIu64 , ptype2str(ph->ptype), size);

    if (ph->ptype != picoquic_packet_version_negotiation &&
        ph->ptype != picoquic_packet_retry) {
        fprintf(f, ", \"packet_number\": %"PRIu64, ph->pn64);
    }

    if (ph->ptype != picoquic_packet_1rtt_protected) {
        if (ctx->version_number != ph->vn) {
            fprintf(f, ", \"version\": \"%08x\"", ph->vn);
            ctx->version_number = ph->vn;
        }
        if (ph->ptype != picoquic_packet_version_negotiation &&
            ph->ptype != picoquic_packet_retry &&
            ph->ptype != picoquic_packet_error) {
            fprintf(f, ", \"payload_length\": %zu", ph->payload_length);
        }
    }

    if (ph->ptype != picoquic_packet_1rtt_protected && ph->srce_cnx_id.id_len > 0) {
        char scid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(scid_name, sizeof(scid_name), &ph->srce_cnx_id);
        fprintf(f, ", \"scid\": \"%s\"", scid_name);
    }

    if (ph->dest_cnx_id.id_len > 0) {
        char dcid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(dcid_name, sizeof(dcid_name), &ph->dest_cnx_id);
        fprintf(f, ", \"dcid\": \"%s\"", dcid_name);
    }

    if (ph->ptype == picoquic_packet_initial && ph->token_length > 0) {
        bytestream token;
        bytestream_ref_init(&token, ph->token_bytes, ph->token_length);
        fprintf(f, ", \"token\": ");
        qlog_string(f, &token, ph->token_length);
    }

    if (ph->ptype == picoquic_packet_1rtt_protected) {
        int need_key_phase = 0;

        if (rxtx == 0) {
            need_key_phase = !ctx->key_phase_sent || (ctx->key_phase_sent_last != ph->key_phase);
            ctx->key_phase_sent = 1;
            ctx->key_phase_sent_last = ph->key_phase;
        }
        else {
            need_key_phase = !ctx->key_phase_received || (ctx->key_phase_received_last != ph->key_phase);
            ctx->key_phase_received_last = ph->key_phase;
            ctx->key_phase_received = 1;
        }
        if (need_key_phase) {
            fprintf(f, ", \"key_phase\": %d", ph->key_phase);
        }
    }

    if (ph->quic_bit_is_zero) {
        fprintf(f, ", \"quic_bit\": 0");
    }

    ctx->packet_type = ph->ptype;

    if (ctx->packet_type == picoquic_packet_version_negotiation ||
        ctx->packet_type == picoquic_packet_retry) {
        fprintf(f, " }");
    }
    else {
        fprintf(f, " }, \"frames\": [");
    }

    ctx->frame_count = 0;
    return 0;
}

void qlog_time_stamp_frame(FILE* f, bytestream* s)
{
    uint64_t time_stamp = 0;

    byteread_vint(s, &time_stamp);
    fprintf(f, ", \"time_stamp\": %"PRIu64"", time_stamp);
}

void qlog_path_abandon_frame(FILE* f, bytestream* s)
{
    uint64_t path_id;
    uint64_t reason;
    
    byteread_vint(s, &path_id);
    byteread_vint(s, &reason);
    fprintf(f, ", \"path_id\": %"PRIu64, path_id);
    fprintf(f, ", \"reason\": %"PRIu64, reason);
}

void qlog_path_backup_frame(FILE* f, bytestream* s)
{
    uint64_t path_id = 0;
    uint64_t sequence;

    byteread_vint(s, &path_id);
    byteread_vint(s, &sequence);
    fprintf(f, ", \"path_id\": %"PRIu64, path_id);
    fprintf(f, ", \"sequence\": %"PRIu64, sequence);
}

void qlog_path_available_frame(FILE* f, bytestream* s)
{
    uint64_t path_id = 0;
    uint64_t sequence;

    byteread_vint(s, &path_id);
    byteread_vint(s, &sequence);
    fprintf(f, ", \"path_id\": %"PRIu64, path_id);
    fprintf(f, ", \"sequence\": %"PRIu64, sequence);
}

void qlog_max_path_id_frame(FILE* f, bytestream* s)
{
    uint64_t max_path_id = 0;
    byteread_vint(s, &max_path_id);
    fprintf(f, ", \"max_path_id\": %"PRIu64, max_path_id);
}

void qlog_path_blocked_frame(FILE* f, bytestream* s)
{
    uint64_t max_path_id = 0;
    byteread_vint(s, &max_path_id);
    fprintf(f, ", \"max_path_id\": %"PRIu64, max_path_id);
}

void qlog_reset_stream_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &error_code);
    fprintf(f, ", \"error_code\": %"PRIu64"", error_code);
    byteread_vint(s, &final_size);
    fprintf(f, ", \"final_size\": %"PRIu64"", final_size);
}

void qlog_stop_sending_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &error_code);
    fprintf(f, ", \"error_code\": %"PRIu64"", error_code);
}

void qlog_closing_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t error_code = 0;
    uint64_t offending_frame_type = 0;
    uint64_t reason_length = 0;
    char const* offensive_type_name = NULL;

    fprintf(f, ", \"error_space\": \"%s\"", 
        (ftype == picoquic_frame_type_connection_close)?"transport":"application");
    byteread_vint(s, &error_code);
    fprintf(f, ", \"error_code\": %"PRIu64"", error_code);
    
    if (ftype == picoquic_frame_type_connection_close &&
        error_code != 0) {
        byteread_vint(s, &offending_frame_type);
        offensive_type_name = ftype2str(offending_frame_type);
        if (strcmp(offensive_type_name, "unknown") == 0) {
            fprintf(f, ", \"trigger_frame_type\": \"%"PRIx64"\"", offending_frame_type);
        }
        else {
            fprintf(f, ", \"trigger_frame_type\": \"%s\"", offensive_type_name);
        }
    }

    byteread_vint(s, &reason_length);
    if (reason_length > 0){
        fprintf(f, ", \"reason\": \"");
        for (uint64_t i = 0; i < reason_length && s->ptr < s->size; i++) {
            int c = s->data[s->ptr++];

            if (c < 0x20 || c > 0x7E) {
                c = '.';
            }
            fprintf(f, "%c", c);
        }
        fprintf(f, "\"");
    }
}

void qlog_max_data_frame(FILE* f, bytestream* s)
{
    uint64_t maximum = 0;
    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_max_stream_data_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t maximum = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_max_streams_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t maximum;

    fprintf(f, ", \"stream_type\": \"%s\"",
        (ftype == picoquic_frame_type_max_streams_bidir) ?
        "bidirectional" : "unidirectional");

    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_blocked_frame(FILE* f, bytestream* s)
{
    uint64_t limit = 0;

    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_stream_blocked_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t limit = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_streams_blocked_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t limit;

    fprintf(f, ", \"stream_type\": \"%s\"", 
        (ftype == picoquic_frame_type_streams_blocked_bidir)?
        "bidirectional":"unidirectional");

    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_new_connection_id_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;
    uint64_t retire_before = 0;
    uint64_t cid_length = 0;

    if (ftype == picoquic_frame_type_path_new_connection_id) {
        uint64_t path_id;
        byteread_vint(s, &path_id);
        fprintf(f, ", \"path_id\": %"PRIu64"", path_id);
    }

    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
    byteread_vint(s, &retire_before);
    fprintf(f, ", \"retire_before\": %"PRIu64"", retire_before);
    byteread_vint(s, &cid_length);
    fprintf(f, ", \"connection_id\": ");
    qlog_string(f, s, cid_length);
    fprintf(f, ", \"reset_token\": ");
    qlog_string(f, s, 16);
}

void qlog_retire_connection_id_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;

    if (ftype == picoquic_frame_type_path_retire_connection_id) {
        uint64_t path_id = 0;
        byteread_vint(s, &path_id);
        fprintf(f, ", \"path_id\": %"PRIu64"", path_id);
    }

    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
}

void qlog_new_token_frame(FILE* f, bytestream* s)
{
    uint64_t toklen = 0;

    fprintf(f, ", \"new_token\": ");
    byteread_vint(s, &toklen);
    qlog_string(f, s, toklen);
}

void qlog_path_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    if (ftype == picoquic_frame_type_path_challenge) {
        fprintf(f, ", \"path_challenge\": ");
    }
    else {
        fprintf(f, ", \"path_response\": ");
    }
    qlog_string(f, s, 8);
}

void qlog_crypto_hs_frame(FILE* f, bytestream* s)
{
    uint64_t offset = 0;
    uint64_t data_length = 0;


    byteread_vint(s, &offset);
    fprintf(f, ", \"offset\": %"PRIu64"", offset);
    byteread_vint(s, &data_length);
    fprintf(f, ", \"length\": %"PRIu64"", data_length);
}

void qlog_datagram_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    unsigned int has_length = ftype & 1;
    uint64_t length = 0;

    if (has_length) {
        byteread_vint(s, &length);
        fprintf(f, ", \"length\": %"PRIu64"", length);
    }
}

void qlog_ack_frequency_frame(FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;
    uint64_t packet_tolerance = 0;
    uint64_t max_ack_delay = 0;
    uint64_t reordering_threshold = 0;
    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
    byteread_vint(s, &packet_tolerance);
    fprintf(f, ", \"packet_tolerance\": %"PRIu64"", packet_tolerance);
    byteread_vint(s, &max_ack_delay);
    fprintf(f, ", \"max_ack_delay\": %"PRIu64"", max_ack_delay);
    byteread_vint(s, &reordering_threshold);
    fprintf(f, ", \"reordering_threshold\": %"PRIu64"", reordering_threshold);
}

void qlog_ack_frame(uint64_t ftype, FILE * f, bytestream* s)
{
    uint64_t largest = 0;
    uint64_t ack_delay = 0;
    uint64_t num = 0;
    uint64_t path_id = 0;
    if (ftype == picoquic_frame_type_path_ack || ftype == picoquic_frame_type_path_ack_ecn) {
        byteread_vint(s, &path_id);
        fprintf(f, ", \"path_id\": %"PRIu64"", path_id);
    }
    byteread_vint(s, &largest);
    byteread_vint(s, &ack_delay);
    fprintf(f, ", \"ack_delay\": %"PRIu64"", ack_delay);
    byteread_vint(s, &num);
    fprintf(f, ", \"acked_ranges\": [");
    for (uint64_t i = 0; i <= num; i++) {
        uint64_t skip = 0;
        int64_t start_range;
        int64_t end_range;

        if (i != 0) {
            byteread_vint(s, &skip);
            skip++;

            largest -= skip;
            fprintf(f, ", ");
        }
        uint64_t range = 0;
        byteread_vint(s, &range);

        start_range = largest - range;
        end_range = (int64_t)largest;
        fprintf(f, "[%"PRId64", %"PRId64"]", start_range, end_range);

        largest -= range + 1;
    }
    fprintf(f, "]");
    if (ftype == picoquic_frame_type_ack_ecn || ftype == picoquic_frame_type_path_ack_ecn) {
        char const* ecn_name[3] = { "ect0", "ect1", "ce" };
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            uint64_t ecn_v = 0;
            byteread_vint(s, &ecn_v);
            fprintf(f, ", \"%s\": %"PRIu64, ecn_name[ecnx], ecn_v);
        }
    }
}

void qlog_erroring_frame(FILE* f, bytestream* s, uint64_t ftype)
{
    size_t extra_bytes = s->size - s->ptr;

    fprintf(f, ",\"unknown_type\": %" PRIu64 ",", ftype);

    fprintf(f, "\"begins_with\": ");

    qlog_string(f, s, (extra_bytes > 8) ? 8 : extra_bytes);
}

int qlog_proposed_versions(FILE* f, bytestream* s)
{
    int nb_versions = 0;
    fprintf(f, ",\n    \"proposed_versions\": [");

    while (bytestream_remain(s) > 0) {
        if (nb_versions > 0) {
            fprintf(f, ", ");
        }
        qlog_string(f, s, 4);
        nb_versions++;
    }
    fprintf(f, "]");
    return 0;
}

int qlog_retry_token(FILE* f, bytestream* s)
{
    size_t l = bytestream_remain(s);

    if (l > 0) {
        fprintf(f, ",\n    \"retry_token\": ");
        qlog_string(f, s, l);
    }
    return 0;
}

void qlog_bdp_frame(FILE* f, bytestream* s)
{
    uint64_t lifetime = 0;
    uint64_t recon_bytes_in_flight = 0;
    uint64_t recon_min_rtt = 0;
    uint64_t ip_len = 0;

    byteread_vint(s, &lifetime);
    byteread_vint(s, &recon_bytes_in_flight);
    byteread_vint(s, &recon_min_rtt);
    byteread_vint(s, &ip_len);
    fprintf(f, ", \"lifetime\": %"PRIu64", \"bytes_in_flight\": %"PRIu64", \"min_rtt\": %"PRIu64", \"ip\": ", lifetime, recon_bytes_in_flight, recon_min_rtt);
    qlog_string(f, s, ip_len);
}

void qlog_observed_address_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    unsigned int port = 0;
    uint64_t sequence = 0;

    byteread_vint(s, &sequence);
    fprintf(f, ", \"sequence\": %"PRIu64", \"address\": \"", sequence);
    if ((ftype & 1) == 0) {
        /* IPv4 address */
        for (int x = 0; x < 4 && s->ptr < s->size; x++) {
            if (x != 0) {
                fprintf(f, ".");
            }
            fprintf(f, "%d", s->data[s->ptr++]);
        }
    }
    else {
        /* IPv6 address */
        for (int x = 0; x < 8 && s->ptr < s->size; x++) {
            uint16_t w = 0;
            for (int y = 0; y < 2 && s->ptr < s->size; y++) {
                w <<= 8;
                w += s->data[s->ptr++];
            }
            if (x != 0) {
                fprintf(f, ":");
            }
            fprintf(f, "%x", w);
        }
    }
    for (int y = 0; y < 2 && s->ptr < s->size; y++) {
        port <<= 8;
        port += s->data[s->ptr++];
    }
    fprintf(f, "\", \"port\": %u", port);
}

int qlog_packet_frame(bytestream * s, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    if (ctx->packet_type == picoquic_packet_version_negotiation) {
        return qlog_proposed_versions(f, s);
    }
    else if (ctx->packet_type == picoquic_packet_retry) {
        return qlog_retry_token(f, s);
    }

    if (ctx->frame_count != 0) {
        fprintf(f, ", ");
    }

    fprintf(f, "{ ");

    uint64_t ftype = 0;
    size_t ptr_before_type = s->ptr;
    byteread_vint(s, &ftype);

    fprintf(f, "\n    \"frame_type\": \"%s\"", ftype2str((picoquic_frame_type_enum_t)ftype));

    if (ftype >= picoquic_frame_type_stream_range_min &&
        ftype <= picoquic_frame_type_stream_range_max) {
        uint64_t stream_id = 0;
        byteread_vint(s, &stream_id);
        uint64_t offset = 0;
        if ((ftype & 4) != 0) {
            byteread_vint(s, &offset);
        }
        uint64_t length = 0;
        byteread_vint(s, &length);
        fprintf(f, ", \"id\": %"PRIu64", \"offset\": %"PRIu64", \"length\": %"PRIu64", \"fin\": %s ",
            stream_id, offset, length, (ftype & 1) ? "true":"false");
        if ((ftype & 2) == 0) {
            fprintf(f, ", \"has_length\": false");
        }
        uint64_t extra_bytes = bytestream_remain(s);
        if (extra_bytes > 0) {
            fprintf(f, ", \"begins_with\": ");
            qlog_string(f, s, extra_bytes);
        }

    } else switch (ftype) {
    case picoquic_frame_type_padding:
        break;
    case picoquic_frame_type_ping: 
        break;
    case picoquic_frame_type_poll:
        break;
    case picoquic_frame_type_ack:
    case picoquic_frame_type_ack_ecn:
    case picoquic_frame_type_path_ack:
    case picoquic_frame_type_path_ack_ecn:
        qlog_ack_frame(ftype, f, s);
        break;
    case picoquic_frame_type_reset_stream:
        qlog_reset_stream_frame(f, s);
        break;
    case picoquic_frame_type_stop_sending:
        qlog_stop_sending_frame(f, s);
        break;
    case picoquic_frame_type_crypto_hs:
        qlog_crypto_hs_frame(f, s);
        break;
    case picoquic_frame_type_new_token:
        qlog_new_token_frame(f, s);
        break;
    case picoquic_frame_type_max_data:
        qlog_max_data_frame(f, s);
        break;
    case picoquic_frame_type_max_stream_data:
        qlog_max_stream_data_frame(f, s);
        break;
    case picoquic_frame_type_max_streams_bidir:
    case picoquic_frame_type_max_streams_unidir:
        qlog_max_streams_frame(ftype, f, s);
        break;
    case picoquic_frame_type_data_blocked:
        qlog_blocked_frame(f, s);
        break;
    case picoquic_frame_type_stream_data_blocked:
        qlog_stream_blocked_frame(f, s);
        break;
    case picoquic_frame_type_streams_blocked_bidir:
    case picoquic_frame_type_streams_blocked_unidir:
        qlog_streams_blocked_frame(ftype, f, s);
        break;
    case picoquic_frame_type_new_connection_id:
    case picoquic_frame_type_path_new_connection_id:
        qlog_new_connection_id_frame(ftype, f, s);
        break;
    case picoquic_frame_type_retire_connection_id:
    case picoquic_frame_type_path_retire_connection_id:
        qlog_retire_connection_id_frame(ftype, f, s);
        break;
    case picoquic_frame_type_path_challenge:
    case picoquic_frame_type_path_response:
        qlog_path_frame(ftype, f, s);
        break;
    case picoquic_frame_type_connection_close:
    case picoquic_frame_type_application_close:
        qlog_closing_frame(ftype, f, s);
        break;
    case picoquic_frame_type_handshake_done:
        break;
    case picoquic_frame_type_datagram:
    case picoquic_frame_type_datagram_l:
        qlog_datagram_frame(ftype, f, s);
        break;
    case picoquic_frame_type_ack_frequency:
        qlog_ack_frequency_frame(f, s);
        break;
    case picoquic_frame_type_immediate_ack:
        break;
    case picoquic_frame_type_time_stamp:
        qlog_time_stamp_frame(f, s);
        break;
    case picoquic_frame_type_path_abandon:
        qlog_path_abandon_frame(f, s);
        break;
    case picoquic_frame_type_path_backup:
        qlog_path_backup_frame(f, s);
        break;
    case picoquic_frame_type_path_available:
        qlog_path_available_frame(f, s);
        break;
    case picoquic_frame_type_bdp:
        qlog_bdp_frame(f, s);
        break;
    case picoquic_frame_type_max_path_id:
        qlog_max_path_id_frame(f, s);
        break;
    case picoquic_frame_type_path_blocked:
        qlog_path_blocked_frame(f, s);
        break;
    case picoquic_frame_type_observed_address_v4:
    case picoquic_frame_type_observed_address_v6:
        qlog_observed_address_frame(ftype, f, s);
        break;
    default:
        s->ptr = ptr_before_type;
        qlog_erroring_frame(f, s, ftype);
        break;
    }

    fprintf(f, "}");
    ctx->frame_count++;
    return 0;
}

int qlog_packet_end(void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    if (ctx->packet_type == picoquic_packet_version_negotiation ||
        ctx->packet_type == picoquic_packet_retry) {
        fprintf(f, "}]");
    }
    else {
        fprintf(f, "]}]");
    }

    ctx->packet_count++; 
    ctx->event_count++;
    return 0;
}

/* Qlog records evolution of congestion control with events of the form:
* [559,"transport","packet_sent","DEFAULT",{"packet_type":"handshake","header":{"packet_size":668,"packet_number":0}}],
* [904,"recovery","metrics_updated","default",{"bytes_in_flight":822}],
* [45228,"recovery","metrics_updated","default",{"bytes_in_flight":668,"cwnd":12154,"smoothed_rtt":46151,
*                          "min_rtt":46151,"latest_rtt":46151}],
*/

int qlog_cc_update(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    int ret = 0;
    uint64_t sequence = 0;
    uint64_t packet_rcvd = 0;
    uint64_t highest_ack = UINT64_MAX;
    uint64_t high_ack_time = 0;
    uint64_t last_time_ack = 0;
    uint64_t cwin = 0;
    uint64_t one_way_delay = 0;
    uint64_t rtt_sample = 0;
    uint64_t SRTT = 0;
    uint64_t RTT_min = 0;
    uint64_t bandwidth_estimate = 0;
    uint64_t receive_rate_estimate = 0;
    uint64_t Send_MTU = 0;
    uint64_t pacing_packet_time = 0;
    uint64_t nb_retrans = 0;
    uint64_t nb_spurious = 0;
    uint64_t cwin_blkd = 0;
    uint64_t flow_blkd = 0;
    uint64_t stream_blkd = 0;
    uint64_t cc_state = 0;
    uint64_t cc_param = 0;
    uint64_t bw_max = 0;
    uint64_t bytes_in_transit = 0;
    uint64_t app_limited = 0;
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    FILE* f = ctx->f_txtlog;

    ret |= byteread_vint(s, &sequence);
    ret |= byteread_vint(s, &packet_rcvd);
    if (packet_rcvd != 0) {
        ret |= byteread_vint(s, &highest_ack);
        ret |= byteread_vint(s, &high_ack_time);
        ret |= byteread_vint(s, &last_time_ack);
    }
    ret |= byteread_vint(s, &cwin);
    ret |= byteread_vint(s, &one_way_delay);
    ret |= byteread_vint(s, &rtt_sample);
    ret |= byteread_vint(s, &SRTT);
    ret |= byteread_vint(s, &RTT_min);
    ret |= byteread_vint(s, &bandwidth_estimate);
    ret |= byteread_vint(s, &receive_rate_estimate);
    ret |= byteread_vint(s, &Send_MTU);
    ret |= byteread_vint(s, &pacing_packet_time);
    ret |= byteread_vint(s, &nb_retrans);
    ret |= byteread_vint(s, &nb_spurious);
    ret |= byteread_vint(s, &cwin_blkd);
    ret |= byteread_vint(s, &flow_blkd);
    ret |= byteread_vint(s, &stream_blkd);

    ret |= byteread_vint(s, &cc_state);
    ret |= byteread_vint(s, &cc_param);
    ret |= byteread_vint(s, &bw_max);
    ret |= byteread_vint(s, &bytes_in_transit);
    /* Not checking the app limited return, because it is not present in old bin logs */
    (void) byteread_vint(s, &app_limited);

    if (ret == 0 &&
        (cwin != ctx->cwin || rtt_sample != ctx->rtt_sample || SRTT != ctx->SRTT ||
            RTT_min != ctx->RTT_min || bytes_in_transit != ctx->bytes_in_transit || 
            pacing_packet_time != ctx->pacing_packet_time)) {
        /* Something changed. Report the event. */
        int64_t delta_time = time - ctx->start_time;
        char* comma = "";

        if (ctx->event_count != 0) {
            fprintf(f, ",\n");
        }
        else {
            fprintf(f, "\n");
        }

        qlog_event_header(f, ctx, delta_time, path_id, "recovery", "metrics_updated");

        if (cwin != ctx->cwin) {
            fprintf(f, "%s\"cwnd\": %" PRIu64, comma, cwin);
            ctx->cwin = cwin;
            comma = ",";
        }

        if (pacing_packet_time != ctx->pacing_packet_time && pacing_packet_time > 0) {
            double bps = ((double)Send_MTU * 8) * 1000000.0 / pacing_packet_time;
            uint64_t bits_per_second = (uint64_t)bps;
            fprintf(f, "%s\"pacing_rate\": %" PRIu64, comma, bits_per_second);
            ctx->pacing_packet_time = pacing_packet_time;
            comma = ",";
        }

        if (bytes_in_transit != ctx->bytes_in_transit) {
            fprintf(f, "%s\"bytes_in_flight\": %" PRIu64, comma, bytes_in_transit);
            ctx->bytes_in_transit = bytes_in_transit;
            comma = ",";
        }

        if (SRTT != ctx->SRTT) {
            fprintf(f, "%s\"smoothed_rtt\": %" PRIu64, comma, SRTT);
            comma = ",";
        }

        if (RTT_min != ctx->RTT_min) {
            fprintf(f, "%s\"min_rtt\": %" PRIu64, comma, RTT_min);
            ctx->RTT_min = RTT_min;
            comma = ",";
        }

        if (rtt_sample != ctx->rtt_sample) {
            fprintf(f, "%s\"latest_rtt\": %" PRIu64, comma, rtt_sample);
            ctx->rtt_sample = rtt_sample;
            comma = ",";
        }

        if (app_limited != ctx->app_limited) {
            fprintf(f, "%s\"app_limited\": %" PRIu64, comma, app_limited);
            ctx->app_limited = (app_limited != 0);
            /* comma = ","; (not useful since last block of function) */
        }

        fprintf(f, "}]");
        ctx->event_count++;
    }

    return ret;
}

int qlog_info_message(uint64_t time, bytestream* s, void* ptr)
{
    int ret = 0;
    qlog_context_t* ctx = (qlog_context_t*)ptr;
    FILE* f = ctx->f_txtlog;
    int64_t delta_time = time - ctx->start_time;
    uint8_t message[BYTESTREAM_MAX_BUFFER_SIZE];
    size_t message_length = 0;

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    qlog_event_header(f, ctx, delta_time, 0, "info", "message");

    fprintf(f, " \"message\": \"");
    message_length = bytestream_remain(s);
    if (message_length > sizeof(message)) {
        message_length = sizeof(message);
    }
    memcpy(message, bytestream_ptr(s), message_length);
    for (size_t i = 0; i < message_length; i++) {
        int c = message[i];
        if (c < 0x20 || c > 0x7e) {
            message[i] = '?';
        }
    }
    fwrite(message, message_length, 1, f);
    fprintf(f, "\"}]");
    ctx->event_count++;

    return ret;
}

int qlog_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    ctx->start_time = time;
    ctx->packet_count = 0;
    ctx->event_count = 0;
    ctx->version_number = 0;


    memset(&ctx->addr_peer, 0, sizeof(struct sockaddr_storage));
    memset(&ctx->addr_local, 0, sizeof(struct sockaddr_storage));

    ctx->cwin = 0;
    ctx->bytes_in_transit = 0;
    ctx->SRTT = PICOQUIC_INITIAL_RTT;
    ctx->RTT_min = 0;
    ctx->rtt_sample = 0;
    ctx->pacing_packet_time = 1;

    ctx->key_phase_sent_last = 0;
    ctx->key_phase_sent = 0;
    ctx->key_phase_received_last = 0;
    ctx->key_phase_received = 0;
    ctx->spin_bit_sent_last = 0;
    ctx->spin_bit_sent = 0;

    fprintf(f, "{ \"qlog_version\": \"draft-00\", \"title\": \"picoquic\", \"traces\": [\n");
    fprintf(f, "{ \"vantage_point\": { \"name\": \"backend-67\", \"type\": \"%s\" },\n",
        client_mode?"client":"server");

    fprintf(f, "\"title\": \"picoquic\", \"description\": \"%s\",", ctx->cid_name);
    if (ctx->trace_flow_id) {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"path_id\", \"category\", \"event\", \"data\"],\n");
    } else {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"category\", \"event\", \"data\"],\n");
    }
    fprintf(f, "\"configuration\": {\"time_units\": \"us\"},\n");
    fprintf(f, "\"common_fields\": { \"protocol_type\": \"QUIC_HTTP3\", \"reference_time\": \"%"PRIu64"\"},\n", ctx->start_time);
    fprintf(f, "\"events\": [");
    ctx->state = 1;
    return 0;
}

int qlog_connection_end(uint64_t time, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]}\n");

    ctx->state = 2;
    return 0;
}

int qlog_convert(const picoquic_connection_id_t* cid, FILE* f_binlog, const char* binlog_name, const char* txt_name, const char* out_dir, uint16_t flags)
{
    int ret = 0;
    FILE* f_txtlog = NULL;
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];

    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }
    else if (txt_name == NULL) {
        f_txtlog = open_outfile(cid_name, binlog_name, out_dir, "qlog");
    }
    else {
        f_txtlog = picoquic_file_open(txt_name, "w");
    }

    if (f_txtlog == NULL) {
        ret = -1;
    }
    else  if (ret == 0) {

        qlog_context_t qlog;

        memset(&qlog, 0, sizeof(qlog_context_t));

        qlog.f_txtlog = f_txtlog;
        qlog.cid_name = cid_name;
        qlog.start_time = 0;
        qlog.packet_count = 0;
        qlog.state = 0;
        qlog.trace_flow_id = (flags & 1) ? 1 : 0;

        binlog_convert_cb_t ctx;
        ctx.connection_start = qlog_connection_start;
        ctx.connection_end = qlog_connection_end;
        ctx.alpn_update = qlog_alpn_update;
        ctx.param_update = qlog_param_update;
        ctx.pdu = qlog_pdu;
        ctx.packet_start = qlog_packet_start;
        ctx.packet_frame = qlog_packet_frame;
        ctx.packet_end = qlog_packet_end;
        ctx.packet_lost = qlog_packet_lost;
        ctx.packet_dropped = qlog_packet_dropped;
        ctx.packet_buffered = qlog_packet_buffered;
        ctx.cc_update = qlog_cc_update;
        ctx.info_message = qlog_info_message;
        ctx.ptr = &qlog;

        ret = binlog_convert(f_binlog, cid, &ctx);

        if (qlog.state == 1) {
            qlog_connection_end(0, &qlog);
        }

        picoquic_file_close(f_txtlog);
    }

    return ret;
}
