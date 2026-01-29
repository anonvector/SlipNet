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
#include "picoquic_internal.h"

const char * ptype2str(picoquic_packet_type_enum ptype)
{
    switch (ptype) {
    case picoquic_packet_error:
        return "error";
    case picoquic_packet_version_negotiation:
        return "version_negotiation";
    case picoquic_packet_initial:
        return "initial";
    case picoquic_packet_retry:
        return "retry";
    case picoquic_packet_handshake:
        return "handshake";
    case picoquic_packet_0rtt_protected:
        return "0RTT";
    case picoquic_packet_1rtt_protected:
        return "1RTT";
    case picoquic_packet_type_max:
    default:
        return "unknown";
    }
}

const char * ftype2str(picoquic_frame_type_enum_t ftype)
{
    if ((int)ftype >= picoquic_frame_type_stream_range_min &&
        (int)ftype <= picoquic_frame_type_stream_range_max) {
        return "stream";
    }

    switch (ftype) {
    case picoquic_frame_type_padding:
        return "padding";
    case picoquic_frame_type_reset_stream:
        return "reset_stream";
    case picoquic_frame_type_connection_close:
    case picoquic_frame_type_application_close:
        return "connection_close";
    case picoquic_frame_type_max_data:
        return "max_data";
    case picoquic_frame_type_max_stream_data:
        return "max_stream_data";
    case picoquic_frame_type_max_streams_bidir:
    case picoquic_frame_type_max_streams_unidir:
        return "max_streams";
    case picoquic_frame_type_ping:
        return "ping";
    case picoquic_frame_type_poll:
        return "poll";
    case picoquic_frame_type_data_blocked:
        return "data_blocked";
    case picoquic_frame_type_stream_data_blocked:
        return "stream_data_blocked";
    case picoquic_frame_type_streams_blocked_bidir:
    case picoquic_frame_type_streams_blocked_unidir:
        return "streams_blocked";
    case picoquic_frame_type_new_connection_id:
        return "new_connection_id";
    case picoquic_frame_type_path_new_connection_id:
        return "path_new_connection_id";
    case picoquic_frame_type_stop_sending:
        return "stop_sending";
    case picoquic_frame_type_ack:
        return "ack";
    case picoquic_frame_type_path_challenge:
        return "path_challenge";
    case picoquic_frame_type_path_response:
        return "path_response";
    case picoquic_frame_type_crypto_hs:
        return "crypto";
    case picoquic_frame_type_new_token:
        return "new_token";
    case picoquic_frame_type_ack_ecn:
        return "ack";
    case picoquic_frame_type_path_ack:
        return "path_ack";
    case picoquic_frame_type_path_ack_ecn:
        return "path_ack";
    case picoquic_frame_type_retire_connection_id:
        return "retire_connection_id";
    case picoquic_frame_type_path_retire_connection_id:
        return "path_retire_connection_id";
    case picoquic_frame_type_handshake_done:
        return "handshake_done";
    case picoquic_frame_type_datagram:
    case picoquic_frame_type_datagram_l:
        return "datagram";
    case picoquic_frame_type_ack_frequency:
        return "ack_frequency";
    case picoquic_frame_type_immediate_ack:
        return "immediate_ack";
    case picoquic_frame_type_time_stamp:
        return "time_stamp";
    case picoquic_frame_type_path_abandon:
        return "path_abandon";
    case picoquic_frame_type_path_backup:
        return "path_backup";
    case picoquic_frame_type_path_available:
        return "path_available";
    case picoquic_frame_type_bdp:
        return "bdp";
    case picoquic_frame_type_max_path_id:
        return "max_path_id";
    case picoquic_frame_type_path_blocked:
        return "path_blocked";
    case picoquic_frame_type_observed_address_v4:
        return "observed_address_v4";
    case picoquic_frame_type_observed_address_v6:
        return "observed_address_v6";
    default:
        return "unknown";
    }
}
