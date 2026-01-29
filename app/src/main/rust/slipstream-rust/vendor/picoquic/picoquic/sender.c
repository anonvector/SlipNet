#include "picoquic_internal.h"
/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/*
 * Sending logic.
 *
 * Data is sent over streams. This is instantiated by the "Post to stream" command, which
 * chains data to the head of stream structure. Data is unchained when it sent for the
 * first time.
 * 
 * Data is sent in packets, which contain stream frames and possibly other frames.
 * The retransmission logic is done by calling functions implemented in
 * `loss_recovery.c`
 * 
 * The retransmission logic operates on packets. If a packet is seen as lost, the
 * important frames that it contains will have to be retransmitted.
 #endif
 *
 * Unacknowledged packets are kept in a chained list. Packets get removed from that
 * list during the processing of acknowledgements. Packets are marked lost when a
 * sufficiently older packet is acknowledged, or after a timer. Lost packets
 * generate new packets, which are queued in the chained list.
 */

static picoquic_stream_head_t* picoquic_find_stream_for_writing(picoquic_cnx_t* cnx,
    uint64_t stream_id, int * ret)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    *ret = 0;

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(stream_id) != cnx->client_mode) {
            *ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }

        if (*ret == 0) {
            stream = picoquic_create_missing_streams(cnx, stream_id, 0);

            if (stream == NULL) {
                *ret = PICOQUIC_ERROR_MEMORY;
            }
        }
    }

    return stream;
}

int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0) {
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

void picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        stream->app_stream_ctx = NULL;
    }
}

int picoquic_mark_datagram_ready(picoquic_cnx_t* cnx, int is_ready)
{
    int ret = 0;
    int was_ready = cnx->is_datagram_ready;

    cnx->is_datagram_ready = is_ready;
    if (!was_ready && is_ready) {
        if (cnx->remote_parameters.max_datagram_frame_size == 0) {
            ret = -1;
        }
        else {
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
        }
    }
    return ret;
}

int picoquic_mark_datagram_ready_path(picoquic_cnx_t* cnx, uint64_t unique_path_id, int is_path_ready)
{
    int ret = 0;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        int was_ready = cnx->path[path_id]->is_datagram_ready;
        cnx->path[path_id]->is_datagram_ready = is_path_ready;
        if (!was_ready && is_path_ready) {
            if (cnx->remote_parameters.max_datagram_frame_size == 0) {
                ret = -1;
            }
            else {
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
            }
        }
    } else {
        ret = -1;
    }
    return ret;
}


int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void * app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0) {
        if (is_active) {
            /* The call only fails if the stream was closed or reset */
            if (!stream->fin_requested && !stream->reset_requested &&
                cnx->callback_fn != NULL) {
                stream->app_stream_ctx = app_stream_ctx;
                if (!stream->is_active) {
                    stream->is_active = 1;
                    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
                }
            }
            else {
                ret = PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM;
            }
        }
        else {
            stream->is_active = 0;
            stream->app_stream_ctx = app_stream_ctx;
        }
    }

    return ret;
}


void picoquic_set_default_datagram_priority(picoquic_quic_t* quic, uint8_t default_datagram_priority)
{
    quic->default_datagram_priority = default_datagram_priority;
}

void picoquic_set_datagram_priority(picoquic_cnx_t* cnx, uint8_t datagram_priority)
{
    cnx->datagram_priority = datagram_priority;
}

void picoquic_set_default_priority(picoquic_quic_t* quic, uint8_t default_stream_priority)
{
    quic->default_stream_priority = default_stream_priority;
}

int picoquic_set_stream_priority(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t stream_priority)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0) {
        stream->stream_priority = stream_priority;
        picoquic_reorder_output_stream(cnx, stream);
    }

    return ret;
}

int picoquic_mark_high_priority_stream(picoquic_cnx_t * cnx, uint64_t stream_id, int is_high_priority)
{
    int ret;

    if (is_high_priority) {
        cnx->high_priority_stream_id = stream_id;
    }
    else if (cnx->high_priority_stream_id == stream_id) {
        cnx->high_priority_stream_id = UINT64_MAX;
    }

    ret = picoquic_set_stream_priority(cnx, stream_id, (is_high_priority) ? 0 : cnx->quic->default_stream_priority);

    return ret;
}

int picoquic_add_to_stream_with_ctx(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin, void * app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0 && set_fin) {
        if (stream->fin_requested) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        } else {
            stream->fin_requested = 1;
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (ret == 0 && (stream->reset_sent || stream->stop_sending_received)) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_queue_node_t* stream_data = (picoquic_stream_queue_node_t*)
            malloc(sizeof(picoquic_stream_queue_node_t));
        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_queue_node_t** pprevious = &stream->send_queue;
                picoquic_stream_queue_node_t* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }

        picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
    }

    if (ret == 0) {
        cnx->nb_bytes_queued += length;
        stream->is_active = 0;
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

int picoquic_add_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin)
{
    return picoquic_add_to_stream_with_ctx(cnx, stream_id, data, length, set_fin, NULL);
}

int picoquic_open_flow_control(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t expected_data_size)
{
    int ret = 0;
    uint8_t buffer[512];
    size_t length = 0;
    size_t consumed = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    if (cnx->cnx_state == picoquic_state_ready && cnx->quic->max_data_limit == 0){
        /* Only send the update in ready state, so that the misc frame is not picked by the
         * wrong transport context.
         * TODO: find way to queue the update so it is only sent as 0RTT or 1RTT packet.
         */
        if (stream == NULL) {
            ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }
        else {
            uint64_t max_required = stream->consumed_offset + expected_data_size;
            uint8_t* bytes_max = buffer + sizeof(buffer);
            int more_data = 0;
            int is_pure_ack = 1;

            if (max_required > stream->maxdata_local) {
                uint8_t* bytes_next = picoquic_format_max_stream_data_frame(cnx, stream, buffer + consumed, bytes_max, &more_data, &is_pure_ack, max_required);
                bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack, expected_data_size);
                if ((length = bytes_next - buffer) > 0) {
                    ret = picoquic_queue_misc_frame(cnx, buffer, length, is_pure_ack,
                        picoquic_packet_context_application);
                }
            }
        }
    }

    return ret;
}

void picoquic_reset_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        stream->app_stream_ctx = NULL;
    }
}

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;
        if (stream->fin_sent && picoquic_check_sack_list(&stream->sack_list, 0, stream->fin_offset) == 0){
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->reset_requested) {
            stream->local_error = local_stream_error;
            stream->reset_requested = 1;
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir)
{
    /* This code could be written as:
     * int stream_type_id = ((cnx->client_mode ^ 1) | ((is_unidir) ? 2 : 0)); 
     * but Visual Studio produces an obnoxious error message about
     * mixing bitwise or and logical or. */
    int stream_type_id = cnx->client_mode ^ 1;
    if (is_unidir) {
        stream_type_id |= 2;
    }

    return cnx->next_stream_id[stream_type_id];     
}

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;

        if (stream->reset_received) {
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->stop_sending_requested) {
            stream->local_stop_error = local_stream_error;
            stream->stop_sending_requested = 1;
            picoquic_insert_output_stream(cnx, stream);
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_discard_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        if (IS_BIDIR_STREAM_ID(stream_id) || !IS_CLIENT_STREAM_ID(stream_id)) {
            ret = picoquic_stop_sending(cnx, stream_id, local_stream_error);
            if (ret == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED) {
                ret = 0;
            }
        }
        if (ret == 0 &&
            (IS_BIDIR_STREAM_ID(stream_id) || IS_CLIENT_STREAM_ID(stream_id))) {
            ret = picoquic_reset_stream(cnx, stream_id, local_stream_error);
            if (ret == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED) {
                ret = 0;
            }
        }
        stream->app_stream_ctx = NULL;
        stream->is_discarded = 1;
    }

    return ret;
}

/*
 * Manage content padding
 */

size_t picoquic_pad_to_target_length(uint8_t * bytes, size_t length, size_t target)
{
    if (length < target) {
        memset(bytes + length, 0, target - length);
        length = target;
    }

    return length;
}

size_t picoquic_pad_to_policy(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, uint32_t max_length)
{
    size_t target = cnx->padding_minsize;

    if (length > target && cnx->padding_multiple != 0) {
        uint32_t delta = (length - target) % cnx->padding_multiple;

        if (delta == 0) {
            target = length;
        }
        else {
            target = length + cnx->padding_multiple - delta;
        }
    }

    if (target > max_length) {
        target = max_length;
    }

    return picoquic_pad_to_target_length(bytes, length, target);
}


/*
 * Packet management
 */

picoquic_packet_t* picoquic_create_packet(picoquic_quic_t * quic)
{
    picoquic_packet_t* packet = quic->p_first_packet;
    
    if (packet == NULL) {
        packet = (picoquic_packet_t*)malloc(sizeof(picoquic_packet_t));
        if (packet != NULL) {
            quic->nb_packets_allocated++;
            if (quic->nb_packets_allocated > quic->nb_packets_allocated_max) {
                quic->nb_packets_allocated_max = quic->nb_packets_allocated;
            }
        }
    }
    else {
        quic->p_first_packet = packet->packet_previous;
        quic->nb_packets_in_pool--;
    }

    if (packet != NULL) {
        /* It might be sufficient to zero the metadata, but zeroing everything
         * appears safer, and does not confuse checkers like valgrind.
         */
        memset(packet, 0, sizeof(picoquic_packet_t));
    }

    return packet;
}

void picoquic_recycle_packet(picoquic_quic_t * quic, picoquic_packet_t* packet)
{
    if (packet != NULL) {
        if (quic->nb_packets_in_pool >= PICOQUIC_MAX_PACKETS_IN_POOL) {
            free(packet);
            quic->nb_packets_allocated--;
        }
        else {
            memset(packet, 0, offsetof(struct st_picoquic_packet_t, bytes));
            packet->packet_previous = quic->p_first_packet;
            quic->p_first_packet = packet;
            quic->nb_packets_in_pool++;
        }
    }
}

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length)
{
    if ((bytes[0] & 0x80) != 0 && header_length > 6 && packet_length > header_length && packet_length < 0x4000)
    {
        picoquic_varint_encode_16(bytes + pnum_index - 2, (uint16_t)(packet_length - header_length));
    }
}

uint8_t picoquic_create_long_packet_type(picoquic_packet_type_enum pt, int version_index)
{
    uint8_t flags = 0xFF; /* Will cause an error... */
    if (version_index < 0) {
        version_index = 0;
    }
    switch (picoquic_supported_versions[version_index].packet_type_version) {
    case PICOQUIC_V1_VERSION:
        switch (pt) {
        case picoquic_packet_initial:
            flags = 0xC3;
            break;
        case picoquic_packet_0rtt_protected:
            flags = 0xD3;
            break;
        case picoquic_packet_handshake:
            flags = 0xE3;
            break;
        case picoquic_packet_retry:
            /* Do not set PP in retry header, the bits are later used for ODCIL */
            flags = 0xF0;
            break;
        default:
            break;
        }
        break;
    case PICOQUIC_V2_VERSION:
        /* Initial packets use a packet type field of 0b01. */
        /* 0-RTT packets use a packet type field of 0b10. */
        /* Handshake packets use a packet type field of 0b11. */
        /* Retry packets use a packet type field of 0b00.*/
        switch (pt) {
        case picoquic_packet_initial:
            flags = 0xD3;
            break;
        case picoquic_packet_0rtt_protected:
            flags = 0xE3;
            break;
        case picoquic_packet_handshake:
            flags = 0xF3;
            break;
        case picoquic_packet_retry:
            /* Do not set PP in retry header, the bits are later used for ODCIL */
            flags = 0xC0;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return flags;
}

size_t picoquic_create_long_header(
    picoquic_packet_type_enum packet_type,
    picoquic_connection_id_t * dest_cnx_id,
    picoquic_connection_id_t * srce_cnx_id,
    int do_grease_quic_bit,
    uint32_t version,
    int version_index,
    uint64_t sequence_number,
    size_t retry_token_length,
    uint8_t * retry_token,
    uint8_t* bytes,
    size_t* pn_offset,
    size_t* pn_length)
{
    /* Create a long packet */
    size_t length = 0;

    /* The first byte is defined in RFC 9000 as:
    *     Header Form (1) = 1,
    *     Fixed Bit (1) = 1,
    *     Long Packet Type (2),
    *     Type-Specific Bits (4)
    * The packet type is version dependent. In fact, the whole first byte is version
    * dependent, the invariant draft only specifies the "header form" bit = 1 for long
    * header. In version 1, the packet specific bytes are two reserved bytes +
    * sequence number length, always set to 3 in picoquic (i.e., 4 bytes).
    *
    */
    bytes[0] = picoquic_create_long_packet_type(packet_type, version_index);

    if (do_grease_quic_bit) {
        bytes[0] &= 0xBF;
    }

    length = 1;
    picoformat_32(&bytes[length], version);
    length += 4;

    bytes[length++] = dest_cnx_id->id_len;
    length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, *dest_cnx_id);
    bytes[length++] = srce_cnx_id->id_len;
    length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, *srce_cnx_id);

    /* Special case of packet initial -- encode token as part of header */
    if (packet_type == picoquic_packet_initial) {
        length += picoquic_varint_encode(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, retry_token_length);
        if (retry_token_length > 0) {
            memcpy(&bytes[length], retry_token, retry_token_length);
            length += retry_token_length;
        }
    }

    if (packet_type == picoquic_packet_retry) {
        /* No payload length and no sequence number for Retry */
        *pn_offset = 0;
        *pn_length = 0;
    }
    else {
        /* Reserve two bytes for payload length */
        bytes[length++] = 0;
        bytes[length++] = 0;
        /* Encode the sequence number */
        *pn_offset = length;
        *pn_length = 4;
        picoformat_32(&bytes[length], (uint32_t)sequence_number);
        length += 4;
    }
    return length;
}

size_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_path_t* path_x,
    size_t header_length,
    uint8_t* bytes,
    size_t* pn_offset,
    size_t* pn_length)
{
    size_t length = 0;

    /* Prepare the packet header */
    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Create a short packet -- using 32 bit sequence numbers for now */
        uint8_t K = (cnx->key_phase_enc) ? 0x04 : 0;
        uint8_t C = 0x40; /* set the QUIC bit */
        size_t pn_l = 4;  /* default packet length to 4 bytes */

        if (cnx->do_grease_quic_bit) {
            /* we grease the quic bit if both local and remote agreed to do so */
            C &= (uint8_t)picoquic_public_random_64();
            cnx->quic_bit_greased |= (C == 0);
        }

        length = 0;
        bytes[length++] = (K | C | picoquic_spin_function_table[cnx->spin_policy].spinbit_outgoing(cnx));
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length,
            (path_x->is_probing_nat && path_x->p_remote_nat_cnxid != NULL) ? path_x->p_remote_nat_cnxid->cnx_id : path_x->p_remote_cnxid->cnx_id);

        *pn_offset = length;
        if (header_length > length && header_length < length + 4) {
            pn_l = header_length - length;
        }
        *pn_length = pn_l;
        bytes[0] |= (pn_l - 1);
        switch (pn_l) {
        case 1:
            bytes[length] = (uint8_t)sequence_number;
            break;
        case 2:
            picoformat_16(&bytes[length], (uint16_t)sequence_number);
            break;
        case 3:
            picoformat_24(&bytes[length], (uint32_t)sequence_number);
            break;
        default:
            picoformat_32(&bytes[length], (uint32_t)sequence_number);
            break;
        }
        length += pn_l;
    }
    else {
        /* Create a long packet */
        picoquic_connection_id_t * dest_cnx_id =
            (cnx->client_mode && (packet_type == picoquic_packet_initial ||
                packet_type == picoquic_packet_0rtt_protected)
                && picoquic_is_connection_id_null(&path_x->p_remote_cnxid->cnx_id)) ?
            &cnx->initial_cnxid : &path_x->p_remote_cnxid->cnx_id;
        picoquic_connection_id_t* srce_cnx_id = &path_x->p_local_cnxid->cnx_id;
        uint32_t version = ((cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) && packet_type == picoquic_packet_initial) ?
            cnx->proposed_version : picoquic_supported_versions[cnx->version_index].version;

        length = picoquic_create_long_header(
            packet_type,
            dest_cnx_id,
            srce_cnx_id,
            cnx->do_grease_quic_bit,
            version,
            cnx->version_index,
            sequence_number,
            cnx->retry_token_length,
            cnx->retry_token,
            bytes,
            pn_offset,
            pn_length);
    }

    return length;
}

size_t picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_packet_context_t * pkt_ctx)
{
    uint32_t header_length = 0;

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(cnx != NULL)
     * but the documentation does not say anything about that for GCC and CLANG */
    if (cnx == NULL) {
        return 0;
    }

    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Predict acceptable length of packet number */
        uint8_t pn_l = 4;
        int64_t delta = pkt_ctx->send_sequence;
        if (pkt_ctx->pending_first != NULL) {
            delta -= pkt_ctx->pending_first->sequence_number;
        }
        if (delta < 262144) {
            pn_l = 3;
            if (pkt_ctx->send_sequence < 1024) {
                pn_l = 2;
                if (pkt_ctx->send_sequence < 16) {
                    pn_l = 1;
                }
            }
        }

        /* Compute length of a short packet header */
        header_length = 1 + cnx->path[0]->p_remote_cnxid->cnx_id.id_len + pn_l;
    }
    else {
        /* Compute length of a long packet header */
        header_length = 1 + /* version */ 4 + /* cnx_id length bytes */ 2;

        /* add dest-id length */
        if (cnx->client_mode && (packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(&cnx->path[0]->p_remote_cnxid->cnx_id)) {
            header_length += cnx->initial_cnxid.id_len;
        }
        else {
            header_length += cnx->path[0]->p_remote_cnxid->cnx_id.id_len;
        }

        /* add srce-id length */
        header_length += cnx->path[0]->p_local_cnxid->cnx_id.id_len;

        /* add length of payload length and packet number */
        header_length += 2 + 4;

        /* add length of tokens for initial packets */
        if (packet_type == picoquic_packet_initial) {
            uint8_t useless[16];
            header_length += (uint32_t)picoquic_varint_encode(useless, 16, cnx->retry_token_length);
            header_length += (uint32_t)cnx->retry_token_length;
        }
    }

    return header_length;
}

/*
 * Management of packet protection
 */
size_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, picoquic_epoch_enum epoch)
{
    size_t ret = 16;

    if (cnx->crypto_context[epoch].aead_encrypt != NULL) {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[epoch].aead_encrypt);
    }
    else {
        DBG_PRINTF("Try getting checksum for empty context, epoch %d", epoch);
    }

    return ret;
}

void picoquic_protect_packet_header(uint8_t * send_buffer, size_t pn_offset, uint8_t first_mask, void* pn_enc)
{
    /* The sample is located after the pn_offset */
    size_t sample_offset = /* header_length */ pn_offset + 4;

    if (pn_offset < sample_offset)
    {
        /* This is always true, as we use pn_length = 4 */
        uint8_t mask_bytes[5] = { 0, 0, 0, 0, 0 };
        uint8_t pn_l;

        picoquic_pn_encrypt(pn_enc, send_buffer + sample_offset, mask_bytes, mask_bytes, 5);
        /* Encode the first byte */
        pn_l = (send_buffer[0] & 3) + 1;
        send_buffer[0] ^= (mask_bytes[0] & first_mask);

        /* Packet encoding is 1 to 4 bytes */
        for (uint8_t i = 0; i < pn_l; i++) {
            send_buffer[pn_offset+i] ^= mask_bytes[i+1];
        }
    }
}

size_t picoquic_protect_packet(picoquic_cnx_t* cnx, 
    picoquic_packet_type_enum ptype,
    uint8_t * bytes, 
    uint64_t sequence_number,
    size_t length, size_t header_length,
    uint8_t* send_buffer, size_t send_buffer_max,
    void * aead_context, void* pn_enc,
    picoquic_path_t* path_x, uint64_t current_time)
{
    size_t send_length;
    size_t h_length;
    size_t pn_offset = 0;
    size_t pn_length = 0;
    size_t aead_checksum_length = picoquic_aead_get_checksum_length(aead_context);
    uint8_t first_mask = 0x0F;

    /* Create the packet header just before encrypting the content */
    h_length = picoquic_create_packet_header(cnx, ptype,
        sequence_number, path_x, header_length, send_buffer, &pn_offset, &pn_length);

    if (h_length != header_length) {
#ifdef HUNTING_FOR_BUFFER_OVERFLOW
        char* x = NULL;
        *x++;
#endif
        picoquic_log_app_message(cnx, "BUFFER OVERFLOW? Packet header prediction fails, %zu instead of %zu\n", h_length, header_length);
    }

    if (ptype == picoquic_packet_1rtt_protected) {
        if (cnx->is_loss_bit_enabled_outgoing) {
            first_mask = 0x07;
            path_x->q_square++;
            if ((path_x->q_square & PICOQUIC_LOSS_BIT_Q_HALF_PERIOD) != 0) {
                send_buffer[0] |= 0x10;
            }
            if (path_x->nb_losses_found > path_x->nb_losses_reported) {
                send_buffer[0] |= 0x08;
                path_x->nb_losses_reported++;
            }
        }
        else {
            first_mask = 0x1F;
        }
    }

    /* Make sure that the payload length is encoded in the header */
    /* Using encryption, the "payload" length also includes the encrypted packet length */
    picoquic_update_payload_length(send_buffer, pn_offset, h_length - pn_length, length + aead_checksum_length);

    /* If fuzzing is required, apply it */
    if (cnx->quic->fuzz_fn != NULL) {
        if (h_length == header_length) {
            memcpy(bytes, send_buffer, header_length);
        }
        length = cnx->quic->fuzz_fn(cnx->quic->fuzz_ctx, cnx, bytes,
            send_buffer_max - aead_checksum_length, length, header_length);
        if (h_length == header_length) {
            memcpy(send_buffer, bytes, header_length);
        }
    }

    /* Encrypt the packet */
    if (cnx->is_multipath_enabled && ptype == picoquic_packet_1rtt_protected) {
        send_length = picoquic_aead_encrypt_mp(send_buffer + /* header_length */ h_length,
            bytes + header_length, length - header_length, path_x->unique_path_id,
            sequence_number, send_buffer, /* header_length */ h_length, aead_context);
    }
    else {
        send_length = picoquic_aead_encrypt_generic(send_buffer + /* header_length */ h_length,
            bytes + header_length, length - header_length,
            sequence_number, send_buffer, /* header_length */ h_length, aead_context);
    }

    send_length += /* header_length */ h_length;

    /* if needed, log the segment before header protection is applied */
    picoquic_log_outgoing_packet(cnx, path_x,
        bytes, sequence_number, pn_length, length,
        send_buffer, send_length, current_time);

    /* Next, encrypt the PN -- The sample is located after the pn_offset */
    picoquic_protect_packet_header(send_buffer, pn_offset, first_mask, pn_enc);

    return send_length;
}

/*
 * Final steps in packet transmission: queue for retransmission, etc
 */

void picoquic_queue_for_retransmit(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    size_t length, uint64_t current_time)
{
    picoquic_packet_context_t* pkt_ctx = NULL;
    
    if (packet->ptype == picoquic_packet_1rtt_protected && cnx->is_multipath_enabled) {
        pkt_ctx = &path_x->pkt_ctx;
    }
    else {
        pkt_ctx = &cnx->pkt_ctx[packet->pc];
    }

    /* Manage the double linked packet list for retransmissions */
    packet->packet_next = NULL;
    if (pkt_ctx->pending_last == NULL) {
        packet->packet_previous = NULL;
        pkt_ctx->pending_first = packet;
    } else {
        packet->packet_previous = pkt_ctx->pending_last;
        packet->packet_previous->packet_next = packet;
    }
    pkt_ctx->pending_last = packet;
    packet->is_queued_for_retransmit = 1;

    if (!packet->is_ack_trap) {
        /* Account for bytes in transit, for congestion control */
        path_x->bytes_in_transit += length;
        path_x->is_cc_data_updated = 1;
        /* Update the pacing data */
        picoquic_update_pacing_after_send(path_x, length, current_time);
    }
}

picoquic_packet_t* picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, 
    picoquic_packet_context_t * pkt_ctx, picoquic_packet_t* p, int should_free,
    int add_to_data_repeat_queue)
{
    size_t dequeued_length = p->length + p->checksum_overhead;

    if (p->is_queued_for_retransmit) {
        /* Remove from list */
        if (p->packet_next == NULL) {
            pkt_ctx->pending_last = p->packet_previous;
        }
        else {
            p->packet_next->packet_previous = p->packet_previous;
        }

        if (p->packet_previous == NULL) {
            pkt_ctx->pending_first = p->packet_next;
        }
        else {
            p->packet_previous->packet_next = p->packet_next;
        }
        p->is_queued_for_retransmit = 0;
    }

    /* Account for bytes in transit, for congestion control */

    if (p->send_path != NULL && !p->is_ack_trap) {
        if (p->send_path->bytes_in_transit > dequeued_length) {
            p->send_path->bytes_in_transit -= dequeued_length;
        }
        else {
            p->send_path->bytes_in_transit = 0;
        }
        p->send_path->is_cc_data_updated = 1;
    }

    /* Replace head of preemptive repeat list if it was this packet. */
    if (pkt_ctx->preemptive_repeat_ptr == p) {
        pkt_ctx->preemptive_repeat_ptr = p->packet_next;
    }

    if (should_free || p->is_ack_trap) {
        if (add_to_data_repeat_queue) {
            picoquic_queue_data_repeat_packet(cnx, p);
        }
        else {
            picoquic_recycle_packet(cnx->quic, p);
            p = NULL;
        }
    } 
    else {
        p->packet_previous = NULL;
        /* add this packet to the retransmitted list */
        if (pkt_ctx->retransmitted_oldest == NULL) {
            pkt_ctx->retransmitted_newest = p;
            pkt_ctx->retransmitted_oldest = p;
            p->packet_next = NULL;
        }
        else {
            pkt_ctx->retransmitted_newest->packet_previous = p;
            p->packet_next = pkt_ctx->retransmitted_newest;
            pkt_ctx->retransmitted_newest = p;
        }
        pkt_ctx->retransmitted_queue_size += 1;
        p->is_queued_for_spurious_detection = 1;

        if (add_to_data_repeat_queue) {
            picoquic_queue_data_repeat_packet(cnx, p);
        }
    }

    return p;
}

void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx, picoquic_packet_t* p)
{
    pkt_ctx->retransmitted_queue_size -= 1;
    if (p->packet_previous == NULL) {
        pkt_ctx->retransmitted_newest = p->packet_next;
    }
    else {
        p->packet_previous->packet_next = p->packet_next;
    }

    if (p->packet_next == NULL) {
        pkt_ctx->retransmitted_oldest = p->packet_previous;
    }
    else {
        p->packet_next->packet_previous = p->packet_previous;
    }

    /* Packets can be queued simultaneously for data repeat and 
    * for detection of spurious losses, so should only be recycled
    * when removed from both queues */
    p->is_queued_for_spurious_detection = 0;
    if (!p->is_queued_for_data_repeat) {
        picoquic_recycle_packet(cnx->quic, p);
    }
}

/*
 * Inserting holes in the send sequence to trap optimistic ack.
 * return 0 if hole was inserted, !0 if packet should be freed.
 */
void picoquic_insert_hole_in_send_sequence_if_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    picoquic_packet_context_t * pkt_ctx, uint64_t current_time, uint64_t * next_wake_time)
{
    if (cnx->quic->sequence_hole_pseudo_period == 0) {
        /* Holing disabled. Set to max value, never worry about it later */
        pkt_ctx->next_sequence_hole = UINT64_MAX;
    } else if (cnx->cnx_state == picoquic_state_ready &&
        pkt_ctx->pending_last != NULL &&
        pkt_ctx->send_sequence >= pkt_ctx->next_sequence_hole) {
        if (pkt_ctx->next_sequence_hole != 0 &&
            !pkt_ctx->pending_last->is_ack_trap) {
            /* Insert a hole in sequence */
            picoquic_packet_t* packet = picoquic_create_packet(cnx->quic);

            if (packet != NULL) {
                packet->is_ack_trap = 1;
                packet->pc = picoquic_packet_context_application;
                packet->ptype = picoquic_packet_1rtt_protected;
                packet->send_time = current_time;
                packet->send_path = NULL;
                packet->sequence_number = pkt_ctx->send_sequence++;
                picoquic_queue_for_retransmit(cnx, path_x, packet, 0, current_time);
                *next_wake_time = current_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                /* Simulate local loss on the Q bit square function. */
                path_x->q_square++;
                cnx->nb_packet_holes_inserted++;
            }
        }
        /* Predict the next hole*/
        pkt_ctx->next_sequence_hole = pkt_ctx->send_sequence + 3 + picoquic_public_uniform_random(((uint64_t)cnx->quic->sequence_hole_pseudo_period)<<cnx->nb_packet_holes_inserted);
    }
}

/*
 * Final steps of encoding and protecting the packet before sending
 */

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx,
    picoquic_packet_t * packet, int ret, 
    size_t length, size_t header_length, size_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, size_t send_buffer_max,
    picoquic_path_t * path_x, uint64_t current_time)
{
    if (length != 0 && length < header_length) {
        length = 0;
    }

    if (ret == 0 && length > 0) {
        packet->length = length;
        
        if (packet->ptype == picoquic_packet_1rtt_protected && cnx->is_multipath_enabled) {
            packet->sequence_number = path_x->pkt_ctx.send_sequence++;
        } else {
            packet->sequence_number = cnx->pkt_ctx[packet->pc].send_sequence++;
        }
        path_x->latest_sent_time = current_time;
        path_x->path_cid_rotated = 0;
        packet->delivered_prior = path_x->delivered_last;
        packet->delivered_time_prior = path_x->delivered_time_last;
        packet->delivered_sent_prior = path_x->delivered_sent_last;
        packet->lost_prior = path_x->total_bytes_lost;
        packet->inflight_prior = path_x->bytes_in_transit;
        packet->delivered_app_limited = (cnx->cnx_state < picoquic_state_ready || path_x->delivered_limited_index != 0);
        if (path_x->bytes_in_transit >= path_x->cwin && cnx->cnx_state == picoquic_state_ready) {
            packet->sent_cwin_limited = 1;
        }

        switch (packet->ptype) {
        case picoquic_packet_version_negotiation:
            /* Packet is not encrypted */
            break;
        case picoquic_packet_initial:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_initial].aead_encrypt, cnx->crypto_context[picoquic_epoch_initial].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_handshake:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt, cnx->crypto_context[picoquic_epoch_handshake].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_retry:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_0rtt].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_0rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_0rtt].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_1rtt_protected:
            /* TODO: if multipath, use 96 bit nonce */
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_1rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_1rtt].pn_enc,
                path_x, current_time);
            break;
        default:
            /* Packet type error. Do nothing at all. */
            length = 0;
            break;
        }

        *send_length = length;

        if (length > 0) {
            packet->checksum_overhead = checksum_overhead;
            picoquic_queue_for_retransmit(cnx, path_x, packet, length, current_time);
            path_x->last_sent_time = current_time;
            path_x->bytes_sent += length;
        } else {
            *send_length = 0;
        }
    }
    else {
        *send_length = 0;
    }
}

/*
 * Returns true if there is nothing to repeat in the retransmission queue
 */
int picoquic_is_pkt_ctx_backlog_empty(picoquic_packet_context_t* pkt_ctx)
{
    int backlog_empty = 1;
    picoquic_packet_t* p = pkt_ctx->pending_first;

    while (p != NULL && backlog_empty == 1) {
        /* check if this is an ACK only packet */
        int ret = 0;
        int frame_is_pure_ack = 0;
        size_t frame_length = 0;
        size_t byte_index = 0; /* Used when parsing the old packet */

        byte_index = p->offset;

        if (!p->is_ack_trap && !p->is_multipath_probe && !p->is_mtu_probe) {
            while (ret == 0 && byte_index < p->length) {
                ret = picoquic_skip_frame(&p->bytes[byte_index],
                    p->length - p->offset, &frame_length, &frame_is_pure_ack);

                if (!frame_is_pure_ack) {
                    backlog_empty = 0;
                    break;
                }
                byte_index += frame_length;
            }
        }

        p = p->packet_next;
    }

    return backlog_empty;
}

int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx)
{
    int backlog_empty = 1;

    if (cnx->cnx_state < picoquic_state_ready) {
        backlog_empty = picoquic_is_pkt_ctx_backlog_empty(&cnx->pkt_ctx[picoquic_packet_context_initial]) &&
            picoquic_is_pkt_ctx_backlog_empty(&cnx->pkt_ctx[picoquic_packet_context_handshake]);
    }

    if (cnx->is_multipath_enabled) {
        for (int i=0; backlog_empty && i < cnx->nb_paths; i++) {
            backlog_empty &= picoquic_is_pkt_ctx_backlog_empty(&cnx->path[i]->pkt_ctx);
        }
    }
    else if (backlog_empty) {
        backlog_empty = picoquic_is_pkt_ctx_backlog_empty(&cnx->pkt_ctx[picoquic_packet_context_application]);
    }

    return backlog_empty;
}

/* Management of preemptive repeats.
 * This function only perform preemptive repeat for packets that contain
 * at least on frame that triggers premptive repeat, such as a stream
 * belonging to a stream for which FIN was sent. If a packet is
 * selected for preemptive repeat, then the function attempts to repeat
 * all frames that are not "pure ack". If all such frames are repeated,
 * the old packet can be marked as "was_preemptively_repeated", so that
 * it will not be repeated if loss is detected. But if not all frames
 * could be repeated, e.g., because of packet size, then the old packet
 * must not be marked as preemptively repeated, because otherwise these
 * non-repeated frames would be lost forever.
 */
static int picoquic_preemptive_retransmit_packet(picoquic_packet_t* old_p,
    picoquic_cnx_t* cnx,
    uint8_t* new_bytes,
    size_t send_buffer_max_minus_checksum,
    size_t* length,
    int * has_data)
{
    /* check if this is an ACK only packet */
    int ret = 0;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;
    size_t byte_index = 0; /* Used when parsing the old packet */
    size_t write_index = 0;
    int is_repeated = 1;
    int do_not_detect_spurious = 0;
    int is_preemptive_needed = 0;
    size_t initial_length = *length;
    *has_data = 0;

    if (!old_p->is_mtu_probe &&
        !old_p->is_ack_trap &&
        !old_p->is_multipath_probe) {
        /* Copy the relevant bytes from one packet to the next */
        byte_index = old_p->offset;

        while (ret == 0 && byte_index < old_p->length) {
            ret = picoquic_skip_frame(&old_p->bytes[byte_index],
                old_p->length - byte_index, &frame_length, &frame_is_pure_ack);

            /* Check whether the data was already acked, which may happen in
             * case of spurious retransmissions */
            if (ret == 0 && frame_is_pure_ack == 0) {
                ret = picoquic_check_frame_needs_repeat(cnx, &old_p->bytes[byte_index],
                    frame_length, old_p->ptype, &frame_is_pure_ack, &do_not_detect_spurious, &is_preemptive_needed);
            }

            /* Prepare retransmission if needed */
            if (ret == 0 && !frame_is_pure_ack) {
                if (PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max) &&
                    picoquic_is_stream_frame_unlimited(&old_p->bytes[byte_index])) {
                    /* If length is not present, check whether needed */
                    if (write_index + frame_length < send_buffer_max_minus_checksum) {
                        size_t pad_needed = send_buffer_max_minus_checksum - write_index - frame_length;
                        memset(&new_bytes[write_index], picoquic_frame_type_padding, pad_needed);
                        *length += pad_needed;
                        write_index += pad_needed;
                    }
                }
                /* copy the frame */
                if (write_index + frame_length <= send_buffer_max_minus_checksum) {
                    memcpy(&new_bytes[write_index], &old_p->bytes[byte_index], frame_length);
                    write_index += frame_length;
                    *length += frame_length;
                    *has_data = 1;
                }
                else {
                    is_repeated = 0;
                }
            }
            byte_index += frame_length;
        }
    }

    if (*has_data) {
        if (!is_preemptive_needed) {
            /* If the packet does not contain any frame requiring preemptive repeat, do not repeat it. */
            *length = initial_length;
            *has_data = 0;
            is_repeated = 0;
        } else if (is_repeated) {
            old_p->was_preemptively_repeated = 1;
        }
    }

    return ret;
}

int picoquic_preemptive_retransmit_in_context(
    picoquic_cnx_t* cnx,
    picoquic_packet_context_t* pkt_ctx,
    uint64_t rtt,
    uint64_t current_time,
    uint64_t* next_wake_time,
    uint8_t* new_bytes,
    size_t send_buffer_max_minus_checksum,
    size_t* length,
    int *has_data,
    int *more_data, 
    int test_only)
{
    /* If there is a single packet context for application frames,
     * the code just has to track the preemptive_repeat_ptr for
     * that context. If there are multiple paths, we need to consider
     * packets from every plausible path.
     */
    int ret = 0;

    /* Check that the connection is still active before adding more preemptive repeats */
    if (cnx->latest_progress_time + rtt < current_time ||
        cnx->latest_receive_time + 2*rtt < current_time) {
        return 0;
    }

    /* Find the first packet that might be repeated */
    if (pkt_ctx->preemptive_repeat_ptr == NULL) {
        pkt_ctx->preemptive_repeat_ptr = pkt_ctx->pending_first;
    }
    /* Skip all packets that are too old to be repeated */
    while (pkt_ctx->preemptive_repeat_ptr != NULL) {
        if (pkt_ctx->preemptive_repeat_ptr->send_time + rtt / 2 >= current_time) {
            break;
        }
        pkt_ctx->preemptive_repeat_ptr = pkt_ctx->preemptive_repeat_ptr->packet_next;
    }
    /* Try to format the repeated packet */
    while (pkt_ctx->preemptive_repeat_ptr != NULL) {
        uint64_t early_delay = (rtt > 8 * PICOQUIC_ACK_DELAY_MAX) ? rtt / 8 : PICOQUIC_ACK_DELAY_MAX;
        uint64_t early_time = pkt_ctx->preemptive_repeat_ptr->send_time + early_delay;

        if (!pkt_ctx->preemptive_repeat_ptr->was_preemptively_repeated) {
            if (early_time > current_time) {
                /* Wait until the next repeat */
                if (*next_wake_time > early_time) {
                    *next_wake_time = early_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
                break;
            }
            if (test_only) {
                *more_data = 1;
                break;
            }
            ret = picoquic_preemptive_retransmit_packet(pkt_ctx->preemptive_repeat_ptr, cnx,
                new_bytes, send_buffer_max_minus_checksum, length, has_data);
            if (ret != 0) {
                break;
            }
        }
        pkt_ctx->preemptive_repeat_ptr = pkt_ctx->preemptive_repeat_ptr->packet_next;
        if (*has_data) {
            cnx->nb_preemptive_repeat++;
            if (pkt_ctx->preemptive_repeat_ptr != NULL) {
                *more_data = 1;
            }
            break;
        }
    }
    return ret;
}

int picoquic_preemptive_retransmit_as_needed(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_packet_context_enum pc,
    uint64_t current_time,
    uint64_t* next_wake_time,
    uint8_t* new_bytes,
    size_t send_buffer_max_minus_checksum,
    size_t* length,
    int* more_data,
    int* is_pure_ack)
{
    /* If there is a single packet context for application frames,
     * the code just has to track the preemptive_repeat_ptr for
     * that context. If there are multiple paths, this gets a bit
     * more complicated, because packets that need to be premptively
     * repeated might be found in many context, and also because some
     * paths may be only used for primary repeats. In that case, we
     * want to try all available packet contexts.
     */
    int ret = 0;
    int has_data = 0;
    picoquic_packet_context_t* pkt_ctx;
    uint64_t rtt = path_x->smoothed_rtt;

    if (pc == picoquic_packet_context_application &&
        cnx->is_multipath_enabled) {
        for (int i = 0; i < cnx->nb_paths; i++) {
            pkt_ctx = &cnx->path[i]->pkt_ctx;
            ret = picoquic_preemptive_retransmit_in_context(
                cnx, pkt_ctx, rtt, current_time, next_wake_time,
                new_bytes, send_buffer_max_minus_checksum, length, &has_data, more_data, is_pure_ack == NULL);
            if (ret != 0 || has_data != 0) {
                break;
            }
        }
    }
    else {
        pkt_ctx = &cnx->pkt_ctx[pc];
        ret = picoquic_preemptive_retransmit_in_context(
            cnx, pkt_ctx, rtt, current_time, next_wake_time,
            new_bytes, send_buffer_max_minus_checksum, length, &has_data, more_data, is_pure_ack == NULL);
    }
    
    if (ret == 0 &&  is_pure_ack != NULL) {
        *is_pure_ack &= !has_data;
    }

    return ret;
}

/* Compute the next logical probe length */
static size_t picoquic_next_mtu_probe_length(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    size_t probe_length;

    if (path_x->send_mtu_max_tried == 0) {
        if (cnx->remote_parameters.max_packet_size > 0) {
            probe_length = cnx->remote_parameters.max_packet_size;

            if (cnx->quic->mtu_max > 0 && (int)probe_length >
                cnx->quic->mtu_max - PICOQUIC_MTU_OVERHEAD((struct sockaddr*)&path_x->peer_addr)) {
                probe_length = cnx->quic->mtu_max - PICOQUIC_MTU_OVERHEAD((struct sockaddr*)&path_x->peer_addr);
            }
            else if (probe_length > PICOQUIC_MAX_PACKET_SIZE) {
                probe_length = PICOQUIC_MAX_PACKET_SIZE;
            }
            if (probe_length < path_x->send_mtu) {
                probe_length = path_x->send_mtu;
            }
        }
        else if (cnx->quic->mtu_max > 0) {
            probe_length = cnx->quic->mtu_max - PICOQUIC_MTU_OVERHEAD((struct sockaddr*)&path_x->peer_addr);
        }
        else {
            probe_length = PICOQUIC_PRACTICAL_MAX_MTU;
        }
    }
    else {
        if (path_x->send_mtu_max_tried > 1500) {
            probe_length = 1500;
        }
        else if (path_x->send_mtu_max_tried > 1400) {
            probe_length = 1400;
        }
        else {
            probe_length = (path_x->send_mtu + path_x->send_mtu_max_tried) / 2;
        }
    }

    return probe_length;
}

/* Decide whether to send an MTU probe */
picoquic_pmtu_discovery_status_enum picoquic_is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = picoquic_pmtu_discovery_not_needed;

    if ((cnx->cnx_state == picoquic_state_ready || 
        cnx->cnx_state == picoquic_state_client_ready_start || 
        cnx->cnx_state == picoquic_state_server_false_start)
        && path_x->mtu_probe_sent == 0 && cnx->pmtud_policy != picoquic_pmtud_blocked) {
        if (path_x->send_mtu_max_tried == 0 || path_x->send_mtu_max_tried > 1400) {
            /* MTU discovery is required if the chances of success are large enough
             * and there are enough packets to send to amortize the discovery cost.
             * Of course we don't know at this stage how much data will be sent 
             * on the connection; we take the amount of data queued as a proxy
             * for that. */
            uint64_t next_probe = picoquic_next_mtu_probe_length(cnx, path_x);
            if (next_probe > path_x->send_mtu) {
                if (cnx->pmtud_policy == picoquic_pmtud_required) {
                    ret = picoquic_pmtu_discovery_required;
                }
                else {
                    uint64_t packets_to_send_before = cnx->nb_bytes_queued / path_x->send_mtu;
                    uint64_t packets_to_send_after = cnx->nb_bytes_queued / next_probe;
                    uint64_t delta = (packets_to_send_before - packets_to_send_after) * 60;
                    if (delta > next_probe) {
                        ret = picoquic_pmtu_discovery_required;
                    }
                    else {
                        if (cnx->pmtud_policy == picoquic_pmtud_basic) {
                            ret = picoquic_pmtu_discovery_optional;
                        }
                        else {
                            ret = picoquic_pmtu_discovery_not_needed;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

/* Prepare an MTU probe packet */
size_t picoquic_prepare_mtu_probe(picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    size_t header_length, size_t checksum_length,
    uint8_t* bytes, size_t bytes_max)
{
    size_t probe_length = picoquic_next_mtu_probe_length(cnx, path_x);
    size_t length = header_length;

    if (probe_length > bytes_max) {
        probe_length = bytes_max;
    }

    bytes[length++] = picoquic_frame_type_ping;
    memset(&bytes[length], 0, probe_length - checksum_length - length);

    return probe_length - checksum_length;
}

/* Prepare the next packet to 0-RTT packet to send in the client initial
 * state, when 0-RTT is available
 */
int picoquic_prepare_packet_0rtt(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    int padding_required, uint64_t * next_wake_time)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_0rtt_protected;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_aead_get_checksum_length(cnx->crypto_context[1].aead_encrypt);
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    int more_data = 0;
    int is_pure_ack = 1;
    int stream_tried_and_failed = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    if (path_x->bytes_in_transit + send_buffer_max > PICOQUIC_DEFAULT_0RTT_WINDOW) {
        if (path_x->bytes_in_transit > PICOQUIC_DEFAULT_0RTT_WINDOW) {
            send_buffer_max = 0;
        }
        else {
            send_buffer_max = (size_t)PICOQUIC_DEFAULT_0RTT_WINDOW - (size_t)path_x->bytes_in_transit;
        }
    }
    bytes_max = bytes + send_buffer_max - checksum_overhead;

    stream = picoquic_find_ready_stream(cnx);
    length = picoquic_predict_packet_header_length(cnx, packet_type, &cnx->pkt_ctx[picoquic_packet_context_application]);
    packet->ptype = picoquic_packet_0rtt_protected;
    packet->offset = length;
    header_length = length;
    packet->pc = picoquic_packet_context_application;
    packet->sequence_number = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    packet->send_time = current_time;
    packet->send_path = path_x;
    packet->checksum_overhead = checksum_overhead;
    bytes_next = bytes + length;


    
    /* Consider sending 0-RTT */
    if ((stream == NULL && cnx->first_misc_frame == NULL && padding_required == 0) || 
        send_buffer_max < PICOQUIC_MIN_SEGMENT_SIZE) {
        length = 0;
    } else {
        /* If present, send misc frame */
        bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
            &more_data, &is_pure_ack, picoquic_packet_context_application);

        /* We assume that if BDP data is associated with the zero RTT ticket, it can be sent */
        /* Encode the bdp frame */
        if (cnx->local_parameters.enable_bdp_frame) {
            bytes_next = picoquic_format_bdp_frame(cnx, bytes_next, bytes_max, path_x, &more_data, &is_pure_ack);
        }

        /* Encode the stream frame, or frames */
        bytes_next = picoquic_format_available_stream_frames(cnx, NULL, bytes_next, bytes_max, UINT64_MAX,
            &more_data, &is_pure_ack, &stream_tried_and_failed, &ret);

        length = bytes_next - bytes;

        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }

        if (stream_tried_and_failed) {
            path_x->last_sender_limited_time = current_time;
        }

        /* Add padding if required */
        if (padding_required) {
            length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        path_x, current_time);

    if (length > 0) {
        /* Accounting of zero rtt packets sent */
        cnx->nb_zero_rtt_sent++;
    }

    /* the reinsertion by wake up time will happen in the calling function */

    return ret;
}

/* Get packet type from epoch */
picoquic_packet_type_enum picoquic_packet_type_from_epoch(int epoch)
{
    picoquic_packet_type_enum ptype;

    switch (epoch) {
    case 0:
        ptype = picoquic_packet_initial;
        break;
    case 1:
        ptype = picoquic_packet_0rtt_protected;
        break;
    case 2:
        ptype = picoquic_packet_handshake;
        break;
    case 3:
        ptype = picoquic_packet_1rtt_protected;
        break;
    default:
        ptype = picoquic_packet_error;
        break;
    }

    return ptype;
}

/* Prepare a required repetition or ack in a previous context */
size_t picoquic_prepare_packet_old_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, picoquic_packet_t* packet, size_t send_buffer_max, uint64_t current_time,
    uint64_t* next_wake_time, size_t* header_length)
{
    picoquic_epoch_enum epoch = (pc == picoquic_packet_context_initial) ? picoquic_epoch_initial :
        (pc == picoquic_packet_context_application) ? picoquic_epoch_0rtt : picoquic_epoch_handshake;
    size_t length = 0;

    /* Safety check: do not attempt to repeat old packets if the crypto
     * context has been deleted */
    if (cnx->crypto_context[epoch].aead_encrypt != NULL) {
        uint8_t* bytes = packet->bytes;
        int more_data = 0;
        size_t checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        uint8_t* bytes_max = bytes + send_buffer_max - checksum_overhead;
        uint8_t* bytes_next;
        size_t this_header_length = 0;
        int is_pure_ack = 0;

        send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
        length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &this_header_length);
        if (length > 0 && (pc == picoquic_packet_context_handshake || cnx->pkt_ctx[picoquic_packet_context_handshake].pending_first == NULL ||
            cnx->cnx_state == picoquic_state_server_init || cnx->cnx_state == picoquic_state_server_handshake)) {
            cnx->initial_repeat_needed = 0;
        }

        if (length == 0 && cnx->ack_ctx[pc].act[0].ack_needed != 0 &&
            pc != picoquic_packet_context_application) {
            packet->ptype =
                (pc == picoquic_packet_context_initial) ? picoquic_packet_initial :
                (pc == picoquic_packet_context_handshake) ? picoquic_packet_handshake :
                picoquic_packet_0rtt_protected;
            length = picoquic_predict_packet_header_length(cnx, packet->ptype, &cnx->pkt_ctx[pc]);
            packet->offset = length;
            this_header_length = length;
            packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
            packet->send_time = current_time;
            packet->send_path = path_x;
        }

        if (length > 0) {
            bytes_next = bytes + length;
            /* If present, send misc frame */
            bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                &more_data, &is_pure_ack, pc);
            if (packet->ptype != picoquic_packet_0rtt_protected) {
                /* Check whether it makes sense to add an ACK at the end of the retransmission */
                bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                    current_time, pc, 0);
            }
            length = bytes_next - bytes;
            packet->length = length;
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
            packet->pc = pc;
            *header_length = this_header_length;
        }
    }

    return length;
}

/* Empty the handshake repeat queues when transitioning to the completely ready state */
void picoquic_implicit_handshake_ack(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t current_time)
{
    picoquic_packet_t* p = cnx->pkt_ctx[pc].pending_first;

    /* Remove packets from the retransmit queue */
    while (p != NULL) {
        picoquic_packet_t* p_next = p->packet_next;
        picoquic_path_t * old_path = p->send_path;

        /* Update the congestion control state for the path, but only for the packets sent
         * before the initial timer. */
        if (old_path != NULL && cnx->congestion_alg != NULL && p->send_time < cnx->start_time + PICOQUIC_INITIAL_RTT) {
            picoquic_per_ack_state_t ack_state = { 0 };
            ack_state.rtt_measurement = old_path->rtt_sample;
            ack_state.nb_bytes_acknowledged = p->length;
            old_path->delivered += p->length;
            ack_state.nb_bytes_delivered_since_packet_sent = old_path->delivered - p->delivered_prior;
            ack_state.is_app_limited = 1;

            cnx->congestion_alg->alg_notify(cnx, old_path,
                picoquic_congestion_notification_acknowledgement,
                &ack_state, current_time);
        }
        /* Update the number of bytes in transit and remove old packet from queue */
        /* The packet will not be placed in the "retransmitted" queue */
        (void)picoquic_dequeue_retransmit_packet(cnx, &cnx->pkt_ctx[pc], p, 1, 0);

        p = p_next;
    }
}

/* Program a migration to the server preferred address if present */
int picoquic_prepare_server_address_migration(picoquic_cnx_t* cnx)
{
    int ret = 0;
    uint64_t transport_error = 0;

    if (cnx->remote_parameters.prefered_address.is_defined) {
        uint64_t unique_path_id = (cnx->is_multipath_enabled) ? 1 : 0;
        int ipv4_received = cnx->remote_parameters.prefered_address.ipv4Port != 0;
        int ipv6_received = cnx->remote_parameters.prefered_address.ipv6Port != 0;

        /* Add the connection ID to the local stash */
        transport_error = picoquic_stash_remote_cnxid(cnx, 0, unique_path_id, 1,
            cnx->remote_parameters.prefered_address.connection_id.id_len,
            cnx->remote_parameters.prefered_address.connection_id.id,
            cnx->remote_parameters.prefered_address.statelessResetToken,
            NULL);
        if (transport_error != 0) {
            ret = picoquic_connection_error(cnx, transport_error, picoquic_frame_type_new_connection_id);
        }
        else if(ipv4_received || ipv6_received) {
            struct sockaddr_storage dest_addr;

            memset(&dest_addr, 0, sizeof(struct sockaddr_storage));

            /* program a migration. */
            if (ipv4_received && cnx->path[0]->peer_addr.ss_family == AF_INET) {
                /* select IPv4 */
                ipv6_received = 0;
            }

            if (ipv6_received) {
                /* configure an IPv6 sockaddr */
                struct sockaddr_in6 * d6 = (struct sockaddr_in6 *)&dest_addr;
                d6->sin6_family = AF_INET6;
                d6->sin6_port = htons(cnx->remote_parameters.prefered_address.ipv6Port);
                memcpy(&d6->sin6_addr, cnx->remote_parameters.prefered_address.ipv6Address, 16);
            }
            else {
                /* configure an IPv4 sockaddr */
                struct sockaddr_in * d4 = (struct sockaddr_in *)&dest_addr;
                d4->sin_family = AF_INET;
                d4->sin_port = htons(cnx->remote_parameters.prefered_address.ipv4Port);
                memcpy(&d4->sin_addr, cnx->remote_parameters.prefered_address.ipv4Address, 4);
            }

            /* Only send a probe if not already using that address
             * and the target address is not using a protected port number
             */
            if (picoquic_compare_addr((struct sockaddr *)&dest_addr, (struct sockaddr *)&cnx->path[0]->peer_addr) != 0 &&
                (cnx->quic->is_port_blocking_disabled || !picoquic_check_addr_blocked((struct sockaddr *)&dest_addr))) {
                struct sockaddr* local_addr = NULL;
                if (cnx->path[0]->local_addr.ss_family != 0 && cnx->path[0]->local_addr.ss_family == dest_addr.ss_family) {
                    local_addr = (struct sockaddr*) & cnx->path[0]->local_addr;
                }

                ret = picoquic_probe_new_path_ex(cnx, (struct sockaddr *)&dest_addr, local_addr, 0,
                    picoquic_get_quic_time(cnx->quic), 1, NULL);
            }
        }
    }

    return ret;
}

/* Prepare the next packet to send when in one of the client initial states */
int picoquic_prepare_packet_client_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time,
    int * is_initial_sent)
{
    int ret = 0;
    int tls_ready = 0;
    size_t checksum_overhead = 16;
    int is_cleartext_mode = 1;
    int retransmit_possible = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    size_t length = 0;
    int is_pure_ack = 1;
    int more_data = 0;
    int epoch = picoquic_epoch_initial;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;

    cnx->initial_validated = 1; /* always validated on client */

    if (cnx->tls_stream[picoquic_epoch_initial].send_queue == NULL) {
        if (cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt != NULL &&
            cnx->tls_stream[picoquic_epoch_0rtt].send_queue != NULL) {
            epoch = picoquic_epoch_0rtt;
            pc = picoquic_packet_context_application;
            packet_type = picoquic_packet_0rtt_protected;
        } else if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL && 
            cnx->tls_stream[picoquic_epoch_0rtt].send_queue == NULL) {
            epoch = picoquic_epoch_handshake;
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
        } 
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header parameters -- depend on connection state */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
        if (cnx->retry_token_length == 0 && cnx->sni != NULL) {
            (void)picoquic_get_token(cnx->quic, cnx->sni, (uint16_t)strlen(cnx->sni),
                NULL, 0, &cnx->retry_token, &cnx->retry_token_length, 1);
        }
        break;
    case picoquic_state_client_init_sent:
    case picoquic_state_client_init_resent:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_renegotiate:
        packet_type = picoquic_packet_initial;
        break;
    case picoquic_state_client_handshake_start:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_almost_ready:
        break;
    default:
        ret = -1;
        break;
    }

    /* If context is handshake, verify first that there is no need for retransmit or ack
     * on initial context */
    int force_handshake_padding = 0;

    if (ret == 0) {
        if (epoch > picoquic_epoch_initial) {
            if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL) {
                if (cnx->ack_ctx[picoquic_packet_context_initial].act[0].ack_needed) {
                    /* Apply some ack delay, because handshake from server arrive in trains */
                    uint64_t ack_delay = cnx->path[0]->smoothed_rtt / 8;
                    uint64_t ack_time;
                    if (ack_delay > PICOQUIC_ACK_DELAY_MAX) {
                        ack_delay = PICOQUIC_ACK_DELAY_MAX;
                    }
                    ack_time = cnx->ack_ctx[picoquic_packet_context_initial].act[0].time_oldest_unack_packet_received + ack_delay;
                    if (ack_time <= current_time) {
                        force_handshake_padding = 1;
                    }
                    else if (ack_time < *next_wake_time) {
                        *next_wake_time = ack_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
                else if (cnx->pkt_ctx[pc].pending_last != NULL) {
                    /* There is a risk of deadlock if the server is doing DDOS mitigation
                     * and does not receive the Handshake sent by the client. If more than RTT has elapsed since
                     * the last handshake packet was sent, force another one to be sent. */
                    uint64_t rto = picoquic_current_retransmit_timer(cnx, cnx->path[0]);
                    uint64_t repeat_time = cnx->pkt_ctx[pc].pending_last->send_time + rto;

                    if (repeat_time <= current_time) {
                        force_handshake_padding = 1;
                        cnx->path[0]->nb_retransmit++;
                        cnx->path[0]->last_loss_event_detected = current_time;
                    }
                    else if (repeat_time < *next_wake_time) {
                        *next_wake_time = repeat_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
            else {
                length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
                    path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
                *is_initial_sent |= (length > 0);
            }
        }
        else {
            /* There is a risk of deadlock if the server is doing DDOS mitigation
             * and does not repeat an initial or handshake packet that was lost. If more than RTT has elapsed since
             * the last initial packet was sent, force another one to be sent. */
            uint64_t rto = picoquic_current_retransmit_timer(cnx, cnx->path[0]);
            uint64_t repeat_time = cnx->path[0]->latest_sent_time + rto;
            if (repeat_time <= current_time) {
                force_handshake_padding = 1;
            } else if (*next_wake_time > repeat_time) {
                *next_wake_time = repeat_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
    }

    if (ret == 0 && epoch > picoquic_epoch_0rtt && length == 0 &&
        cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt != NULL) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_application,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    /* If there is nothing to send in previous context, check this one too */
    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        packet->checksum_overhead = checksum_overhead;
        bytes_max = bytes + send_buffer_max - checksum_overhead;
        packet->pc = pc;

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        if (ret == 0 && retransmit_possible &&
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &header_length)) > 0) {
            /* Check whether it makes sense to add an ACK at the end of the retransmission */
            if (epoch != picoquic_epoch_0rtt && length > header_length) {
                bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc, 0);
                length = bytes_next - bytes;
            } 
            /* document the send time & overhead */
            packet->length = length;
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
            *is_initial_sent = (packet->ptype == picoquic_packet_initial);
        }
        else if (ret == 0 && is_cleartext_mode && tls_ready == 0
            && picoquic_find_first_misc_frame(cnx, pc) == NULL
            && !cnx->ack_ctx[pc].act[0].ack_needed && !force_handshake_padding) {
            /* when in a clear text mode, only send packets if there is
            * actually something to send, or resend. */

            packet->length = 0;
        }
        else if (ret == 0) {
            if (cnx->crypto_context[epoch].aead_encrypt == NULL) {
                packet->length = 0;
            }
            else {
                length = picoquic_predict_packet_header_length(cnx, packet_type, &cnx->pkt_ctx[pc]);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;
                bytes_next = bytes + length;
                bytes_max = bytes + send_buffer_max - checksum_overhead;

                if ((tls_ready == 0 || path_x->cwin <= path_x->bytes_in_transit || cnx->quic->cwin_max <= path_x->bytes_in_transit)
                    && (cnx->cnx_state == picoquic_state_client_almost_ready
                        || picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc, 0) == 0)
                    && picoquic_find_first_misc_frame(cnx, pc) == NULL && !force_handshake_padding) {
                    length = 0;
                }
                else {
                    if (force_handshake_padding) {
                        /* Add PING if handshake is forced */
                        *bytes_next++ = picoquic_frame_type_ping;
                    }
                    if (epoch != picoquic_epoch_0rtt && 
                        (cnx->ack_ctx[pc].act[0].ack_needed ||
                            (force_handshake_padding && picoquic_sack_list_last(&cnx->ack_ctx[pc].sack_list) != UINT64_MAX))) {
                        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc, 0);
                    }

                    /* If present, send misc frame -- but only if for the current packet context */
                    bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                        &more_data, &is_pure_ack, pc);
                    length = bytes_next - bytes;

                    if (ret == 0 && path_x->cwin > path_x->bytes_in_transit && cnx->quic->cwin_max > path_x->bytes_in_transit) {
                        /* Encode the crypto handshake frame */
                        if (tls_ready != 0) {
                            /* Encode the crypto frame */
                            bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[epoch],
                                bytes_next, bytes_max, &more_data, &is_pure_ack);
                            length = bytes_next - bytes;
                        }

                        if (packet_type == picoquic_packet_initial) {
                            *is_initial_sent = 1;
                            if (cnx->crypto_context[1].aead_encrypt == NULL ||
                                cnx->cnx_state == picoquic_state_client_renegotiate ||
                                cnx->original_cnxid.id_len != 0) {
                                /* Pad to minimum packet length. But don't do that if the
                                 * initial packet will be coalesced with 0-RTT packet */
                                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
                            }
                        }
                    }

                    if (length > header_length && epoch == picoquic_epoch_handshake) {
                        cnx->ack_ctx[picoquic_packet_context_initial].act[0].ack_needed = 0;
                    }

                    /* If TLS packets are sent, progress the state */
                    if (ret == 0 && tls_ready != 0 && 
                        cnx->tls_stream[epoch].send_queue == NULL) {
                        switch (cnx->cnx_state) {
                        case picoquic_state_client_init:
                            cnx->cnx_state = picoquic_state_client_init_sent;
                            break;
                        case picoquic_state_client_renegotiate:
                            cnx->cnx_state = picoquic_state_client_init_resent;
                            break;
                        case picoquic_state_client_almost_ready:
                            if (cnx->tls_stream[0].send_queue == NULL &&
                                cnx->tls_stream[1].send_queue == NULL &&
                                cnx->tls_stream[2].send_queue == NULL) {
                                cnx->cnx_state = picoquic_state_client_ready_start;
                                /* Signal the application, because data can now be sent. */
                                if (cnx->callback_fn != NULL) {
                                    if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                                        picoquic_log_app_message(cnx, "Callback almost ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                                        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                                    }
                                }
                            }
                            break;
                        default:
                            break;
                        }
                    }
                }
            }
        }
    }

    if (ret == 0 && length == 0 && cnx->crypto_context[1].aead_encrypt != NULL) {
        ret = picoquic_prepare_packet_0rtt(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length,
                *is_initial_sent, next_wake_time);
    }
    else {
        if (ret == 0 && more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }

        if (ret == 0 && *is_initial_sent) {
            if (packet->ptype == picoquic_packet_initial) {
                if (length > 0 && cnx->crypto_context[1].aead_encrypt == NULL && 
                    (cnx->crypto_context[2].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max ||
                        !picoquic_is_tls_stream_ready(cnx))) {
                    length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
                }
            }
            else if (packet->ptype == picoquic_packet_handshake && length + checksum_overhead < send_buffer_max &&
                (cnx->crypto_context[3].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max)) {
                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
            }
            else if (packet->ptype == picoquic_packet_1rtt_protected) {
                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
            }
        }

        if (length > 0 && packet->ptype == picoquic_packet_handshake && !is_pure_ack) {
            /* Sending an ack eliciting handshake packet terminates the use of the initial context */
            picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
            picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);
        }

        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            send_length, send_buffer, send_buffer_max,
            path_x, current_time);
    }

    return ret;
}

/* Compute the time at which to send the next challenge
 */

uint64_t picoquic_next_challenge_time(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time, unsigned int * is_nat)
{
    /* "Challenge time" holds the time at which the last challenge was set. We
     * use the value to compute an estimate of the RTT */
    uint64_t next_challenge_time = path_x->challenge_time;

    if (path_x->challenge_repeat_count == 0) {
        next_challenge_time = current_time;
    } else {
        if (path_x->challenge_repeat_count >= 2) {
            next_challenge_time += path_x->retransmit_timer << (path_x->challenge_repeat_count-1);
        }
        else {
            next_challenge_time += PICOQUIC_INITIAL_RETRANSMIT_TIMER;
        }
    }

    if (is_nat != NULL) {
        *is_nat = 0;
        if (cnx->is_multipath_enabled && path_x->nat_local_addr.ss_family != AF_UNSPEC)
        {
            uint64_t nat_challenge_time = path_x->nat_challenge_time;
            if (path_x->nat_challenge_repeat_count == 0) {
                nat_challenge_time = current_time;
            }
            else {
                if (path_x->challenge_repeat_count >= 2) {
                    nat_challenge_time += path_x->retransmit_timer << path_x->challenge_repeat_count;
                }
                else {
                    nat_challenge_time += path_x->retransmit_timer;
                }
            }
            if (nat_challenge_time <= current_time && path_x->nat_challenge_repeat_count >= PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* NAT Challenge failed. Resetting the address so we forget about it. */
                picoquic_log_app_message(cnx, "NAT Challenge failed on path %" PRIu64, path_x->unique_path_id);
                path_x->nat_local_addr.ss_family = AF_UNSPEC;
            } else if (nat_challenge_time < next_challenge_time) {
                *is_nat = 1;
                next_challenge_time = nat_challenge_time;
            }
        }
    }

    return next_challenge_time;
}

/* Prepare the next packet to send when in one the server initial states */
int picoquic_prepare_packet_server_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time,
    int* is_initial_sent)
{
    int ret = 0;
    int tls_ready = 0;
    picoquic_epoch_enum epoch = picoquic_epoch_initial;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    size_t checksum_overhead = 8;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    size_t length = 0;
    int more_data = 0;
    int is_pure_ack = 1;

    if (*next_wake_time > cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX) {
        *next_wake_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(path_x != NULL)"
     * but the documentation does not say anything about that for GCC and CLANG */
    if (path_x == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL &&
        cnx->tls_stream[picoquic_epoch_initial].send_queue == NULL) {
        epoch = picoquic_epoch_handshake;
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    if (!cnx->initial_validated &&
        (cnx->initial_data_sent + send_buffer_max) > 3 * cnx->initial_data_received){
        /* Sending more data now would break the amplication limit */
        *send_length = 0;
        return 0;
    }

    /* If context is handshake, verify first that there is no need for retransmit or ack
     * on initial context */
    if (pc == picoquic_packet_context_handshake) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        bytes_max = bytes + send_buffer_max - checksum_overhead;
        tls_ready = (cnx->tls_stream[epoch].send_queue != NULL &&
            cnx->tls_stream[epoch].send_queue->length > cnx->tls_stream[epoch].send_queue->offset);
        length = picoquic_predict_packet_header_length(cnx, packet_type, &cnx->pkt_ctx[pc]);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        packet->pc = pc;
        bytes_next = bytes + length;

        if (((tls_ready || picoquic_find_first_misc_frame(cnx, pc) != NULL)
            && path_x->cwin > path_x->bytes_in_transit && cnx->quic->cwin_max > path_x->bytes_in_transit) 
            || cnx->ack_ctx[pc].act[0].ack_needed) {
            bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc, 0);
            /* Encode misc frames if present */
            bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                &more_data, &is_pure_ack, pc);
            /* Encode the crypto frame if present */
            bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[epoch],
                bytes_next, bytes_max, &more_data, &is_pure_ack);
            length = bytes_next - bytes;
            *is_initial_sent |= (epoch == picoquic_epoch_initial && !is_pure_ack);

            /* progress the state if the epoch data is all sent */
            if (ret == 0 && tls_ready != 0 && cnx->tls_stream[epoch].send_queue == NULL) {
                if (epoch == picoquic_epoch_handshake && picoquic_tls_client_authentication_activated(cnx->quic) == 0) {
                    picoquic_false_start_transition(cnx, current_time);

                    if (cnx->callback_fn != NULL) {
                        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                            picoquic_log_app_message(cnx, "Callback almost ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                        }
                    }
                }
                else {
                    cnx->cnx_state = picoquic_state_server_handshake;
                }
            }
            packet->length = length;
        }
        else if ((length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
            cnx->initial_repeat_needed = 0;
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            bytes_max = bytes + send_buffer_max - checksum_overhead;
            bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc, 0);
            length = bytes_next - bytes;
            packet->length = length;
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        } else {
            length = 0;
            packet->length = 0;
        }
    }

    if (ret == 0 && length == 0 && more_data) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    if (ret == 0 && *is_initial_sent) {
        if (packet->ptype == picoquic_packet_initial) {
            if (length > 0 && cnx->crypto_context[1].aead_encrypt == NULL && 
                (cnx->crypto_context[2].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max ||
                    !picoquic_is_tls_stream_ready(cnx) || cnx->quic->dont_coalesce_init)) {
                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
            }
        }
        else if (packet->ptype == picoquic_packet_handshake && length + checksum_overhead < send_buffer_max &&
            (cnx->crypto_context[3].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max)) {
            length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        path_x, current_time);

    /* Account for data sent during handshake */
    if (!cnx->initial_validated) {
        cnx->initial_data_sent += *send_length;
    }

    return ret;
}

/* Prepare the next packet to send when in one the closing states */
int picoquic_prepare_packet_closing(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_packet_type_enum packet_type = 0;
    size_t checksum_overhead = 8;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    int more_data = 0;
    size_t length = 0;
    int is_pure_ack = 1;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    picoquic_packet_context_t * pkt_ctx;
    picoquic_epoch_enum epoch = picoquic_epoch_1rtt;

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(path_x != NULL)"
     * but the documentation does not say anything about that for GCC and CLANG */
    if (path_x == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_handshake_failure:
        /* TODO: check whether closing can be requested in "initial" mode */
        if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL &&
            picoquic_sack_list_first(&cnx->ack_ctx[picoquic_packet_context_handshake].sack_list) != UINT64_MAX) {
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
            epoch = picoquic_epoch_handshake;
        }
        else {
            pc = picoquic_packet_context_initial;
            packet_type = picoquic_packet_initial;
        }
        break;
    case picoquic_state_handshake_failure_resend:
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
        epoch = picoquic_epoch_handshake;
        break;
    case picoquic_state_disconnecting:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_closing_received:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_closing:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_draining:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_disconnected:
        ret = PICOQUIC_ERROR_DISCONNECTED;
        break;
    default:
        ret = -1;
        break;
    }

    /* At this stage, we don't try to retransmit any old packet, whether in
     * the current context or in previous contexts. */

    if (packet_type == picoquic_packet_1rtt_protected && cnx->is_multipath_enabled) {
        pkt_ctx = &path_x->pkt_ctx;
    }
    else {
        pkt_ctx = &cnx->pkt_ctx[pc];
    }

    checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
    packet->pc = pc;
    bytes_max = bytes + send_buffer_max - checksum_overhead;

    if (ret == 0 && cnx->cnx_state == picoquic_state_closing_received) {
        /* Send a closing frame, move to draining state */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        length = picoquic_predict_packet_header_length(cnx, packet_type, pkt_ctx);
        bytes_next = bytes + length;
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* Send the disconnect frame */
        bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        length = bytes_next - bytes;
        cnx->last_close_sent = current_time;
        cnx->cnx_state = picoquic_state_draining;
        *next_wake_time = exit_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    } else if (ret == 0 && cnx->cnx_state == picoquic_state_closing) {
        /* if more than 3*RTO is elapsed, move to disconnected */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;
        uint64_t next_close_time = cnx->last_close_sent + path_x->smoothed_rtt;

        if (current_time >= exit_time) {
            picoquic_connection_disconnect(cnx);
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        else if (current_time >= next_close_time) {
            uint64_t delta_t = path_x->rtt_min;
            uint64_t next_time = 0;

            if (delta_t * 2 < path_x->retransmit_timer) {
                delta_t = path_x->retransmit_timer / 2;
            }
            /* if more than N packet received, repeat and erase */
            if (cnx->ack_ctx[pc].act[0].ack_needed) {
                length = picoquic_predict_packet_header_length(
                    cnx, packet_type, pkt_ctx);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = pkt_ctx->send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;
                bytes_next = bytes + length;

                /* Resend the disconnect frame */
                if (cnx->local_error == 0) {
                    bytes_next = picoquic_format_application_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                } else {
                    bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }
                length = bytes_next - bytes;
                cnx->ack_ctx[pc].act[0].ack_needed = 0;
                cnx->ack_ctx[pc].act[0].out_of_order_received = 0;
                cnx->last_close_sent = current_time;
            }
            next_time = current_time + delta_t;
            if (next_time > exit_time) {
                next_time = exit_time;
            }

            *next_wake_time = next_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        else {
            if (*next_wake_time > exit_time) {
                *next_wake_time = exit_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
    } else if (ret == 0 && cnx->cnx_state == picoquic_state_draining) {
        /* Nothing is ever sent in the draining state */
        /* if more than 3*RTO is elapsed, move to disconnected */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        if (current_time >= exit_time) {
            picoquic_connection_disconnect(cnx);
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        else {
            *next_wake_time = exit_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        length = 0;
    } else if (ret == 0 && (cnx->cnx_state == picoquic_state_disconnecting || 
        cnx->cnx_state == picoquic_state_handshake_failure || 
        cnx->cnx_state == picoquic_state_handshake_failure_resend)) {

        length = picoquic_predict_packet_header_length(
            cnx, packet_type, pkt_ctx);
        bytes_next = bytes + length;
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* send either app close or connection close, depending on error code */
        uint64_t delta_t = path_x->rtt_min;

        if (2 * delta_t < path_x->retransmit_timer) {
            delta_t = path_x->retransmit_timer / 2;
        }

        /* add a final ack so receiver gets clean state */
        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc, 0);

        /* Send the disconnect frame */
        if (cnx->local_error == 0) {
            bytes_next = picoquic_format_application_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        }
        else {
            bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        }
        length = bytes_next - bytes;

        if (cnx->cnx_state == picoquic_state_handshake_failure) {
            if (pc == picoquic_packet_context_initial &&
                cnx->crypto_context[2].aead_encrypt != NULL) {
                cnx->cnx_state = picoquic_state_handshake_failure_resend;
            }
            else {
                picoquic_connection_disconnect(cnx);
            }
        }
        else if (cnx->cnx_state == picoquic_state_handshake_failure_resend) {
            picoquic_connection_disconnect(cnx);
        }
        else {
            cnx->cnx_state = picoquic_state_closing;
        }
        cnx->latest_progress_time = current_time;
        cnx->last_close_sent = current_time;
        *next_wake_time = current_time + delta_t;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        cnx->ack_ctx[pc].act[0].ack_needed = 0;
    }
    else {
        length = 0;
    }

    if (length > 0 && packet->ptype == picoquic_packet_initial && cnx->client_mode) {
        length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        path_x, current_time);

    return ret;
}

/* Create required ID, register, and format the corresponding connection ID frame */
uint8_t * picoquic_format_new_local_id_as_needed(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t * bytes_max,
    uint64_t current_time, uint64_t * next_wake_time, int * more_data, int * is_pure_ack)
{
    int no_space_left = 0;
    picoquic_local_cnxid_list_t* local_cnxid_list = cnx->first_local_cnxid_list;
    if (cnx->is_multipath_enabled) {
        /* If the number of local list is lower than the max number of paths, 
        * update that number and queue a MAX PATH ID frame.
         */
        uint64_t new_max_path_id = cnx->next_path_id_in_lists +
            cnx->local_parameters.initial_max_path_id -
            cnx->nb_local_cnxid_lists;
        if (cnx->max_path_id_local < new_max_path_id) {
            uint8_t * bytes_next = picoquic_format_max_path_id_frame(bytes, bytes_max, new_max_path_id, more_data);
            if (bytes_next == bytes) {
                no_space_left = 1;
            }
            else {
                bytes = bytes_next;
                cnx->max_path_id_local = new_max_path_id;
            }
        }
        /* If the number of local lists is lower than the max number of paths,
         * create more. The code assume that path[0] is created during handshake. */
        while (!no_space_left && cnx->nb_local_cnxid_lists <= cnx->local_parameters.initial_max_path_id &&
            cnx->next_path_id_in_lists <= cnx->max_path_id_remote) {
            (void) picoquic_find_or_create_local_cnxid_list(cnx, cnx->next_path_id_in_lists, 1);
        }
    }

    while (local_cnxid_list != NULL && !no_space_left) {
        /* Check whether time has comed to obsolete local CID */
        picoquic_check_local_cnxid_ttl(cnx, local_cnxid_list, current_time, next_wake_time);

        /* Push new CID if needed */
        while (
            local_cnxid_list->nb_local_cnxid < ((int)(cnx->remote_parameters.active_connection_id_limit) + local_cnxid_list->nb_local_cnxid_expired) &&
            local_cnxid_list->nb_local_cnxid <= (PICOQUIC_NB_PATH_TARGET + local_cnxid_list->nb_local_cnxid_expired)) {
            uint8_t* bytes0 = bytes;
            picoquic_local_cnxid_t* l_cid = picoquic_create_local_cnxid(cnx, local_cnxid_list->unique_path_id, NULL, current_time);

            if (l_cid == NULL) {
                /* OOPS, no memory left */
                no_space_left = 1;
                break;
            }
            else {
                bytes = picoquic_format_new_connection_id_frame(cnx, local_cnxid_list, bytes, bytes_max, more_data, is_pure_ack, l_cid);

                if (bytes == bytes0) {
                    no_space_left = 1;
                    /* Oops. Try again next time. */
                    picoquic_delete_local_cnxid(cnx, l_cid);
                    local_cnxid_list->local_cnxid_sequence_next--;
                    break;
                }
            }
        }
        local_cnxid_list = local_cnxid_list->next_list;
    }
    return bytes;
}

picoquic_local_cnxid_list_t* picoquic_find_or_create_local_cnxid_list(picoquic_cnx_t* cnx, uint64_t unique_path_id, int do_create);
picoquic_local_cnxid_t* picoquic_create_local_cnxid(picoquic_cnx_t* cnx,
    uint64_t unique_path_id, picoquic_connection_id_t* suggested_value, uint64_t current_time);

void picoquic_false_start_transition(picoquic_cnx_t* cnx, uint64_t current_time)
{
    /* Transition to false start state. */
    cnx->cnx_state = picoquic_state_server_false_start;

    /* On a server that does address validation, send a NEW TOKEN frame */
    if (!cnx->client_mode && (cnx->quic->check_token || cnx->quic->provide_token)) {
        uint8_t token_buffer[256];
        size_t token_size;
        picoquic_connection_id_t n_cid = picoquic_null_connection_id;

        if (picoquic_prepare_retry_token(cnx->quic, (struct sockaddr*) & cnx->path[0]->peer_addr,
            current_time + PICOQUIC_TOKEN_DELAY_LONG, &n_cid, &n_cid, 0,
            token_buffer, sizeof(token_buffer), &token_size) == 0) {
            if (picoquic_queue_new_token_frame(cnx, token_buffer, token_size) != 0) {
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_new_token);
            }
        }
    }
}

void picoquic_client_almost_ready_transition(picoquic_cnx_t* cnx)
{
    cnx->cnx_state = picoquic_state_client_almost_ready;
    /* If client, make sure that 0-RTT packets are in correct context */
    if (cnx->is_multipath_enabled) {
        picoquic_packet_context_t* o_pkt_ctx = &cnx->pkt_ctx[0];
        picoquic_packet_context_t* n_pkt_ctx = &cnx->path[0]->pkt_ctx;

        *n_pkt_ctx = *o_pkt_ctx;
        picoquic_init_packet_ctx(cnx, o_pkt_ctx, picoquic_packet_context_application);
    }
}

void picoquic_ready_state_transition(picoquic_cnx_t* cnx, uint64_t current_time)
{
    /* Transition to server ready state.
     * The handshake is complete, all the handshake packets are implicitly acknowledged */
    cnx->cnx_state = picoquic_state_ready;
    cnx->is_handshake_finished = 1;
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_handshake, current_time);

    (void)picoquic_register_net_secret(cnx);
    if (!cnx->quic->use_predictable_random) {
        picoquic_public_random_seed(cnx->quic);
    }

    if (!cnx->client_mode) {
        (void)picoquic_queue_handshake_done_frame(cnx);
    }

    if (cnx->is_half_open){
        if (cnx->quic->current_number_half_open > 0) {
            cnx->quic->current_number_half_open--;
        }
        cnx->is_half_open = 0;
        if (cnx->quic->current_number_half_open < cnx->quic->max_half_open_before_retry) {
            cnx->quic->check_token = cnx->quic->force_check_token;
        }
    }

    /* Remove handshake and initial keys if they are still around */
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_0rtt]);
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_handshake]);

    /* Remove the frames queued in initial and handshake contexts */
    picoquic_purge_misc_frames_after_ready(cnx);

    /* Trim the memory buffers allocated during handshake */
    picoquic_tlscontext_trim_after_handshake(cnx);

    /* Set the confidentiality limit if not already set */
    if (cnx->crypto_epoch_length_max == 0) {
        cnx->crypto_epoch_length_max = 
            picoquic_aead_confidentiality_limit(cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt);
    }

    /* Start migration to server preferred address if present */
    if (cnx->client_mode) {
        (void)picoquic_prepare_server_address_migration(cnx);
    }

    /* Notify the application */
    if (cnx->callback_fn != NULL) {
        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_ready, cnx->callback_ctx, NULL) != 0) {
            picoquic_log_app_message(cnx, "Callback ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }
    }

    /* Ask for ACK frequency update, or initialize variables if not available */
    if (cnx->is_ack_frequency_negotiated) {
        cnx->is_ack_frequency_updated = 1;
    }
    else {
        picoquic_compute_ack_gap_and_delay(cnx, cnx->path[0]->rtt_min, PICOQUIC_ACK_DELAY_MIN,
            cnx->path[0]->receive_rate_max, &cnx->ack_gap_remote, &cnx->ack_delay_remote);

        /* Keep track of statistics on ACK parameters */
        if (cnx->ack_gap_remote > cnx->max_ack_gap_remote) {
            cnx->max_ack_gap_remote = cnx->ack_gap_remote;
        }
        if (cnx->ack_delay_remote > cnx->max_ack_delay_remote) {
            cnx->max_ack_delay_remote = cnx->ack_delay_remote;
        }
        else if (cnx->ack_delay_remote < cnx->min_ack_delay_remote) {
            cnx->min_ack_delay_remote = cnx->ack_delay_remote;
        }
    }

    /* Perform a check of the PN decryption key, for sanity */
    picoquic_log_pn_dec_trial(cnx);
}

uint8_t * picoquic_prepare_path_challenge_frames(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_context_enum pc, int is_nominal_ack_path,
    uint8_t * bytes_next, uint8_t * bytes_max, 
    int * more_data, int* is_pure_ack, int* is_challenge_padding_needed,
    uint64_t current_time, uint64_t * next_wake_time)
{
    if (path_x->challenge_verified == 0 && path_x->challenge_failed == 0) {
        unsigned int is_nat = 0;
        uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, path_x, current_time, &is_nat);

        if (next_challenge_time <= current_time) {
            int ack_needed = cnx->ack_ctx[pc].act[0].ack_needed;
            uint8_t* bytes_challenge = bytes_next;
            if (is_nat) {
                /* Format a NAT challenge, or at least try. */
                bytes_next = picoquic_format_path_challenge_frame(bytes_next, bytes_max, more_data, is_pure_ack,
                    path_x->nat_challenge[path_x->nat_challenge_repeat_count]);
                if (bytes_next > bytes_challenge) {
                    path_x->nat_challenge_time = current_time;
                    path_x->nat_challenge_repeat_count++;
                    *is_challenge_padding_needed = 1;
                }
            }
            else if (path_x->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* When blocked, repeat the path challenge or wait */

                bytes_next = picoquic_format_path_challenge_frame(bytes_next, bytes_max, more_data, is_pure_ack,
                    path_x->challenge[path_x->challenge_repeat_count]);
                if (bytes_next > bytes_challenge) {
                    path_x->challenge_time = current_time;
                    path_x->challenge_repeat_count++;
                    if (path_x->is_nat_challenge == 0){
                        if (cnx->client_mode || ((path_x->bytes_sent + PICOQUIC_ENFORCED_INITIAL_MTU) <= path_x->received)) {
                            *is_challenge_padding_needed = 1;
                        }
                        else {
                            /* Sending a full size packet would defeat the amplification limits, so we take
                             * advantage of the escape clause in RFC 9000, "An endpoint MUST expand datagrams
                             * that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum
                             * datagram size of 1200 bytes, unless the anti-amplification limit for the path
                             * does not permit sending a datagram of this size."
                             */
                            *is_challenge_padding_needed = 0;
                        }
                    }
                    else {
                        /* never pad the packets sent in response to NAT rebinding. */
                        *is_challenge_padding_needed = 0;
                    }
                }

                /* add an ACK just to be nice */
                if (ack_needed && is_nominal_ack_path) {
                    bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, more_data,
                        current_time, pc, 1);
                }
                /* Reset the next challenge time to match the new challenge count */
                next_challenge_time = picoquic_next_challenge_time(cnx, path_x, current_time, &is_nat);
                if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
            else {
                if (path_x == cnx->path[0]) {
                    /* Try to find an alternate path */
                    for (int i = 1; i < cnx->nb_paths; i++) {
                        if (cnx->path[i]->challenge_failed == 0) {
                            cnx->path[0] = cnx->path[i];
                            cnx->path[i] = path_x;
                            break;
                        }
                    }
                }

                if (path_x == cnx->path[0]) {
                    DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                    picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, disconnect");
                    cnx->local_error = PICOQUIC_ERROR_REPEAT_TIMEOUT;
                    picoquic_connection_disconnect(cnx);
                }
                else {
                    DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                    picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, abandon path");
                    path_x->challenge_failed = 1;
                    cnx->path_demotion_needed = 1;
                }
            }
        }
        else {
            if (next_challenge_time < *next_wake_time) {
                *next_wake_time = next_challenge_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
    }

    if (path_x->response_required) {
        uint8_t* bytes_response = bytes_next;
        if ((bytes_next = picoquic_format_path_response_frame(bytes_response, bytes_max,
            more_data, is_pure_ack, path_x->challenge_response)) > bytes_response) {
            path_x->response_required = 0;
            *is_challenge_padding_needed |= cnx->client_mode || ((path_x->bytes_sent + PICOQUIC_ENFORCED_INITIAL_MTU) <= path_x->received);
        }
    }

    return bytes_next;
}

/* sending of datagrams */
static uint8_t* picoquic_prepare_datagram_ready(picoquic_cnx_t* cnx, picoquic_path_t * path_x, uint8_t* bytes_next, uint8_t* bytes_max,
    int* more_data, int* is_pure_ack, int* datagram_tried_and_failed, int* datagram_sent, int * ret)
{
    uint8_t* bytes0 = bytes_next;

    if (cnx->first_datagram != NULL) {
        bytes_next = picoquic_format_first_datagram_frame(cnx, bytes_next, bytes_max, more_data, is_pure_ack);
        *more_data |= (cnx->first_datagram != NULL);
    }
    else {
        while (cnx->is_datagram_ready || path_x->is_datagram_ready) {
            uint8_t* dg_start = bytes_next;
            bytes_next = picoquic_format_ready_datagram_frame(cnx, path_x, bytes_next, bytes_max,
                more_data, is_pure_ack, ret);
            if (bytes_next == NULL || bytes_next == dg_start) {
                break;
            }
        }
    }
    *datagram_tried_and_failed = (bytes_next == bytes0);
    *datagram_sent = !*datagram_tried_and_failed;

    return bytes_next;
}


/*
* Sending Datagrams and Stream Packets per priority.
* 
* The API allows setting a priority for a stream or for the datagrams.
* We need to schedule frames according to these priorities. For "new"
* stream data, this is managed by the stream selection algorithm which
* selects the highest priority stream available, while also managing
* whether that priority level implement a FIFO or round robin logic.
* Retransmitting packets are scheduled according to the priority of
* the stream to which they belong.
* 
* The API manages several flags.
*
* The "no_data_to_send" is set when there
* was nothing to send. It is used to decide it is OK to send
* redundancies, e.g., repeats of old packets.
* 
* The "more data" flag is set when there is more data queued than
* could be sent. It should be set if either of these conditions
* is true:
* 
* - There are still datagrams waiting to be sent
* - The repeat packet queue is not empty
* - There is still data waiting to be sent
* 
* The "datagram_conflicts_count" counts how many times sending data
* is skipped because datagrams were sent instead. It is reset to
* zero each time the application sends data.
* 
* There is some complexity in managing these flags, because we
* are going to loop through several priorities. For example, if
* a datagram is sent with P1 and a P1 data stream cannot be sent,
* this is a conflict. But if a datagram is sent with P1 and a P2
* data stream cannot be sent, this is not a conflict. The rule is,
* detect a conflict only in the first round. "No data to send" means 
* no data at any priority. That too can be assessed at the first
* round.
* 
* Yet another level of complexity comes for the possibility for
* the application to renege on a sending promise -- for example,
* set the datagram ready flag, but then do not actually send data,
* maybe because the buffer is too small.
*/

static uint8_t* picoquic_prepare_stream_and_datagrams(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint8_t* bytes_next, uint8_t* bytes_max,
    uint64_t max_priority_allowed, uint64_t current_time,
    int* more_data, int* is_pure_ack, int* no_data_to_send, int* ret)
{
    int datagram_sent = 0;
    int datagram_tried_and_failed = 0;
    int stream_tried_and_failed = 0;
    int more_data_this_round = 0;
    int is_first_round = 1;

    while (bytes_next + 8 < bytes_max && *ret == 0) {
        /* Find the highest priority level for which there is something to send, then
        * format the frames to send at that level. Repeat in a loop until the
        * packet is full or there is nothing more to send. */
        uint64_t datagram_present = cnx->first_datagram != NULL || cnx->is_datagram_ready || path_x->is_datagram_ready;
        picoquic_stream_head_t* first_stream = picoquic_find_ready_stream_path(cnx,
            (cnx->is_multipath_enabled) ? path_x : NULL);
        picoquic_packet_t* first_repeat = picoquic_first_data_repeat_packet(cnx);
        uint64_t current_priority = UINT64_MAX;
        uint64_t stream_priority = UINT64_MAX;
        uint8_t* bytes_before_iteration = bytes_next;
        int something_sent = 0;
        int conflict_found = 0;

        more_data_this_round = 0;

        int datagram_first = (cnx->datagram_conflicts_max >= cnx->datagram_conflicts_count);
        if (datagram_present) {
            current_priority = cnx->datagram_priority;
        }
        if (first_stream != NULL) {
            stream_priority = first_stream->stream_priority;
        }
        if (first_repeat != NULL && first_repeat->data_repeat_priority < stream_priority) {
            stream_priority = first_repeat->data_repeat_priority;
        }
        if (stream_priority < current_priority) {
            current_priority = stream_priority;
        }

        if (current_priority == UINT64_MAX || current_priority >= max_priority_allowed) {
            /* Nothing to send! */
            if (is_first_round) {
                *no_data_to_send = 1;
            }
            break;
        }

        if (datagram_present &&
            cnx->datagram_priority == current_priority &&
            (cnx->datagram_priority < stream_priority || datagram_first)) {
            bytes_next = picoquic_prepare_datagram_ready(cnx, path_x, bytes_next, bytes_max,
                &more_data_this_round, is_pure_ack, &datagram_tried_and_failed, &datagram_sent, ret);
            something_sent = datagram_sent;
        }

        if (first_repeat != NULL && first_repeat->data_repeat_priority == current_priority) {
            uint8_t* bytes_first = bytes_next;
            if (bytes_next + 8 < bytes_max) {
                bytes_next = picoquic_copy_stream_frames_for_retransmit(cnx, bytes_next, bytes_max,
                    UINT64_MAX, &more_data_this_round, is_pure_ack);
                if (bytes_next > bytes_first) {
                    cnx->datagram_conflicts_count = 0;
                    something_sent = 1;
                }
            }
            else {
                more_data_this_round |= 1;
                conflict_found = 1;
            }
        }

        if (first_stream != NULL && first_stream->stream_priority == current_priority) {
            /* Encode the stream frame, or frames */
            uint8_t* bytes_first = bytes_next;
            if (bytes_next + 8 < bytes_max) {
                bytes_next = picoquic_format_available_stream_frames(cnx, path_x, bytes_next, bytes_max, UINT64_MAX,
                    &more_data_this_round, is_pure_ack, &stream_tried_and_failed, ret);
                if (bytes_next > bytes_first) {
                    cnx->datagram_conflicts_count = 0;
                    something_sent = 1;
                }
            }
            else {
                more_data_this_round |= 1;
                conflict_found = 1;
            }
        }

        if (datagram_sent && conflict_found) {
            cnx->datagram_conflicts_count += 1;
        }

        if (datagram_present &&
            cnx->datagram_priority == current_priority &&
            cnx->datagram_priority <= stream_priority &&
            !datagram_first) {
            bytes_next = picoquic_prepare_datagram_ready(cnx, path_x, bytes_next, bytes_max,
                more_data, is_pure_ack, &datagram_tried_and_failed, &datagram_sent, ret);
            something_sent = datagram_sent;
        }

        if (current_priority < cnx->priority_limit_for_bypass && bytes_next > bytes_before_iteration) {
            picoquic_update_pacing_data_after_send(&cnx->priority_bypass_pacing, bytes_next - bytes_before_iteration,
                cnx->path[0]->send_mtu, current_time);
        }

        if (is_first_round) {
            *no_data_to_send = ((first_stream == NULL && first_repeat == NULL) || stream_tried_and_failed) &&
                (!datagram_present || datagram_tried_and_failed);
        }
        is_first_round = 0;
        if (!something_sent) {
            break;
        }
    }
    *more_data |= more_data_this_round;

    return bytes_next;
}

/* Prepare the next packet to send when in one the ready states 
 * Lots of the same code as in the "ready" case, but we deal here with extra
 * complexity because the handshake is not finished.
 */
int picoquic_prepare_packet_almost_ready(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time,
    int* is_initial_sent)
{
    int ret = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int tls_ready = 0;
    int is_pure_ack = 1;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    uint8_t* bytes_max = bytes + send_buffer_min_max - checksum_overhead;
    uint8_t* bytes_next = NULL;
    int more_data = 0;
    int no_data_to_send = 0;
    int is_challenge_padding_needed = 0;

    /* Perform amplification prevention check */
    if (!cnx->initial_validated &&
        (cnx->initial_data_sent + send_buffer_min_max) > 3 * cnx->initial_data_received) {
        *send_length = 0;
        return 0;
    }

    /* Verify first that there is no need for retransmit or ack
     * on initial or handshake context. */
    if (path_x->p_local_cnxid != NULL) {
        if (cnx->crypto_context[picoquic_epoch_initial].aead_encrypt != NULL) {
            length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
                path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);
        }
        else {
            length = 0;
        }

        if (length == 0) {
            length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
                path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);
            if (length == 0 && (*is_initial_sent == 1) && cnx->cnx_state == picoquic_state_server_false_start) {
                /* Add a simple Handshake Ping to work around bugs in some implementations */
                packet->ptype = picoquic_packet_handshake;
                length = picoquic_predict_packet_header_length(cnx, packet->ptype, &cnx->pkt_ctx[picoquic_packet_context_handshake]);
                header_length = length;
                packet->offset = length;
                packet->sequence_number = cnx->pkt_ctx[picoquic_packet_context_handshake].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;
                packet->bytes[length] = picoquic_frame_type_ping;
                length++;
                checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
                packet->checksum_overhead = checksum_overhead;
                packet->pc = picoquic_packet_context_handshake;
                is_pure_ack = 0;
                *is_initial_sent += 1;
            }
            if (length > 0) {
                checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
                bytes_max = bytes + send_buffer_min_max - checksum_overhead;
            }
        }
        else {
            checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_initial);
            bytes_max = bytes + send_buffer_min_max - checksum_overhead;

            *is_initial_sent = 1;
        }

        if (length > 0) {
            cnx->initial_repeat_needed = 0;

            if (cnx->client_mode && *is_initial_sent && send_buffer_min_max < length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE) {
                length = picoquic_pad_to_target_length(packet->bytes, length, send_buffer_min_max - checksum_overhead);
            }
        }
    }

    if (length == 0) {
        picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[pc];
        if (cnx->is_multipath_enabled) {
            pkt_ctx = &path_x->pkt_ctx;
        }

        tls_ready = picoquic_is_tls_stream_ready(cnx);
        packet->pc = pc;
        length = picoquic_predict_packet_header_length(
            cnx, packet_type, pkt_ctx);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        bytes_next = bytes + length;

        bytes_next = picoquic_prepare_path_challenge_frames(cnx, path_x,
            pc, 1 /* is_nominal_ack_path */,
            bytes_next, bytes_max,
            &more_data, &is_pure_ack, &is_challenge_padding_needed,
            current_time, next_wake_time);

        length = bytes_next - bytes;

        if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {
            /* There are no frames yet that would be exempt from pacing control, but if there
             * was they should be sent here. */

            if (picoquic_is_sending_authorized_by_pacing(cnx, path_x, current_time, next_wake_time)) {
                /* There should not be any retransmission at the server if not ready.
                 * At the client, it mostly makes sense to retransmit zero_rtt data, if lost,
                 * but other data might be lost too if the client lingers in that state for
                 * several RTT.
                 */
                if (length <= header_length && cnx->client_mode &&
                    picoquic_find_first_misc_frame(cnx, pc) == NULL &&
                    (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet,
                        send_buffer_min_max, &header_length)) > 0) {
                    /* Check whether it makes sense to add an ACK at the end of the retransmission */
                    /* Testing header length for defense in depth -- avoid creating new packet if
                     * picoquic_retransmit_needed erroneously returns length <= header_length */
                    if (bytes + length + 256 < bytes_max && length > header_length) {
                        /* Don't do that if it risks mixing clear text and encrypted ack */
                        bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data,
                            current_time, pc, 0);
                        length = bytes_next - bytes;
                    }
                    /* document the send time & overhead */
                    is_pure_ack = 0;
                    packet->send_time = current_time;
                    packet->checksum_overhead = checksum_overhead;
                }

                /* Send here the frames that are not exempt from the pacing control,
                 * but are exempt for congestion control */
                if (picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc, 0)) {
                    bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                        current_time, pc, 0);
                }

                length = bytes_next - bytes;
                if (path_x->cwin < path_x->bytes_in_transit) {
                    picoquic_per_ack_state_t ack_state = { 0 };
                    cnx->cwin_blocked = 1;
                    path_x->last_cwin_blocked_time = current_time;
                    if (cnx->congestion_alg != NULL) {
                        cnx->congestion_alg->alg_notify(cnx, path_x,
                            picoquic_congestion_notification_cwin_blocked,
                            &ack_state, current_time);
                    }
                }
                else {
                    /* Send here the frames that are subject to both congestion and pacing control.
                     * this includes the PMTU probes.
                     * Check whether PMTU discovery is required. The call will return
                     * three values: not needed at all, optional, or required.
                     * If required, PMTU discovery takes priority over sending stream data.
                     */
                    picoquic_pmtu_discovery_status_enum pmtu_discovery_needed = picoquic_is_mtu_probe_needed(cnx, path_x);

                    /* if present, send tls data */
                    if (tls_ready) {
                        bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[picoquic_epoch_1rtt],
                            bytes_next, bytes_max, &more_data, &is_pure_ack);
                    }


                    if (pc != picoquic_packet_context_application) {
                        bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                            &more_data, &is_pure_ack, pc);
                        length = bytes_next - bytes;
                    }
                    else {
                        length = bytes_next - bytes;
                        if (length > header_length || pmtu_discovery_needed != picoquic_pmtu_discovery_required ||
                            send_buffer_max <= path_x->send_mtu) {
                            /* No need or no way to do pmtu discovery */
                            /* If present, send misc frame */
                            bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                                &more_data, &is_pure_ack, pc);

                            if (cnx->is_address_discovery_provider) {
                                /* If a new address was learned, prepare an observed address frame */
                                bytes_next = picoquic_prepare_observed_address_frame(bytes_next, bytes_max,
                                    path_x, current_time, next_wake_time, &more_data, &is_pure_ack);
                            }

                            /* If there are not enough published CID, create and advertise */
                            if (ret == 0) {
                                bytes_next = picoquic_format_new_local_id_as_needed(cnx, bytes_next, bytes_max,
                                    current_time, next_wake_time, &more_data, &is_pure_ack);
                            }
                            if (cnx->is_ack_frequency_updated && cnx->is_ack_frequency_negotiated) {
                                bytes_next = picoquic_format_ack_frequency_frame(cnx, bytes_next, bytes_max, &more_data);
                            }
                            if (ret == 0) {
                                bytes_next = picoquic_prepare_stream_and_datagrams(cnx, path_x, bytes_next, bytes_max,
                                    UINT64_MAX, current_time,
                                    &more_data, &is_pure_ack, &no_data_to_send, &ret);
                            }
                            /* TODO: replace this by posting of frame when CWIN estimated */
                            /* Send bdp frames if there are no stream frames to send
                             * and if client wishes to receive bdp frames */
                            if (!cnx->client_mode && cnx->send_receive_bdp_frame) {
                                bytes_next = picoquic_format_bdp_frame(cnx, bytes_next, bytes_max, path_x, &more_data, &is_pure_ack);
                            }

                            length = bytes_next - bytes;
                            if (length <= header_length) {
                                /* Mark the bandwidth estimation as application limited */
                                path_x->delivered_limited_index = path_x->delivered;
                                /* Notify the peer if something is blocked */
                                bytes_next = picoquic_format_blocked_frames(cnx, &bytes[length], bytes_max, &more_data, &is_pure_ack);
                                length = bytes_next - bytes;
                            }

                            if (no_data_to_send) {
                                path_x->last_sender_limited_time = current_time;
                            }
                        } /* end of PMTU not required */

                        if (ret == 0 && length <= header_length
                            && path_x->cwin > path_x->bytes_in_transit && cnx->quic->cwin_max > path_x->bytes_in_transit
                            && pmtu_discovery_needed != picoquic_pmtu_discovery_not_needed) {
                            if (send_buffer_max > path_x->send_mtu) {
                                /* Since there is no data to send, this is an opportunity to send an MTU probe */
                                length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes, send_buffer_max);
                                packet->length = length;
                                packet->send_path = path_x;
                                packet->is_mtu_probe = 1;
                                path_x->mtu_probe_sent = 1;
                                is_pure_ack = 0;
                            }
                            else if (cnx->is_sending_large_buffer) {
                                /* Should attempt PMTU discovery at next opportunity */
                                *next_wake_time = current_time;
                                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                            }
                        }
                    }
                } /* end of congestion blocked */
            } /* end of CC */
        } /* End of pacing */
        if (length <= header_length) {
            length = 0;
        }

        if (cnx->cnx_state != picoquic_state_disconnected) {
            /* If necessary, encode and send the keep alive packet!
             * We only send keep alive packets when no other data is sent!
             */
            if (is_pure_ack == 0)
            {
                cnx->latest_progress_time = current_time;
            }
            else if (cnx->keep_alive_interval != 0) {
                if (cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                    length = picoquic_predict_packet_header_length(
                        cnx, packet_type, pkt_ctx);
                    packet->ptype = packet_type;
                    packet->pc = pc;
                    packet->offset = length;
                    header_length = length;
                    packet->sequence_number = pkt_ctx->send_sequence;
                    packet->send_path = path_x;
                    packet->send_time = current_time;
                    bytes[length++] = picoquic_frame_type_ping;
                    bytes[length++] = 0;
                    cnx->latest_progress_time = current_time;
                }
                else if (cnx->latest_progress_time + cnx->keep_alive_interval < *next_wake_time) {
                    *next_wake_time = cnx->latest_progress_time + cnx->keep_alive_interval;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }
    }

    if (ret == 0 && length > header_length) {
        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            ret = 0;
        }

        /* Ensure that all packets are properly padded before being sent. */

        if ((*is_initial_sent && (packet->ptype != picoquic_packet_initial || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_min_max || cnx->quic->dont_coalesce_init)) ||
            (is_challenge_padding_needed && length < PICOQUIC_ENFORCED_INITIAL_MTU) ){
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
        else {
            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        path_x, current_time);

    if (*send_length > 0) {
        /* Account for data sent during handshake */
        if (!cnx->initial_validated) {
            cnx->initial_data_sent += *send_length;
        }
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (picoquic_cnx_is_still_logging(cnx)) {
            picoquic_log_cc_dump(cnx, current_time);
        }
    }

    return ret;
}

/*  Prepare the next packet to send when in the ready state */
int picoquic_prepare_packet_ready(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time,
    int* is_initial_sent)
{
    int ret = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int is_pure_ack = 1;
    size_t header_length = 0;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max = bytes + send_buffer_min_max - checksum_overhead;
    uint8_t* bytes_next;
    int more_data = 0;
    int ack_sent = 0;
    int is_challenge_padding_needed = 0;
    int is_nominal_ack_path = (cnx->is_multipath_enabled) ?
        (path_x->is_nominal_ack_path || cnx->nb_paths == 1) : path_x == cnx->path[0];

    picoquic_packet_context_t* pkt_ctx = (cnx->is_multipath_enabled) ?
        &path_x->pkt_ctx :
        &cnx->pkt_ctx[picoquic_packet_context_application];

    /* Check whether to insert a hole in the sequence of packets */
    if (pkt_ctx->send_sequence >= pkt_ctx->next_sequence_hole) {
        picoquic_insert_hole_in_send_sequence_if_needed(cnx, path_x, pkt_ctx, current_time, next_wake_time);
    }

    packet->pc = picoquic_packet_context_application;

    /* If there was no packet sent on this path for a long time, rotate the
     * CID prior to sending a new packet. The point is to make it harder for
     * casual observers to track traffic, especially across NAT resets.
     * Long time is defined by either a 5 second refresh delay or 3 RTTs,
     * whichever is longer.
     */
    
    if (cnx->client_mode &&
        path_x->challenge_verified &&
        !path_x->path_cid_rotated &&
        path_x->latest_sent_time + PICOQUIC_CID_REFRESH_DELAY < current_time &&
        path_x->latest_sent_time + 3*path_x->rtt_min < current_time)
    {
        /* Ignore renewal failure mode, since this is an optional feature */
        (void)picoquic_renew_path_connection_id(cnx, path_x);
        path_x->path_cid_rotated = 1;
    }

    /* If the number of packets sent is larger that the max length of
     * a crypto epoch, prepare a key rotation */
    if ((cnx->nb_packets_sent - cnx->crypto_epoch_sequence >
        cnx->crypto_epoch_length_max) &&
        current_time > cnx->crypto_rotation_time_guard) {
        if (picoquic_start_key_rotation(cnx) != 0) {
            picoquic_log_app_message(cnx, "Cannot start key rotation after %"PRIu64" packets",
                cnx->pkt_ctx[picoquic_packet_context_application].send_sequence);
        }
    }

    /* The first action is normally to retransmit lost packets. These lost packets
     * are queued in the connection context as `cnx->data_repeat_first` when data 
     * frames need to be repeated, and under `cnx->first_misc_frame` when other
     * individual frames need repetition. */
    if (cnx->first_misc_frame == NULL && 
        (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, 
        send_buffer_min_max, &header_length)) > 0) {
        /* Check whether it makes sense to add an ACK at the end of the retransmission */
        /* Testing header length for defense in depth -- avoid creating new packet if
         * picoquic_retransmit_needed erroneously returns length <= header_length */
        if (bytes + length + 256 < bytes_max  && length > header_length) {
            /* Don't do that if it risks mixing clear text and encrypted ack */
            bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data,
                current_time, pc, !is_nominal_ack_path);
            length = bytes_next - bytes;
        }
        /* document the send time & overhead */
        is_pure_ack = 0;
        packet->send_time = current_time;
        packet->checksum_overhead = checksum_overhead;
    }
    else if (cnx->cnx_state == picoquic_state_disconnected) {
        DBG_PRINTF("%s", "Retransmission check caused a disconnect");
    }
    else {
        length = picoquic_predict_packet_header_length(
            cnx, packet_type, pkt_ctx);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        bytes_next = bytes + length;

        /* If required, prepare challenge and response frames.
         * These frames will be sent immediately, regardless of pacing or flow control.
         */
        bytes_next = picoquic_prepare_path_challenge_frames(cnx, path_x,
            pc, is_nominal_ack_path,
            bytes_next, bytes_max,
            &more_data, &is_pure_ack, &is_challenge_padding_needed,
            current_time, next_wake_time);

        /* Compute the length before pacing block */
        length = bytes_next - bytes;

        if (path_x->is_multipath_probe_needed) {
            packet->is_multipath_probe = 1;
            path_x->is_multipath_probe_needed = 0;
            is_pure_ack = 0;
            *bytes_next = picoquic_frame_type_ping;
            length++;
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
            bytes_next = bytes + length;
        } else if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {
            /* There are no frames yet that would be exempt from pacing control, but if there
             * was they should be sent here. */

            if (picoquic_is_sending_authorized_by_pacing(cnx, path_x, current_time, next_wake_time)) {
                /* Send here the frames that are not exempt from the pacing control,
                 * but are exempt for congestion control */
                if (picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc, !is_nominal_ack_path)) {
                    uint8_t* bytes_ack = bytes_next;
                    bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                        current_time, pc, !is_nominal_ack_path);
                    ack_sent = (bytes_next > bytes_ack);
                }

                /* if necessary, prepare the MAX STREAM frames */
                if (ret == 0) {
                    bytes_next = picoquic_format_max_streams_frame_if_needed(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }

                /* If necessary, encode the max data frame */
                if (ret == 0){
                    if (cnx->quic->max_data_limit != 0) {
                        if (cnx->data_consumed + ((3 * cnx->quic->max_data_limit) / 4) > cnx->maxdata_local) {
                            uint64_t max_data_increase = cnx->data_consumed + cnx->quic->max_data_limit - cnx->maxdata_local;
                            bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                                max_data_increase);
                        }
                    }
                    else if (2 * cnx->data_consumed > cnx->maxdata_local) {
                        bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                            picoquic_cc_increased_window(cnx, cnx->maxdata_local));
                    }
                }

                /* If necessary, encode the max stream data frames */
                if (ret == 0 && cnx->max_stream_data_needed) {
                    bytes_next = picoquic_format_required_max_stream_data_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }
                /* Funky code alert:
                * if misc frames are present the function `picoquic_retransmit_needed` is bypassed.
                * if "more data" was not set, the code would not reset the wait time, and the
                * program could stall.
                * TODO: rework the way packets are repeated so this is not necessary.
                */
                if (cnx->first_misc_frame != NULL) {
                    more_data = 1;
                }
                /* If present, send misc frame */
                bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
                    &more_data, &is_pure_ack, pc);

                /* Compute the length before entering the CC block */
                length = bytes_next - bytes;

                if ((path_x->cwin < path_x->bytes_in_transit || cnx->quic->cwin_max < path_x->bytes_in_transit)
                    &&!path_x->is_pto_required) {
                        /* Implementation of experimental API, picoquic_set_priority_limit_for_bypass */
                        uint8_t* bytes_next_before_bypass = bytes_next;
                        int no_data_to_send = 0;
                        if (cnx->priority_limit_for_bypass > 0 && cnx->nb_paths == 1 &&
                            picoquic_is_authorized_by_pacing(&cnx->priority_bypass_pacing, current_time, next_wake_time,
                                cnx->quic->packet_train_mode, cnx->quic)) {
                            bytes_next = picoquic_prepare_stream_and_datagrams(cnx, path_x, bytes_next, bytes_max,
                                cnx->priority_limit_for_bypass, current_time,
                                &more_data, &is_pure_ack, &no_data_to_send, &ret);
                        }
                        if (bytes_next != bytes_next_before_bypass) {
                            length = bytes_next - bytes;
                        }
                        else {
                            cnx->cwin_blocked = 1;
                            path_x->last_cwin_blocked_time = current_time;
                            if (cnx->congestion_alg != NULL) {
                                picoquic_per_ack_state_t ack_state = { 0 };

                                cnx->congestion_alg->alg_notify(cnx, path_x,
                                    picoquic_congestion_notification_cwin_blocked,
                                    &ack_state, current_time);
                            }
                        }
                }
                else {
                    /* Send here the frames that are subject to both congestion and pacing control.
                     * this includes the PMTU probes.
                     * Check whether PMTU discovery is required. The call will return
                     * three values: not needed at all, optional, or required.
                     * If required, PMTU discovery takes priority over sending stream data.
                     */
                    int no_data_to_send = 1;
                    int preemptive_repeat = 0;
                    picoquic_pmtu_discovery_status_enum pmtu_discovery_needed = picoquic_is_mtu_probe_needed(cnx, path_x);

                    /* if present, send tls data */
                    if (picoquic_is_tls_stream_ready(cnx)) {
                        bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[picoquic_epoch_1rtt],
                            bytes_next, bytes_max, &more_data, &is_pure_ack);
                    }

                    if (cnx->is_address_discovery_provider) {
                        /* If a new address was learned, prepare an observed address frame */
                        bytes_next = picoquic_prepare_observed_address_frame(bytes_next, bytes_max,
                            path_x, current_time, next_wake_time, &more_data, &is_pure_ack);
                    }

                    if (length > header_length || pmtu_discovery_needed != picoquic_pmtu_discovery_required ||
                        send_buffer_max <= path_x->send_mtu) {
                        /* No need or no way to do path MTU discovery, just go on with formatting packets */
                        /* If there are not enough local CID published, create and advertise */
                        if (ret == 0) {
                            bytes_next = picoquic_format_new_local_id_as_needed(cnx, bytes_next, bytes_max,
                                current_time, next_wake_time, &more_data, &is_pure_ack);
                        }
                        if (ret == 0 && cnx->is_ack_frequency_updated && cnx->is_ack_frequency_negotiated) {
                            bytes_next = picoquic_format_ack_frequency_frame(cnx, bytes_next, bytes_max, &more_data);
                        }
                        if (ret == 0) {
                            bytes_next = picoquic_prepare_stream_and_datagrams(cnx, path_x, bytes_next, bytes_max,
                                UINT64_MAX, current_time, &more_data, &is_pure_ack, &no_data_to_send, &ret);
                        }

                        /* TODO: replace this by scheduling of BDP frame when window has been estimated */
                        /* Send bdp frames if there are no stream frames to send 
                         * and if peer wishes to receive bdp frames */
                        if(!cnx->client_mode && cnx->send_receive_bdp_frame) {
                           bytes_next = picoquic_format_bdp_frame(cnx, bytes_next, bytes_max, path_x, &more_data, &is_pure_ack);
                        }

                        length = bytes_next - bytes;

                        if (length <= header_length || is_pure_ack) {
                            /* Mark the bandwidth estimation as application limited */
                            path_x->delivered_limited_index = path_x->delivered;
                            /* Notify the peer if something is blocked */
                            bytes_next = picoquic_format_blocked_frames(cnx, &bytes[length], bytes_max, &more_data, &is_pure_ack);
                            length = bytes_next - bytes;
                        }

                        if (cnx->is_preemptive_repeat_enabled ||
                            (cnx->is_forced_probe_up_required && path_x->is_cca_probing_up)) {
                            if (length <= header_length) {
                                /* Consider redundant retransmission:
                                 * if the redundant retransmission index is null:
                                 * - if the packet loss rate is large enough compared to BDP, set index to last sent packet.
                                 * - if not, do not perform redundant retransmission.
                                 * if the packet contains a stream frame, if that stream is finished, and if the
                                 * data range has not been acked, and it fits: copy it to the data. Move the index to the previous packet.
                                 */
                                 ret = picoquic_preemptive_retransmit_as_needed(cnx, path_x, pc, current_time, next_wake_time, bytes_next,
                                    bytes_max - bytes_next, &length, &more_data, &is_pure_ack);
                                 if (length > header_length) {
                                     preemptive_repeat = 1;
                                     packet->is_preemptive_repeat = 1;
                                     bytes_next = bytes + length;
                                 }
                                 else if (cnx->is_forced_probe_up_required && path_x->is_cca_probing_up) {
                                     *bytes_next++ = picoquic_frame_type_ping;
                                     memset(bytes_next, picoquic_frame_type_padding, bytes_max - bytes_next);
                                     bytes_next = bytes_max;
                                     length = bytes_next - bytes;
                                     is_pure_ack = 0;
                                 }
                            }
                            else if (!more_data){
                                /* Check whether preemptive retrasmission is needed. Same code as above,
                                 * but in "test_only" mode, will set "more_data" or wait time if repeat is ready 
                                 */
                                ret = picoquic_preemptive_retransmit_as_needed(cnx, path_x, pc, current_time, next_wake_time, bytes_next,
                                    bytes_max - bytes_next, &length, &more_data, NULL);
                            }
                        }

                        if (no_data_to_send && !preemptive_repeat) {
                            path_x->last_sender_limited_time = current_time;
                        }
                    } /* end of PMTU not required */

                    if (ret == 0 && path_x->is_pto_required){
                        if ((length <= header_length || is_pure_ack) && bytes_next < bytes_max){
                            /* PTO probe required. */
                            *bytes_next++ = picoquic_frame_type_ping;
                            length++;
                            is_pure_ack = 0;
                        }
                    } 

                    if (ret == 0 && length <= header_length) {
                        if (send_buffer_max > path_x->send_mtu
                            && path_x->cwin > path_x->bytes_in_transit 
                            && cnx->quic->cwin_max > path_x->bytes_in_transit
                            && pmtu_discovery_needed != picoquic_pmtu_discovery_not_needed) {
                            /* Since there is no data to send, this is an opportunity to send an MTU probe */
                            length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes, send_buffer_max);
                            packet->length = length;
                            packet->send_path = path_x;
                            packet->is_mtu_probe = 1;
                            path_x->mtu_probe_sent = 1;
                            is_pure_ack = 0;
                        }
                    }

                    // if we didn't add any frames, we need to check if we need to send a ping frame
                    if (ret == 0 && cnx->is_poll_requested && length <= header_length) {
                        if (bytes_next < bytes_max) {
                            *bytes_next++ = picoquic_frame_type_poll;
                            length++;
                            cnx->is_poll_requested = 0;
                        }
                    }
                } /* end of CC */
            } /* End of pacing */
            else if (cnx->priority_limit_for_bypass > 0 && cnx->nb_paths == 1 &&
                picoquic_is_authorized_by_pacing(&cnx->priority_bypass_pacing, current_time, next_wake_time,
                    cnx->quic->packet_train_mode, cnx->quic)) {
                /* If congestion bypass is implemented, also consider pacing bypass */
                int no_data_to_send = 0;

                if ((bytes_next = picoquic_prepare_stream_and_datagrams(cnx, path_x, bytes_next, bytes_max,
                    cnx->priority_limit_for_bypass, current_time,
                    &more_data, &is_pure_ack, &no_data_to_send, &ret)) != NULL) {
                    length = bytes_next - bytes;
                }
            }
        } /* End of challenge verified */
    }

    if (length <= header_length) {
        length = 0;
    }

    if (cnx->cnx_state != picoquic_state_disconnected) {
        if (length > 0){
            path_x->is_pto_required &= is_pure_ack;
            pkt_ctx->ack_of_ack_requested |= !is_pure_ack;
            if (!pkt_ctx->ack_of_ack_requested && ack_sent) {
                /* If we have sent many ACKs, add a PING to get an ack of ack */
                /* The number 24 is chosen to not break any of the unit tests. If the number is
                 * too small, the PING mechanism can cause delayed end of the connection, or 
                 * early breakage */
                const uint64_t ack_repeat_interval = 24;
                bytes_next = bytes + length;
                if (bytes_next < bytes_max &&
                    pkt_ctx->highest_acknowledged + ack_repeat_interval < pkt_ctx->send_sequence &&
                    path_x == cnx->path[0] &&
                    pkt_ctx->highest_acknowledged_time + path_x->smoothed_rtt < current_time) {
                    /* Bundle a Ping with ACK, so as to get trigger an Acknowledgement */
                    *bytes_next++ = picoquic_frame_type_ping;
                    pkt_ctx->ack_of_ack_requested = 1;
                    is_pure_ack = 0;
                    length = bytes_next - bytes;
                }
            }

            if (is_pure_ack && cnx->is_multipath_enabled && 
                path_x->is_ack_lost && !path_x->is_ack_expected) {
                /* In some multipath scenarios, we may need to ping a path if we see 
                 * non-ackable packets being lost. */
                bytes_next = bytes + length;
                if (bytes_next < bytes_max) {
                    is_pure_ack = 0;
                    *bytes_next = picoquic_frame_type_ping;
                    length++;
                }
            }

            if (!is_pure_ack) {
                path_x->is_ack_expected = 1;
            }
        }

        if (is_pure_ack == 0)
        {
            cnx->latest_progress_time = current_time;
        }
        else if (cnx->keep_alive_interval != 0) {
            /* If necessary, encode and send the keep alive packet.
             * We only send keep alive packets when no other data is sent.
             */
            if (cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                length = picoquic_predict_packet_header_length(
                    cnx, packet_type, pkt_ctx);
                packet->ptype = packet_type;
                packet->pc = pc;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = pkt_ctx->send_sequence;
                packet->send_path = path_x;
                packet->send_time = current_time;
                bytes[length++] = picoquic_frame_type_ping;
                bytes[length++] = 0;
                cnx->latest_progress_time = current_time;
            }
            else if (cnx->latest_progress_time + cnx->keep_alive_interval < *next_wake_time) {
                *next_wake_time = cnx->latest_progress_time + cnx->keep_alive_interval;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }

        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            ret = 0;
        }
    }

    if (ret == 0 && length > header_length) {
        /* Ensure that all packets are properly padded before being sent. */

        if (*is_initial_sent || (is_challenge_padding_needed && length < PICOQUIC_ENFORCED_INITIAL_MTU)){
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
        else {
            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        path_x, current_time);

    if (*send_length > 0) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (ret == 0 && picoquic_cnx_is_still_logging(cnx)) {
            picoquic_log_cc_dump(cnx, current_time);
        }
    }
    return ret;
}

static int picoquic_check_idle_timer(picoquic_cnx_t* cnx, uint64_t* next_wake_time, uint64_t current_time)
{
    int ret = 0;
    uint64_t idle_timer = 0;

    if (cnx->cnx_state >= picoquic_state_ready) {
        uint64_t rto = picoquic_current_retransmit_timer(cnx, cnx->path[0]);
        idle_timer = cnx->idle_timeout;
        if (idle_timer < 3 * rto) {
            idle_timer = 3 * rto;
        }
        idle_timer += cnx->latest_receive_time;

        if (idle_timer < cnx->idle_timeout) {
            idle_timer = UINT64_MAX;
        }
    }
    else if (cnx->quic->default_handshake_timeout > 0) {
        idle_timer = cnx->start_time + cnx->quic->default_handshake_timeout;
    }
    else if (cnx->local_parameters.max_idle_timeout > 0) {
        idle_timer = cnx->start_time + cnx->local_parameters.max_idle_timeout*1000ull;
    }
    else {
        idle_timer = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    }

    if (current_time >= idle_timer) {
        /* Too long silence, break it. */
        if (cnx->cnx_state != picoquic_state_draining) {
            cnx->local_error = PICOQUIC_ERROR_IDLE_TIMEOUT;
        }
        ret = PICOQUIC_ERROR_DISCONNECTED;
        picoquic_connection_disconnect(cnx);
    } else if (idle_timer < *next_wake_time) {
        *next_wake_time = idle_timer;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_segment(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    uint64_t* next_wake_time, int* is_initial_sent)
{
    int ret = 0;

    /* Reset the blocked indicators */
    cnx->cwin_blocked = 0;
    cnx->flow_blocked = 0;
    cnx->stream_blocked = 0;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
    case picoquic_state_client_init_sent:
    case picoquic_state_client_init_resent:
    case picoquic_state_client_renegotiate:
    case picoquic_state_client_handshake_start:
    case picoquic_state_client_almost_ready:
        ret = picoquic_prepare_packet_client_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_server_almost_ready:
    case picoquic_state_server_init:
    case picoquic_state_server_handshake:
        ret = picoquic_prepare_packet_server_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_server_false_start:
        /*
         * Manage the end of false start transition, and if needed start
         * preparing packet in ready state.
         */
        if (cnx->cnx_state == picoquic_state_server_false_start &&
            cnx->crypto_context[3].aead_decrypt != NULL) {
            picoquic_ready_state_transition(cnx, current_time);
            return picoquic_prepare_packet_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        }
        /* Else, just fall through to almost ready behavior.
         */
    case picoquic_state_client_ready_start:
        ret = picoquic_prepare_packet_almost_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_ready:
        ret = picoquic_prepare_packet_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_handshake_failure:
    case picoquic_state_handshake_failure_resend:
    case picoquic_state_disconnecting:
    case picoquic_state_closing_received:
    case picoquic_state_closing:
    case picoquic_state_draining:
        ret = picoquic_prepare_packet_closing(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time);
        break;
    case picoquic_state_disconnected:
        ret = PICOQUIC_ERROR_DISCONNECTED;
        break;
    case picoquic_state_client_retry_received:
        DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
        ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
        break;
    default:
        DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
        ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
        break;
    }

    return ret;
}

/*
 * The version 1 of Quic only supports path migration, not full multipath.
 * This code finds whether there is a path being probed that could become the
 * default path, or that needs an immediate challenge sent or replied to.
 * If no other path is suitable, the code returns the default path.
 *
 * If multipath is enabled, the logic changes. Paths have two attributes:
 * availability, and for paths that are available, priority. The availability
 * criteria evolves over time:
 * - as long as continuity is not verified, a path is not available.
 * - if continuity is verified but the path is not "validated", the path
 *   is marked as standby.
 * - if the path is validated and no other path has a higher priority,
 *   the path is available.
 * If several paths are available at the same priority level, the code
 * checks whether one of them is "ready to send", i.e. is not blocked
 * by either pacing or congestion control. The first path for which the
 * condition is verified will be selected.
 *
 * There are potential corner cases. If a challenge or a response is required
 * on a path, that takes priority over sending data. A challenge may be required
 * on a "standby" path to test continuity if no data has been received for
 * a long time, or maybe following a packet loss episode.
 *
 * If all available paths are blocked by congestion control and acknowledgements
 * need to be sent, the lowest RTT path not blocked by pacing is selected.
 *
 * Need to consider special code for dealing with packet losses. If a path
 * exhibits persistent packet loss, it loses its priority and moves to "standby"
 * state. At that point, the "challenge needed" flag is set, triggering a
 * continuity test.
 *
 * The multipath option bundles enabling multipath and using a separate number
 * space per path. This is not strictly necessary. A simpler design would just make 
 * the change in "picoquic_select_next_path_mp" below, without affecting the
 * reminder of the protocol code. This could be enabled for example by
 * a "multipath_simple" option.
 * 
 * The path affinity implementation introduces a degree of complexity. The algorithm
 * as defined above will wake up the first path that has CWIN available, but
 * we should really choose a path that both has CWIN available and has something
 * to send, which can be either:
 *  - there is high priority activity pending on any path,
 *  - there are datagram ready to be sent on this path, or,
 *  - there are datagram ready to be sent on any path, or,
 *  - there is an active stream on that path, 
 *  - there is an active stream on any path.
 * 
 * TODO: this is probably too complicated, and it does not align well with the
 * general archictecture of picoquic in which:
 * 
 * - various external actions mark the connection as ready and set the
 *   connection wakeup time to "current"
 * - the "prepare packet" function is called at the wake up time
 * - at various places in the sending process, the code tries an action,
 *   and if it is not possible yet sets the wakeup time to a later value.
 * 
 * The solution micht be to manage a wakeup time per path, and set the
 * per connection time to the min of the per path times. This is not hard,
 * except for the part where "various external actions mark the connection as ready".
 * Instead, these various interactions may need to be selective, mark some
 * paths as ready based on conditions.
 * 
 * The handling of "standby" should be integrated in the sending process,
 * so congestion controlled data is not sent on standby path, and delay
 * sensitive data is not sent on suspect paths.
 */

static void picoquic_set_path_addresses(picoquic_cnx_t* cnx, int path_id, int is_nat,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index)
{
    if (is_nat) {
        if (p_addr_to != NULL) {
            picoquic_store_addr(p_addr_to, (struct sockaddr*)&cnx->path[path_id]->nat_peer_addr);
        }

        if (p_addr_from != NULL) {
            picoquic_store_addr(p_addr_from, (struct sockaddr*)&cnx->path[path_id]->nat_local_addr);
        }

        if (if_index != NULL) {
            *if_index = cnx->path[path_id]->if_index_nat_dest;
        }
    }
    else {
        if (p_addr_to != NULL) {
            picoquic_store_addr(p_addr_to, (struct sockaddr*)&cnx->path[path_id]->peer_addr);
        }

        if (p_addr_from != NULL) {
            picoquic_store_addr(p_addr_from, (struct sockaddr*)&cnx->path[path_id]->local_addr);
        }

        if (if_index != NULL) {
            *if_index = cnx->path[path_id]->if_index_dest;
        }
    }
}

static int picoquic_select_next_path_mp(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time,
    struct sockaddr_storage * p_addr_to, struct sockaddr_storage * p_addr_from, int* if_index)
{
    int path_id = -1;
    int highest_priority = -1;
    int data_path_cwin = -1;
    int data_path_pacing = -1;
    int challenge_path = -1;
    uint64_t pacing_time_next = UINT64_MAX;
    uint64_t challenge_time_next = UINT64_MAX;
    uint64_t highest_retransmit = UINT64_MAX;
    uint64_t last_sent_pacing = UINT64_MAX;
    uint64_t last_sent_cwin = UINT64_MAX;
    int i;
    int i_min_rtt = -1;
    int is_min_rtt_pacing_ok = 0;
    int is_ack_needed = 0;
    picoquic_stream_head_t* next_stream = picoquic_find_ready_stream(cnx);
    int affinity_path_id = -1;
    unsigned int is_nat = 0;

    cnx->last_path_polled++;
    if (cnx->last_path_polled > cnx->nb_paths) {
        cnx->last_path_polled = 0;
    }

    for (i = 0; i < cnx->nb_paths; i++) {
        int path_priority = (cnx->path[i]->path_is_standby) ? 0 : 1;
        cnx->path[i]->is_probing_nat = 0;
        if (cnx->path[i]->nb_retransmit > 0) {
            path_priority = 0;
        }
        cnx->path[i]->is_nominal_ack_path = 0;
        if (cnx->path[i]->path_is_demoted) {
            continue;
        }
        else if (cnx->path[i]->challenge_failed) {
            picoquic_demote_path(cnx, i, current_time, 0, NULL);
            continue;
        }
        else
        {
            if (cnx->path[i]->response_required) {
                challenge_path = i;
                cnx->path[i]->responder++;
                break;
            }
            else if (cnx->path[i]->challenge_required && !cnx->path[i]->challenge_verified) {
                uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, cnx->path[i], current_time, &is_nat);
                if (current_time >= next_challenge_time) {
                    cnx->path[i]->challenger++;
                    cnx->path[i]->is_probing_nat = (is_nat) ? 1 : 0;
                    challenge_path = i;
                    break;
                }
                else if (next_challenge_time < challenge_time_next) {
                    challenge_time_next = next_challenge_time;
                }
            }
            else if (cnx->path[i]->challenge_verified && cnx->path[i]->nb_retransmit > 0 && 
                cnx->cnx_state == picoquic_state_ready && cnx->path[i]->bytes_in_transit == 0) {
                cnx->path[i]->is_multipath_probe_needed = 1;
                challenge_path = i;
                break;
            }
            if (cnx->path[i]->challenge_verified) {
                int is_polled = 0;
                int is_new_priority = 0;
                /* Set the congestion algorithm for the new path */
                if (cnx->congestion_alg != NULL && cnx->path[i]->congestion_alg_state == NULL) {
                    cnx->congestion_alg->alg_init(cnx, cnx->path[i], current_time);
                }

                if (path_priority > highest_priority) {
                    is_polled = 1;
                    is_new_priority = 1;
                }
                else if (path_priority == highest_priority) {
                    if (cnx->path[i]->nb_retransmit < highest_retransmit) {
                        is_polled = 1;
                        is_new_priority = 1;
                    }
                    else if (cnx->path[i]->nb_retransmit == highest_retransmit) {
                        is_polled = 1;
                    }
                }

                if (is_new_priority) {
                    highest_priority = path_priority;
                    highest_retransmit = cnx->path[i]->nb_retransmit;
                    data_path_cwin = -1;
                    data_path_pacing = -1;
                    pacing_time_next = UINT64_MAX;
                    last_sent_pacing = UINT64_MAX;
                    last_sent_cwin = UINT64_MAX;
                    i_min_rtt = -1;
                    is_min_rtt_pacing_ok = 0;
                }
                if (is_polled) {
                    /* This path is a candidate for min rtt */
                    if (i_min_rtt < 0 ||
                        cnx->path[i]->nb_retransmit < cnx->path[i_min_rtt]->nb_retransmit ||
                        (cnx->path[i]->nb_retransmit == cnx->path[i_min_rtt]->nb_retransmit &&
                        cnx->path[i]->rtt_min < cnx->path[i_min_rtt]->rtt_min)) {
                        i_min_rtt = i;
                        is_min_rtt_pacing_ok = 0;
                    }
                    cnx->path[i]->polled++;
                    if (picoquic_is_sending_authorized_by_pacing(cnx, cnx->path[i], current_time, &pacing_time_next)) {
                        if (cnx->path[i]->last_sent_time < last_sent_pacing) {
                            last_sent_pacing = cnx->path[i]->last_sent_time;
                            data_path_pacing = i;
                            if (i == i_min_rtt) {
                                is_min_rtt_pacing_ok = 1;
                            }
                        }
                        if (cnx->path[i]->bytes_in_transit < cnx->path[i]->cwin &&
                            cnx->path[i]->bytes_in_transit <  cnx->quic->cwin_max) {
                            if (cnx->path[i]->last_sent_time < last_sent_cwin) {
                                last_sent_cwin = cnx->path[i]->last_sent_time;
                                data_path_cwin = i;
                            }
                            if (affinity_path_id < 0) {
                                /* we select here the first path that is either ready to send on
                                 * the highest priority stream with affinity on this path, or
                                 * ready to send datagrams on this path. */
                                if (next_stream != NULL && cnx->path[i] == next_stream->affinity_path) {
                                    affinity_path_id = i;
                                }
                                else if (cnx->path[i]->is_datagram_ready || cnx->is_datagram_ready) {
                                    affinity_path_id = i;
                                }
                            }
                        }
                        else {
                            cnx->path[i]->congested++;
                        }
                    }
                    else {
                        cnx->path[i]->paced++;
                    }
                }
            }
        }
    }

    /* Ensure that at most one path is marked as nominal ack path */
    for (i += 1; i < cnx->nb_paths; i++) {
        cnx->path[i]->is_nominal_ack_path = 0;
    }
     if (i_min_rtt >= 0) {
        is_ack_needed = picoquic_is_ack_needed(cnx, current_time, next_wake_time, 0, 0);
        cnx->path[i_min_rtt]->is_nominal_ack_path = 1;
    }

    if (challenge_path >= 0) {
        path_id = challenge_path;
    }
    else if (is_ack_needed && is_min_rtt_pacing_ok) {
        path_id = i_min_rtt;
    }
    else if (data_path_cwin >= 0) {
        /* if there is a path ready to send the most urgent data, select it */
        if (affinity_path_id >= 0) {
            path_id = affinity_path_id;
        }
        else {
            path_id = data_path_cwin;
        }
    }
    else if (data_path_pacing >= 0) {
        path_id = data_path_pacing;
    }
    else {
        uint64_t path_wake_time = pacing_time_next;
        if (challenge_time_next < path_wake_time) {
            path_wake_time = challenge_time_next;
        }
        if (path_wake_time < *next_wake_time) {
            *next_wake_time = path_wake_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        path_id = 0;
    }
    if (cnx->path[path_id]->path_is_standby && challenge_path != path_id) {
        /* Set the selected path to available if it was standby. Selecting a standby
         * path means that the available path was of lower quality, the only exception
         * being if the selection was due to a pending challenge. */
        (void)picoquic_set_path_status(cnx, cnx->path[path_id]->unique_path_id, picoquic_path_status_available);
    }
    cnx->path[path_id]->selected++;
    picoquic_set_path_addresses(cnx, path_id, is_nat, p_addr_to, p_addr_from, if_index);

    return path_id;
}

int picoquic_select_next_path(picoquic_cnx_t * cnx, uint64_t current_time, uint64_t * next_wake_time,
    struct sockaddr_storage * p_addr_to, struct sockaddr_storage * p_addr_from, int* if_index)
{
    int path_id = -1;

    if (cnx->is_multipath_enabled && cnx->cnx_state >= picoquic_state_ready) {
        return picoquic_select_next_path_mp(cnx, current_time, next_wake_time, p_addr_to, p_addr_from, if_index);
    }

    /* Select the path */
    for (int i = 1; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->path_is_demoted) {
            continue;
        }
        else if (cnx->path[i]->challenge_failed) {
            picoquic_demote_path(cnx, i, current_time, 0, NULL);
            continue;
        }
        else if (cnx->path[i]->challenge_verified && cnx->cnx_state == picoquic_state_ready) {
            /* logic to synchronize path selection between server and client:
             * On the client side, this is driven by the "probe/validate" sequence; the
             * assumption is that if the client probes a new path, it want to use it
             * as soon as confirmed. On the server side, this is enforced by observing
             * incoming traffic: if a path is validated and "non path probing"
             * frames were received, then the path should be promoted. However, on
             * the server side, we have to be careful with packet reordering, and
             * verify that only the "most recent" packets trigger the validation
             * logic.
             */
            if (cnx->client_mode || cnx->path[i]->last_non_path_probing_pn >=
                picoquic_sack_list_last(&cnx->ack_ctx[picoquic_packet_context_application].sack_list) ||
                cnx->path[i]->is_nat_challenge) {
                /* This path becomes the new default */
                picoquic_promote_path_to_default(cnx, i, current_time);
                path_id = 0;
            }
            break;
        }
        else if (path_id < 0) {
            if (cnx->path[i]->response_required) {
                path_id = i;
            }
            else if (cnx->path[i]->challenge_required) {
                uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, cnx->path[i], current_time, NULL);
                if (cnx->path[i]->challenge_repeat_count == 0 ||
                    current_time >= next_challenge_time) {
                    /* will try this path, unless a validated path came in */
                    path_id = i;
                }
                else if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }
    }

    if (path_id < 0) {
        path_id = 0;
    }

    picoquic_set_path_addresses(cnx, path_id, 0, p_addr_to, p_addr_from, if_index);

    return path_id;
}

/* manage the CC timer, if any */
static int picoquic_check_cc_feedback_timer(picoquic_cnx_t* cnx, uint64_t* next_wake_time, uint64_t current_time)
{
    int ret = 0;

    if (cnx->is_lost_feedback_notification_required && cnx->congestion_alg != NULL) {
        for (int i = 0; i < cnx->nb_paths; i++) {
            picoquic_path_t* path_x = cnx->path[i];
            if (!path_x->is_lost_feedback_notified){
                picoquic_packet_context_t* pkt_ctx = (cnx->is_multipath_enabled)?
                    &path_x->pkt_ctx:&cnx->pkt_ctx[picoquic_packet_context_application];
                if (pkt_ctx->pending_first != NULL) {
                    uint64_t delta_sent = (pkt_ctx->pending_first->send_time <= path_x->last_time_acked_data_frame_sent) ? 0 :
                        (pkt_ctx->pending_first->send_time - path_x->last_time_acked_data_frame_sent);
                    uint64_t lost_feedback_time = pkt_ctx->highest_acknowledged_time + delta_sent + 2 * cnx->ack_frequency_delay_local;
                            
                    if (lost_feedback_time <= current_time) {
                        path_x->is_lost_feedback_notified = 1;
                        cnx->congestion_alg->alg_notify(cnx, path_x,
                            picoquic_congestion_notification_lost_feedback,
                            NULL, current_time);
                    }
                    else if (lost_feedback_time < *next_wake_time) {
                        *next_wake_time = lost_feedback_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
        }
    }
    return ret;
}

int picoquic_handle_app_wake_time(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;
    while (cnx->app_wake_time != 0 && cnx->app_wake_time <= current_time){
        cnx->app_wake_time = 0;
        if (cnx->callback_fn != NULL) {
            ret = cnx->callback_fn(cnx, current_time, NULL, 0, picoquic_callback_app_wakeup,
                cnx->callback_ctx, NULL);
        }
    }
    return ret;
}

int picoquic_program_app_wake_time(picoquic_cnx_t* cnx, uint64_t* next_wake_time)
{
    int ret = 0;

    if (cnx->app_wake_time != 0 && cnx->app_wake_time < *next_wake_time) {
        *next_wake_time = cnx->app_wake_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }
    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_packet_ex(picoquic_cnx_t* cnx, int path_id_request,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage * p_addr_to, struct sockaddr_storage * p_addr_from, int* if_index, size_t* send_msg_size)
{

    int ret = 0;
    picoquic_packet_t * packet = NULL;
    uint64_t initial_next_time;
    uint64_t next_wake_time = cnx->latest_receive_time + 2*PICOQUIC_MICROSEC_SILENCE_MAX;

    if (cnx->local_parameters.max_idle_timeout >(PICOQUIC_MICROSEC_SILENCE_MAX / 500)) {
        next_wake_time = cnx->latest_receive_time + cnx->local_parameters.max_idle_timeout * 1000ull;
    }

    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

    if (cnx->recycle_sooner_needed) {
        picoquic_process_sooner_packets(cnx, current_time);
    }

    *send_length = 0;

    ret = picoquic_handle_app_wake_time(cnx, current_time);

    if (ret == 0) {
        ret = picoquic_check_idle_timer(cnx, &next_wake_time, current_time);
    }

    if (ret == 0) {
        ret = picoquic_check_cc_feedback_timer(cnx, &next_wake_time, current_time);
    }

    if (send_buffer_max < PICOQUIC_ENFORCED_INITIAL_MTU) {
        DBG_PRINTF("Invalid buffer size: %zu", send_buffer_max);
        ret = -1;
    }

    if (ret == 0) {
        int path_id;

        /* Remove delete paths */
        if (cnx->path_demotion_needed) {
            picoquic_delete_abandoned_paths(cnx, current_time, &next_wake_time);
        }

        /* Select the next path, and the corresponding addresses */
        path_id = picoquic_select_next_path(cnx, current_time, &next_wake_time, p_addr_to, p_addr_from, if_index);
        if (path_id_request != -1) {
            path_id = path_id_request;
        }

        /* Send the available packets */
        if (send_msg_size != NULL) {
            *send_msg_size = cnx->path[path_id]->send_mtu;
        }
        initial_next_time = next_wake_time;

        if (send_buffer_max > cnx->path[path_id]->send_mtu) {
            cnx->is_sending_large_buffer = 1;
        }

        int segment_count = 0;
        while (ret == 0 && segment_count < 128)
        {
            /* Create a new packet, which may include several segments */
            int is_initial_sent = 0;
            size_t packet_size = 0;
            size_t packet_max = send_buffer_max - *send_length;
            uint8_t* packet_buffer = send_buffer + *send_length;
            /* Reset the wake time to the initial value after sending packets */
            next_wake_time = initial_next_time;

            if (send_msg_size != NULL && *send_msg_size > 0 && *send_length > 0 &&
                packet_max > * send_msg_size) {
                /* Consecutive packets should not be larger than first packet */
                packet_max = *send_msg_size;
            }

            /* Send the available segments in that packet. */
            while (ret == 0 && segment_count < 128)
            {
                /* Create the segments that fit in the new packet */
                size_t available = packet_max;
                size_t segment_length = 0;

                if (packet_size > 0) {
                    packet_max = cnx->path[path_id]->send_mtu;

                    if (packet_max < packet_size + PICOQUIC_MIN_SEGMENT_SIZE) {
                        break;
                    }
                    else {
                        available = packet_max - packet_size;
                    }
                }

                packet = picoquic_create_packet(cnx->quic);

                if (packet == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                    break;
                }
                else {
                    ret = picoquic_prepare_segment(cnx, cnx->path[path_id], packet, current_time,
                        packet_buffer + packet_size, available, &segment_length, &next_wake_time, &is_initial_sent);

                    if (ret == 0) {
                        packet_size += segment_length;
                        segment_count++;
                        if (packet->length == 0) {
                            /* Nothing more to send */
                            picoquic_recycle_packet(cnx->quic, packet);
                            break;
                        }
                        else if (packet->ptype == picoquic_packet_1rtt_protected) {
                            /* Cannot coalesce packets after 1 rtt packet */
                            break;
                        }
                        else if (segment_length == 0) {
                            DBG_PRINTF("Send bug: segment length = %zu, packet length = %zu\n", segment_length, packet->length);
                            break;
                        } else if (segment_count == 128) {
                            DBG_PRINTF("Reached max segment count, packet length = %zu\n", packet->length);
                            break;
                        }
                    }
                    else {
                        picoquic_recycle_packet(cnx->quic, packet);
                        packet = NULL;

                        if (packet_size != 0) {
                            ret = 0;
                        }
                        break;
                    }

                    if (cnx->quic->dont_coalesce_init) {
                        break;
                    }
                }
            }
            if (packet_size > packet_max) {
#ifdef HUNTING_FOR_BUFFER_OVERFLOW
                int* x = NULL;
                *x += 1;
#endif
                picoquic_log_app_message(cnx, "BUFFER OVERFLOW? Packet size %zu larger than %zu", packet_size, packet_max);
            }
            if (packet_size > 0) {
                if (packet_size > cnx->max_mtu_sent) {
                    cnx->max_mtu_sent = packet_size;
                }
                cnx->nb_packets_sent++;
                /* if needed, log that the packet is sent */
                if (p_addr_to != NULL && p_addr_from != NULL) {
                    picoquic_log_pdu(cnx, 0, current_time,
                        (struct sockaddr*)p_addr_to, (struct sockaddr*)p_addr_from, packet_size);
                }
            }

            /* Update the wake up time for the connection */
            if (packet_size > 0 || cnx->cnx_state == picoquic_state_disconnected) {
                next_wake_time = current_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }

            /* Account for the bytes in the packet. */
            *send_length += packet_size;

            /* Check whether to keep coalescing multiple packets in the send buffer */
            if (send_msg_size == NULL) {
                break;
            }
            else if (packet_size > *send_msg_size) {
                /* This can only happen for the first packet in a batch. */
                *send_msg_size = packet_size;
            }
            else if (packet_size != *send_msg_size) {
                if (*send_length > 0) {
                    if (packet_size == 0 && *send_length < 8*(*send_msg_size)) {
                        if (cnx->path[path_id]->cwin <= cnx->path[path_id]->bytes_in_transit) {
                            cnx->nb_trains_blocked_cwin++;
                        }
                        else if (picoquic_is_pacing_blocked(&cnx->path[path_id]->pacing)) {
                            cnx->nb_trains_blocked_pacing++;
                        }
                        else {
                            cnx->nb_trains_blocked_others++;
                        }
                    }
                    else {
                        cnx->nb_trains_short++;
                    }
                }
                break;
            }
            else if (*send_length + *send_msg_size > send_buffer_max) {
                break;
            }
        }
        if (*send_length > 0) {
            cnx->nb_trains_sent++;
        }
    }

    if (ret == 0) {
        ret = picoquic_program_app_wake_time(cnx, &next_wake_time);
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_wake_time);

    return ret;
}

int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index)
{
    return picoquic_prepare_packet_ex(cnx, -1, current_time, send_buffer, send_buffer_max, send_length,
        p_addr_to, p_addr_from, if_index, NULL);
}

int picoquic_close(picoquic_cnx_t* cnx, uint64_t application_reason_code)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(cnx->quic);

    if (cnx->cnx_state == picoquic_state_ready ||
        cnx->cnx_state == picoquic_state_server_false_start || cnx->cnx_state == picoquic_state_client_ready_start) {
        cnx->cnx_state = picoquic_state_disconnecting;
        cnx->application_error = application_reason_code;
    } else if (cnx->cnx_state < picoquic_state_client_ready_start) {
        cnx->cnx_state = picoquic_state_handshake_failure;
        cnx->application_error = 0;
        cnx->local_error = PICOQUIC_TRANSPORT_APPLICATION_ERROR;
    } else {
        ret = -1;
    }
    cnx->offending_frame_type = 0;
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);

    return ret;
}

void picoquic_close_immediate(picoquic_cnx_t* cnx)
{
    if (cnx->cnx_state < picoquic_state_draining) {
        /* Behave exactly as if having received a closing message from the peer */
        uint64_t current_time = picoquic_get_quic_time(cnx->quic);
        uint64_t exit_time = current_time + 3 * cnx->path[0]->retransmit_timer;
        cnx->cnx_state = picoquic_state_draining;
        cnx->local_error = UINT64_MAX;
        cnx->latest_progress_time = current_time;
        cnx->last_close_sent = current_time;
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, exit_time);
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }
}

/* Quic context level call.
 * will send a stateless packet if one is queued, or ask the first connection in
 * the wake list to prepare a packet */

int picoquic_prepare_next_packet_ex(picoquic_quic_t* quic,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int * if_index,
    picoquic_connection_id_t * log_cid, picoquic_cnx_t** p_last_cnx, size_t * send_msg_size)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(quic);

    if (p_last_cnx) {
        *p_last_cnx = NULL;
    }

    if (sp != NULL) {
        if (sp->length > send_buffer_max) {
            *send_length = 0;
        }
        else {
            memcpy(send_buffer, sp->bytes, sp->length);
            *send_length = sp->length;
            picoquic_store_addr(p_addr_to, (struct sockaddr*) & sp->addr_to);
            picoquic_store_addr(p_addr_from, (struct sockaddr*) & sp->addr_local);
            *if_index = sp->if_index_local;
            if (log_cid != NULL) {
                *log_cid = sp->initial_cid;
            }
        }
        picoquic_delete_stateless_packet(sp);
    }
    else {
        picoquic_cnx_t* cnx = picoquic_get_earliest_cnx_to_wake(quic, current_time);

        if (cnx == NULL) {
            *send_length = 0;
        }
        else {
            ret = picoquic_prepare_packet_ex(cnx, -1, current_time, send_buffer, send_buffer_max, send_length, p_addr_to, p_addr_from,
                if_index, send_msg_size);
            if (log_cid != NULL) {
                *log_cid = cnx->initial_cnxid;
            }

            if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                ret = 0;

                picoquic_log_app_message(cnx, "Closed. Retrans= %d, spurious= %d, max sp gap = %d, max sp delay = %d, dg-coal: %f",
                    (int)cnx->nb_retransmission_total, (int)cnx->nb_spurious,
                    (int)cnx->path[0]->max_reorder_gap, (int)cnx->path[0]->max_spurious_rtt,
                    (cnx->nb_trains_sent > 0) ? ((double)cnx->nb_packets_sent / (double)cnx->nb_trains_sent) : 0.0);

                if (quic->F_log != NULL) {
                    fflush(quic->F_log);
                }

                if (cnx->f_binlog != NULL) {
                    fflush(cnx->f_binlog);
                }

                if (cnx->client_mode) {
                    /* Do not unilaterally delete the connection context, as it was set by the application */
                    picoquic_reinsert_by_wake_time(cnx->quic, cnx, UINT64_MAX);
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
                else {
                    picoquic_delete_cnx(cnx);
                }
            }
            else {
                if (*if_index == -1) {
                    *if_index = picoquic_get_local_if_index(cnx);
                }
                if (p_last_cnx) {
                    *p_last_cnx = cnx;
                }
            }
        }
    }

    return ret;
}

int picoquic_prepare_next_packet(picoquic_quic_t* quic,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_connection_id_t* log_cid, picoquic_cnx_t** p_last_cnx)
{
    return picoquic_prepare_next_packet_ex(quic, current_time, send_buffer, send_buffer_max, send_length,
        p_addr_to, p_addr_from, if_index, log_cid, p_last_cnx, NULL);
}
