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

/*
 * Management of transport parameters for PicoQUIC.
 */

#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <string.h>

uint8_t* picoquic_transport_param_varint_encode_old(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64) 
{
    if (bytes + 2 > bytes_max) {
        bytes = NULL;
    }
    else {
        uint8_t * byte_l;
        size_t l;

        *bytes++ = 0;
        byte_l = bytes;
        *bytes++ = 0;
        l = picoquic_varint_encode(bytes, bytes_max - bytes, n64);
        if (l == 0) {
            bytes = NULL;
        }
        else {
            *byte_l = (uint8_t) l;
            bytes += l;
        }
    }

    return bytes;
}

uint64_t picoquic_transport_param_varint_decode(picoquic_cnx_t * cnx, uint8_t* bytes, uint64_t extension_length, int* ret) 
{
    uint64_t n64 = 0;
    uint64_t l_v = picoquic_varint_decode(bytes, (size_t)extension_length, &n64);

    if (l_v == 0 || l_v != extension_length) {
        *ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    return n64;
}

uint8_t* picoquic_transport_param_type_varint_encode_old(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, uint64_t n64)
{
    if (bytes != NULL && bytes + 2 <= bytes_max) {
        picoformat_16(bytes, (uint16_t)tp_type);
        bytes = picoquic_transport_param_varint_encode_old(bytes + 2, bytes_max, n64);
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

uint8_t* picoquic_transport_param_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64)
{
    if (bytes + 1 > bytes_max) {
        bytes = NULL;
    }
    else {
        uint8_t* byte_l = bytes++;
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, n64);
        if (bytes != NULL) {
            *byte_l = (uint8_t)((bytes - byte_l) - 1);
        }
    }

    return bytes;
}

uint8_t* picoquic_transport_param_type_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, uint64_t n64)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        bytes = picoquic_transport_param_varint_encode(bytes, bytes_max, n64);
    }
    return bytes;
}

uint8_t* picoquic_transport_param_type_flag_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, 0);
    }
    return bytes;
}

uint8_t* picoquic_transport_param_cid_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, picoquic_connection_id_t * cid)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        /* frame encoding includes length and the value. */
        bytes = picoquic_frames_cid_encode(bytes, bytes_max, cid);
    }
    return bytes;
}

int picoquic_transport_param_cid_decode(picoquic_cnx_t * cnx, uint8_t* bytes, uint64_t extension_length, picoquic_connection_id_t* cid)
{
    int ret = 0;
    cid->id_len = (uint8_t)picoquic_parse_connection_id(bytes, (uint8_t)extension_length, cid);
    if ((size_t)cid->id_len != extension_length) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    return ret;
}

uint8_t* picoquic_encode_transport_param_prefered_address_old(uint8_t* bytes, uint8_t* bytes_max,
    picoquic_tp_prefered_address_t* prefered_address)
{
    /* first compute the length */
    uint16_t coded_length = 4u + 2u + 16u + 2u + 1u + prefered_address->connection_id.id_len + 16u;

    if (bytes == NULL || bytes + coded_length > bytes_max) {
        bytes = NULL;
    }
    else {
        picoformat_16(bytes, picoquic_tp_server_preferred_address);
        bytes += 2;
        picoformat_16(bytes, coded_length);
        bytes += 2;
        memcpy(bytes, prefered_address->ipv4Address, 4);
        bytes += 4;
        picoformat_16(bytes, prefered_address->ipv4Port);
        bytes += 2;
        memcpy(bytes, prefered_address->ipv6Address, 16);
        bytes += 16;
        picoformat_16(bytes, prefered_address->ipv4Port);
        bytes += 2;
        *bytes++ = prefered_address->connection_id.id_len;
        bytes += picoquic_format_connection_id(bytes, bytes_max - bytes,
            prefered_address->connection_id);
        memcpy(bytes, prefered_address->statelessResetToken, 16);
        bytes += 16;
    }

    return bytes;
}

uint8_t * picoquic_encode_transport_param_prefered_address(uint8_t * bytes, uint8_t * bytes_max,
    picoquic_tp_prefered_address_t * prefered_address)
{
    /* first compute the length */
    uint64_t coded_length = ((uint64_t)(4 + 2 + 16 + 2 + 1)) + prefered_address->connection_id.id_len + ((uint64_t)16);

    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_server_preferred_address)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, coded_length)) != NULL){
        if (bytes + coded_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, prefered_address->ipv4Address, 4);
            bytes += 4;
            picoformat_16(bytes, prefered_address->ipv4Port);
            bytes += 2;
            memcpy(bytes, prefered_address->ipv6Address, 16);
            bytes += 16;
            picoformat_16(bytes, prefered_address->ipv4Port);
            bytes += 2;
            *bytes++ = prefered_address->connection_id.id_len;
            bytes += picoquic_format_connection_id(bytes, bytes_max - bytes,
                prefered_address->connection_id);
            memcpy(bytes, prefered_address->statelessResetToken, 16);
            bytes += 16;
        }
    }

    return bytes;
}

size_t picoquic_decode_transport_param_prefered_address(uint8_t * bytes, size_t bytes_max,
    picoquic_tp_prefered_address_t * prefered_address)
{
    /* first compute the minimal length */
    size_t byte_index = 0;
    uint8_t cnx_id_length = 0;
    size_t minimal_length = 4u + 2u + 16u + 2u + 1u /* + prefered_address->connection_id.id_len */ + 16u;
    size_t ret = 0;

    if (bytes_max >= minimal_length) {
        memcpy(prefered_address->ipv4Address, bytes + byte_index, 4);
        byte_index += 4;
        prefered_address->ipv4Port = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        memcpy(prefered_address->ipv6Address, bytes + byte_index, 16);
        byte_index += 16;
        prefered_address->ipv6Port = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        cnx_id_length = bytes[byte_index++];
        if (cnx_id_length > 0 && cnx_id_length <= PICOQUIC_CONNECTION_ID_MAX_SIZE &&
            byte_index + (size_t)cnx_id_length + 16u <= bytes_max &&
            cnx_id_length == picoquic_parse_connection_id(bytes + byte_index, cnx_id_length,
                &prefered_address->connection_id)){
            byte_index += cnx_id_length;
            memcpy(prefered_address->statelessResetToken, bytes + byte_index, 16);
            byte_index += 16;
            ret = byte_index;
            prefered_address->is_defined = 1;
        }
    }

    return ret;
}

/* Version negotiation. This is an implementation of:
 *     https://quicwg.org/version-negotiation/draft-ietf-quic-version-negotiation.html
 * 
 * The version information parameter is defined as:
 * 
 * Version Information {
 *   Chosen Version (32),
 *   Other Versions (32) ...,
 * }
 * 
 * On the client side, the other version include the versions that the client will want
 * to upgrade to, in order of preference. Somewhere in the list is the currently chosen
 * version, to indidcate its order of preference.
 * 
 * On the server side, the other version provides the list of versions supported by the server.
 */
uint8_t* picoquic_encode_transport_param_version_negotiation(uint8_t* bytes, uint8_t* bytes_max,
    int extension_mode, picoquic_cnx_t* cnx)
{
    uint8_t* bytes_len;
    bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_version_negotiation);
    bytes_len = bytes;


    if (bytes != NULL &&
        (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, 0)) != NULL &&
        (bytes = picoquic_frames_uint32_encode(bytes, bytes_max,
            picoquic_supported_versions[cnx->version_index].version)) != NULL) {
        if (extension_mode == 0) {
            if (cnx->desired_version != 0 && cnx->desired_version != picoquic_supported_versions[cnx->version_index].version) {
                bytes = picoquic_frames_uint32_encode(bytes, bytes_max, cnx->desired_version);
            }
            if (bytes != NULL) {
                bytes = picoquic_frames_uint32_encode(bytes, bytes_max,
                    picoquic_supported_versions[cnx->version_index].version);
            }
        }
        else {
            for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
                if ((bytes = picoquic_frames_uint32_encode(bytes, bytes_max,
                    picoquic_supported_versions[i].version)) == NULL) {
                    break;
                }
            }
        }
    }

    if (bytes != NULL) {
        size_t len = bytes - (bytes_len + 2);

        if (len > 0x3FFF) {
            bytes = NULL;
        }
        else {
            bytes_len[0] = (uint8_t)((len >> 8) & 0x3f) | 0x40;
            bytes_len[1] = (uint8_t)(len & 0xff);
        }
    }

    return bytes;
}

const uint8_t * picoquic_process_tp_version_negotiation(const uint8_t* bytes, const uint8_t* bytes_max,
    int extension_mode, uint32_t envelop_vn, uint32_t *negotiated_vn, int * negotiated_index, uint64_t * vn_error)
{
    uint32_t current;

    *negotiated_vn = 0;
    *negotiated_index = -1;
    *vn_error = 0;

    if ((bytes = picoquic_frames_uint32_decode(bytes, bytes_max, &current)) == NULL) {
        *vn_error = PICOQUIC_TRANSPORT_PARAMETER_ERROR;
    } else {
        if (current != envelop_vn) {
            /* Packet was tempered with */
            *vn_error = PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR;
            bytes = NULL;
        }
        else if (extension_mode == 0) {
            /* Processing the client extensions */
            while (bytes < bytes_max) {
                uint32_t proposed;
                if ((bytes = picoquic_frames_uint32_decode(bytes, bytes_max, &proposed)) == NULL) {
                    /* Decoding error */
                    *vn_error = PICOQUIC_TRANSPORT_PARAMETER_ERROR;
                    break;
                }
                else {
                    /* Select the first version proposed by the client that is locally supported,
                     * and is deemed compatible with the current version
                     */
                    int this_rank = picoquic_get_version_index(proposed);
                    if (this_rank >= 0) {
                        *negotiated_vn = proposed;
                        *negotiated_index = this_rank;
                        break;
                    }
                }
            }
        }
        else {
            /* Processing the server extensions */
            /* TODO: Check whether the chosen version corresponds to something the client wanted */
            /* TODO: Check whether the chosen version is officially supported, could be reused in 0-RTT */
            while (bytes < bytes_max) {
                uint32_t proposed;
                if ((bytes = picoquic_frames_uint32_decode(bytes, bytes_max, &proposed)) == NULL) {
                    /* Decoding error */
                    *vn_error = PICOQUIC_TRANSPORT_PARAMETER_ERROR;
                    break;
                }
            }
        }
    }

    return bytes;
}

int picoquic_negotiate_multipath_option(picoquic_cnx_t* cnx)
{
    int ret = 0;

    cnx->is_multipath_enabled = 0;

    if (cnx->remote_parameters.is_multipath_enabled &&
        cnx->local_parameters.is_multipath_enabled) {
        /* Enable the multipath option */
        cnx->is_multipath_enabled = 1;
        cnx->max_path_id_acknowledged = cnx->local_parameters.initial_max_path_id;
        cnx->max_path_id_remote = cnx->remote_parameters.initial_max_path_id;
        cnx->max_path_id_local = cnx->local_parameters.initial_max_path_id;
    }
    else {
        if (!cnx->client_mode) {
            cnx->local_parameters.is_multipath_enabled = 0;
        } 
    }

    return ret;
}

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_length, size_t* consumed)
{
    int ret = 0;
    uint8_t* bytes_zero = bytes;
    uint8_t* bytes_max = bytes + bytes_length;

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_bidi_local,
        cnx->local_parameters.initial_max_stream_data_bidi_local);

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_data,
        cnx->local_parameters.initial_max_data);

    if (cnx->local_parameters.initial_max_stream_id_bidir > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_streams_bidi,
            cnx->local_parameters.initial_max_stream_id_bidir);
    }

    if (cnx->local_parameters.max_idle_timeout > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_idle_timeout,
            cnx->local_parameters.max_idle_timeout);
    }

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_packet_size,
        cnx->local_parameters.max_packet_size);

    if (cnx->local_parameters.ack_delay_exponent != 3) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_ack_delay_exponent,
            cnx->local_parameters.ack_delay_exponent);
    }

    if (cnx->local_parameters.initial_max_stream_id_unidir > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_streams_uni,
            cnx->local_parameters.initial_max_stream_id_unidir);
    }

    if (cnx->local_parameters.prefered_address.is_defined) {
        bytes = picoquic_encode_transport_param_prefered_address(
            bytes, bytes_max, &cnx->local_parameters.prefered_address);
    }

    if (cnx->local_parameters.migration_disabled != 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_flag_encode(bytes, bytes_max, picoquic_tp_disable_migration);
    }

    if (cnx->local_parameters.initial_max_stream_data_bidi_remote > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_bidi_remote,
            cnx->local_parameters.initial_max_stream_data_bidi_remote);
    }

    if (cnx->local_parameters.initial_max_stream_data_uni > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_uni,
            cnx->local_parameters.initial_max_stream_data_uni);
    }

    if (cnx->local_parameters.active_connection_id_limit > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_active_connection_id_limit,
            cnx->local_parameters.active_connection_id_limit);
    }

    if (cnx->local_parameters.max_ack_delay != PICOQUIC_ACK_DELAY_MAX_DEFAULT) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_ack_delay,
            (cnx->local_parameters.max_ack_delay + 999) / 1000); /* Max ACK delay in milliseconds */
    }
    bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_handshake_connection_id, &cnx->path[0]->p_local_cnxid->cnx_id);

    if (extension_mode == 1){
        if (cnx->original_cnxid.id_len > 0) {
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_original_connection_id, &cnx->original_cnxid);
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_retry_connection_id, &cnx->initial_cnxid);
        }
        else if (cnx->is_hcid_verified) {
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_original_connection_id, &cnx->initial_cnxid);
        }
    }

    if (extension_mode == 1) {
        if (bytes != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_stateless_reset_token)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE)) != NULL) {
            if (bytes + PICOQUIC_RESET_SECRET_SIZE < bytes_max) {
                (void)picoquic_create_cnxid_reset_secret(cnx->quic, &cnx->path[0]->p_local_cnxid->cnx_id, bytes);
                bytes += PICOQUIC_RESET_SECRET_SIZE;
            }
            else {
                bytes = NULL;
            }
        }
    }

    if (!cnx->client_mode && cnx->local_parameters.max_datagram_frame_size == 0 &&
        cnx->remote_parameters.max_datagram_frame_size > 0) {
        cnx->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }

    if (cnx->local_parameters.max_datagram_frame_size > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_datagram_frame_size,
            cnx->local_parameters.max_datagram_frame_size);
    }

    if (cnx->grease_transport_parameters) {
        /* Do not use a purely random value, so we can repetitive tests */
        int n = 31 * (cnx->initial_cnxid.id[0] + cnx->client_mode) + 27;
        uint64_t v = cnx->initial_cnxid.id[1];
        while (n == picoquic_tp_test_large_chello) {
            n += 31;
        }
        v = (v << 8) + cnx->initial_cnxid.id[2];
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, n, v);
    }

    if (cnx->test_large_chello && bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_test_large_chello)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, 1200)) != NULL){
        if (bytes + 1200 > bytes_max) {
            bytes = NULL;
        }
        else {
            memset(bytes, 'Q', 1200);
            bytes += 1200;
        }
    }

    if (cnx->local_parameters.enable_loss_bit > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_enable_loss_bit,
            (cnx->local_parameters.enable_loss_bit > 1) ? 1 : 0);
    }

    if (bytes != NULL && cnx->local_parameters.min_ack_delay > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_min_ack_delay,
            cnx->local_parameters.min_ack_delay);
    }

    if (cnx->local_parameters.enable_time_stamp > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_enable_time_stamp,
            cnx->local_parameters.enable_time_stamp);
    }

    if (cnx->local_parameters.do_grease_quic_bit && bytes != NULL) {
        bytes = picoquic_transport_param_type_flag_encode(bytes, bytes_max, picoquic_tp_grease_quic_bit);
    }

    if (cnx->do_version_negotiation && bytes != NULL) {
        bytes = picoquic_encode_transport_param_version_negotiation(bytes, bytes_max, extension_mode, cnx);
    }

    if (cnx->local_parameters.enable_bdp_frame > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_enable_bdp_frame,
            (uint64_t)cnx->local_parameters.enable_bdp_frame);
    }

    if (cnx->local_parameters.is_multipath_enabled > 0 && bytes != NULL){
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, 
            picoquic_tp_initial_max_path_id,
            (uint64_t)cnx->local_parameters.initial_max_path_id);
    }

    if (cnx->local_parameters.address_discovery_mode > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max,
            picoquic_tp_address_discovery,
            (uint64_t)(cnx->local_parameters.address_discovery_mode - 1));
    }

    /* This test extension must be the last one in the encoding, as it consumes all the available space */
    if (extension_mode == 1 && !cnx->test_large_chello &&
        cnx->quic->test_large_server_flight && bytes != NULL){
        size_t available = bytes_max - bytes;
        size_t pad_length = (available > 24) ? available - 24 : 1;

        if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_test_large_chello)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, pad_length)) != NULL) {
            if (bytes + pad_length > bytes_max) {
                bytes = NULL;
            }
            else {
                memset(bytes, 'Q', pad_length);
                bytes += pad_length;
            }
        }
    }

    if (bytes == NULL) {
        *consumed = 0;
        ret = PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL;
    }
    else {
        *consumed = bytes - bytes_zero;
        picoquic_log_transport_extension(cnx, 1, *consumed, bytes_zero);
    }

    return ret;
}

void picoquic_clear_transport_extensions(picoquic_cnx_t* cnx)
{
    cnx->remote_parameters.initial_max_stream_data_bidi_local = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_stream_data_bidi_remote = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_stream_data_uni = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_data = 0;
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->remote_parameters.initial_max_stream_id_bidir = 0;
    cnx->max_stream_id_bidir_remote = 0;
    cnx->remote_parameters.max_idle_timeout = 0;
    cnx->remote_parameters.max_packet_size = 1500;
    cnx->remote_parameters.ack_delay_exponent = 3;
    cnx->remote_parameters.initial_max_stream_id_unidir = 0;
    cnx->max_stream_id_unidir_remote = 0;
    cnx->remote_parameters.migration_disabled = 0;
    cnx->remote_parameters.max_ack_delay = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
    cnx->remote_parameters.max_datagram_frame_size = 0;
    cnx->remote_parameters.active_connection_id_limit = 0;
    cnx->remote_parameters.enable_loss_bit = 0;
    cnx->remote_parameters.enable_time_stamp = 0;
    cnx->remote_parameters.min_ack_delay = 0;
    cnx->remote_parameters.do_grease_quic_bit = 0;
    cnx->remote_parameters.enable_bdp_frame = 0;
    cnx->remote_parameters.initial_max_path_id = 0;
}

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t present_flag = 0;
    picoquic_connection_id_t original_connection_id = picoquic_null_connection_id;
    picoquic_connection_id_t handshake_connection_id = picoquic_null_connection_id;
    picoquic_connection_id_t retry_connection_id = picoquic_null_connection_id;

    cnx->remote_parameters_received = 1;
    picoquic_clear_transport_extensions(cnx);

    picoquic_log_transport_extension(cnx, 0, bytes_max, bytes);

    /* Set the parameters to default value zero */
    memset(&cnx->remote_parameters, 0, sizeof(picoquic_tp_t));
    /* Except for ack_delay_exponent, whose default is 3 */
    cnx->remote_parameters.ack_delay_exponent = 3;

    while (ret == 0 && byte_index < bytes_max) {
        size_t ll_type = 0;
        size_t ll_length = 0;
        uint64_t extension_type = UINT64_MAX;
        uint64_t extension_length = 0;

        if (byte_index + 2 > bytes_max) {
            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "TP length");
        }
        else {
            ll_type = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_type);
            byte_index += ll_type;
            ll_length = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_length);
            byte_index += ll_length;

            if (ll_type == 0 || ll_length == 0 || byte_index + extension_length > bytes_max) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
            }
            else {
                if (extension_type < 64) {
                    if ((present_flag & (1ull << extension_type)) != 0) {
                        /* Malformed, already present */
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Malformed TP");
                    }
                    else {
                        present_flag |= (1ull << extension_type);
                    }
                }

                switch (extension_type) {
                case picoquic_tp_initial_max_stream_data_bidi_local:
                    cnx->remote_parameters.initial_max_stream_data_bidi_local =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);

                    /* If we sent zero rtt data, the streams were created with the
                     * old value of the remote parameter. We need to update that.
                     */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_stream_data_bidi_remote:
                    cnx->remote_parameters.initial_max_stream_data_bidi_remote =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* If we sent zero rtt data, the streams were created with the
                    * old value of the remote parameter. We need to update that.
                    */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_stream_data_uni:
                    cnx->remote_parameters.initial_max_stream_data_uni =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* If we sent zero rtt data, the streams were created with the
                    * old value of the remote parameter. We need to update that.
                    */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_data:
                    cnx->remote_parameters.initial_max_data =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
                    break;
                case picoquic_tp_initial_max_streams_bidi: {
                    uint64_t old_limit = cnx->max_stream_id_bidir_remote;
                    cnx->remote_parameters.initial_max_stream_id_bidir =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    cnx->max_stream_id_bidir_remote = STREAM_ID_FROM_RANK(
                        (cnx->remote_parameters.initial_max_stream_id_bidir == 0xFFFFFFFF) ? 0 : cnx->remote_parameters.initial_max_stream_id_bidir,
                        cnx->client_mode, 0);
                    cnx->max_stream_data_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                    picoquic_add_output_streams(cnx, old_limit, cnx->max_stream_id_bidir_remote, 1);
                    break;
                }
                case picoquic_tp_idle_timeout:
                    cnx->remote_parameters.max_idle_timeout = 
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;

                case picoquic_tp_max_packet_size: {
                    /* The default for this parameter is the maximum permitted UDP payload of 65527. Values below 1200 are invalid. */
                    uint64_t max_packet_size = picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    if (ret == 0){
                        if (max_packet_size < PICOQUIC_ENFORCED_INITIAL_MTU || max_packet_size > 65527) {
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Max packet size TP");
                        }
                        else {
                            cnx->remote_parameters.max_packet_size = (uint32_t)max_packet_size;
                        }
                    }
                    break;
                }
                case picoquic_tp_stateless_reset_token:
                    if (extension_mode != 1) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Reset token from client");
                    }
                    else if (extension_length != PICOQUIC_RESET_SECRET_SIZE) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Reset token TP");
                    }
                    else {
                        memcpy(cnx->path[0]->p_remote_cnxid->reset_secret, bytes + byte_index, PICOQUIC_RESET_SECRET_SIZE);
                    }
                    break;
                case picoquic_tp_ack_delay_exponent:
                    cnx->remote_parameters.ack_delay_exponent = (uint8_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                case picoquic_tp_initial_max_streams_uni: {
                    uint64_t old_limit = cnx->max_stream_id_unidir_remote;
                    cnx->remote_parameters.initial_max_stream_id_unidir =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    cnx->max_stream_id_unidir_remote = STREAM_ID_FROM_RANK(
                        (cnx->remote_parameters.initial_max_stream_id_unidir == 0xFFFFFFFF) ? 0 : cnx->remote_parameters.initial_max_stream_id_unidir,
                        cnx->client_mode, 1);
                    picoquic_add_output_streams(cnx, old_limit, cnx->max_stream_id_unidir_remote, 0);
                    break;
                }
                case picoquic_tp_server_preferred_address:
                {
                    uint64_t coded_length = picoquic_decode_transport_param_prefered_address(
                        bytes + byte_index, (size_t)extension_length, &cnx->remote_parameters.prefered_address);

                    if (coded_length != extension_length) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Preferred address TP");
                    }
                    break;
                }
                case picoquic_tp_disable_migration:
                    if (extension_length != 0) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Disable migration TP");
                    }
                    else {
                        cnx->remote_parameters.migration_disabled = 1;
                    }
                    break;
                case picoquic_tp_max_ack_delay:
                    cnx->remote_parameters.max_ack_delay = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret) * 1000;
                    if (cnx->remote_parameters.max_ack_delay > PICOQUIC_MAX_ACK_DELAY_MAX_MS * 1000) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Max ack delay TP");
                    }
                    break;
                case picoquic_tp_original_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &original_connection_id);
                    break;
                case picoquic_tp_retry_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &retry_connection_id);
                    break;
                case picoquic_tp_handshake_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &handshake_connection_id);
                    if (ret == 0) {
                        if (picoquic_compare_connection_id(&cnx->path[0]->p_remote_cnxid->cnx_id, &handshake_connection_id) != 0) {
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "HCID check");
                        }
                        else {
                            cnx->is_hcid_verified = 1;
                        }
                    }
                    break;
                case picoquic_tp_active_connection_id_limit:
                    cnx->remote_parameters.active_connection_id_limit = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* TODO: may need to check the value, but conditions are unclear */
                    break;
                case picoquic_tp_max_datagram_frame_size:
                    cnx->remote_parameters.max_datagram_frame_size = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                case picoquic_tp_enable_loss_bit: {
                    uint64_t enabled = picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    if (ret == 0) {
                        if (enabled == 0) {
                            /* Send only variant of loss bit */
                            cnx->remote_parameters.enable_loss_bit = 1;
                        }
                        else if (enabled == 1) {
                            /* Both send and receive are enabled */
                            cnx->remote_parameters.enable_loss_bit = 2;
                        }
                        else {
                            /* Only values 0 and 1 are expected */
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Loss bit TP");
                        }
                    }
                    break;
                }
                case picoquic_tp_min_ack_delay:
                    cnx->remote_parameters.min_ack_delay =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* Values of 0 and values larger that 2^24 are not expected */
                    if (ret == 0 &&
                        (cnx->remote_parameters.min_ack_delay == 0 ||
                            cnx->remote_parameters.min_ack_delay > PICOQUIC_ACK_DELAY_MIN_MAX_VALUE)) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0, "Min ack delay TP");
                    }
                    else {
                        if (cnx->local_parameters.min_ack_delay > 0) {
                            cnx->is_ack_frequency_negotiated = 1;
                        }
                    }
                    break;
                case picoquic_tp_enable_time_stamp: {
                    uint64_t tp_time_stamp =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);

                    if (ret == 0) {
                        if (tp_time_stamp < 1 || tp_time_stamp > 3) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        else {
                            cnx->remote_parameters.enable_time_stamp = (int)tp_time_stamp;
                        }
                    }
                    break;
                }
                case picoquic_tp_grease_quic_bit:
                    if (extension_length != 0) {
                        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Grease TP");
                    }
                    else {
                        cnx->remote_parameters.do_grease_quic_bit = 1;
                    }
                    break;
                case picoquic_tp_initial_max_path_id: {
                    cnx->remote_parameters.is_multipath_enabled = 1;
                    cnx->remote_parameters.initial_max_path_id = 
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                }

                case picoquic_tp_version_negotiation: {
                    uint64_t error_found;
                    uint32_t negotiated_vn;
                    int negotiated_index;
                    const uint8_t* final = picoquic_process_tp_version_negotiation(bytes + byte_index,
                        bytes + byte_index + extension_length, extension_mode,
                        picoquic_supported_versions[cnx->version_index].version,
                        &negotiated_vn, &negotiated_index, &error_found);
                    if (final == NULL) {
                        ret = picoquic_connection_error_ex(cnx, error_found, 0, "V. Negotiation TP");
                    }
                    else {
                        cnx->do_version_negotiation = 1;
                        if (negotiated_vn != 0 && cnx->version_index != negotiated_index){
                            ret = picoquic_process_version_upgrade(cnx, cnx->version_index, negotiated_index);
                        }
                    }
                    break;
                }
                case picoquic_tp_enable_bdp_frame: {
                    uint64_t enable_bdp =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    if (ret == 0) {
                        if (enable_bdp > 1) {
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "BDP parameter");
                        }
                        else {
                            cnx->remote_parameters.enable_bdp_frame = (int)enable_bdp;
                        }
                    }
                    break;
                }
                case picoquic_tp_address_discovery: {
                    uint64_t address_discovery_mode =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    if (ret == 0) {
                        if (address_discovery_mode > 2) {
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "Address discovery parameter");
                        }
                        else {
                            /* After doing +1, we get the following:
                            * address_discovery_mode == 0: nothing goes (TP is absent)
                            * address_discovery_mode == 1: send only (TP value 0)
                            * address_discovery_mode == 2: receive only (TP value 1)
                            * address_discovery_mode == 3: both (TP value 2)
                            */
                            cnx->remote_parameters.address_discovery_mode = (int)(address_discovery_mode + 1);
                            cnx->is_address_discovery_provider = ((cnx->remote_parameters.address_discovery_mode & 2) != 0 &&
                                (cnx->local_parameters.address_discovery_mode & 1) != 0);
                            cnx->is_address_discovery_receiver = ((cnx->remote_parameters.address_discovery_mode & 1) != 0 &&
                                (cnx->local_parameters.address_discovery_mode & 2) != 0);
                        }
                    }
                    break;
                }
                default:
                    /* ignore unknown extensions */
                    break;
                }

                if (ret == 0) {
                    byte_index += (size_t)extension_length;
                }
            }
        }
    }

    /* Compute the negotiated version of the time out.
     * The parameter values are expressed in milliseconds,
     * but the connection context variable is in microseconds.
     * If the keep alive interval was set to a too short value,
     * reset it.
     */
    cnx->idle_timeout = cnx->local_parameters.max_idle_timeout*1000ull;
    if (cnx->local_parameters.max_idle_timeout == 0 ||
        (cnx->remote_parameters.max_idle_timeout > 0 && cnx->remote_parameters.max_idle_timeout < 
            cnx->local_parameters.max_idle_timeout)) {
        cnx->idle_timeout = cnx->remote_parameters.max_idle_timeout*1000ull;
    }
    if (cnx->idle_timeout == 0) {
        cnx->idle_timeout = UINT64_MAX;
    }
    else if (cnx->keep_alive_interval != 0 &&
        cnx->keep_alive_interval > cnx->idle_timeout / 2) {
        cnx->keep_alive_interval = cnx->idle_timeout / 2;
    }

    if (ret == 0 && (present_flag & (1ull << picoquic_tp_max_ack_delay)) == 0) {
        cnx->remote_parameters.max_ack_delay = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
    }

    if (ret == 0 && (present_flag & (1ull << picoquic_tp_active_connection_id_limit)) == 0) {
        if (cnx->path[0]->p_local_cnxid->cnx_id.id_len == 0) {
            cnx->remote_parameters.active_connection_id_limit = 0;
        }
        else {
            cnx->remote_parameters.active_connection_id_limit = PICOQUIC_NB_PATH_DEFAULT;
        }
    }

    /* Clients must not include reset token, server address, retry cid or original cid  */

    if (ret == 0 && extension_mode == 0 &&
        ((present_flag & (1ull << picoquic_tp_stateless_reset_token)) != 0 ||
        (present_flag & (1ull << picoquic_tp_server_preferred_address)) != 0 ||
            (present_flag & (1ull << picoquic_tp_original_connection_id)) != 0 ||
            (present_flag & (1ull << picoquic_tp_retry_connection_id)) != 0)) {
        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "T. Param. unexpected on client");
    }

    /* In the old versions, there was only one parameter: original CID. In the new versions,
     * there are also retry CID and handshake CID, and the verification logic changed. 
     * If the new extensions are not used and the version is old, we support the
     * old behavior. If the HCID extension is present, we support the new behavior.
     * Most of the verifications happen on the client side, upon receiving server
     * parameters. 
     * TODO: clean up when removing support for version 27.
     */

    if (ret == 0 && picoquic_supported_versions[cnx->version_index].version != PICOQUIC_SEVENTEENTH_INTEROP_VERSION &&
        (present_flag & (1ull << picoquic_tp_handshake_connection_id)) == 0) {
        /* HCID extension becomes mandatory after draft 27 */
        ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "HCID missing");
    }

    if (ret == 0 && extension_mode == 1) {
        /* Reeciving server parameters */
        if ((present_flag & (1ull << picoquic_tp_handshake_connection_id)) != 0) {
            /* The HCID extension is present. Verify that the original and retry cnxid are as expected */
            if (cnx->original_cnxid.id_len != 0) {
                /* OCID should be present and match original_cid.
                 * RCID should be present and match initial_cid, since token parsing
                 * verified that initial_cid matches source CID of retry packet. */
                if ((present_flag & (1ull << picoquic_tp_retry_connection_id)) == 0 ||
                    (present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->original_cnxid, &original_connection_id) != 0 ||
                    picoquic_compare_connection_id(&cnx->initial_cnxid, &retry_connection_id) != 0) {
                    ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "OCID verification");
                }
            }
            else {
                /* RCID should not be present, OCID should be present and match initial_cid */
                if ((present_flag & (1ull << picoquic_tp_retry_connection_id)) != 0 ||
                    (present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->initial_cnxid, &original_connection_id) != 0) {
                    ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "HCID or no OCID");
                }
            }
        }
        else  if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_SEVENTEENTH_INTEROP_VERSION) {
            /* Old behavior. Original CID only present if retry */
            if (cnx->original_cnxid.id_len != 0 &&
                ((present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->original_cnxid, &original_connection_id) != 0)) {
                ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0, "old draft version");
            }
        }
    }

    if (ret == 0) {
        /* Negotiate the multipath option */
        ret = picoquic_negotiate_multipath_option(cnx);
    }

    /* Loss bit is only enabled if negotiated by both parties */
    cnx->is_loss_bit_enabled_outgoing = (cnx->local_parameters.enable_loss_bit > 1) && (cnx->remote_parameters.enable_loss_bit > 0);
    cnx->is_loss_bit_enabled_incoming = (cnx->local_parameters.enable_loss_bit > 0) && (cnx->remote_parameters.enable_loss_bit > 1);

    /* Send-receive BDP frame is only enabled if negotiated by both parties */
    cnx->send_receive_bdp_frame = (cnx->local_parameters.enable_bdp_frame > 0) && (cnx->remote_parameters.enable_bdp_frame > 0);

    /* One way delay, Quic_bit_grease and Multipath only enabled if asked by client and accepted by server */
    if (cnx->client_mode) {
        cnx->is_time_stamp_enabled = 
            (cnx->local_parameters.enable_time_stamp&1) && (cnx->remote_parameters.enable_time_stamp&2);
        cnx->is_time_stamp_sent =
            (cnx->local_parameters.enable_time_stamp & 2) && (cnx->remote_parameters.enable_time_stamp & 1);
        cnx->do_grease_quic_bit = cnx->local_parameters.do_grease_quic_bit && cnx->remote_parameters.do_grease_quic_bit;
    }
    else
    {
        if (cnx->remote_parameters.enable_time_stamp) {
            int v_local = 0;
            if (cnx->remote_parameters.enable_time_stamp & 1) {
                /* Peer wants TS. Say that we can send. */
                v_local |= 2;
                cnx->is_time_stamp_sent = 1;
            }
            if (cnx->remote_parameters.enable_time_stamp & 2) {
                /* Peer can do TS. Say that we want to receive. */
                v_local |= 1;
                cnx->is_time_stamp_enabled = 1;
            }
            cnx->local_parameters.enable_time_stamp = v_local;
        }
        /* When the one way option is set, the server will grease the quic bit if the client supports that,
         * but will not announce support of the grease quic bit, thus asking the client to not set it */
        cnx->local_parameters.do_grease_quic_bit = cnx->remote_parameters.do_grease_quic_bit && !cnx->quic->one_way_grease_quic_bit;
        cnx->do_grease_quic_bit = cnx->remote_parameters.do_grease_quic_bit;
    }

    /* ACK Frequency is only enabled on server if negotiated by client */
    if (!cnx->client_mode && !cnx->is_ack_frequency_negotiated) {
        cnx->local_parameters.min_ack_delay = 0;
    }

    *consumed = byte_index;

    return ret;
}
