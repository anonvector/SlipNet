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

/* This file contains a set of tests copied from the "QUIC Tester"
*/


#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"
#include "autoqlog.h"

/* Wait until handshake key is ready */
int tester_wait_handshake_key(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;
    int was_active = 0;

    while (*simulated_time < time_out &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        ret == 0) {
        was_active = 0;
        nb_trials++;
        
        if (test_ctx->cnx_client->cnx_state >= picoquic_state_client_handshake_start &&
            test_ctx->cnx_client->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL) {
            break;
        }

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
            *simulated_time += 1000;
        }
        else {
            nb_inactive++;
        }
    }

    return ret;
}
/* Format a minimalistic ACK frame
 */
size_t tester_simple_ack_frame(uint8_t* bytes, size_t bytes_size, uint64_t last_packet_number)
{
    size_t length = 0;
    uint8_t* bytes_max = bytes + bytes_size;
    uint8_t* bytes_first = bytes;

    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_frame_type_ack)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, last_packet_number)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, 0 /* ack delay */)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, 0 /* range count */)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, 0 /* first ack range */)) != NULL) {
        length = bytes - bytes_first;
    }
    return length;
}


/* Forcefully insert a packet in the client flow
 */

picoquic_packet_t* tester_init_packet(picoquic_cnx_t* cnx, picoquic_packet_type_enum ptype)
{
    picoquic_packet_t* packet = picoquic_create_packet(cnx->quic);

    if (packet != NULL) {
        packet->checksum_overhead = 16;
        packet->ptype = ptype;
        switch (ptype) {
        case picoquic_packet_initial:
            packet->pc = picoquic_packet_context_initial;
            break;
        case picoquic_packet_handshake:
            packet->pc = picoquic_packet_context_handshake;
            break;
        case picoquic_packet_0rtt_protected:
            packet->pc = picoquic_packet_context_application;
            break;
        case picoquic_packet_1rtt_protected:
            packet->pc = picoquic_packet_context_application;
            break;
        default:
            picoquic_recycle_packet(cnx->quic, packet);
            break;
        }
    }
    if (packet != NULL) {
        packet->offset = picoquic_predict_packet_header_length(cnx, ptype, &cnx->pkt_ctx[packet->pc]);
        packet->length = packet->offset;
        packet->send_path = cnx->path[0];
    }
    return (packet);
}

void tester_add_frame(picoquic_packet_t* packet, uint8_t* frame, size_t frame_length)
{
    if (packet->length + frame_length < sizeof(packet->bytes)) {
        memcpy(&packet->bytes[packet->length], frame, frame_length);
        packet->length += frame_length;
    }
}

void tester_finalize_packet(picoquic_cnx_t* cnx,
    picoquic_packet_t* packet, size_t length, uint64_t current_time,
    size_t* send_length,
    uint8_t* send_buffer, size_t send_buffer_max)
{
    picoquic_path_t* path_x = cnx->path[0];
    packet->length = length;

    picoquic_finalize_and_protect_packet(cnx, packet,
        0, length, packet->offset, packet->checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        path_x, current_time);
}

int tester_push_frame_packet(picoquic_test_tls_api_ctx_t* test_ctx,
    picoquic_packet_type_enum ptype, uint8_t* frame, size_t frame_length,
    int shall_pad, int shall_queue, uint64_t current_time)
{
    int ret = 0;
    picoquic_packet_t* packet = tester_init_packet(test_ctx->cnx_client,
        ptype);

    if (packet == NULL) {
        ret = -1;
    }
    else {
        tester_add_frame(packet, frame, frame_length);
    }

    if (shall_pad) {
        packet->length = picoquic_pad_to_target_length(
            packet->bytes, packet->length,
            packet->send_path->send_mtu - packet->checksum_overhead);
    }

    if (ret == 0) {
        picoquictest_sim_packet_t* sim_packet = picoquictest_sim_link_create_packet();

        if (sim_packet != NULL) {
            uint8_t* send_buffer = sim_packet->bytes;
            size_t send_length = 0;

            tester_finalize_packet(test_ctx->cnx_client,
                packet, packet->length, current_time,
                &send_length, send_buffer, PICOQUIC_MAX_PACKET_SIZE);

            if (shall_queue) {
                picoquic_store_addr(&sim_packet->addr_from, (struct sockaddr*)&test_ctx->client_addr);
                picoquic_store_addr(&sim_packet->addr_to, (struct sockaddr*)&test_ctx->server_addr);
                sim_packet->ecn_mark = test_ctx->packet_ecn_default;
                sim_packet->length = send_length;
                picoquictest_sim_link_submit(test_ctx->c_to_s_link, sim_packet, current_time);
            }
            else {
                picoquic_incoming_packet(test_ctx->qserver, send_buffer, send_length,
                    (struct sockaddr*)&test_ctx->client_addr, (struct sockaddr*)&test_ctx->server_addr, 0,
                    0, current_time);
                free(sim_packet);
            }
        }
    }
    return ret;
}

/*
Initial ping test.
The QUIC tester sends a "ping" frame before sending the
client hello. The test checks what happens, whether the
server responds properly, or at all.
*/

int initial_ping_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint8_t ping_frame[1] = { 1 };
    picoquic_connection_id_t initial_cid = { {0x4e, 0x54, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else {
        picoquic_set_qlog(test_ctx->qserver, ".");
    }

    /*
    Insert a ping frame at the client, pass it to the server.
    */
    if (ret == 0) {
        ret = tester_push_frame_packet(test_ctx,
            picoquic_packet_initial,
            ping_frame, sizeof(ping_frame),
            1, 0, simulated_time);
    }

    /*
    * Finish the test
    */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_test_with_loss_final(test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
Initial ping and ack test.
The QUIC tester sends a "ping" frame before sending the
client hello. Then, it sends an initial ACK and a handshake ACK
as soon as the server hello has been received.

The test checks what happens, whether the
server responds properly, or at all.
*/

int initial_ping_ack_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint8_t ping_frame[1] = { 1 };
    picoquic_connection_id_t initial_cid = { {0x4e, 0x54, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else {
        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->s_to_c_link->microsec_latency = 1;
        test_ctx->c_to_s_link->microsec_latency = 1;
    }

    /*
    Insert a ping frame at the client, pass it to the server.
    */
    if (ret == 0) {
        ret = tester_push_frame_packet(test_ctx,
            picoquic_packet_initial,
            ping_frame, sizeof(ping_frame),
            1, 1, simulated_time);
    }

    /*
    * Wait until the server hello has been received and the handshake key has
    * been computed.
    */
    if (ret == 0) {
        ret = tester_wait_handshake_key(test_ctx, &simulated_time);
    }

    /* Insert Initial ACK packet as specified in issue report. */

    if (ret == 0) {
        uint8_t ack_frame[128];
        size_t ack_frame_length = tester_simple_ack_frame(ack_frame, sizeof(ack_frame), 1);

        ret = tester_push_frame_packet(test_ctx, picoquic_packet_initial,
            ack_frame, ack_frame_length, 1, 0, simulated_time);
    }

    /* Insert Handshake ack packets, as specified.
     */
    if (ret == 0) {
        uint8_t ack_frame[128];
        size_t ack_frame_length = tester_simple_ack_frame(ack_frame, sizeof(ack_frame), 1);
        ret = tester_push_frame_packet(test_ctx, picoquic_packet_handshake,
            ack_frame, ack_frame_length, 0, 0, simulated_time);
    }

    /*
    * Finish the test
    */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_test_with_loss_final(test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}