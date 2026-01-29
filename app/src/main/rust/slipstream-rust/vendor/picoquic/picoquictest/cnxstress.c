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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <picotls.h>
#include "picoquic_utils.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <signal.h>
#endif

#define CNX_STRESS_ALPN "cnxstress"

typedef struct st_cnx_stress_stream_ctx_t {
    /* For receive streams, just look at the first 16 bytes,
     * ignore the following until everything is received 
     * For send streams, send the first bytes, followed by
     * random or fixed data up to message size. */
    struct st_cnx_stress_stream_ctx_t* previous_stream;
    struct st_cnx_stress_stream_ctx_t* next_stream;
    uint64_t stream_id;
    uint64_t send_time;
    uint64_t nb_bytes_expected;
    uint64_t nb_bytes_received;
    uint64_t nb_bytes_sent;
} cnx_stress_stream_ctx_t;

typedef struct st_cnx_stress_callback_ctx_t {
    struct st_cnx_stress_ctx_t* stress_ctx;
    picoquic_cnx_t* cnx;
    uint64_t next_stream_send;
    int mode;
    int rank;
    cnx_stress_stream_ctx_t* first_stream;
    cnx_stress_stream_ctx_t* last_stream;
} cnx_stress_callback_ctx_t;

typedef enum {
    cnx_stress_event_none = 0,
    cnx_stress_event_new_message,
    cnx_stress_event_client_creation,
    cnx_stress_event_client_removal,
    cnx_stress_event_client_arrival,
    cnx_stress_event_client_prepare,
    cnx_stress_event_server_arrival,
    cnx_stress_event_server_prepare
} cnx_stress_event_enum;

typedef struct st_cnx_stress_ctx_t {
    uint64_t simulated_time;
    uint64_t random_ctx;
    picoquic_quic_t* qserver;
    picoquic_quic_t* qclient;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    picoquictest_sim_link_t* link_to_clients;
    picoquictest_sim_link_t* link_to_server;
    int is_limit_test;
    int limit_test_got_server_busy;
    int nb_clients;
    int nb_servers;
    int nb_client_target;
    int nb_clients_deleted;
    uint64_t client_creation_interval;
    uint64_t next_client_creation_time;
    uint64_t client_deletion_interval;
    uint64_t next_client_deletion_time;
    uint64_t message_creation_interval;
    uint64_t next_message_creation_time;
    /* Statistics on message arrival delay */
    int nb_messages_target;
    size_t message_size;
    int nb_messages_sent;
    int nb_messages_errors;
    int nb_messages_received;
    int64_t sum_message_delays;
    double sum_square_message_delays;
    int64_t message_delay_min;
    int64_t message_delay_max;
    /* The array of client and server contexts are created with size "nb_client target"
     * during the initialization of the test. The variables nb_clients and nb_servers
     * hold the number of clients and servers actually created. */
    cnx_stress_callback_ctx_t** c_ctx;
    cnx_stress_callback_ctx_t** s_ctx;
    cnx_stress_callback_ctx_t* default_ctx;
} cnx_stress_ctx_t;

#if 0
/*
 * Portable abort call, should work on Linux and Windows.
 * We deliberately do not call the ASSERT macros, becuse these
 * macros can be made no-op if compiled with NDEBUG
 */

static int stress_debug_break(int break_if_fuzzing)
{
    if (picoquic_fuzz_in_progress == 0 || break_if_fuzzing) {
#ifdef _WINDOWS
        DebugBreak();
#else
        raise(SIGTRAP);
#endif
        return -1;
    }

    return 0;
}
#endif

/* Callback context and protocol handling.
 * Nothing really special here? For message sending, assume short messages,
 * just use the write and forget API. For message receiving, process to
 * parse the message protocol in real time.
 * Stream context for receive: created when first data arrives on the stream.
 * Context accumulate the message ID from the first 8 bytes, then ignores the
 * rest of the data.
 */
cnx_stress_stream_ctx_t* cnx_stress_create_stream_context(
    cnx_stress_callback_ctx_t* cnx_ctx,
    uint64_t stream_id) {
    cnx_stress_stream_ctx_t* stream_ctx = (cnx_stress_stream_ctx_t*)malloc(sizeof(cnx_stress_stream_ctx_t));
    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(cnx_stress_stream_ctx_t));
        if (cnx_ctx->last_stream == NULL) {
            cnx_ctx->first_stream = stream_ctx;
        }
        else {
            stream_ctx->previous_stream = cnx_ctx->last_stream;
            cnx_ctx->last_stream->next_stream = stream_ctx;
        }
        cnx_ctx->last_stream = stream_ctx;
        stream_ctx->stream_id = stream_id;
    }
    return stream_ctx;
}

void cnx_stress_delete_stream_context(
    cnx_stress_callback_ctx_t* cnx_ctx, cnx_stress_stream_ctx_t* stream_ctx) {
    if (stream_ctx != NULL) {
        /* Unchain the stream context */
        if (stream_ctx == cnx_ctx->first_stream) {
            cnx_ctx->first_stream = stream_ctx->next_stream;
        }
        else {
            stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
        }
        if (stream_ctx == cnx_ctx->last_stream) {
            cnx_ctx->last_stream = stream_ctx->previous_stream;
        }
        else {
            stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
        }
        /* Remove from connection context */
        picoquic_unlink_app_stream_ctx(cnx_ctx->cnx, stream_ctx->stream_id);
        /* Release the memory */
        memset(stream_ctx, 0, sizeof(cnx_stress_stream_ctx_t));
        free(stream_ctx);
    }
}

cnx_stress_callback_ctx_t* cnx_stress_callback_create_context(cnx_stress_ctx_t * stress_ctx,
    picoquic_cnx_t* cnx, int mode) {
    cnx_stress_callback_ctx_t* cnx_ctx = (cnx_stress_callback_ctx_t*)malloc(sizeof(cnx_stress_callback_ctx_t));
    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(cnx_stress_callback_ctx_t));
        cnx_ctx->stress_ctx = stress_ctx;
        cnx_ctx->cnx = cnx;
        cnx_ctx->mode = mode;
        if (mode == 0) {
            stress_ctx->c_ctx[stress_ctx->nb_clients] = cnx_ctx;
            cnx_ctx->rank = stress_ctx->nb_clients;
            stress_ctx->nb_clients += 1;
        } else if (mode == 1) {
            cnx_ctx->stress_ctx->s_ctx[cnx_ctx->stress_ctx->nb_servers] = cnx_ctx;
            cnx_ctx->rank = cnx_ctx->stress_ctx->nb_servers;
            cnx_ctx->stress_ctx->nb_servers += 1;
        }
        else {
            /* Pseudo context, used for setting default context on server */
        }
    }
    return cnx_ctx;
}

void cnx_stress_callback_delete_context(cnx_stress_callback_ctx_t* cnx_ctx) {
    if (cnx_ctx->mode == 0) {
        if (cnx_ctx->stress_ctx->is_limit_test &&
            cnx_ctx->rank == cnx_ctx->stress_ctx->nb_client_target - 1 &&
            cnx_ctx->cnx->cnx_state == picoquic_state_disconnected &&
            cnx_ctx->cnx->remote_error == PICOQUIC_TRANSPORT_SERVER_BUSY) {
            /* This test verifies that the limit test is successful */
            cnx_ctx->stress_ctx->limit_test_got_server_busy = 1;
        }
        cnx_ctx->stress_ctx->c_ctx[cnx_ctx->rank] = NULL;
    }
    else if (cnx_ctx->mode == 1) {
        cnx_ctx->stress_ctx->s_ctx[cnx_ctx->rank] = NULL;
    }
    while (cnx_ctx->first_stream != NULL) {
        cnx_stress_delete_stream_context(cnx_ctx, cnx_ctx->last_stream);
    }
    memset(cnx_ctx, 0, sizeof(cnx_stress_callback_ctx_t));
    free(cnx_ctx);
}

int cnx_stress_callback_data(cnx_stress_callback_ctx_t* cnx_ctx,
    cnx_stress_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event)
{
    int ret = 0;
    /* If this is the first reference to the stream, create a context */
    if (stream_ctx == NULL) {
        stream_ctx = cnx_stress_create_stream_context(cnx_ctx, stream_id);
        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_set_app_stream_ctx(cnx_ctx->cnx, stream_id, stream_ctx);
        }
    }

    if (ret == 0) {
        /* Handle arrival of data on the stream: decode stream header if not yet received. */
        while (length > 0 && stream_ctx->nb_bytes_received < 8) {
            stream_ctx->send_time <<= 8;
            stream_ctx->send_time += *bytes;
            bytes++;
            length--;
            stream_ctx->nb_bytes_received++;
        }
        while (length > 0 && stream_ctx->nb_bytes_received < 16) {
            stream_ctx->nb_bytes_expected <<= 8;
            stream_ctx->nb_bytes_expected += *bytes;
            bytes++;
            length--;
            stream_ctx->nb_bytes_received++;
        }
        if (length > 0) {
            stream_ctx->nb_bytes_received += length;
        }
        /* On FIN or RESET, terminate the stream */
        if (fin_or_event == picoquic_callback_stream_fin) {
            /* If FIN received: if not enough data, record an error. Else,
             * accumulate the statistics. */
            cnx_stress_ctx_t* stress_ctx = cnx_ctx->stress_ctx;
            if (stream_ctx->nb_bytes_received < 16 ||
                stream_ctx->nb_bytes_received < stream_ctx->nb_bytes_expected) {
                /* Receive error */
                stress_ctx->nb_messages_errors++;
            }
            else {
                uint64_t time_now = picoquic_get_quic_time(cnx_ctx->cnx->quic);
                int64_t delta_t = time_now - stream_ctx->send_time;
                stress_ctx->nb_messages_received++;
                stress_ctx->sum_message_delays += delta_t;
                stress_ctx->sum_square_message_delays += ((double)delta_t) * ((double)delta_t);
                if (delta_t > stress_ctx->message_delay_max) {
                    stress_ctx->message_delay_max = delta_t;
                }
                if (delta_t < stress_ctx->message_delay_min) {
                    if (delta_t < 10000) {
                        DBG_PRINTF("Unexpected message delay; %d", (int)delta_t);
                    }
                    stress_ctx->message_delay_min = delta_t;
                }
            }
            /* Delete the stream context */
            cnx_stress_delete_stream_context(cnx_ctx, stream_ctx);
        }
    }

    return ret;
}

int cnx_stress_callback_prepare_to_send(cnx_stress_callback_ctx_t* cnx_ctx,
    cnx_stress_stream_ctx_t* stream_ctx, uint64_t stream_id,
    void* context, size_t length)
{
    int ret = 0;
    size_t data_length = length;
    uint8_t* buffer;
    int is_fin = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(stream_id);
#endif
    /* Compute the number of bytes that can be sent */
    if (stream_ctx->nb_bytes_sent + data_length >= stream_ctx->nb_bytes_expected) {
        data_length = (size_t)(stream_ctx->nb_bytes_expected - stream_ctx->nb_bytes_sent);
        is_fin = 1;
    }
    buffer = picoquic_provide_stream_data_buffer(context, data_length, is_fin, !is_fin);
    
    if (buffer != NULL) {
        /* If the first 16 bytes have not been sent yet, send the header */
        while (data_length > 0 && stream_ctx->nb_bytes_sent < 8) {
            *buffer = (uint8_t)((stream_ctx->send_time >> (8 * (7 - stream_ctx->nb_bytes_sent))) & 0xff);
            buffer++; 
            stream_ctx->nb_bytes_sent++;
            data_length--;
        }
        while (data_length > 0 && stream_ctx->nb_bytes_sent < 16) {
            *buffer = (uint8_t)((stream_ctx->nb_bytes_expected >> (8 * (15 - stream_ctx->nb_bytes_sent))) & 0xff);
            buffer++;
            stream_ctx->nb_bytes_sent++;
            data_length--;
        }
        /* Fill the reminder with data */
        if (data_length > 0) {
            memset(buffer, 'z', data_length);
        }

        if (is_fin) {
            /* delete the stream context */
            cnx_stress_delete_stream_context(cnx_ctx, stream_ctx);
        }
    }
    else {
        ret = -1;
    }

    return ret;
}

int cnx_stress_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    cnx_stress_callback_ctx_t* cnx_ctx = (cnx_stress_callback_ctx_t*)callback_ctx;
    cnx_stress_stream_ctx_t* stream_ctx = (cnx_stress_stream_ctx_t*)v_stream_ctx;

    if (cnx_ctx == NULL) {
        /* Unexpected error: for the clients the contexts are created by the
         * application before starting the connection. For the server, the
         * connections are created with a default context */
        picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        return -1;
    }
    else if (cnx_ctx->cnx == NULL) {
        if (fin_or_event == picoquic_callback_stateless_reset ||
            fin_or_event == picoquic_callback_close ||
            fin_or_event == picoquic_callback_application_close) {
            /* Nothing to do */
            return 0;
        }
        else {
            /* In the case of server connections, the connection is NULL for the
             * default context. It should be initialized with a proper context */
            cnx_ctx = cnx_stress_callback_create_context(cnx_ctx->stress_ctx, cnx, 1);
            if (cnx_ctx == NULL) {
                /* cannot handle the connection */
                picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                return -1;
            }
            else {
                picoquic_set_callback(cnx, cnx_stress_callback, cnx_ctx);
            }
        }
    }
    else if (cnx_ctx->cnx != cnx) {
        DBG_PRINTF("%s", "Invalid connection context!");
        ret = -1;
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        ret = cnx_stress_callback_data(cnx_ctx, stream_ctx, stream_id, bytes, length, fin_or_event);
        break;
    case picoquic_callback_stream_reset: 
        /* Sender reset stream, abandon transmission */
        if (stream_ctx != NULL) {
            /* Mark the stream as abandoned before full transmission */
            cnx_ctx->stress_ctx->nb_messages_errors += 1;
            /* delete the stream context */
            cnx_stress_delete_stream_context(cnx_ctx, stream_ctx);
        }
        break;
    case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
        /* TODO: probably no need for this in the test application. */
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        cnx_stress_callback_delete_context(cnx_ctx);
        picoquic_set_callback(cnx, NULL, NULL);
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        /* Should trigger a failure */
        break;
    case picoquic_callback_prepare_to_send:
        ret = cnx_stress_callback_prepare_to_send(cnx_ctx, stream_ctx, stream_id, (void*)bytes, length);
        break;
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        break;
    case picoquic_callback_datagram:/* No datagram support */
        break;
    case picoquic_callback_version_negotiation:
        break;
    case picoquic_callback_request_alpn_list: /* Provide the list of supported ALPN */
    case picoquic_callback_set_alpn: /* Set ALPN to negotiated value */
        break;
    default:
        /* unexpected */
        break;
    }

    return ret;
}

/* Handling of data messages.
 * The simulation generates messages at specified intervals, in turn from
 * the server and from the client. For each message, the simulation
 * picks a target connection from the connections already established.
 * This requires being able to select a connection context at random
 * from those established on the client side or the server side.
 * We need a structure for that, so we can retrieve the connection context,
 * with the following constraints:
 * 1) Light weigth
 * 2) Synchronized with creation and deletion of contexts at clients or server.
 * The synchronization will be achieved through the per connection callback
 * mechanism. The callback context holds the index of the connection in the
 * array. It is initialized on the client side when the connection is
 * created, and on the server side when the connection context is created.
 * It is deleted and the pointer set to null when the "end of connection"
 * callback is received.
 * We need to monitor the transmission delay of messages, in simulation time.
 * For that, we encode the sending time in the message, and retrieve it when
 * the message is received.
 * Each message is sent on its own one-way stream, delineated by the end of
 * stream mechanism. The connection parameters set these "allowed stream"
 * parameters to a large enough value to not cause flow control issues.
 * To do: should we keep an array of message departure and arrival times for
 * fine grain statistics, is it enough to compute min, max, average and stdev?
 */

cnx_stress_callback_ctx_t * cnx_stress_cnx_from_rank(
    int msg_num, int nb_ctx, cnx_stress_callback_ctx_t** v_ctx)
{
    int nb_trials = 0;
    int rank = msg_num % nb_ctx;
    cnx_stress_callback_ctx_t* cnx_ctx = v_ctx[rank];
    while ((cnx_ctx == NULL || cnx_ctx->cnx == NULL) && nb_trials < nb_ctx) {
        rank = (rank + 1) % nb_ctx;
        cnx_ctx = v_ctx[rank];
        nb_trials++;
    }
    return cnx_ctx;
}

int cnx_stress_initiate_message(cnx_stress_ctx_t* stress_ctx)
{
    /* Client or server? */
    int ret = 0;
    cnx_stress_callback_ctx_t* cnx_ctx;

    stress_ctx->nb_messages_sent += 1;
    cnx_ctx = ((stress_ctx->nb_messages_sent & 1) != 0) ?
        cnx_stress_cnx_from_rank(stress_ctx->nb_messages_sent,
            stress_ctx->nb_clients, stress_ctx->c_ctx):
        cnx_stress_cnx_from_rank(stress_ctx->nb_messages_sent,
            stress_ctx->nb_servers, stress_ctx->s_ctx);
    if (cnx_ctx == NULL) {
        ret = -1;
    }
    else {
        uint64_t stream_id = picoquic_get_next_local_stream_id(cnx_ctx->cnx, 1);
        cnx_stress_stream_ctx_t* stream_ctx = cnx_stress_create_stream_context(cnx_ctx, stream_id);
        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            stream_ctx->send_time = stress_ctx->simulated_time;
            stream_ctx->nb_bytes_expected = stress_ctx->message_size;

            ret = picoquic_mark_active_stream(cnx_ctx->cnx, stream_id, 1, stream_ctx);
        }
    }
    return ret;
}

int cnx_stress_create_client_cnx(cnx_stress_ctx_t* stress_ctx)
{
    int ret = 0;
    picoquic_cnx_t* cnx = picoquic_create_cnx(
        stress_ctx->qclient, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*) & stress_ctx->server_addr, stress_ctx->simulated_time, 0,
        PICOQUIC_TEST_SNI, CNX_STRESS_ALPN, 1);
    if (cnx == NULL) {
        ret = -1;
    }
    else {
        /* Create the context and register it in cnx  stress context */
        cnx_stress_callback_ctx_t* cnx_ctx = cnx_stress_callback_create_context(
            stress_ctx, cnx, 0);
        if (cnx_ctx == NULL) {
            picoquic_delete_cnx(cnx);
            ret = -1;
        }
        else {
            /* Set callback */
            picoquic_set_callback(cnx, cnx_stress_callback, cnx_ctx);
            /* Set keep alive to default value based on timeout. */
            picoquic_enable_keep_alive(cnx, 0);
            /* start the connection */
            ret = picoquic_start_client_cnx(cnx);
        }
    }
    return ret;
}

int cnx_stress_close_one_connection(cnx_stress_ctx_t* stress_ctx)
{
    /* TODO: consider closing the connections in a random order. */
    int ret = 0;
    int rank;

    stress_ctx->nb_clients_deleted++;
    rank = stress_ctx->nb_clients - stress_ctx->nb_clients_deleted;

    if (stress_ctx->c_ctx[rank] != NULL) {
        ret = picoquic_close(stress_ctx->c_ctx[rank]->cnx, 0);
    }

    return ret;
}

int cnx_stress_link_arrival(picoquic_quic_t * quic, picoquictest_sim_link_t * link, 
    uint64_t current_time)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet =
        picoquictest_sim_link_dequeue(link, current_time);

    if (packet != NULL) {
        ret = picoquic_incoming_packet(quic, packet->bytes,
            (uint32_t)packet->length,
            (struct sockaddr*) & packet->addr_from,
            (struct sockaddr*) & packet->addr_to, 0, 0, current_time);
        free(packet);
    }
    return ret;
}

int cnx_stress_prepare(picoquic_quic_t* quic, picoquictest_sim_link_t* link,
    struct sockaddr * default_source, uint64_t current_time)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    } else {
        picoquic_connection_id_t log_cid;
        picoquic_cnx_t* last_cnx;
        int if_index = 0;

        ret = picoquic_prepare_next_packet(quic, current_time, packet->bytes, 
            PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, &log_cid, &last_cnx);

        if (ret == 0 && packet->length > 0) {
            if (packet->addr_from.ss_family == AF_UNSPEC) {
                picoquic_store_addr(&packet->addr_from, default_source);
            }
            picoquictest_sim_link_submit(link, packet, current_time);
        }
        else {
            free(packet);
        }
    }
    return ret;
}

/* Loop -- manage arrival of clients, traffic, messages, etc. */
int cnx_stress_loop_step(cnx_stress_ctx_t * stress_ctx)
{
    int ret = 0;
    cnx_stress_event_enum next_event = cnx_stress_event_none;
    uint64_t next_time = UINT64_MAX;

    /* Is it time to inject a message ? */
    if (stress_ctx->next_message_creation_time < next_time) {
        next_event = cnx_stress_event_new_message;
        next_time = stress_ctx->next_message_creation_time;
    }
    /* Is it time to inject a new connection? */
    if (stress_ctx->next_client_creation_time < next_time) {
        next_event = cnx_stress_event_client_creation;
        next_time = stress_ctx->next_client_creation_time;
    }
    /* Is it time to delete a connection? */
    if (stress_ctx->next_client_deletion_time < next_time) {
        next_event = cnx_stress_event_client_removal;
        next_time = stress_ctx->next_client_deletion_time;
    }
    /* Is it time for client message arrival? */
    if (stress_ctx->link_to_clients->first_packet != NULL &&
        stress_ctx->link_to_clients->first_packet->arrival_time < next_time) {
        next_event = cnx_stress_event_client_arrival;
        next_time = stress_ctx->link_to_clients->first_packet->arrival_time;
    }
    /* Is it time for client message preparation? */
    if (picoquic_get_next_wake_time(stress_ctx->qclient, stress_ctx->simulated_time) < next_time) {
        next_event = cnx_stress_event_client_prepare;
        next_time = picoquic_get_next_wake_time(stress_ctx->qclient, stress_ctx->simulated_time);
    }
    /* Is it time for server message arrival? */
    if (stress_ctx->link_to_server->first_packet != NULL && 
        stress_ctx->link_to_server->first_packet->arrival_time < next_time) {
        next_event = cnx_stress_event_server_arrival;
        next_time = stress_ctx->link_to_server->first_packet->arrival_time;
    }
    /* Is it time for server message preparation? */
    if (picoquic_get_next_wake_time(stress_ctx->qserver, stress_ctx->simulated_time) < next_time) {
        next_event = cnx_stress_event_server_prepare;
        next_time = picoquic_get_next_wake_time(stress_ctx->qserver, stress_ctx->simulated_time);
    }
    /* Update the simulation time based on next time */
    if (next_time > stress_ctx->simulated_time) {
        stress_ctx->simulated_time = next_time;
    }
    /* TODO: Execute the selected action */
    switch (next_event) {
    case cnx_stress_event_new_message:
        ret = cnx_stress_initiate_message(stress_ctx);
        if (stress_ctx->nb_messages_sent >= stress_ctx->nb_messages_target) {
            stress_ctx->next_message_creation_time = UINT64_MAX;
        }
        else {
            stress_ctx->next_message_creation_time += stress_ctx->message_creation_interval;
        }
        break;
    case cnx_stress_event_client_creation:
        ret = cnx_stress_create_client_cnx(stress_ctx);
        /* Prep the next connection time. */
        if (stress_ctx->nb_clients >= stress_ctx->nb_client_target) {
            stress_ctx->next_client_creation_time = UINT64_MAX;
        }
        else {
            stress_ctx->next_client_creation_time += stress_ctx->client_creation_interval;
        }
        break;
    case cnx_stress_event_client_removal:
        ret = cnx_stress_close_one_connection(stress_ctx);
        if (stress_ctx->nb_clients_deleted >= stress_ctx->nb_clients) {
            stress_ctx->next_client_deletion_time = UINT64_MAX;
        }
        else {
            stress_ctx->next_client_deletion_time += stress_ctx->client_deletion_interval;
        }
        break;
    case cnx_stress_event_client_arrival:
        /* If there is something to receive on the client , do it now */
        ret = cnx_stress_link_arrival(stress_ctx->qclient,
            stress_ctx->link_to_clients, stress_ctx->simulated_time);
        break;
    case cnx_stress_event_client_prepare:
        /* If a client packet is ready to send, send it. */
        ret = cnx_stress_prepare(stress_ctx->qclient, stress_ctx->link_to_server,
            (struct sockaddr *)&stress_ctx->client_addr, stress_ctx->simulated_time);
        break;
    case cnx_stress_event_server_arrival:
        /* If there is something to receive on the client , do it now */
        ret = cnx_stress_link_arrival(stress_ctx->qserver,
            stress_ctx->link_to_server, stress_ctx->simulated_time);
        break;
    case cnx_stress_event_server_prepare:
        /* If a client packet is ready to send, send it. */
        ret = cnx_stress_prepare(stress_ctx->qserver, stress_ctx->link_to_clients,
            (struct sockaddr*) & stress_ctx->server_addr, stress_ctx->simulated_time);
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

/* Connection stress:
 *
 *  Create a QUIC context for the server
 *  Create a QUIC context for the client
 *  Create simulated links from client to server and vice-versa
 *  In a loop, until the desired number of connections is obtained
 *      Create a new connection on the client
 *      Queue a first message on that client connection
 *      Run the simulated send/receive loop for a small number of iterations
 *   Once all clients are created
 *       Run the simulation until the desired time interval has passed
 *  In a loop, close each of the connections
 *
 * All that while getting statistics on:
 *
 *   The simulated connection establishment delays
 *   The simulated message delays from injection to delivery
 *   Whether undesirable events occur, e.g., loss of connections
 *   The "real time" required to run the test for the simulated time
 *
 */

/* Set transport parameters to adequate value for cnx stress */
int cnx_stress_set_default_tp(picoquic_quic_t* quic)
{
    int ret = 0;
    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(picoquic_tp_t));
    /* This is a server context. The "remote" bidi streams are those
        * initiated by the client, and should be authorized to send
        * a 64K-1 packet */
    tp.initial_max_stream_data_bidi_local = 0;
    tp.initial_max_stream_data_bidi_remote = 0;
    tp.initial_max_stream_id_bidir = 0;
    tp.initial_max_stream_data_uni = 0x20000;
    tp.initial_max_stream_id_unidir = 64;
    tp.initial_max_data = 0x20000;
    tp.max_idle_timeout = 60000;
    tp.max_packet_size = PICOQUIC_MAX_PACKET_SIZE;
    tp.max_ack_delay = 10000;
    tp.active_connection_id_limit = 3;
    tp.ack_delay_exponent = 3;
    tp.migration_disabled = 0;
    ret = picoquic_set_default_tp(quic, &tp);
    return ret;
}

void cnx_stress_delete_ctx(cnx_stress_ctx_t* stress_ctx)
{
    if (stress_ctx->link_to_clients != NULL) {
        picoquictest_sim_link_delete(stress_ctx->link_to_clients);
        stress_ctx->link_to_clients = NULL;
    }

    if (stress_ctx->link_to_server != NULL) {
        picoquictest_sim_link_delete(stress_ctx->link_to_server);
        stress_ctx->link_to_server = NULL;
    }

    if (stress_ctx->qserver != NULL) {
        picoquic_free(stress_ctx->qserver);
        stress_ctx->qserver = NULL;
    }

    if (stress_ctx->qclient != NULL) {
        picoquic_free(stress_ctx->qclient);
        stress_ctx->qclient = NULL;
    }

    if (stress_ctx->default_ctx != NULL) {
        free(stress_ctx->default_ctx);
        stress_ctx->default_ctx = NULL;
    }

    if (stress_ctx->c_ctx != NULL) {
        for (int i = 0; i < stress_ctx->nb_clients; i++) {
            if (stress_ctx->c_ctx[i] != NULL) {
                cnx_stress_callback_delete_context(stress_ctx->c_ctx[i]);
            }
        }
        free(stress_ctx->c_ctx);
        stress_ctx->c_ctx = NULL;
    }

    if (stress_ctx->s_ctx != NULL) {
        for (int i = 0; i < stress_ctx->nb_servers; i++) {
            if (stress_ctx->s_ctx[i] != NULL) {
                cnx_stress_callback_delete_context(stress_ctx->s_ctx[i]);
            }
        }
        free(stress_ctx->s_ctx);
        stress_ctx->s_ctx = NULL;
    }

    free(stress_ctx);
}

cnx_stress_ctx_t* cnx_stress_create_ctx(uint64_t duration, int nb_clients, int limit_test) 
{
    cnx_stress_ctx_t* stress_ctx = (cnx_stress_ctx_t*)malloc(sizeof(cnx_stress_ctx_t));

    if (stress_ctx != NULL) {
        int ret = 0;

        memset(stress_ctx, 0, sizeof(cnx_stress_ctx_t));
        /* The random seed depends only on initialization parameters */
        stress_ctx->random_ctx = 0xBabaC001BaddBab1ull;
        stress_ctx->random_ctx ^= duration;
        (void)picoquic_test_random(&stress_ctx->random_ctx);
        stress_ctx->random_ctx ^= (uint64_t)nb_clients;
        (void)picoquic_test_random(&stress_ctx->random_ctx);

        /* Document addresses for the simulation */
        picoquic_set_test_address(&stress_ctx->client_addr, 0x08080808, 12345);
        picoquic_set_test_address(&stress_ctx->server_addr, 0x01010101, 4433);

        /* Set and verify the simulation intervals */
        stress_ctx->nb_client_target = nb_clients;
        stress_ctx->client_creation_interval = 2000;
        stress_ctx->next_client_creation_time = 0;
        stress_ctx->client_deletion_interval = 100;
        if ((stress_ctx->client_creation_interval + stress_ctx->client_deletion_interval) * nb_clients
            > duration) {
            ret = -1;
        }
        else {
            stress_ctx->next_client_deletion_time = duration -
                stress_ctx->client_deletion_interval * nb_clients;
            stress_ctx->nb_messages_target = (nb_clients > 20000) ? 20000 : nb_clients;
            stress_ctx->message_size = 1024;
            stress_ctx->message_delay_min = INT64_MAX;
            stress_ctx->message_creation_interval = stress_ctx->next_client_deletion_time /
                ((uint64_t)3 * stress_ctx->nb_messages_target);
            stress_ctx->next_message_creation_time = stress_ctx->next_client_deletion_time / 3;
            if (stress_ctx->message_creation_interval <= 0) {
                ret = -1;
            }
            else {
                stress_ctx->c_ctx = (cnx_stress_callback_ctx_t**)malloc(
                    sizeof(cnx_stress_callback_ctx_t*) * (nb_clients + limit_test));
                if (stress_ctx->c_ctx != NULL) {
                    memset(stress_ctx->c_ctx, 0, 
                        sizeof(cnx_stress_callback_ctx_t*) * (nb_clients + limit_test));
                }
                stress_ctx->s_ctx = (cnx_stress_callback_ctx_t**)malloc(
                    sizeof(cnx_stress_callback_ctx_t*) * (nb_clients + limit_test));
                if (stress_ctx->s_ctx != NULL) {
                    memset(stress_ctx->s_ctx, 0, sizeof(cnx_stress_callback_ctx_t*) * (nb_clients + limit_test));
                }
                stress_ctx->default_ctx = cnx_stress_callback_create_context(stress_ctx, NULL, 2);
                if (stress_ctx->s_ctx == NULL || stress_ctx->c_ctx == NULL || stress_ctx->default_ctx == NULL) {
                    ret = -1;
                }
                else {
                    char test_server_cert_file[512];
                    char test_server_key_file[512];

                    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

                    if (ret == 0) {
                        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
                    }
                    if (ret == 0) {
                        stress_ctx->qclient = picoquic_create((nb_clients + limit_test), NULL, NULL,
                            NULL, CNX_STRESS_ALPN, NULL, NULL, NULL, NULL,
                            NULL, stress_ctx->simulated_time, &stress_ctx->simulated_time,
                            NULL, NULL, 0);
                        stress_ctx->qserver = picoquic_create(nb_clients, test_server_cert_file, test_server_key_file,
                            NULL, CNX_STRESS_ALPN, cnx_stress_callback, stress_ctx->default_ctx, NULL, NULL,
                            NULL, stress_ctx->simulated_time, &stress_ctx->simulated_time,
                            NULL, NULL, 0);
                        stress_ctx->link_to_clients = picoquictest_sim_link_create(1.0,
                            10000, NULL, 20000, 0);
                        stress_ctx->link_to_server = picoquictest_sim_link_create(1.0,
                            10000, NULL, 20000, 0);
                        if (stress_ctx->qclient == NULL || stress_ctx->qserver == NULL ||
                            stress_ctx->link_to_clients == NULL || stress_ctx->link_to_server == NULL) {
                            ret = -1;
                        }
                        else {
                            ret = picoquic_set_low_memory_mode(stress_ctx->qclient, 1);
                            if (ret == 0) {
                                ret = picoquic_set_low_memory_mode(stress_ctx->qserver, 1);
                            }
                            if (ret == 0) {
                                ret = cnx_stress_set_default_tp(stress_ctx->qclient);
                            }
                            if (ret == 0) {
                                ret = cnx_stress_set_default_tp(stress_ctx->qserver);
                            }
                        }
                    }
                }
            }
        }

        if (ret != 0) {
            cnx_stress_delete_ctx(stress_ctx);
            stress_ctx = NULL;
        }
    }
    return stress_ctx;
}

int cnx_stress_do_test(uint64_t duration, int nb_clients, int do_report)
{
    int ret = 0;
    cnx_stress_ctx_t* stress_ctx = cnx_stress_create_ctx(duration, nb_clients, 0);

    if (stress_ctx != NULL) {
        uint64_t wall_time_start = picoquic_current_time();

        /* loop until time exhausted */
        while (ret == 0 && stress_ctx->simulated_time < duration) {
            ret = cnx_stress_loop_step(stress_ctx);
        }

        if (ret == 0) {
            uint64_t wall_time_end = picoquic_current_time();
            uint64_t wall_time_elapsed = wall_time_end - wall_time_start;

            if (wall_time_elapsed > stress_ctx->simulated_time) {
                DBG_PRINTF("Simulating %" PRIu64 " in %" PRIu64, 
                    stress_ctx->simulated_time, wall_time_elapsed);
                ret = -1;
            }
            else if (stress_ctx->nb_clients != stress_ctx->nb_client_target ||
                stress_ctx->nb_servers != stress_ctx->nb_client_target) {
                DBG_PRINTF("Expected %d connections, got %d (client) and %d (server)",
                    stress_ctx->nb_client_target, stress_ctx->nb_clients, stress_ctx->nb_servers);
                ret = -1;
            }
            else if (stress_ctx->nb_messages_received != stress_ctx->nb_messages_target) {
                DBG_PRINTF("Expected %d messages, sent %d, received %d",
                    stress_ctx->nb_messages_target, 
                    stress_ctx->nb_messages_sent, stress_ctx->nb_messages_received);
                ret = -1;
            }
            else if (do_report) {
                double msg_avg_delay = (stress_ctx->nb_messages_target > 0) ?
                    (double)stress_ctx->sum_message_delays / (double)stress_ctx->nb_messages_target : 0;
                msg_avg_delay /= 1000000.0;
                fprintf(stdout, "Many connection stress (cnx_stress) succeeds:\n");
                fprintf(stdout, "Processed %d connections for %fs (simulated) in %fs (wall time).\n",
                    stress_ctx->nb_client_target,
                    ((double)stress_ctx->simulated_time)/1000000.0,
                    ((double)wall_time_elapsed)/1000000.0);
                fprintf(stdout, "Processed %d messages, delays min/avg/max= %fs, %fs, %fs.\n",
                    stress_ctx->nb_messages_target, ((double)stress_ctx->message_delay_min)/ 1000000.0,
                    msg_avg_delay, ((double)stress_ctx->message_delay_max)/ 1000000.0);
            }
        }

        cnx_stress_delete_ctx(stress_ctx);
    }
    return ret;
}

/* The unit test entry point executes the cnx stress test with a 
 * small duration and a small number of clients, the goal being to check that
 * the cnx stress code actually works. */
int cnx_stress_unit_test()
{
    return cnx_stress_do_test(120000000, 100, 0);
}

/*Connection limit
 * Test that if one attempts to create more than the set limit of
 * connections, it fails. This is complementary to the cnx_stress
 * test, which verifies that if one creates exactly the "limit" number of connections, 
 * they all succeed.
 */
int cnx_limit_test()
{
    int ret = 0;
    int nb_clients = 4;
    uint64_t duration = 120000000;
    cnx_stress_ctx_t* stress_ctx = cnx_stress_create_ctx(duration, nb_clients, 1);

    if (stress_ctx == NULL) {
        ret = -1;
    }

    if (stress_ctx != NULL) {
        int is_done = 0;

        /* loop until time exhausted or all created */
        while (ret == 0 && stress_ctx->simulated_time < duration && !is_done) {
            ret = cnx_stress_loop_step(stress_ctx);
            if (stress_ctx->nb_clients == (uint32_t)nb_clients &&
                stress_ctx->nb_servers == (uint32_t)nb_clients) {
                is_done = 1;
                for (int c = 0; c < nb_clients; c++) {
                    if (stress_ctx->c_ctx[c] == NULL ||
                        stress_ctx->c_ctx[c]->cnx == NULL ||
                        stress_ctx->c_ctx[c]->cnx->cnx_state <
                        picoquic_state_client_almost_ready) {
                        is_done = 0;
                        break;
                    }
                }
            }
        }
        if (!is_done) {
            ret = -1;
        }

        if (ret == 0) {
            /* Try creating one more client. Loop until time exhausted or
             * verify new client refused because server busy */

            stress_ctx->is_limit_test = 1;
            stress_ctx->next_client_creation_time = stress_ctx->simulated_time;
            stress_ctx->nb_client_target++;
            while (ret == 0 && stress_ctx->simulated_time < duration &&
                !stress_ctx->limit_test_got_server_busy) {
                ret = cnx_stress_loop_step(stress_ctx);
            }
            if (!stress_ctx->limit_test_got_server_busy) {
                ret = -1;
            }
        }

        cnx_stress_delete_ctx(stress_ctx);
    }

    return ret;
}