/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <signal.h>
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define PICOQUIC_MAX_STRESS_CLIENTS 1024
#define PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS 16
#define PICOQUIC_STRESS_MINIMAL_QUERY_SIZE 127
#define PICOQUIC_STRESS_DEFAULT_RESPONSE_SIZE 257
#define PICOQUIC_STRESS_RESPONSE_LENGTH_MAX 1000000
#define PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE 0x10000
#define PICOQUIC_STRESS_MAX_CLIENT_STREAMS 16

uint64_t picoquic_stress_test_duration = 60000000; /* Default to 1 minutes */
size_t picoquic_stress_nb_clients = 4; /* Default to 4 clients */
uint64_t picoquic_stress_max_bidir = 8 * 4; /* Default to 8 streams max per connection */
size_t picoquic_stress_max_open_streams = 4; /* Default to 4 simultaneous streams max per connection */
uint64_t stress_random_ctx = 0xBabaC001BaddBab1ull;
uint32_t picoquic_stress_max_message_before_drop = 25;
uint32_t picoquic_stress_max_message_before_migrate = 8;
static int picoquic_fuzz_in_progress = 0;

typedef struct st_picoquic_stress_server_callback_ctx_t {
    // picoquic_first_server_stream_ctx_t* first_stream;
    size_t data_received_on_stream[PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS];
    uint32_t data_sum_of_stream[PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS];
    uint8_t buffer[PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE];
} picoquic_stress_server_callback_ctx_t;

typedef struct st_picoquic_stress_client_callback_ctx_t {
    uint64_t test_id;
    uint64_t max_bidir;
    uint64_t next_bidir;
    size_t max_open_streams;
    size_t nb_open_streams;
    uint64_t stream_id[PICOQUIC_STRESS_MAX_CLIENT_STREAMS];
    uint64_t last_interaction_time;
    uint32_t nb_client_streams;
    uint32_t message_disconnect_trigger;
    uint32_t message_migration_trigger;
    int progress_observed;
    struct st_picoquic_stress_ctx_t* stress_ctx;
} picoquic_stress_client_callback_ctx_t;

typedef struct st_picoquic_stress_client_t {
    picoquic_quic_t* qclient;
    struct sockaddr_in client_addr;
    char ticket_file_name[32];
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    uint64_t client_next_time;
    picosplay_node_t client_node;
} picoquic_stress_client_t;

typedef struct st_picoquic_stress_ctx_t {
    picoquic_quic_t* qserver;
    struct sockaddr_in server_addr;
    uint64_t simulated_time;
    int sum_data_received_from_server;
    int nb_connections_complete;
    int nb_clients;
    int nb_connections;
    picoquic_stress_client_t * c_ctx[PICOQUIC_MAX_STRESS_CLIENTS];
    picosplay_tree_t c_tree;
} picoquic_stress_ctx_t;

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

/* Manage a splay of stress contexts, ordered by next time.
 */
static int64_t stress_client_compare(void *l, void *r)
{
    return ((picoquic_stress_client_t*)l)->client_next_time - ((picoquic_stress_client_t*)r)->client_next_time;
}

static picosplay_node_t *stress_client_node_create(void * value)
{
    return &((picoquic_stress_client_t *)value)->client_node;
}

void * stress_client_node_value(picosplay_node_t * node)
{
    return (node == NULL)?NULL:(void*)((char*)node - offsetof(struct st_picoquic_stress_client_t, client_node));
}

static void stress_client_node_delete(void * tree, picosplay_node_t * node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    memset(node, 0, sizeof(picosplay_node_t));
}

static void stress_client_eval_next_time(picoquic_stress_client_t* c_ctx, uint64_t simulated_time)
{
    uint64_t best_wake_time;

    /* set wake time if no connection! */
    if (c_ctx->qclient->cnx_list == NULL) {
        best_wake_time = simulated_time;
    }
    else {
        /* Find the arrival time of the next packet, by looking at
        * the various links. remember the winner */
        best_wake_time = simulated_time + picoquic_get_next_wake_delay(c_ctx->qclient,
            simulated_time, 100000000);

        if (c_ctx->s_to_c_link->first_packet != NULL &&
            c_ctx->s_to_c_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = c_ctx->s_to_c_link->first_packet->arrival_time;
        }

        if (c_ctx->c_to_s_link->first_packet != NULL &&
            c_ctx->c_to_s_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = c_ctx->c_to_s_link->first_packet->arrival_time;
        }
    }

    c_ctx->client_next_time = best_wake_time;
}

static void stress_context_reorder(picoquic_stress_ctx_t* stress_ctx, picoquic_stress_client_t* c_ctx, uint64_t simulated_time)
{
    picosplay_delete_hint(&stress_ctx->c_tree, &c_ctx->client_node);
    stress_client_eval_next_time(c_ctx, simulated_time);
    picosplay_insert(&stress_ctx->c_tree, c_ctx);
}

/*
* Call back function, server side.
*
* Try to provide some code coverage on the server side while maintaining as
* little state as possible.
* TODO: add debug_break on error condition.
*/

static int stress_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoquic_stress_server_callback_ctx_t* stress_ctx = (picoquic_stress_server_callback_ctx_t*)callback_ctx;

    if (fin_or_event == picoquic_callback_close ||
        fin_or_event == picoquic_callback_stateless_reset ||
        fin_or_event == picoquic_callback_application_close ||
        fin_or_event == picoquic_callback_version_negotiation) {
        if (stress_ctx != NULL) {
            free(stress_ctx);
            picoquic_set_callback(cnx, stress_server_callback, NULL);
        }
    }
    else if (
        fin_or_event == picoquic_callback_version_negotiation ||
        fin_or_event == picoquic_callback_almost_ready ||
        fin_or_event == picoquic_callback_ready) {
        /* do nothing */
    } else if (fin_or_event == picoquic_callback_prepare_to_send) {
        /* unexpected call */
        ret = -1;
    } else {
        if (stress_ctx == NULL) {
            picoquic_stress_server_callback_ctx_t* new_ctx = (picoquic_stress_server_callback_ctx_t*)
                malloc(sizeof(picoquic_stress_server_callback_ctx_t));
            if (new_ctx == NULL) {
                /* Should really be a debug-break error */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                ret = stress_debug_break(0);
            }
            else {
                memset(new_ctx, 0, sizeof(picoquic_stress_server_callback_ctx_t));
                picoquic_set_callback(cnx, stress_server_callback, new_ctx);
                stress_ctx = new_ctx;
            }
        }

        if (stress_ctx != NULL) {
            /* verify state and copy data to the stream buffer */
            if (fin_or_event == picoquic_callback_stop_sending) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    ret = stress_debug_break(0);
                }
            }
            else if (fin_or_event == picoquic_callback_stream_reset) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    ret = stress_debug_break(0);
                }
            }
            else if (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin) {
                /* Write a response, which should somehow depend on the stream data and
                * the stream status and the data bytes */
                if ((stream_id & 3) != 0) {
                    /* This is not a client-initiated bidir stream. Just ignore the data */
                }
                else {
                    uint64_t bidir_id = stream_id / 4;
                    size_t response_length = 0;


                    if (bidir_id < PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS) {
                        size_t received = stress_ctx->data_received_on_stream[bidir_id] + length;
                        if (stress_ctx->data_received_on_stream[bidir_id] < PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                            /* Computing the size of the response as a pseudo random function of the
                             * content of the query. The response size will be between 0 and 
                             * PICOQUIC_STRESS_RESPONSE_LENGTH_MAX.
                             *
                             * The query size is arbitrary, thus the code only computes the
                             * pseudo random number on the the first bytes of the query,
                             * up to PICOQUIC_STRESS_MINIMAL_QUERY_SIZE.
                             *
                             * The random function is: hash[n] = hash[n-1]*101 + x[n]
                             *
                             * TODO: This may be too clever by half, and we could make the case for encoding the
                             * desired response size in the first four bytes of the query, and computing the
                             * random function at the client.
                             */
                            int processed = (int) length;
                            if (received >= PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                                processed = (int) received - PICOQUIC_STRESS_MINIMAL_QUERY_SIZE;
                            }

                            for (int i = 0; i < processed; i++) {
                                stress_ctx->data_sum_of_stream[bidir_id] =
                                    stress_ctx->data_sum_of_stream[bidir_id] * 101 + bytes[i];
                            }

                            if (received >= PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                                response_length = stress_ctx->data_sum_of_stream[bidir_id] % PICOQUIC_STRESS_RESPONSE_LENGTH_MAX;
                            }
                        }
                        stress_ctx->data_received_on_stream[bidir_id] += length;
                    }

                    /* for all streams above the limit, or all streams with short queries,just send a fixed size answer,
                    * after receiving all the client data */
                    if (fin_or_event == picoquic_callback_stream_fin &&
                        (bidir_id >= PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS ||
                            stress_ctx->data_received_on_stream[bidir_id] < PICOQUIC_STRESS_MINIMAL_QUERY_SIZE)) {

                        response_length = PICOQUIC_STRESS_DEFAULT_RESPONSE_SIZE;
                    }

                    if (response_length > 0) {
                        /* Push data on the stream */

                        while (response_length > PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE && ret == 0) {
                            if ( (ret = picoquic_add_to_stream(cnx, stream_id, stress_ctx->buffer,
                                PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE, 0)) != 0) {
                                ret = stress_debug_break(0);
                            }

                            response_length -= PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE;
                        }
                        if (ret == 0 && (ret = picoquic_add_to_stream(cnx, stream_id, stress_ctx->buffer,
                                response_length, 1)) != 0) {
                            ret = stress_debug_break(0);
                        }
                    }
                }
            } else {
                /* Unexpected frame */
                if ((ret = picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION)) != 0) {
                    ret = stress_debug_break(0);
                }
            }
        }
    }

    /* that's it */
    return (ret == 0) ? 0 : -1;
}

/* Callback function, client side.
* Implement simple scenarios for query generations, such as
* number of queries and interval between queries */

/* Stress client callback: same as the demo client callback, 
 * based on scenarios. But we need to account for failures,
 * effectively doing debugbreak in case of execution
 * failure, so the stress can be run under debugger.
 *
 * Consider also adding client misbehavior in the future,
 * including silent departure, version negotiation, or
 * zero share start.
 */


static int stress_client_start_streams(picoquic_cnx_t* cnx,
    picoquic_stress_client_callback_ctx_t* cb_ctx) 
{
    int ret = 0;
    uint8_t buf[32];

    while (cb_ctx->nb_open_streams < cb_ctx->max_open_streams &&
        cb_ctx->next_bidir <= cb_ctx->max_bidir) {
        int stream_index = -1;
        for (size_t i = 0; i < cb_ctx->max_open_streams; i++) {
            if (cb_ctx->stream_id[i] == UINT64_MAX) {
                stream_index = (int) i;
                break;
            }
        }

        if (stream_index < 0) {
            ret = stress_debug_break(1);
        }
        else {
            memset(buf, 0, sizeof(buf));
            picoformat_64(buf, cb_ctx->test_id);
            picoformat_64(&buf[8], cb_ctx->next_bidir);

            cb_ctx->stream_id[stream_index] = cb_ctx->next_bidir;
            cb_ctx->next_bidir += 4;
            cb_ctx->nb_open_streams++;
            // MTEST;
            if ((ret = picoquic_add_to_stream(cnx, cb_ctx->stream_id[stream_index], buf, sizeof(buf), 1)) != 0){
                ret = stress_debug_break(1);
            }
        }
    }

    return ret;
}

static int stress_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoquic_stress_client_callback_ctx_t* cb_ctx = (picoquic_stress_client_callback_ctx_t*)callback_ctx;

    if (fin_or_event == picoquic_callback_version_negotiation) {
        /* Do nothing */
    } else  if (fin_or_event == picoquic_callback_close || 
        fin_or_event == picoquic_callback_application_close ||
        fin_or_event == picoquic_callback_stateless_reset) {
        /* Free per connection resource */
        if (cb_ctx != NULL) {
            free(cb_ctx);
            picoquic_set_callback(cnx, stress_client_callback, NULL);
        }
    } else if (fin_or_event == picoquic_callback_almost_ready) {
        /* do nothing */
    } else if (cb_ctx != NULL) {

        if (fin_or_event == picoquic_callback_ready) {
            cb_ctx->stress_ctx->nb_connections_complete++;
        }
        else {
            /* if stream is already present, check its state. New bytes? */
            int stream_index = -1;
            int is_finished = 0;

            cb_ctx->last_interaction_time = picoquic_current_time();
            cb_ctx->progress_observed = 1;


            for (size_t i = 0; i < cb_ctx->max_open_streams; i++) {
                if (cb_ctx->stream_id[i] == stream_id) {
                    stream_index = (int)i;
                    break;
                }
            }

            if (stream_index >= 0) {
                if (fin_or_event == picoquic_callback_stream_data ||
                    fin_or_event == picoquic_callback_stream_fin) {
                    cb_ctx->stress_ctx->sum_data_received_from_server += (int)length;
                }
                /* if stream is finished, maybe start new ones */
                if (fin_or_event == picoquic_callback_stream_reset) {
                    if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                        ret = stress_debug_break(0);
                    }
                    is_finished = 1;
                }
                else if (fin_or_event == picoquic_callback_stop_sending) {
                    if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                        ret = stress_debug_break(0);
                    }
                    is_finished = 1;
                }
                else if (fin_or_event == picoquic_callback_stream_fin) {
                    is_finished = 1;
                }

                if (is_finished != 0) {
                    if (cb_ctx->nb_open_streams > 0) {
                        cb_ctx->nb_open_streams--;
                    }
                    else {
                        ret = stress_debug_break(0);
                    }

                    cb_ctx->stream_id[stream_index] = UINT64_MAX;

                    if (cb_ctx->next_bidir >= cb_ctx->max_bidir) {
                        /* This was the last stream */
                        if (cb_ctx->nb_open_streams == 0) {
                            if ((ret = picoquic_close(cnx, 0)) != 0) {
                                ret = stress_debug_break(0);
                            }
                        }
                    }
                    else {
                        /* Initialize the next bidir stream  */
                        ret = stress_client_start_streams(cnx, cb_ctx);
                    }
                }
            }
        }
    }

    /* that's it */
    return ret;
}

int stress_client_set_callback(picoquic_cnx_t* cnx, picoquic_stress_ctx_t * stress_ctx) 
{
    static uint64_t test_id = 0;
    int ret = 0;

    if (picoquic_get_callback_context(cnx) != NULL) {
        /* Duplicate init call. This is a bug */
        ret = stress_debug_break(1);
    }
    else {
        picoquic_stress_client_callback_ctx_t* cb_ctx = 
            (picoquic_stress_client_callback_ctx_t*)malloc(sizeof(picoquic_stress_client_callback_ctx_t));
        if (cb_ctx == NULL) {
            /* Break even if fuzzing */
            ret = stress_debug_break(1);
        }
        else {
            memset(cb_ctx, 0, sizeof(picoquic_stress_client_callback_ctx_t));
            cb_ctx->test_id = test_id++;
            cb_ctx->max_bidir = picoquic_stress_max_bidir;
            cb_ctx->max_open_streams = picoquic_stress_max_open_streams;
            cb_ctx->next_bidir = 4; /* TODO: change to zero when cream/crack gets done */
            for (size_t i = 0; i < cb_ctx->max_open_streams; i++) {
                cb_ctx->stream_id[i] = UINT64_MAX;
            }
            picoquic_set_callback(cnx, stress_client_callback, cb_ctx);

            if ((cb_ctx->message_disconnect_trigger = (uint32_t) picoquic_test_uniform_random(&stress_random_ctx, ((uint64_t)2)* picoquic_stress_max_message_before_drop)) >= picoquic_stress_max_message_before_drop){
                cb_ctx->message_disconnect_trigger = 0;
            }
            else {
                cb_ctx->message_disconnect_trigger++;
            }

            if ((cb_ctx->message_migration_trigger = (uint32_t)picoquic_test_uniform_random(&stress_random_ctx, ((uint64_t)2) * picoquic_stress_max_message_before_migrate)) >= picoquic_stress_max_message_before_migrate) {
                cb_ctx->message_migration_trigger = 0;
            }
            else {
                cb_ctx->message_migration_trigger++;
            }
            cb_ctx->stress_ctx = stress_ctx;

            ret = stress_client_start_streams(cnx, cb_ctx);
        }
    }

    return ret;
}

/* Orchestration of the simulation: one server, N simulation
 * links. On each link, there may be a new client added in
 * the future. Links have different delays, capacity, and
 * different client arrival rates.
 */

/*
 * Message loop and related functions
 */

static void stress_set_ip_address_from_index(struct sockaddr_in * addr, int c_index)
{
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = (ULONG) c_index;
#else
    addr->sin_addr.s_addr = (uint32_t)c_index;;
#endif
    addr->sin_port = 4321;
}

static int stress_get_index_from_ip_address(struct sockaddr_in * addr)
{
    uint32_t c_index;
#ifdef _WINDOWS
    c_index = (int)addr->sin_addr.S_un.S_addr;
#else
    c_index = (int)addr->sin_addr.s_addr;
#endif
    return c_index;
}


static int stress_submit_sp_packets(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, picoquic_stress_client_t* c_ctx)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = NULL;
    picoquictest_sim_link_t* target_link = NULL;

    while ((sp = picoquic_dequeue_stateless_packet(q)) != NULL) {
        if (sp->length > 0) {
            picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

            if (packet == NULL) {
                /* Break even if fuzzing */
                ret = stress_debug_break(1);
                break;
            }
            else {
                memcpy(&packet->addr_from, &sp->addr_local,
                    (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                memcpy(&packet->addr_to, &sp->addr_to,
                    (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                memcpy(packet->bytes, sp->bytes, sp->length);
                packet->length = sp->length;

                if (c_ctx != NULL)
                {
                    target_link = c_ctx->c_to_s_link;
                }
                else {
                    /* find target from address */
                    int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &sp->addr_to);

                    if (d_index < 0 || d_index >= ctx->nb_clients) {
                        /* Break even if fuzzing */
                        ret = stress_debug_break(1);
                    }
                    else {
                        target_link = ctx->c_ctx[d_index]->s_to_c_link;
                    }
                }

                if (target_link != NULL) {
                    picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
                }
                else {
                    free(packet);
                    /* Break even if fuzzing */
                    ret = stress_debug_break(1);
                    break;
                }
            }
        }
        picoquic_delete_stateless_packet(sp);
    }

    return ret;
}

static int stress_handle_packet_arrival(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, picoquictest_sim_link_t* link, struct sockaddr * dest_addr)
{
    int ret = 0;
    /* dequeue packet from server to client and submit */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, ctx->simulated_time);

    if (packet != NULL) {
        /* Check that the destination address matches the current address */
        if (picoquic_compare_addr(dest_addr, (struct sockaddr*)&packet->addr_to) == 0) {
            ret = picoquic_incoming_packet(q, packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
                ctx->simulated_time);

            if (ret != 0) {
                ret = stress_debug_break(0);
            }
        }
        free(packet);
    }

    return ret;
}

static int stress_handle_packet_prepare(picoquic_stress_ctx_t * stress_ctx, picoquic_quic_t * q, picoquic_stress_client_t * client_ctx)
{
    /* prepare packet and submit */
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquic_cnx_t* cnx = picoquic_get_earliest_cnx_to_wake(q, 0);
    picoquictest_sim_link_t* target_link = NULL;
    int simulate_disconnect = 0;

    if (packet != NULL && cnx != NULL) {
        /* Check that the client connection was properly terminated */
        picoquic_stress_client_callback_ctx_t* c_ctx = (client_ctx != NULL) ?
            (picoquic_stress_client_callback_ctx_t*)picoquic_get_callback_context(cnx) : NULL;

        /* Check whether immediate abrubt disconnection is required */
        if (c_ctx != NULL && cnx->cnx_state != picoquic_state_disconnected &&
            c_ctx->message_disconnect_trigger != 0) {
            uint64_t nb_sent = 0;
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                nb_sent += cnx->pkt_ctx[pc].send_sequence;
            }
            if (nb_sent > c_ctx->message_disconnect_trigger) {
                /* simulate an abrupt disconnect */
                ret = PICOQUIC_ERROR_DISCONNECTED;
                simulate_disconnect = 1;
            }
        }

        if (ret == 0 && c_ctx != NULL && cnx->cnx_state == picoquic_state_ready && client_ctx != NULL &&
            cnx->first_remote_cnxid_stash->cnxid_stash_first != NULL && c_ctx->message_migration_trigger != 0 &&
            cnx->pkt_ctx[picoquic_packet_context_application].send_sequence > c_ctx->message_migration_trigger){
            /* Simulate a migration */
            client_ctx->client_addr.sin_port++;
            ret = picoquic_probe_new_path(cnx, (struct sockaddr *)&stress_ctx->server_addr, 
                (struct sockaddr *)&client_ctx->client_addr, stress_ctx->simulated_time);
            if (ret != 0) {
                ret = stress_debug_break(0);
            } else {
                /* Prep for a future migration */
                c_ctx->message_migration_trigger += 32;
            }
        }


        if (c_ctx == NULL || cnx->cnx_state == picoquic_state_disconnected 
            || simulate_disconnect == 0) { 
            ret = picoquic_prepare_packet(cnx, stress_ctx->simulated_time,
                packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
                &packet->addr_to, &packet->addr_from, NULL);
        }

        if (ret == 0 && packet->length > 0) {
            int d_index = -1;
            if (packet->addr_from.ss_family == 0) {
                if (client_ctx != NULL) {
                    memcpy(&packet->addr_from, (struct sockaddr *)&client_ctx->client_addr, 
                        sizeof(client_ctx->client_addr));
                }
                else {
                    memcpy(&packet->addr_from, (struct sockaddr *)&stress_ctx->server_addr,
                        sizeof(stress_ctx->server_addr));
                }
            } 

            if (client_ctx != NULL)
            {
                target_link = client_ctx->c_to_s_link;
            }
            else {
                /* find target from address */
                d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &packet->addr_to);

                if (d_index < 0 || d_index >= stress_ctx->nb_clients) {
                    /* Break even if fuzzing */
                    ret = stress_debug_break(1);
                }
                else {
                    target_link = stress_ctx->c_ctx[d_index]->s_to_c_link;
                }
            }
            if (target_link != NULL) {
                picoquictest_sim_link_submit(target_link, packet, stress_ctx->simulated_time);
            }
            else {
                /* Break even if fuzzing */
                ret = stress_debug_break(1);
            }
            if (d_index > 0) {
                stress_context_reorder(stress_ctx, stress_ctx->c_ctx[d_index], stress_ctx->simulated_time);
            }
            else if (client_ctx != NULL) {
                stress_context_reorder(stress_ctx, client_ctx, stress_ctx->simulated_time);
            }
        }
        else {
            free(packet);
            packet = NULL;

            if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                /* Check the context again, it may have been freed in a callback */
                picoquic_stress_client_callback_ctx_t* cb_ctx = (client_ctx != NULL) ?
                    (picoquic_stress_client_callback_ctx_t*)picoquic_get_callback_context(cnx) : NULL;

                if (client_ctx != NULL) {
                    ret = 0;
                    if (cb_ctx != NULL) {
                        if (simulate_disconnect == 0 && (
                            cb_ctx->next_bidir < cb_ctx->max_bidir ||
                            cb_ctx->nb_open_streams != 0)) {
                            ret = stress_debug_break(0);
                        }
                        free(cb_ctx);
                        picoquic_set_callback(cnx, NULL, NULL);
                    }
                }
                else {
                    ret = 0;
                }
                picoquic_delete_cnx(cnx);
                if (client_ctx != NULL && picoquic_get_earliest_cnx_to_wake(q, 0) != NULL) {
                    /* error: only one connection at a time per client context,
                     * connection was just deleted, yet there is a connection in wake list */
                    ret = stress_debug_break(1);
                }
                if (client_ctx != NULL) {
                    stress_context_reorder(stress_ctx, client_ctx, stress_ctx->simulated_time);
                }
            }
            else if (ret != 0) {
                ret = stress_debug_break(0);
            }
        }
    }
    else
    {
        if (cnx != NULL) {
            /* Break even if fuzzing */
            ret = stress_debug_break(0);
        }
        if (packet != NULL) {
            free(packet);
        }
    }

    return ret;
}

static int stress_start_client_connection(picoquic_quic_t * qclient, picoquic_stress_ctx_t * stress_ctx)
{
    int ret = 0;

    picoquic_cnx_t * cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&stress_ctx->server_addr, stress_ctx->simulated_time,
        0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

    if (cnx == NULL) {
        /* Break even if fuzzing */
        ret = stress_debug_break(1);
    }
    else {
        ret = stress_client_set_callback(cnx, stress_ctx);

        if (ret == 0) {
            ret = picoquic_start_client_cnx(cnx);
            if (ret != 0) {
                ret = stress_debug_break(0);
            }
        }
        else {
            ret = stress_debug_break(0);
        }
    }

    return ret;
}

static int stress_loop_poll_context(picoquic_stress_ctx_t * stress_ctx) 
{
    int ret = 0;
    int64_t delay_max = 100000000;
    uint64_t best_wake_time = stress_ctx->simulated_time + delay_max;
    picoquic_stress_client_t* c_ctx = NULL;

    ret = stress_submit_sp_packets(stress_ctx, stress_ctx->qserver, NULL);

    if (ret != 0) {
        ret  = stress_debug_break(0);
    }
    if (ret == 0) {
        best_wake_time = stress_ctx->simulated_time + picoquic_get_next_wake_delay(
            stress_ctx->qserver, stress_ctx->simulated_time, delay_max);
        c_ctx = (picoquic_stress_client_t*)
            stress_client_node_value(picosplay_first(&stress_ctx->c_tree));
        if (c_ctx != NULL && c_ctx->client_next_time < best_wake_time) {
            best_wake_time = c_ctx->client_next_time;
        } else {
            c_ctx = NULL;
        }
    }
    if (ret == 0) {
        /* Progress the current time */
        stress_ctx->simulated_time = best_wake_time;

        if (c_ctx == NULL) {
            /* The server is ready first */
            ret = stress_handle_packet_prepare(stress_ctx, stress_ctx->qserver, NULL);

            if (ret != 0) {
                ret = stress_debug_break(0);
            }
        }
        else {
            if (c_ctx->qclient->cnx_list == NULL) {
                ret = stress_start_client_connection(c_ctx->qclient, stress_ctx);
                stress_ctx->nb_connections += 1;
                if (ret != 0) {
                    ret = stress_debug_break(0);
                }
            }
            else {
                if (c_ctx->s_to_c_link->first_packet != NULL &&
                    c_ctx->s_to_c_link->first_packet->arrival_time <= stress_ctx->simulated_time) {
                    /* dequeue packet from server to client and submit */
                    ret = stress_handle_packet_arrival(stress_ctx, c_ctx->qclient, c_ctx->s_to_c_link,
                        (struct sockaddr*)&c_ctx->client_addr);
                    if (ret != 0) {
                        ret = stress_debug_break(0);
                    }
                }

                if (ret == 0 && c_ctx->c_to_s_link->first_packet != NULL &&
                    c_ctx->c_to_s_link->first_packet->arrival_time <= stress_ctx->simulated_time) {
                    /* dequeue packet from client to server and submit */
                    ret = stress_handle_packet_arrival(stress_ctx, stress_ctx->qserver, c_ctx->c_to_s_link,
                        (struct sockaddr*)&stress_ctx->server_addr);
                    if (ret != 0) {
                        ret = stress_debug_break(0);
                    }
                }

                if (ret == 0) {
                    ret = stress_submit_sp_packets(stress_ctx, c_ctx->qclient, c_ctx);
                }
                if (ret == 0) {
                    picoquic_cnx_t* cnx;

                    cnx = picoquic_get_earliest_cnx_to_wake(c_ctx->qclient, 0);
                    if (cnx != NULL) {
                        /* If the connection is valid, check whether it is ready */
                        if (cnx->next_wake_time <= stress_ctx->simulated_time) {
                            ret = stress_handle_packet_prepare(stress_ctx, c_ctx->qclient, c_ctx);
                            if (ret != 0) {
                                ret = stress_debug_break(0);
                            }
                        }
                    }
                }
            }
            if (ret == 0) {
                stress_context_reorder(stress_ctx, c_ctx, stress_ctx->simulated_time);
            }
        }
    }

    return ret;
}

/* Stress test management
 * Parameters:
 *    Number of clients
 *    Simulated duration of stress test
 *    Profile of client run, i.e. max number of queries/client.
 *
 * Operation:
 *    Initialize the context:
 *    Loop:
 *        Clean terminated connections (part of simulation loop)
 *        Create connection for empty client contexts (part of simulation loop?)
 *        Run the loop, sending packets, etc.
 *    Clean up:
 *        Set termination flag for all contexts: close existing connections, do not create new ones.
 *        Run the loop until all contexts are freed.
 *        Fail if cannot clean up on a timeout.
 *    Report:
 *        Statistics on duration, volume, connections.
 *
 * Stress succeeds if it comes to a successful end.
 */

static const uint8_t stress_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static int stress_create_client_context(int client_index, picoquic_stress_ctx_t * stress_ctx)
{
    int ret = 0;
    picoquic_stress_client_t * c_ctx = (picoquic_stress_client_t *)malloc(sizeof(picoquic_stress_client_t));

    if (c_ctx == NULL) {
        DBG_PRINTF("Cannot create the client context #%d.\n", (int)client_index);
        ret = -1;
    }
    else {
        memset(c_ctx, 0, sizeof(picoquic_stress_client_t));
        /* Initialize client specific address */
        stress_set_ip_address_from_index(&c_ctx->client_addr, (int)client_index);
        /* set stream ID to default value */

        /* initialize client specific ticket file */
        memcpy(c_ctx->ticket_file_name, "stress_ticket_000.bin", 21);
        c_ctx->ticket_file_name[14] = (uint8_t)('0' + client_index / 100);
        c_ctx->ticket_file_name[15] = (uint8_t)('0' + (client_index / 10) % 10);
        c_ctx->ticket_file_name[16] = (uint8_t)('0' + client_index % 10);
        c_ctx->ticket_file_name[21] = 0;

        ret = picoquic_save_tickets(NULL, stress_ctx->simulated_time, c_ctx->ticket_file_name);
        if (ret != 0) {
            DBG_PRINTF("Cannot create ticket file <%s>.\n", c_ctx->ticket_file_name);
        }
        else {
            /* initialize the simulation links from client to server and back. */
            const double target_bandwidth[4] = { 0.001, 0.01, 0.03, 0.1 };
            uint64_t random_latency = 1000 + picoquic_test_uniform_random(&stress_random_ctx, 99000);
            uint64_t bandwidth_index = picoquic_test_uniform_random(&stress_random_ctx, 4);
            double bandwidth = target_bandwidth[bandwidth_index];
            c_ctx->c_to_s_link = picoquictest_sim_link_create(bandwidth, random_latency, 0, 0, 2 * random_latency);
            c_ctx->s_to_c_link = picoquictest_sim_link_create(bandwidth, random_latency, 0, 0, 2 * random_latency);
            if (c_ctx->c_to_s_link == NULL ||
                c_ctx->s_to_c_link == NULL) {
                DBG_PRINTF("Cannot create the sim links for client #%d.\n", (int)client_index);
                ret = -1;
            }
        }

        if (ret == 0) {
            /* Create the quic context for this client*/
            char test_server_cert_store_file[512];

            ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);

            if (ret != 0) {
                DBG_PRINTF("%s", "Cannot set the cert store file name.\n");
            }
            else {
                c_ctx->qclient = picoquic_create(8, NULL, NULL, test_server_cert_store_file, NULL, NULL,
                    NULL, NULL, NULL, NULL, stress_ctx->simulated_time, &stress_ctx->simulated_time,
                    c_ctx->ticket_file_name, NULL, 0);
                if (c_ctx->qclient == NULL) {
                    DBG_PRINTF("Cannot create the quic client #%d.\n", (int)client_index);
                    ret = -1;
                }
            }
        }
        if (ret == 0) {
            picosplay_insert(&stress_ctx->c_tree, c_ctx);
        }
    }

    stress_ctx->c_ctx[client_index] = c_ctx;

    return ret;
}

static void stress_delete_client_context(int client_index, picoquic_stress_ctx_t * stress_ctx)
{
    picoquic_stress_client_t * c_ctx = stress_ctx->c_ctx[client_index];
    picoquic_stress_client_callback_ctx_t* cb_ctx;

    if (stress_ctx != NULL) {
        picosplay_delete_hint(&stress_ctx->c_tree, &c_ctx->client_node);

        while (c_ctx->qclient->cnx_list != NULL) {
            cb_ctx = (picoquic_stress_client_callback_ctx_t*)
                picoquic_get_callback_context(c_ctx->qclient->cnx_list);
            free(cb_ctx);
            picoquic_set_callback(c_ctx->qclient->cnx_list, NULL, NULL);
            picoquic_delete_cnx(c_ctx->qclient->cnx_list);
        }

        if (c_ctx->qclient != NULL) {
            picoquic_free(c_ctx->qclient);
            c_ctx->qclient = NULL;
        }

        if (c_ctx->c_to_s_link != NULL) {
            picoquictest_sim_link_delete(c_ctx->c_to_s_link);
            c_ctx->c_to_s_link = NULL;
        }

        if (c_ctx->s_to_c_link != NULL) {
            picoquictest_sim_link_delete(c_ctx->s_to_c_link);
            c_ctx->s_to_c_link = NULL;
        }
        free(c_ctx);

        stress_ctx->c_ctx[client_index] = NULL;
    }
}

static int stress_or_fuzz_test(picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx, uint64_t duration, uint64_t wall_time_max)
{
    int ret = 0;
    picoquic_stress_ctx_t stress_ctx;
    double run_time_seconds = 0;
    double target_seconds = 0;
    double wall_time_seconds = 0;
    uint64_t wall_time_start = picoquic_current_time();
    uint64_t nb_connections = 0;
    uint64_t sim_time_next_log = 1000000;
    const int nb_clients = (const int)picoquic_stress_nb_clients;

    stress_random_ctx = 0xBabaC001BaddBab1ull;

    picoquic_fuzz_in_progress = (fuzz_fn == NULL) ? 0 : 1;

    /* Initialization */
    memset(&stress_ctx, 0, sizeof(picoquic_stress_ctx_t));
    /* Initialize the tree that orders clients by wake time */
    picosplay_init_tree(&stress_ctx.c_tree, stress_client_compare, stress_client_node_create, stress_client_node_delete, stress_client_node_value);
    /* Initialize the server */
    stress_set_ip_address_from_index(&stress_ctx.server_addr, -1);
    stress_ctx.nb_clients = nb_clients;
    if (stress_ctx.nb_clients > PICOQUIC_MAX_STRESS_CLIENTS) {
        DBG_PRINTF("Number of stress clients too high (%d). Should be at most %d\n",
            stress_ctx.nb_clients, PICOQUIC_MAX_STRESS_CLIENTS);
        ret = -1;
    } else {
        char test_server_cert_file[512];
        char test_server_key_file[512];
        char test_server_cert_store_file[512];

        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
        }

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
        }
        else {
            stress_ctx.qserver = picoquic_create(PICOQUIC_MAX_STRESS_CLIENTS,
                test_server_cert_file, test_server_key_file, test_server_cert_store_file,
                PICOQUIC_TEST_ALPN, stress_server_callback, NULL, NULL, NULL, NULL,
                stress_ctx.simulated_time, &stress_ctx.simulated_time, NULL,
                stress_ticket_encrypt_key, sizeof(stress_ticket_encrypt_key));

            if (stress_ctx.qserver == NULL) {
                DBG_PRINTF("%s", "Cannot create the test server.\n");
                ret = -1;
            }
            else {
                for (int i = 0; ret == 0 && i < nb_clients; i++) {
                    ret = stress_create_client_context(i, &stress_ctx);
                    if (ret == 0 && fuzz_fn != NULL) {
                        picoquic_set_fuzz(stress_ctx.c_ctx[i]->qclient, fuzz_fn, fuzz_ctx);
                    }
                }
            }
        }
    }

    /* Run the simulation until the specified time */
    sim_time_next_log = stress_ctx.simulated_time + 1000000;
    while (ret == 0 && stress_ctx.simulated_time < duration) {
        if ((picoquic_current_time() - wall_time_start) > wall_time_max) {
            DBG_PRINTF("Stress time takes more than %d, still %d remaining\n",
                (int)wall_time_max, (int)(duration - stress_ctx.simulated_time));
            ret = -1;
            break;
        }

        if (stress_ctx.simulated_time > sim_time_next_log) {
            double log_time = ((double)stress_ctx.simulated_time) / 1000000.0;
            DBG_PRINTF("T:%f. Nb cnx: %ull\n", log_time, 
                (unsigned long long)nb_connections);
            sim_time_next_log = stress_ctx.simulated_time + 1000000;
        }

        if (ret == 0) {
            /* Poll for new packet transmission */
            ret = stress_loop_poll_context(&stress_ctx);
        }

        if (ret != 0) {
            ret = stress_debug_break(0);
        }
    }

    /* Shut down everything */
    for (int i = 0; i < nb_clients; i++) {
        stress_delete_client_context(i, &stress_ctx);
    }

    if (stress_ctx.qserver != NULL) {
        picoquic_free(stress_ctx.qserver);
        stress_ctx.qserver = NULL;
    }

    /* Report */
    run_time_seconds = ((double)stress_ctx.simulated_time) / 1000000.0;
    target_seconds = ((double)duration) / 1000000.0;
    wall_time_seconds = ((double)(picoquic_current_time() - wall_time_start)) / 1000000.0;

    if (stress_ctx.simulated_time < duration) {
        DBG_PRINTF("Stress incomplete after simulating %3fs instead of %3fs in %3f s., returns %d\n",
            run_time_seconds, target_seconds, wall_time_seconds, ret);
        ret = -1;
    }
    else {
        DBG_PRINTF("Stress complete after simulating %3f s. in %3f s., returns %d, nb_cnx = %" PRIu64 ", rand % x\n",
            run_time_seconds, wall_time_seconds, ret, stress_ctx.nb_connections, (int)((picoquic_test_random(&stress_random_ctx)>>48)&0xFFFF));
    }

    picoquic_fuzz_in_progress = 0;

    return ret;
}

int stress_test()
{
    return stress_or_fuzz_test(NULL, NULL, picoquic_stress_test_duration, 10*picoquic_stress_test_duration);
}

/*
 * Basic fuzz test just tries to flip some bits in random packets
 */

typedef struct st_basic_fuzzer_ctx_t {
    uint32_t nb_packets;
    uint32_t nb_fuzzed;
    uint32_t nb_fuzzed_length;
    uint64_t random_context;
    picoquic_state_enum highest_state_fuzzed;
} basic_fuzzer_ctx_t;

static uint32_t basic_fuzzer(void * fuzz_ctx, picoquic_cnx_t* cnx, 
    uint8_t * bytes, size_t bytes_max, size_t length, size_t header_length)
{
    basic_fuzzer_ctx_t * stress_ctx = (basic_fuzzer_ctx_t *)fuzz_ctx;
    uint64_t fuzz_pilot = picoquic_test_random(&stress_ctx->random_context);
    int should_fuzz = 0;
    uint32_t fuzz_index = 0;

    stress_ctx->nb_packets++;

    if (cnx->cnx_state > stress_ctx->highest_state_fuzzed) {
        should_fuzz = 1;
        stress_ctx->highest_state_fuzzed = cnx->cnx_state;
    } else {
        /* if already fuzzed this state, fuzz one packet in 16 */
        should_fuzz = ((fuzz_pilot & 0xF) == 0xD);
        fuzz_pilot >>= 4;
    }

    if (should_fuzz) {
        /* Once in 16, fuzz by changing the length */
        if ((fuzz_pilot & 0xF) == 0xD) {
            uint32_t fuzz_length_max = (uint32_t)(length + 16u);
            uint32_t fuzzed_length;

            if (fuzz_length_max > bytes_max) {
                fuzz_length_max = (uint32_t)bytes_max;
            }
            fuzz_pilot >>= 4;
            fuzzed_length = 16 + (uint32_t)((fuzz_pilot&0xFFFF) % fuzz_length_max);
            fuzz_pilot >>= 16;
            if (fuzzed_length > length) {
                for (uint32_t i = (uint32_t)length; i < fuzzed_length; i++) {
                    bytes[i] = (uint8_t)fuzz_pilot;
                }
            } 
            length = fuzzed_length;

            if (length < header_length) {
                length = header_length;
            }
            stress_ctx->nb_fuzzed_length++;
        }
        /* Find the position that shall be fuzzed */
        fuzz_index = (uint32_t)((fuzz_pilot & 0xFFFF) % length);
        fuzz_pilot >>= 16;
        while (fuzz_pilot != 0 && fuzz_index < length) {
            /* flip one byte */
            bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
            fuzz_pilot >>= 8;
            stress_ctx->nb_fuzzed++;
        }
    }

    return (uint32_t)length;
}

int fuzz_test()
{
    basic_fuzzer_ctx_t fuzz_ctx;
    int ret = 0;

    fuzz_ctx.nb_packets = 0;
    fuzz_ctx.nb_fuzzed = 0;
    fuzz_ctx.nb_fuzzed_length = 0;
    fuzz_ctx.highest_state_fuzzed = 0;
    /* Random seed depends on duration, so different durations do not all start 
     * with exactly the same message sequences. */
    fuzz_ctx.random_context = 0xDEADBEEFBABACAFEull;
    fuzz_ctx.random_context ^= picoquic_stress_test_duration;

    ret = stress_or_fuzz_test(basic_fuzzer, &fuzz_ctx, picoquic_stress_test_duration, picoquic_stress_test_duration);

    DBG_PRINTF("Fuzzed %d packets out of %d, changed %d lengths, ret = %d\n",
        fuzz_ctx.nb_fuzzed, fuzz_ctx.nb_packets, fuzz_ctx.nb_fuzzed_length, ret);

    return ret;
}

/*
* Test that the random generation works the same on every platform. This is meant to
* give us assurance that the stress and fuzz tests behave identically on all platforms.
*
* A test sequence is defined by:
*   - A test seed value;
*   - The result to three successive calls to "picoquic_test_random"
*   - The result of 4 tests to "picoquic_test_uniform_random" with ranges 31, 32, 100, 1000.
* We run several such sequences, and check that the results match expectation
*/

typedef struct st_test_random_tester_t {
    uint64_t seed;
    uint64_t trials[3];
    int uniform[4];
} test_random_tester_t;

static int uniform_test[4] = { 31, 32, 100, 1000 };

static test_random_tester_t random_cases[] = {
#ifndef COMPUTING_RANDOM_TABLE
    { 0xdeadbeefbabac001ull,
        { 0x5e15223d01b20defull, 0x9ede0d895c9bd2a6ull, 0xe3a0ed91f612c17full },
        { 0, 0, 70, 197 } },
    { 0x56df77dd5d6000efull,
        { 0xdfccc8d428187e18ull, 0x7d7552fd225a16d7ull, 0x32dabe642e7390cull },
        { 30, 5, 34, 751 } },
    { 0x6fbbeeaeb00077abull,
        { 0x43131e190d5c97full, 0x42fb1ccc58b906dull, 0x610a3b5abef97be4ull },
        { 26, 16, 12, 939 } },
    { 0xddf75758003bd5b7ull,
        { 0x3a8d9a1a727aba2dull, 0xe9279c9bb67c725cull, 0x1acf0953978b79e8ull },
        { 3, 11, 41, 82 } },
    { 0xfbabac001deadbeeull,
        { 0x5112b0a7de31f1b7ull, 0xd691b591d3598619ull, 0xf1b42dc66cf4f215ull },
        { 17, 10, 44, 527 } },
    { 0xd5d6000ef56df77dull,
        { 0xb699f9cadcb2a474ull, 0xc2213dfa4ec1c973ull, 0x843f0e6573dda32eull },
        { 9, 30, 52, 680 } },
    { 0xeb00077ab6fbbeeaull,
        { 0x6dd0c0b399bae357ull, 0xa5a6b1ec22fa894bull, 0x85f25e84ba0843a0ull },
        { 16, 5, 5, 899 } },
    { 0x8003bd5b7ddf7575ull,
        { 0xf7745169aa75f266ull, 0x551964d08e2c25e0ull, 0x17b86c9be72f96bbull },
        { 4, 24, 48, 21 } },
    { 0x1deadbeefbabac0ull,
        { 0xc51696cc9c124ff9ull, 0x1b9d1372c2f72058ull, 0xe539681abb702c48ull },
        { 20, 21, 96, 865 } },
    { 0xef56df77dd5d6000ull,
        { 0xf40b816f8efc0ec8ull, 0xd8a949c49d03c01cull, 0x170902fde977c269ull },
        { 2, 30, 55, 720 } }
#else
    /* Dummy value used when computing the table */
    { 0, { 0, 0, 0}, { 0, 0, 0, 0}}
#endif
};

static size_t nb_random_cases = sizeof(random_cases) / sizeof(test_random_tester_t);

int random_tester_test()
{
    /* This is the initial run, so we merely write the expected value */
    uint64_t t_seed = 0xDEADBEEFBABAC001ull;
    int ret = 0;

    if (nb_random_cases < 2) {
        /* This code was used to generate the table of random cases */
        for (int i = 0; i < 10; i++)
        {
            /* Rotate the seed */
            uint64_t stress_ctx = t_seed;
            /* Generate the values */
            printf("{ 0x%llxull, \n{ ", (unsigned long long)t_seed);
            for (int j = 0; j < 3; j++) {
                printf("0x%llxull%s", (unsigned long long)picoquic_test_random(&stress_ctx), (j < 2) ? ", " : "},\n{ ");
            }
            for (int j = 0; j < 4; j++) {
                printf("%d%s", (int)picoquic_test_uniform_random(&stress_ctx, uniform_test[j]),
                    (j < 3) ? ", " : "}},\n");
            }
            t_seed = (t_seed << 7) | (t_seed >> 57);
        }
    }
    else {
        for (int i = 0; ret == 0 && i < (int)nb_random_cases; i++)
        {
            uint64_t stress_ctx = random_cases[i].seed;
            for (int j = 0; ret == 0 && j < 3; j++) {
                uint64_t r = picoquic_test_random(&stress_ctx);
                if (r != random_cases[i].trials[j]) {
                    DBG_PRINTF("Case %d, seed %llx, trial[%d] = %llx, expected %llx\n",
                        i, (unsigned long long)random_cases[i].seed, j,
                        (unsigned long long)r, (unsigned long long)random_cases[i].trials[j]);
                    ret = -1;
                }
            }
            for (int j = 0; ret == 0 && j < 4; j++) {
                int r = (int)picoquic_test_uniform_random(&stress_ctx, uniform_test[j]);
                if (r != random_cases[i].uniform[j]) {
                    DBG_PRINTF("Case %d, seed %llx, uniform(%d) = %d, expected %d\n",
                        i, (unsigned long long)random_cases[i].seed, uniform_test[j],
                        (unsigned long long)r, (unsigned long long)random_cases[i].uniform[j]);
                    ret = -1;
                }
            }
        }
    }

    return ret;
}

#define RANDOM_GAUSS_NB_TESTS 255
int random_gauss_test()
{
    uint64_t t_seed = 0xDEADBEEFBABAC001ull;
    int ret = 0;
    double x2 = 0;
    double x_sum = 0;
    double a;
    double v;

    for (int i = 0; i < RANDOM_GAUSS_NB_TESTS; i++) {
        double x = picoquic_test_gauss_random(&t_seed);
        x_sum += x;
        x2 += x * x;
    }

    a = x_sum / RANDOM_GAUSS_NB_TESTS;
    v = x2 / RANDOM_GAUSS_NB_TESTS;

    if (a < -0.02 || a > 0.02) {
        ret = -1;
    }
    else if (v < 0.97 || v > 1.03) {
        ret = -1;
    }

    return ret;
}

/*
 * Initial fuzz test.
 *
 * This test specializes in fuzzing the initial packet, and checking what happens. All the
 * packets sent there are illegitimate, and should result in broken connections.
 *
 * The test reuses the frame definitions of the skip frame test.
 */


typedef struct st_initial_fuzzer_ctx_t {
    uint32_t current_frame;
    uint32_t fuzz_position;
    int initial_fuzzing_done;
    uint64_t random_context;
} initial_fuzzer_ctx_t;

static uint32_t initial_fuzzer(void * fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t * bytes, size_t bytes_max, size_t length, size_t header_length)
{
    initial_fuzzer_ctx_t * stress_ctx = (initial_fuzzer_ctx_t *)fuzz_ctx;
    uint32_t should_fuzz = 0;

    if (cnx->cnx_state == picoquic_state_client_init_sent) {
        should_fuzz = 1;
        if (stress_ctx->initial_fuzzing_done == 0) {
            if (stress_ctx->current_frame >= nb_test_skip_list) {
                stress_ctx->fuzz_position++;
                stress_ctx->current_frame = 0;

                if (stress_ctx->fuzz_position > 2) {
                    stress_ctx->fuzz_position = 0;
                    stress_ctx->initial_fuzzing_done = 1;
                }
            }
        }
    }

    if (should_fuzz) {
        if (!stress_ctx->initial_fuzzing_done) {
            size_t len = test_skip_list[stress_ctx->current_frame].len;
            switch (stress_ctx->fuzz_position) {
            case 0:
                if (length + len <= bytes_max) {
                    /* First test variant: add a random frame at the end of the packet */
                    memcpy(&bytes[length], test_skip_list[stress_ctx->current_frame].val, len);
                    length += len;
                }
                break;
            case 1:
                if (length + len <= bytes_max) {
                    /* Second test variant: add a random frame at the beginning of the packet */
                    memmove(bytes + header_length + len, bytes + header_length, len);
                    memcpy(&bytes[header_length], test_skip_list[stress_ctx->current_frame].val, len);
                    length += len;
                }
                break;
            case 2:
                if (length + len <= bytes_max) {
                    /* Third test variant: replace the packet by a random frame */
                    memcpy(&bytes[header_length], test_skip_list[stress_ctx->current_frame].val, len);

                    if (length > header_length + len) {
                        /* If there is room left, */
                        memset(&bytes[header_length + len], 0, length - (header_length + len));
                    }
                    else {
                        length = header_length + len;
                    }
                }
                break;
            default:
                break;
            }
            stress_ctx->current_frame++;
        }
        else {
            uint64_t fuzz_pilot = picoquic_test_random(&stress_ctx->random_context);
            uint32_t fuzz_index = (uint32_t)((fuzz_pilot & 0xFFFF) % (uint32_t)length);
            uint8_t fuzz_length;
            fuzz_pilot >>= 16;
            fuzz_length = (uint8_t)(((fuzz_pilot & 0xFF) % 5) + 1);
            fuzz_pilot >>= 8;

            while (fuzz_length != 0 && fuzz_index < length) {
                /* flip one byte */
                bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
                fuzz_length--;
            }
        }
    }

    return (uint32_t)length;
}

int fuzz_initial_test()
{
    initial_fuzzer_ctx_t fuzz_ctx;
    int ret = 0;

    memset(&fuzz_ctx, 0, sizeof(initial_fuzzer_ctx_t));
    fuzz_ctx.random_context = 0x01234567DEADBEEFull;
    fuzz_ctx.random_context ^= picoquic_stress_test_duration;

    ret = stress_or_fuzz_test(initial_fuzzer, &fuzz_ctx, 2*picoquic_stress_test_duration, 4*picoquic_stress_test_duration);

    return ret;
}
