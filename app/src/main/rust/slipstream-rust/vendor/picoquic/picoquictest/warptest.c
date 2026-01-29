/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "autoqlog.h"

/* Warp tests:
* These tests are very similar to the "media tests", with one twist.
* Instead of sending the simulated media as series of frames on a
* QUIC stream, each frame is sent on a stream by itself.
* 
* This requires writing a data generation model that mimics real time.
* The network topology will be simple: client, server, link.
* 
* Data generation is linked to a callback. The callback accomodate for:
* - video generation model, 60 fps, combined one large "I" frame and
*   then 99 "P" frames, repeated three times.
* - Audio generation model, 50 fps, 30 bytes per frame.
* - Data generation model, some number of megabytes.
* 
* The test must verify that frame delays are within specified bounds.
* For that, we will format the frames:
* - length: in bytes
* - type: Audio, Video, Data.
* - time sent.
* Each frame will be sent as an unidirectional stream.
* 
* When a media frame is generated, we create a unilateral stream
* context to send that frame. If frames are created faster than
* they are being sent, there will be multiple unidirectional stream
* context sent in parallel, and received in parallel. 
* On the receiver, there is a unidirectional stream context opened
* for each frame that is being received. The receiver parses the
* frame header to find indication of media, frame ID, etc.
* 
* The first versions of this test only use the unidirectional stream.
* We want to test a couple of reported issues:
* 
* - Protocol error because the client and server disagree on the value
*   of the number of streams limit. Shall be tested by picking a low limit.
*   Probably needs to test in both directions.
* - Slow transmission of frames when the frame size exceeds the
*   default max stream data limit. Shall be reproed by picking a low
*   limit value, then measured fixed with a high enough limit.
* - Slow transmission when frames are created faster than number of
*   stream limit allows.
*/

#define WARPTEST_ALPN "picoquic_mediatest"
#define WARPTEST_HEADER_SIZE 21
#define WARPTEST_ERROR_INTERNAL 1
#define WARPTEST_DURATION 10000000
#define WARPTEST_AUDIO_PERIOD 20000
#define WARPTEST_VIDEO_PERIOD 33333
#define WARPTEST_DATA_FRAME_SIZE 0x4000


typedef enum {
    warptest_data = 0,
    warptest_audio,
    warptest_video,
    warptest_nb_types
} warptest_type_enum;

typedef struct st_warptest_message_buffer_t {
    size_t bytes_sent;
    size_t bytes_received;
    warptest_type_enum message_type;
    uint32_t message_size;
    uint64_t frame_number;
    uint64_t sent_time;
    uint8_t header[WARPTEST_HEADER_SIZE];
} warptest_message_buffer_t;

typedef struct st_warptest_uni_stream_ctx_t {
    /* Organize the streams as part of the connection */
    struct st_warptest_uni_stream_ctx_t* next_uni_stream;
    struct st_warptest_uni_stream_ctx_t* previous_uni_stream;
    struct st_warptest_cnx_ctx_t* cnx_ctx;
    /* stream identifier */
    uint64_t stream_id;
    /* Specify the type of stream */
    warptest_type_enum stream_type;
    /* Specify the state of the stream: number of frames sent  or received */
    unsigned int is_sender : 1;

    /* TODO: check what data is actually needed */
    size_t bytes_sent;
    size_t bytes_received;
    /* TODO: do we need to buffer the entire data? */
    warptest_message_buffer_t message_sent;
    warptest_message_buffer_t message_received;
} warptest_uni_stream_ctx_t;

/* Mediatest per connection context */
typedef struct st_warptest_cnx_ctx_t {
    struct st_warptest_cnx_ctx_t* next_cnx;
    struct st_warptest_cnx_ctx_t* previous_cnx;
    struct st_warptest_ctx_t* mt_ctx;

    char* sni;
    struct sockaddr_storage addr;
    picoquic_cnx_t* cnx;
    int is_server;

    struct st_warptest_stream_ctx_t* first_stream;
    struct st_warptest_stream_ctx_t* last_stream;

    struct st_warptest_uni_stream_ctx_t* first_uni_stream;
    struct st_warptest_uni_stream_ctx_t* last_uni_stream;
} warptest_cnx_ctx_t;

/* Mediatest statistics per media type */
typedef struct st_warptest_media_stats_t {
    int nb_frames;
    uint64_t sum_delays;
    uint64_t sum_square_delays;
    uint64_t min_delay;
    uint64_t max_delay;
} warptest_media_stats_t;

/* Mediatest context */
typedef struct st_warptest_ctx_t {
    uint64_t simulated_time;
    picoquic_quic_t* quic[2]; /* QUIC Context for client[0] or server[1] */
    picoquictest_sim_link_t* link[2]; /* Link from client to server [0] and back [1] */
    struct sockaddr_storage addr[2]; /* addresses of client [0] and server [1]*/
    warptest_cnx_ctx_t* client_cnx; /* client connection context */
    struct st_warptest_cnx_ctx_t* first_cnx;
    struct st_warptest_cnx_ctx_t* last_cnx;
    /* Management of media streams.
     * For the data stream, "frame to send" is expressed in bytes, just as "frames_sent"
     */
    uint64_t frames_to_send[warptest_nb_types];
    uint64_t frames_sent[warptest_nb_types];
    uint64_t next_frame_time[warptest_nb_types];
    /* managemenent of datagram load */
    size_t datagram_data_requested;
    size_t datagram_data_sent;
    size_t datagram_data_received;
    int nb_datagrams_sent;
    int nb_datagrams_received;

    /* Statistics */
    warptest_media_stats_t media_stats[warptest_nb_types];
} warptest_ctx_t;

/* warptest test specification */
typedef struct st_warptest_spec_t {
    picoquic_congestion_algorithm_t* ccalgo; 
    int do_audio;
    int do_video;
    size_t data_size;
    size_t datagram_data_size;
    uint64_t max_streams_client;
    uint64_t max_streams_server;
    uint64_t max_stream_data;
    double bandwidth;
} warptest_spec_t;

int warptest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

static const uint8_t warptest_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

int warptest_format_message_header(warptest_message_buffer_t * message_sent, warptest_type_enum message_type)
{
    int ret = 0;
    message_sent->header[0] = (uint8_t)message_type;
    if (picoquic_frames_uint32_encode(message_sent->header + 1,
        message_sent->header + WARPTEST_HEADER_SIZE, (uint32_t)message_sent->message_size) == NULL ||
        picoquic_frames_uint64_encode(message_sent->header + 5,
            message_sent->header + WARPTEST_HEADER_SIZE, message_sent->frame_number) == NULL ||
        picoquic_frames_uint64_encode(message_sent->header + 13,
            message_sent->header + WARPTEST_HEADER_SIZE, message_sent->sent_time) == NULL) {
        ret = -1;
    }

    return ret;
}

int warptest_fill_receive_buffer(warptest_message_buffer_t* message_received, uint8_t* bytes, size_t length,
    size_t* msg_read, int* is_complete)
{
    int ret = 0;
    size_t available = 0;
    *msg_read = 0;
    *is_complete = 0;

    /* Receive the message buffer. If at least 2 bytes, compute the size. */
    while (length > *msg_read && ret == 0 && message_received->bytes_received < WARPTEST_HEADER_SIZE) {
        message_received->header[message_received->bytes_received++] = bytes[*msg_read];
        *msg_read += 1;
        if (message_received->bytes_received == WARPTEST_HEADER_SIZE) {
            message_received->message_type = message_received->header[0];
            if (picoquic_frames_uint32_decode(message_received->header + 1,
                message_received->header + WARPTEST_HEADER_SIZE, &message_received->message_size) == NULL ||
                picoquic_frames_uint64_decode(message_received->header + 5,
                    message_received->header + WARPTEST_HEADER_SIZE, &message_received->sent_time) == NULL) {
                ret = -1;
            }
        }
    }

    if (length > *msg_read && ret == 0) {
        available = length - *msg_read;
        if (message_received->bytes_received > message_received->message_size) {
            ret = -1;
        }
        else {
            size_t required = message_received->message_size - message_received->bytes_received;
            if (required <= available) {
                available = required;
                *is_complete = 1;
            }
            message_received->bytes_received += available;
            *msg_read += available;
        }
    }

    return ret;
}


void warptest_record_stats(warptest_ctx_t* mt_ctx, warptest_message_buffer_t* message_received)
{
    uint64_t delay = mt_ctx->simulated_time - message_received->sent_time;

    if (message_received->message_type >= 0 && message_received->message_type < warptest_nb_types) {
        warptest_media_stats_t* stats = mt_ctx->media_stats + message_received->message_type;
        stats->nb_frames++;
        stats->sum_delays += delay;
        stats->sum_square_delays += delay * delay;
        if (stats->min_delay > delay) {
            stats->min_delay = delay;
        }
        if (stats->max_delay < delay) {
            stats->max_delay = delay;
        }
        /* TODO: add stats on order of packets */
    }
}

/* Management of the stream context used for data.
 */

typedef struct st_warptest_stream_ctx_t {
    /* Organize the streams as part of the connection */
    struct st_warptest_stream_ctx_t* next_stream;
    struct st_warptest_stream_ctx_t* previous_stream;
    struct st_warptest_cnx_ctx_t* cnx_ctx;
    /* stream identifier */
    uint64_t stream_id;
    /* Specify the state of the stream: number of frames sent  or received */
    unsigned int is_sender : 1;
    unsigned int finished_sending : 1;
    unsigned int fin_received : 1;
    unsigned int is_fin_sent : 1;

    warptest_ctx_t* mt_ctx;
    uint64_t frame_number;
    warptest_message_buffer_t message_sent;
    warptest_message_buffer_t message_received;
} warptest_stream_ctx_t;

int warptest_receive_stream_data(warptest_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;

    if (stream_ctx->is_sender && length > 0) {
        picoquic_log_app_message(stream_ctx->cnx_ctx->cnx, "WARPTEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
        DBG_PRINTF("WARPTEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
        ret = -1;
    }

    while (length > 0 && ret == 0) {
        size_t msg_read = 0;
        int is_complete = 0;
        /* Receive the message buffer */
        ret = warptest_fill_receive_buffer(&stream_ctx->message_received, bytes, length, &msg_read, &is_complete);

        if (ret == 0) {
            if (is_complete) {
                if (stream_ctx->message_received.message_type != warptest_data) {
                    ret = -1;
                }
                else {
                    /* Record statistics */
                    warptest_record_stats(stream_ctx->cnx_ctx->mt_ctx, &stream_ctx->message_received);
                    /* Prepare for next message */
                    memset(&stream_ctx->message_received, 0, sizeof(warptest_message_buffer_t));
                }
            }
            length -= msg_read;
            bytes += msg_read;
        }
    }

    if (is_fin && ret == 0) {
        /* Check whether the stream should be marked finished. */
        /* If both sides finished, delete stream? */
        stream_ctx->fin_received = 1;
        if (!stream_ctx->is_fin_sent) {
            picoquic_mark_active_stream(stream_ctx->cnx_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
    }
    return ret;
}

/* Send stream data.
 * For sender, if message is sent and time has come, create a new frame.
 * If frame data available, send it.
 * If no more frame, mark FIN.
 * For receiver, only send a FIN mark if FIN has been received.
 */
int warptest_prepare_to_send_on_stream(warptest_stream_ctx_t* stream_ctx, void* context, size_t space, uint64_t current_time)
{
    int ret = 0;

    if (stream_ctx->is_sender) {
        /* If no ongoing message, try prepare a new one. */
        if (stream_ctx->message_sent.message_size == 0 && !stream_ctx->finished_sending) {
            /* Should the data stream be activated? */
            int64_t available = stream_ctx->mt_ctx->frames_to_send[warptest_data] - stream_ctx->mt_ctx->frames_sent[warptest_data];
            if (available > 0) {
                if (available > WARPTEST_DATA_FRAME_SIZE) {
                    available = WARPTEST_DATA_FRAME_SIZE;
                }
                else if (available < WARPTEST_HEADER_SIZE) {
                    available = WARPTEST_HEADER_SIZE;
                }
                stream_ctx->message_sent.message_size = (uint32_t)available;
                stream_ctx->message_sent.message_type = warptest_data;
                stream_ctx->message_sent.sent_time = current_time;
                stream_ctx->message_sent.frame_number = stream_ctx->frame_number;
                stream_ctx->frame_number += 1;
                ret = warptest_format_message_header(&stream_ctx->message_sent, warptest_data);
            }
        }
        if (ret == 0 && stream_ctx->message_sent.message_size > stream_ctx->message_sent.bytes_sent) {
            uint8_t* buffer;
            size_t header_bytes = 0;
            int is_still_active = 0;
            int is_fin = 0;
            /* Compute bytes that need to be sent */
            size_t available = stream_ctx->message_sent.message_size - stream_ctx->message_sent.bytes_sent;
            if (available > space) {
                available = space;
                is_still_active = 1;
            }
            else {
                stream_ctx->mt_ctx->frames_sent[warptest_data] += stream_ctx->message_sent.message_size;
                is_fin = (stream_ctx->mt_ctx->frames_sent[warptest_data] >= stream_ctx->mt_ctx->frames_to_send[warptest_data]);
                is_still_active = !is_fin;
            }
            buffer = (uint8_t*)picoquic_provide_stream_data_buffer(context, available, is_fin, is_still_active);
            if (buffer == NULL) {
                ret = -1;
            }
            else {
                stream_ctx->is_fin_sent = is_fin;
                stream_ctx->finished_sending |= is_fin;
                /* fill the header bytes if needed */
                if (stream_ctx->message_sent.bytes_sent < WARPTEST_HEADER_SIZE) {
                    header_bytes = WARPTEST_HEADER_SIZE - stream_ctx->message_sent.bytes_sent;
                    if (header_bytes > available) {
                        header_bytes = available;
                    }
                    memcpy(buffer, stream_ctx->message_sent.header + stream_ctx->message_sent.bytes_sent, header_bytes);
                }
                /* fill the other bytes */
                if (available > header_bytes) {
                    memset(buffer + header_bytes, (uint8_t)stream_ctx->message_sent.message_type, available - header_bytes);
                }
                stream_ctx->message_sent.bytes_sent += available;
                if (stream_ctx->message_sent.bytes_sent >= stream_ctx->message_sent.message_size) {
                    memset(&stream_ctx->message_sent, 0, sizeof(warptest_message_buffer_t));
                }
            }
        }
        else {
            (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
        }
    }
    else if (stream_ctx->fin_received && !stream_ctx->is_fin_sent) {
        (void)picoquic_provide_stream_data_buffer(context, 0, 1, 0);
        stream_ctx->is_fin_sent = 1;
    }
    return ret;
}

void warptest_delete_stream_ctx(warptest_stream_ctx_t* stream_ctx)
{
    if (stream_ctx->previous_stream == NULL) {
        stream_ctx->cnx_ctx->first_stream = stream_ctx->next_stream;
    }
    else {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }

    if (stream_ctx->next_stream == NULL) {
        stream_ctx->cnx_ctx->last_stream = stream_ctx->previous_stream;
    }
    else {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }

    if (stream_ctx->cnx_ctx->cnx != NULL) {
        picoquic_unlink_app_stream_ctx(stream_ctx->cnx_ctx->cnx, stream_ctx->stream_id);
    }

    free(stream_ctx);
}

warptest_stream_ctx_t* warptest_create_stream_context(warptest_cnx_ctx_t* cnx_ctx, uint64_t stream_id)
{
    warptest_stream_ctx_t* stream_ctx = (warptest_stream_ctx_t*)malloc(sizeof(warptest_stream_ctx_t));
    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(warptest_stream_ctx_t));
        stream_ctx->cnx_ctx = cnx_ctx;
        stream_ctx->stream_id = stream_id;
        if (cnx_ctx->last_stream == NULL) {
            cnx_ctx->first_stream = stream_ctx;
        }
        else {
            cnx_ctx->last_stream->next_stream = stream_ctx;
        }
        stream_ctx->previous_stream = cnx_ctx->last_stream;
        cnx_ctx->last_stream = stream_ctx;
        /* simplification: only clients are senders. */
        stream_ctx->is_sender = !cnx_ctx->is_server;
        stream_ctx->mt_ctx = cnx_ctx->mt_ctx;

        if (cnx_ctx->cnx != NULL) {
            (void)picoquic_set_app_stream_ctx(cnx_ctx->cnx, stream_id, stream_ctx);
        }
    }

    return stream_ctx;
}

warptest_stream_ctx_t* warptest_find_or_create_stream(
    uint64_t stream_id,
    warptest_cnx_ctx_t* cnx_ctx,
    int should_create)
{
    warptest_stream_ctx_t* stream_ctx = cnx_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->stream_id == stream_id) {
            break;
        }
        stream_ctx = stream_ctx->next_stream;
    }
    if (stream_ctx == NULL && should_create) {
        stream_ctx = warptest_create_stream_context(cnx_ctx, stream_id);
    }

    return stream_ctx;
}


/* Management of the unidir stream contexts used for audio and video
 */
void warptest_delete_uni_stream_ctx(warptest_uni_stream_ctx_t* stream_ctx)
{
    if (stream_ctx->previous_uni_stream == NULL) {
        stream_ctx->cnx_ctx->first_uni_stream = stream_ctx->next_uni_stream;
    }
    else {
        stream_ctx->previous_uni_stream->next_uni_stream = stream_ctx->next_uni_stream;
    }

    if (stream_ctx->next_uni_stream == NULL) {
        stream_ctx->cnx_ctx->last_uni_stream = stream_ctx->previous_uni_stream;
    }
    else {
        stream_ctx->next_uni_stream->previous_uni_stream = stream_ctx->previous_uni_stream;
    }

    if (stream_ctx->cnx_ctx->cnx != NULL) {
        picoquic_unlink_app_stream_ctx(stream_ctx->cnx_ctx->cnx, stream_ctx->stream_id);
    }

    free(stream_ctx);
}

warptest_uni_stream_ctx_t* warptest_create_uni_stream_context(warptest_cnx_ctx_t* cnx_ctx, uint64_t stream_id)
{
    warptest_uni_stream_ctx_t* stream_ctx = (warptest_uni_stream_ctx_t*)malloc(sizeof(warptest_uni_stream_ctx_t));
    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(warptest_uni_stream_ctx_t));
        stream_ctx->cnx_ctx = cnx_ctx;
        stream_ctx->stream_id = stream_id;
        if (cnx_ctx->last_uni_stream == NULL) {
            cnx_ctx->first_uni_stream = stream_ctx;
        }
        else {
            cnx_ctx->last_uni_stream->next_uni_stream = stream_ctx;
        }
        stream_ctx->previous_uni_stream = cnx_ctx->last_uni_stream;
        cnx_ctx->last_uni_stream = stream_ctx;
        /* simplification: only clients are senders. */
        stream_ctx->is_sender = !stream_ctx->cnx_ctx->is_server;

        if (cnx_ctx->cnx != NULL) {
            (void)picoquic_set_app_stream_ctx(cnx_ctx->cnx, stream_id, stream_ctx);
        }
    }

    return stream_ctx;
}

warptest_uni_stream_ctx_t* warptest_find_or_create_uni_stream(
    uint64_t stream_id,
    warptest_cnx_ctx_t* cnx_ctx,
    int should_create)
{
    warptest_uni_stream_ctx_t* stream_ctx = cnx_ctx->first_uni_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->stream_id == stream_id) {
            break;
        }
        stream_ctx = stream_ctx->next_uni_stream;
    }
    if (stream_ctx == NULL && should_create) {
        stream_ctx = warptest_create_uni_stream_context(cnx_ctx, stream_id);
    }

    return stream_ctx;
}

/* Delete a connection context */
void warptest_delete_cnx_context(warptest_cnx_ctx_t* cnx_ctx)
{
    while (cnx_ctx->first_uni_stream != NULL) {
        warptest_delete_uni_stream_ctx(cnx_ctx->first_uni_stream);
    }

    while (cnx_ctx->first_stream != NULL) {
        warptest_delete_stream_ctx(cnx_ctx->first_stream);
    }

    if (cnx_ctx->cnx != NULL) {
        picoquic_set_callback(cnx_ctx->cnx, NULL, NULL);
        /* Check whether this is right, versus just delete the context link. */
        picoquic_delete_cnx(cnx_ctx->cnx);
    }

    if (cnx_ctx->previous_cnx == NULL) {
        cnx_ctx->mt_ctx->first_cnx = cnx_ctx->next_cnx;
    }
    else {
        cnx_ctx->previous_cnx->next_cnx = cnx_ctx->next_cnx;
    }

    if (cnx_ctx->next_cnx == NULL) {
        cnx_ctx->mt_ctx->last_cnx = cnx_ctx->previous_cnx;
    }
    else {
        cnx_ctx->next_cnx->previous_cnx = cnx_ctx->previous_cnx;
    }

    free(cnx_ctx);
}

/* Create a connection context. 
 * QUIC connection has to be created before the WARP connection context 
 * Decide whether media stream belongs in test context or connection context.
 */
warptest_cnx_ctx_t* warptest_create_cnx_context(warptest_ctx_t* mt_ctx, picoquic_cnx_t * cnx)
{
    warptest_cnx_ctx_t* cnx_ctx = (warptest_cnx_ctx_t*)malloc(sizeof(warptest_cnx_ctx_t));

    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(warptest_cnx_ctx_t));
        /* document quic connection */
        cnx_ctx->cnx = cnx;
        /* Add the connection in the double linked list */
        if (mt_ctx->last_cnx == NULL) {
            mt_ctx->first_cnx = cnx_ctx;
        }
        else {
            mt_ctx->last_cnx->next_cnx = cnx_ctx;
        }
        cnx_ctx->previous_cnx = mt_ctx->last_cnx;
        mt_ctx->last_cnx = cnx_ctx;
        cnx_ctx->mt_ctx = mt_ctx;
        picoquic_set_callback(cnx, warptest_callback, cnx_ctx);
    }
    return cnx_ctx;
}

/* TODO: do that based on uni streams.
 * Add stats for Out Of Order delivery:
 * - highest number received
 * - In sequence if new > highest received.
 * - If in sequence, compute size of sequence gaps, both as
 *   packet numbers and as time values.
 */

int warptest_check_stats(warptest_ctx_t* mt_ctx, warptest_type_enum media_type)
{
    int ret = 0;

    if (media_type >= 0 && media_type < warptest_nb_types) {
        warptest_media_stats_t* stats = mt_ctx->media_stats + media_type;
        uint64_t period = (media_type == warptest_audio) ? WARPTEST_AUDIO_PERIOD : WARPTEST_VIDEO_PERIOD;
        uint64_t expected = WARPTEST_DURATION / period;

        if (stats->nb_frames != expected) {
            ret = -1;
        }
        else if (stats->nb_frames != 0) {
            uint64_t average = stats->sum_delays / stats->nb_frames;
            uint64_t variance = (stats->sum_square_delays / stats->nb_frames) - (average * average);
            uint64_t sigma = picoquic_sqrt_for_tests(variance);

            if (average > 25000 || sigma > 12500 || stats->max_delay > 100000) {
                ret = -1;
            }

            /* TODO: add tests for acceptable out of order deliveries */
        }
    }

    return ret;
}

int warptest_receive_uni_stream_data(warptest_uni_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;
    size_t msg_read = 0;
    size_t available = 0;

    if (stream_ctx->is_sender) {
        picoquic_log_app_message(stream_ctx->cnx_ctx->cnx, "WARPTEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
        DBG_PRINTF("WARPTEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
        ret = -1;
    } else {
        /* Receive the message buffer. If at least 2 bytes, compute the size. */
        while (length > msg_read && ret == 0 && stream_ctx->message_received.bytes_received < WARPTEST_HEADER_SIZE) {
            stream_ctx->message_received.header[stream_ctx->message_received.bytes_received++] = bytes[msg_read++];
            if (stream_ctx->message_received.bytes_received == WARPTEST_HEADER_SIZE) {
                stream_ctx->message_received.message_type = stream_ctx->message_received.header[0];
                if (picoquic_frames_uint32_decode(stream_ctx->message_received.header + 1,
                    stream_ctx->message_received.header + WARPTEST_HEADER_SIZE, &stream_ctx->message_received.message_size) == NULL ||
                    picoquic_frames_uint64_decode(stream_ctx->message_received.header + 5,
                        stream_ctx->message_received.header + WARPTEST_HEADER_SIZE, &stream_ctx->message_received.frame_number) == NULL ||
                    picoquic_frames_uint64_decode(stream_ctx->message_received.header + 13,
                        stream_ctx->message_received.header + WARPTEST_HEADER_SIZE, &stream_ctx->message_received.sent_time) == NULL) {
                    ret = -1;
                }
                else {
                    stream_ctx->stream_type = stream_ctx->message_received.message_type;
                }
            }
        }
        /* Receive the next bytes */
        if (length > msg_read && ret == 0) {
            size_t required = stream_ctx->message_received.message_size - stream_ctx->message_received.bytes_received;
            available = length - msg_read;
            
            if (available > required) {
                /* Should not happen -- only one message per stream */
                ret = -1;
            }
            else {
                stream_ctx->message_received.bytes_received += available;
                length = 0;
            
                if (available == required){
                    /* Record statistics */
                    warptest_record_stats(stream_ctx->cnx_ctx->mt_ctx, &stream_ctx->message_received);
                    memset(&stream_ctx->message_received, 0, sizeof(warptest_message_buffer_t));
                }
            }
        }
        /* Check FIN */
        if (ret == 0 && is_fin) {
            if (stream_ctx->message_received.bytes_received < stream_ctx->message_received.message_size) {
                /* This is an error -- stream closed before all bytes sent. */
                ret = -1;
            }
            else {
                ret = picoquic_mark_active_stream(stream_ctx->cnx_ctx->cnx, stream_ctx->stream_id, 0, NULL);
                if (ret == 0) {
                    warptest_delete_uni_stream_ctx(stream_ctx);
                }
            }
        }
    }

    return ret;
}

/* Prepare next frame. Do this as soon as we know that a new frame can be sent.
 * - For each new frame:
 *      - create a new sender unidirectional stream
 *      - prepare the message in uni stream context
 *      - mark the new unidir stream context as ready.
 * - Consider the number of frames or the time limit. 
 * Issue: queuing a "data" frame does not progress the time. This leads to 
 * a loop, because there is no flow control applied, and eventually the tests
 * fail. There are two plausible solutions:
 * - Send the data stream as a single QUIC stream, instead of multiple streams.
 * - Send the data stream one frame at a time, but implement a flow control
 *   for that stream.
 * The first solution is the most natural, so we implement it.
 */
int warptest_prepare_new_frame(warptest_ctx_t* mt_ctx, uint64_t current_time)
{
    int ret = 0;
    int priority = 255;

    /* Is this the right time for a real time stream?
     * (Data streams are sent when data stream is ready)
     */
    for (int i = 0; i < warptest_nb_types; i++) {
        warptest_type_enum message_type = (warptest_type_enum)i;
        if (mt_ctx->next_frame_time[i] <= current_time &&
            message_type != warptest_data) {
            warptest_uni_stream_ctx_t* stream_ctx = warptest_create_uni_stream_context(mt_ctx->client_cnx,
                picoquic_get_next_local_stream_id(mt_ctx->client_cnx->cnx, 1));
            stream_ctx->is_sender = 1;
            stream_ctx->message_sent.sent_time = mt_ctx->next_frame_time[i];
            stream_ctx->message_sent.message_type = message_type;
            stream_ctx->message_sent.frame_number = mt_ctx->frames_sent[i];
            switch (message_type) {
            case warptest_audio:
                stream_ctx->message_sent.message_size = 32;
                mt_ctx->next_frame_time[i] += WARPTEST_AUDIO_PERIOD;
                priority = 3;
                break;
            case warptest_video:
                stream_ctx->message_sent.message_size = ((mt_ctx->frames_sent[i] % 100) == 0) ? 0x8000 : 0x800;
                mt_ctx->next_frame_time[i] += WARPTEST_VIDEO_PERIOD;
                priority = 5;
                break;
            default:
                ret = -1;
                break;
            }
            /* Update the frame number now, and override next time if all sent. */
            mt_ctx->frames_sent[i] += 1;
            if (mt_ctx->frames_sent[i] >= mt_ctx->frames_to_send[i]) {
                mt_ctx->next_frame_time[i] = UINT64_MAX;
            }
            /* Encode the message header, and start the stream */
            if (ret == 0) {
                stream_ctx->message_sent.header[0] = (uint8_t)message_type;
                if (picoquic_frames_uint32_encode(stream_ctx->message_sent.header + 1,
                    stream_ctx->message_sent.header + WARPTEST_HEADER_SIZE, (uint32_t)stream_ctx->message_sent.message_size) == NULL ||
                    picoquic_frames_uint64_encode(stream_ctx->message_sent.header + 5,
                        stream_ctx->message_sent.header + WARPTEST_HEADER_SIZE, stream_ctx->message_sent.frame_number) == NULL ||
                    picoquic_frames_uint64_encode(stream_ctx->message_sent.header + 13,
                        stream_ctx->message_sent.header + WARPTEST_HEADER_SIZE, stream_ctx->message_sent.sent_time) == NULL) {
                    ret = -1;
                }
                else {
                    /* Mark the stream as active */
                    ret = picoquic_mark_active_stream(mt_ctx->client_cnx->cnx, stream_ctx->stream_id, 1, stream_ctx);
                    if (ret == 0) {
                        ret = picoquic_set_stream_priority(mt_ctx->client_cnx->cnx, stream_ctx->stream_id, priority);
                    }
                }
            }
        }
    }

    return ret;
}

/* Send stream data on unidirectional stream.
 * On the sender side, the "new frame" action should happen at the
 * creation of the stream, followed by the formating of the 
 * message header.
 * 
 * When polled, just send the missing bytes.
 */
int warptest_prepare_to_send_on_uni_stream(warptest_uni_stream_ctx_t* stream_ctx, void* context, size_t space, uint64_t current_time)
{
    int ret = 0;

    if (stream_ctx->is_sender) {
        if (stream_ctx->message_sent.message_size > stream_ctx->message_sent.bytes_sent) {
            uint8_t* buffer;
            size_t header_bytes = 0;
            int is_fin = 0;
            /* Compute bytes that need to be sent */
            size_t available = stream_ctx->message_sent.message_size - stream_ctx->message_sent.bytes_sent;
            if (available > space) {
                available = space;
            }
            else {
                is_fin = 1;
            }
            buffer = (uint8_t*)picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
            if (buffer == NULL) {
                ret = -1;
            }
            else {
                /* fill the header bytes if needed */
                if (stream_ctx->message_sent.bytes_sent < WARPTEST_HEADER_SIZE) {
                    header_bytes = WARPTEST_HEADER_SIZE - stream_ctx->message_sent.bytes_sent;
                    if (header_bytes > available) {
                        header_bytes = available;
                    }
                    memcpy(buffer, stream_ctx->message_sent.header + stream_ctx->message_sent.bytes_sent, header_bytes);
                }
                /* fill the other bytes */
                if (available > header_bytes) {
                    memset(buffer + header_bytes, (uint8_t)stream_ctx->message_sent.message_type, available - header_bytes);
                }
                stream_ctx->message_sent.bytes_sent += available;
                stream_ctx->bytes_sent += available;
                if (is_fin) {
                    /* delete the stream. */
                    warptest_delete_uni_stream_ctx(stream_ctx);
                }
            }
        }
        else {
            /* TODO: this should be treated as an error, as the data are
             * always available unless the stream is finished */
            (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
        }
    }
    else {
        /* If not the sender, cannot send on unidir streams. Return an error */
        ret = -1;
    }
    return ret;
}


/* Receive datagram data.
 * We only use datagrams to test conflicts between datagrams and streams,
 * deliberately causing bandwidth saturation with datagrams.
 */
int warptest_receive_datagram(warptest_cnx_ctx_t* cnx_ctx, size_t  length)
{
    cnx_ctx->mt_ctx->nb_datagrams_received++;
    cnx_ctx->mt_ctx->datagram_data_received += length;
    return 0;
}

int warptest_prepare_to_send_datagram(warptest_cnx_ctx_t* cnx_ctx, void * context, size_t length)
{
    int ret = 0;
    warptest_ctx_t* mt_ctx = cnx_ctx->mt_ctx;
    size_t available = 0;
    int is_active = 0;
    if (mt_ctx->datagram_data_sent < mt_ctx->datagram_data_requested) {
        void* buffer;

        is_active = 1;
        available = mt_ctx->datagram_data_requested - mt_ctx->datagram_data_sent;
        if (available < length) {
            length = available;
            is_active = 0;
        }
        /* Get a buffer inside the datagram packet */
        buffer = picoquic_provide_datagram_buffer(context, length);
        if (buffer == NULL) {
            ret = -1;
        }
        else {
            memset(buffer, 'd', length);
            mt_ctx->datagram_data_sent += length;
            mt_ctx->nb_datagrams_sent++;
        }
    }
    if (ret == 0) {
        ret = picoquic_mark_datagram_ready(cnx_ctx->cnx, is_active);
    }

    return ret;
}

/* Callback from Quic
*/
int warptest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{

    int ret = 0;
    warptest_cnx_ctx_t* cnx_ctx = (warptest_cnx_ctx_t*)callback_ctx;
    warptest_uni_stream_ctx_t* uni_stream_ctx = NULL;
    warptest_stream_ctx_t* stream_ctx = NULL;

    /* If this is the first reference to the connection, the application context is set
    * to the default value defined for the server. This default value contains the pointer
    * to the global context in which streams and roles are defined.
    */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        if (fin_or_event == picoquic_callback_close) {
            picoquic_set_callback(cnx, NULL, NULL);
            return 0;
        }
        else {
            cnx_ctx = warptest_create_cnx_context((warptest_ctx_t*)callback_ctx, cnx);
            if (cnx_ctx == NULL) {
                /* cannot handle the connection */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                return -1;
            }
            else {
                cnx_ctx->is_server = 1;
                picoquic_set_callback(cnx, warptest_callback, cnx_ctx);
            }
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */

            if (!PICOQUIC_IS_BIDIR_STREAM_ID(stream_id)) {
                uni_stream_ctx = (warptest_uni_stream_ctx_t*)v_stream_ctx;
                if (uni_stream_ctx == NULL) {
                    /* Retrieve, or create and initialize stream context */
                    uni_stream_ctx = warptest_find_or_create_uni_stream(stream_id, cnx_ctx, 1);
                }
                if (uni_stream_ctx == NULL) {
                    /* Internal error */
                    (void)picoquic_reset_stream(cnx, stream_id, WARPTEST_ERROR_INTERNAL);
                    ret = -1;
                }
                else {
                    ret = warptest_receive_uni_stream_data(uni_stream_ctx, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
                }
            }
            else {
                stream_ctx = (warptest_stream_ctx_t*)v_stream_ctx;
                if (stream_ctx == NULL) {
                    /* Retrieve, or create and initialize stream context */
                    stream_ctx = warptest_find_or_create_stream(stream_id, cnx_ctx, 1);
                }
                if (stream_ctx == NULL) {
                    /* Internal error */
                    (void)picoquic_reset_stream(cnx, stream_id, WARPTEST_ERROR_INTERNAL);
                    ret = -1;
                }
                else {
                    ret = warptest_receive_stream_data(stream_ctx, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (v_stream_ctx == NULL) {
                /* This should never happen */
                picoquic_log_app_message(cnx, "WARPTEST callback returns %d, event %d", ret, fin_or_event);
                    DBG_PRINTF("Prepare to send on NULL context, steam: %" PRIu64, stream_id);
                    ret = -1;
            } else if (!PICOQUIC_IS_BIDIR_STREAM_ID(stream_id)) {
                uni_stream_ctx = (warptest_uni_stream_ctx_t*)v_stream_ctx;
                ret = warptest_prepare_to_send_on_uni_stream(uni_stream_ctx, bytes, length, cnx_ctx->mt_ctx->simulated_time);
            }
            else {
                stream_ctx = (warptest_stream_ctx_t*)v_stream_ctx;
                ret = warptest_prepare_to_send_on_stream(stream_ctx, bytes, length, cnx_ctx->mt_ctx->simulated_time);
            }
            break;
        case picoquic_callback_datagram:
            /* Receive data in a datagram */
            ret = warptest_receive_datagram(cnx_ctx, length);
            break;
        case picoquic_callback_prepare_datagram:
            /* Prepare to send a datagram */
        {
            ret = warptest_prepare_to_send_datagram(cnx_ctx, bytes, length);
            break;
        }
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
                                             /* TODO: react to abandon stream, etc. */
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
                                                  /* Remove the connection from the context, and then delete it */
            cnx_ctx->cnx = NULL;
            warptest_delete_cnx_context(cnx_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            if (cnx_ctx->mt_ctx->datagram_data_requested > 0 && !cnx_ctx->is_server) {
                ret = picoquic_mark_datagram_ready(cnx, 1);
            }
            break;
        case picoquic_callback_datagram_acked:
            /* Ack for packet carrying datagram-object received from peer */
        case picoquic_callback_datagram_lost:
            /* Packet carrying datagram-object probably lost */
        case picoquic_callback_datagram_spurious:
            /* Packet carrying datagram-object was not really lost */
            /* Ignore datagram feedback, since not used in test */
            ret = 0;
            break;
        case picoquic_callback_pacing_changed:
            /* Notification of rate change from congestion controller */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    if (ret != 0) {
        picoquic_log_app_message(cnx, "WARPTEST callback returns %d, event %d", ret, fin_or_event);
        DBG_PRINTF("WARPTEST callback returns %d, event %d", ret, fin_or_event);
    }

    return ret;
}

/* Process arrival of a packet from a link */
int warptest_packet_arrival(warptest_ctx_t* mt_ctx, int link_id, int * is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(mt_ctx->link[link_id], mt_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;

        ret = picoquic_incoming_packet(mt_ctx->quic[link_id],
                packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
            mt_ctx->simulated_time);

        free(packet);
    }

    return ret;
}

/* Packet departure from selected node */
int warptest_packet_departure(warptest_ctx_t* mt_ctx, int node_id, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(mt_ctx->quic[node_id], mt_ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL, NULL);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            free(packet);
            ret = -1;
        }
        else if (packet->length > 0) {
            /* Only one link per node */
            int link_id = 1 - node_id;

            /* If the source address is not set, set it */
            if (packet->addr_from.ss_family == 0) {
                picoquic_store_addr(&packet->addr_from, (struct sockaddr*)& mt_ctx->addr[link_id]);
            }
            /* send now. */
            *is_active = 1;
            picoquictest_sim_link_submit(mt_ctx->link[link_id], packet, mt_ctx->simulated_time);
        }
        else {
            free(packet);
        }
    }

    return ret;
}

/* Simulation step */
int warptest_step(warptest_ctx_t* mt_ctx, int* is_active)
{
    int ret = 0;
    uint64_t next_arrival_time = UINT64_MAX;
    int arrival_index = -1;
    uint64_t next_departure_time = UINT64_MAX;
    int departure_index = -1;
    int need_frame_departure = 0;
    uint64_t next_frame_time = UINT64_MAX;
    uint64_t next_time = UINT64_MAX;

    /* Check earliest packet arrival */
    for (int i = 0; i < 2; i++) {
        uint64_t arrival = picoquictest_sim_link_next_arrival(mt_ctx->link[i], next_arrival_time);
        if (arrival < next_arrival_time) {
            next_arrival_time = arrival;
            arrival_index = i;
        }
    }
    if (next_arrival_time < next_time) {
        next_time = next_arrival_time;
    }

    /* Check earliest packet departure */
    for (int i = 0; i < 2; i++) {
        uint64_t departure = picoquic_get_next_wake_time(mt_ctx->quic[i], mt_ctx->simulated_time);
        if (departure < next_departure_time) {
            next_departure_time = departure;
            departure_index = i;
        }
    }
    if (next_time > next_departure_time) {
        next_time = next_departure_time;
    }

    /* Check whether new media frame should be injected,
     * but only do that if the client connection is ready.
     */
    if (mt_ctx->client_cnx->cnx != NULL && picoquic_get_cnx_state(mt_ctx->client_cnx->cnx) >= picoquic_state_client_ready_start) {
        for (int i = 0; i < warptest_nb_types; i++) {
            if (i == warptest_data) {
                continue;
            }
            if (mt_ctx->next_frame_time[i] == 0) {
                mt_ctx->next_frame_time[i] = mt_ctx->simulated_time;
            }
            if (mt_ctx->next_frame_time[i] <= next_frame_time) {
                next_frame_time = mt_ctx->next_frame_time[i];
            }
        }
    }
    if (next_frame_time < next_time) {
        next_time = next_frame_time;
        need_frame_departure = 1;
    }

    /* Update the time now, because the call to "active stream" reads the simulated time. */
    if (next_time > mt_ctx->simulated_time) {
        mt_ctx->simulated_time = next_time;
    }
    else {
        next_time = mt_ctx->simulated_time;
    }

    /* Generate a frame if needed  */
    if (need_frame_departure) {
        ret = warptest_prepare_new_frame(mt_ctx, next_time);

        /* Recompute the departure time */
        for (int i = 0; i < 2 && ret == 0; i++) {
            uint64_t departure = picoquic_get_next_wake_time(mt_ctx->quic[i], next_time);
            if (departure <= next_time) {
                next_departure_time = next_time;
                departure_index = i;
            }
        }
    }

    if (ret == 0) {
        /* Perform earliest action */
        if (next_arrival_time <= next_time) {
            /* Process next packet from simulated link */
            ret = warptest_packet_arrival(mt_ctx, arrival_index, is_active);
        }
        else {
            /* Prepare next packet from selected connection */
            ret = warptest_packet_departure(mt_ctx, departure_index, is_active);
        }
    }
    if (ret < 0) {
        DBG_PRINTF("Simulation fails at T=%" PRIu64, mt_ctx->simulated_time);
    }

    return ret;
}

int warptest_is_finished(warptest_ctx_t* mt_ctx)
{
    int is_finished = 1;

    /* If at least one connection is still up, verify that all frames
     * have been sent.
     */
    for (int i = 0; is_finished && i < warptest_nb_types; i++) {
        if (i == warptest_data) {
            is_finished &= (mt_ctx->frames_sent[i] >= mt_ctx->frames_to_send[i]);
        }
        else {
            is_finished &= (mt_ctx->frames_sent[i] == mt_ctx->frames_to_send[i]) &&
                (mt_ctx->frames_sent[i] == mt_ctx->media_stats[i].nb_frames);
        }
    }
    if (is_finished) {
        DBG_PRINTF("Media transmission finished at %" PRIu64, mt_ctx->simulated_time);
    }

    return is_finished;
}

/* max_data_uni and max_stream_id_unidir will be set according
 * to test scenario
 */
void warptest_init_transport_parameters(picoquic_tp_t* tp, int client_mode, warptest_spec_t* spec)
{
    memset(tp, 0, sizeof(picoquic_tp_t));
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65535;
    if (spec->max_stream_data == 0) {
        tp->initial_max_stream_data_uni = 65535;
    }
    else {
        tp->initial_max_stream_data_uni = spec->max_stream_data;
    }
    tp->initial_max_data = 0x100000;
    tp->initial_max_stream_id_bidir = 512;
    if (spec->max_streams_client == 0) {
        tp->initial_max_stream_id_unidir = 16;
    }
    else {
        tp->initial_max_stream_id_unidir = spec->max_streams_client;
    }
    tp->max_idle_timeout = 30000;
    tp->max_packet_size = PICOQUIC_MAX_PACKET_SIZE;
    tp->ack_delay_exponent = 3;
    tp->active_connection_id_limit = 4;
    tp->max_ack_delay = 10000ull;
    tp->enable_loss_bit = 2;
    tp->min_ack_delay = 1000ull;
    tp->enable_time_stamp = 0;
    tp->max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
}

void warptest_delete_ctx(warptest_ctx_t* mt_ctx)
{
    /* Delete the connections */
    while (mt_ctx->first_cnx != NULL) {
        warptest_delete_cnx_context(mt_ctx->first_cnx);
    }
    /* Delete the links */
    for (int i = 0; i < 2; i++) {
        if (mt_ctx->link[i] != NULL) {
            picoquictest_sim_link_delete(mt_ctx->link[i]);
        }
    }
    /* Delete the QUIC contexts */
    for (int i = 0; i < 2; i++) {
        if (mt_ctx->quic[i] != NULL) {
            picoquic_free(mt_ctx->quic[i]);
        }
    }
    /* Free the context */
    free(mt_ctx);
}

warptest_ctx_t * warptest_configure(int warptest_id,  warptest_spec_t * spec)
{
    int ret = 0;
    warptest_ctx_t* mt_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_connection_id_t icid = { { 0xed, 0x1a, 0x1d, 0x18, 0, 0, 0, 0}, 8 };
    icid.id[4] = warptest_id;

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
        mt_ctx = (warptest_ctx_t*)malloc(sizeof(warptest_ctx_t));
        if (mt_ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(mt_ctx, 0, sizeof(warptest_ctx_t));
        /* Create the QUIC contexts */
        mt_ctx->quic[0] = picoquic_create(4, NULL, NULL, test_server_cert_store_file, NULL, warptest_callback,
            (void*)mt_ctx, NULL, NULL, NULL, mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, NULL, 0);
        mt_ctx->quic[1] = picoquic_create(4,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            WARPTEST_ALPN, warptest_callback, (void*)mt_ctx, NULL, NULL, NULL,
            mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, warptest_ticket_encrypt_key, sizeof(warptest_ticket_encrypt_key));

        if (mt_ctx->quic[0] == NULL || mt_ctx->quic[1] == NULL) {
            ret = -1;
        }
        
        if (spec->ccalgo != NULL) {
            for (int i = 0; i < 2 && ret == 0; i++) {
                picoquic_tp_t server_parameters;
                picoquic_set_default_congestion_algorithm(mt_ctx->quic[i], spec->ccalgo);
                ret = picoquic_set_qlog(mt_ctx->quic[i], ".");
                /* Init of transport parameters per quic context */
                warptest_init_transport_parameters(&server_parameters, 0, spec);
                ret = picoquic_set_default_tp(mt_ctx->quic[i], &server_parameters);
            }
        }
    }

    if (ret == 0) {
        /* Do not use randomization by default during tests */
        for (int i = 0; i < 2; i++) {
            picoquic_set_random_initial(mt_ctx->quic[i], 0);
        }
        /* Init of the IP addresses */
        for (uint16_t i = 0; i < 2; i++) {
            picoquic_set_test_address((struct sockaddr_in*)&mt_ctx->addr[i], 0x0A000001 + i, 1234 + i);
        }
        /* register the links */
        for (int i = 0; i < 2; i++) {
            mt_ctx->link[i] = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
            if (mt_ctx->link[i] == NULL) {
                ret = -1;
                break;
            }
        }
    }
    if (ret == 0) {
        /* Create the client connection, from which media will flow. */
        picoquic_cnx_t * cnx = picoquic_create_cnx(mt_ctx->quic[0],
            icid, picoquic_null_connection_id,
            (struct sockaddr*)&mt_ctx->addr[1], mt_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, WARPTEST_ALPN, 1);
        /* Start the connection and create the context */
        if (cnx != NULL) {
            if (picoquic_start_client_cnx(cnx) != 0) {
                picoquic_delete_cnx(cnx);
                ret = -1;
            }
            if (cnx != NULL) {
                picoquic_tp_t client_parameters;
                warptest_init_transport_parameters(&client_parameters, 1, spec);
                picoquic_set_transport_parameters(cnx, &client_parameters);
                mt_ctx->client_cnx = warptest_create_cnx_context(mt_ctx, cnx);
                if (mt_ctx->client_cnx == NULL) {
                    picoquic_delete_cnx(cnx);
                    ret = -1;
                }
                if (ret == 0) {
                    if (spec->data_size > 0) {
                        /* Find the next available stream id */
                        uint64_t stream_id = picoquic_get_next_local_stream_id(mt_ctx->client_cnx->cnx, 0);
                        /* Create a stream context */
                        warptest_stream_ctx_t* stream_ctx = warptest_create_stream_context(mt_ctx->client_cnx, stream_id);
                        if (stream_ctx == NULL) {
                            ret = -1;
                        }
                        else {
                            /* Set the media generation parameters */
                            mt_ctx->frames_to_send[warptest_data] = spec->data_size;
                            /* Set priority to data level */
                            picoquic_set_stream_priority(mt_ctx->client_cnx->cnx, stream_id, 7);
                            /* Activate the stream for sending */
                            ret = picoquic_mark_active_stream(mt_ctx->client_cnx->cnx, stream_id, 1, stream_ctx);
                        }
                    }
                    else {
                        mt_ctx->next_frame_time[warptest_data] = UINT64_MAX;
                    }

                    if (spec->do_audio) {
                        mt_ctx->frames_to_send[warptest_audio] = WARPTEST_DURATION / WARPTEST_AUDIO_PERIOD;
                    }
                    else {
                        mt_ctx->next_frame_time[warptest_audio] = UINT64_MAX;
                    }

                    if (spec->do_video) {
                        mt_ctx->frames_to_send[warptest_video] = WARPTEST_DURATION / WARPTEST_VIDEO_PERIOD;
                    }
                    else {
                        mt_ctx->next_frame_time[warptest_video] = UINT64_MAX;
                    }
                }

                if (spec->datagram_data_size > 0 && ret == 0) {
                    mt_ctx->datagram_data_requested = spec->datagram_data_size;
                }
            
                for (int i = 0; i < warptest_nb_types; i++) {
                    mt_ctx->media_stats[i].min_delay = UINT64_MAX;
                }
            }
        }
    }

    if (ret != 0 && mt_ctx != NULL) {
        warptest_delete_ctx(mt_ctx);
        mt_ctx = NULL;
    }

    return mt_ctx;
}

/* One test */
int warptest_one(int warptest_id, warptest_spec_t * spec)
{
    int ret = 0;
    int nb_steps = 0;
    int nb_inactive = 0;
    int is_finished = 0;

    /* set the configuration */
    warptest_ctx_t* mt_ctx = warptest_configure(warptest_id, spec);
    if (mt_ctx == NULL) {
        ret = -1;
    }
    /* Run the simulation until done */
    while (ret == 0 && !is_finished && nb_steps < 100000 && nb_inactive < 512 && mt_ctx->simulated_time < 30000000) {
        int is_active = 0;
        nb_steps += 1;
        ret = warptest_step(mt_ctx, &is_active);
        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive += 1;
        }
        is_finished = warptest_is_finished(mt_ctx);
    }

    /* Check that the simulation ran to the end. */
    if (ret == 0) {
        if (!is_finished) {
            ret = -1;
        }
        /* Check that the results are as expected. */
        if (ret == 0 && spec->do_audio) {
            ret = warptest_check_stats(mt_ctx, warptest_audio);
        }
        if (ret == 0 && spec->do_video) {
            ret = warptest_check_stats(mt_ctx, warptest_video);
        }
        
    }
    if (mt_ctx != NULL) {
        warptest_delete_ctx(mt_ctx);
    }
    return ret;
}

/* Test cases */
int warptest_video_test()
{
    int ret;
    warptest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    ret = warptest_one(1, &spec);

    return ret;
}

int warptest_video_audio_test()
{
    int ret;
    warptest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    ret = warptest_one(2, &spec);

    return ret;
}

int warptest_video_data_audio_test()
{
    int ret;
    warptest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    spec.data_size = 10000000;
    ret = warptest_one(3, &spec);

    return ret;
}

int warptest_worst_test()
{
    int ret;
    warptest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    spec.datagram_data_size = 10000000;
    ret = warptest_one(4, &spec);

    return ret;
}

int warptest_param_test()
{
    int ret;
    warptest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    spec.max_streams_client = 4;
    spec.max_streams_server = 4;

    ret = warptest_one(5, &spec);

    return ret;
}