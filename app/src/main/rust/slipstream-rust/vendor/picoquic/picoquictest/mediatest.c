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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_binlog.h"

/* Media tests: simulate media transmission, include cases in which
* the media bandwidth is much lower than the available bandwidth on
* average, but sometimes higher when sending large frames. Also
* consider case of audio + video, sent as stream, together with
* data. Shall verify that audio and video delays do not suffer
* in presence of data streams.
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
* 
*/

#define MEDIATEST_ALPN "picoquic_mediatest"
#define MEDIATEST_HEADER_SIZE 13
#define MEDIATEST_ERROR_INTERNAL 1
#define MEDIATEST_DURATION 10000000
#define MEDIATEST_AUDIO_PERIOD 20000
#define MEDIATEST_VIDEO_PERIOD 33333
#define MEDIATEST_VIDEO2_PERIOD 16666
#define MEDIATEST_DATA_FRAME_SIZE 0x4000

typedef enum {
    mediatest_video = 1,
    mediatest_video_audio = 2,
    mediatest_video_data_audio = 3,
    mediatest_worst = 4,
    mediatest_video2_down = 5,
    mediatest_wifi = 6,
    mediatest_video2_back = 7,
    mediatest_suspension = 8,
    mediatest_video2_probe = 9,
    mediatest_suspension2 = 10
} mediatest_id_enum;

typedef enum {
    media_test_data = 0,
    media_test_audio,
    media_test_video,
    media_test_video2,
    media_test_nb_types
} media_test_type_enum;

typedef struct st_mediatest_message_buffer_t {
    size_t bytes_sent;
    size_t bytes_received;
    media_test_type_enum message_type;
    uint32_t message_size;
    uint64_t sent_time;
    uint8_t header[MEDIATEST_HEADER_SIZE];
} mediatest_message_buffer_t;

typedef struct st_mediatest_stream_ctx_t {
    /* Organize the streams as part of the connection */
    struct st_mediatest_stream_ctx_t* next_stream;
    struct st_mediatest_stream_ctx_t* previous_stream;
    struct st_mediatest_cnx_ctx_t* cnx_ctx;
    /* stream identifier */
    uint64_t stream_id;
    /* Specify the type of stream */
    media_test_type_enum stream_type;
    /* Specify the state of the stream: number of frames sent  or received */
    unsigned int is_sender : 1;
    unsigned int finished_sending : 1;
    unsigned int fin_received : 1;
    unsigned int is_fin_sent : 1;
    unsigned int is_reset : 1;

    uint64_t frames_to_send;
    uint64_t frames_sent;
    uint64_t frames_skipped;
    uint64_t frames_received;
    size_t bytes_sent;
    size_t bytes_received;
    uint64_t next_frame_time;
    uint64_t next_iframe_time;

    mediatest_message_buffer_t message_sent;
    mediatest_message_buffer_t message_received;
} mediatest_stream_ctx_t;

/* Mediatest per connection context */
typedef struct st_mediatest_cnx_ctx_t {
    struct st_mediatest_cnx_ctx_t* next_cnx;
    struct st_mediatest_cnx_ctx_t* previous_cnx;
    struct st_mediatest_ctx_t* mt_ctx;

    char* sni;
    struct sockaddr_storage addr;
    picoquic_cnx_t* cnx;
    int is_server;

    struct st_mediatest_stream_ctx_t* first_stream;
    struct st_mediatest_stream_ctx_t* last_stream;
} mediatest_cnx_ctx_t;

/* Mediatest statistics per media type */
typedef struct st_mediatest_media_stats_t {
    int nb_frames;
    uint64_t sum_delays;
    uint64_t sum_square_delays;
    uint64_t min_delay;
    uint64_t max_delay;
} mediatest_media_stats_t;

/* Mediatest context */
typedef struct st_mediatest_ctx_t {
    uint64_t simulated_time;
    picoquic_quic_t* quic[2]; /* QUIC Context for client[0] or server[1] */
    picoquictest_sim_link_t* link[2]; /* Link from client to server [0] and back [1] */
    struct sockaddr_storage addr[2]; /* addresses of client [0] and server [1]*/
    mediatest_cnx_ctx_t* client_cnx; /* client connection context */
    struct st_mediatest_cnx_ctx_t* first_cnx;
    struct st_mediatest_cnx_ctx_t* last_cnx;
    /* Starting point of statistics -- after the initial disruption */
    uint64_t disruption_clear;
    /* managemenent of datagram load */
    size_t datagram_data_requested;
    size_t datagram_data_sent;
    size_t datagram_data_received;
    int nb_datagrams_sent;
    int nb_datagrams_received;

    /* Statistics */
    mediatest_media_stats_t media_stats[media_test_nb_types];
} mediatest_ctx_t;

/* mediatest test specification */
typedef struct st_mediatest_spec_t {
    picoquic_congestion_algorithm_t* ccalgo; 
    int do_audio;
    int do_video;
    int do_video2;
    int do_probe_up;
    size_t data_size;
    size_t datagram_data_size;
    double bandwidth;
    uint64_t link_latency;
    uint64_t latency_average;
    uint64_t latency_max;
    uint8_t priority_limit_for_bypass;
    int do_not_check_video2;
    int nb_suspensions;
    uint64_t suspension_start_time;
    uint64_t suspension_up_time;
    uint64_t suspension_down_time;

} mediatest_spec_t;

int mediatest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

static const uint8_t mediatest_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};


void mediatest_delete_stream_ctx(mediatest_stream_ctx_t* stream_ctx)
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

mediatest_stream_ctx_t* mediatest_create_stream_context(mediatest_cnx_ctx_t* cnx_ctx, uint64_t stream_id)
{
    mediatest_stream_ctx_t* stream_ctx = (mediatest_stream_ctx_t*)malloc(sizeof(mediatest_stream_ctx_t));
    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(mediatest_stream_ctx_t));
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
        stream_ctx->is_sender = !stream_ctx->cnx_ctx->is_server;

        if (cnx_ctx->cnx != NULL) {
            (void)picoquic_set_app_stream_ctx(cnx_ctx->cnx, stream_id, stream_ctx);
        }
    }

    return stream_ctx;
}

mediatest_stream_ctx_t* mediatest_find_or_create_stream(
    uint64_t stream_id,
    mediatest_cnx_ctx_t* cnx_ctx,
    int should_create)
{
    mediatest_stream_ctx_t* stream_ctx = cnx_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->stream_id == stream_id) {
            break;
        }
        stream_ctx = stream_ctx->next_stream;
    }
    if (stream_ctx == NULL && should_create) {
        stream_ctx = mediatest_create_stream_context(cnx_ctx, stream_id);
    }

    return stream_ctx;
}

/* Delete a connection context */
void mediatest_delete_cnx_context(mediatest_cnx_ctx_t* cnx_ctx)
{
    while (cnx_ctx->first_stream != NULL) {
        mediatest_delete_stream_ctx(cnx_ctx->first_stream);
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
* The QUIC connection has to be created before the QUICRQ connection. */
mediatest_cnx_ctx_t* mediatest_create_cnx_context(mediatest_ctx_t* mt_ctx, picoquic_cnx_t * cnx)
{
    mediatest_cnx_ctx_t* cnx_ctx = (mediatest_cnx_ctx_t*)malloc(sizeof(mediatest_cnx_ctx_t));

    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(mediatest_cnx_ctx_t));
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
        picoquic_set_callback(cnx, mediatest_callback, cnx_ctx);
    }
    return cnx_ctx;
}

void mediatest_record_stats(mediatest_ctx_t* mt_ctx, mediatest_stream_ctx_t* stream_ctx)
{
    if (stream_ctx->message_received.sent_time > mt_ctx->disruption_clear) {
        uint64_t delay = mt_ctx->simulated_time - stream_ctx->message_received.sent_time;

        if (stream_ctx->message_received.message_type >= 0 && stream_ctx->message_received.message_type < media_test_nb_types) {
            mediatest_media_stats_t* stats = mt_ctx->media_stats + stream_ctx->message_received.message_type;
            stats->nb_frames++;
            stats->sum_delays += delay;
            stats->sum_square_delays += delay * delay;
            if (stats->min_delay > delay) {
                stats->min_delay = delay;
            }
            if (stats->max_delay < delay) {
                stats->max_delay = delay;
            }
        }
    }
}

int mediatest_check_stats(mediatest_ctx_t* mt_ctx, mediatest_spec_t * spec, media_test_type_enum media_type)
{
    int ret = 0;

    if (media_type >= 0 && media_type < media_test_nb_types) {
        mediatest_media_stats_t* stats = mt_ctx->media_stats + media_type;
        uint64_t period = (media_type == media_test_audio) ? MEDIATEST_AUDIO_PERIOD :
            ((media_type == media_test_video2) ? MEDIATEST_VIDEO2_PERIOD : MEDIATEST_VIDEO_PERIOD);
        uint64_t expected = MEDIATEST_DURATION / period;

        if (stats->nb_frames != expected && mt_ctx->disruption_clear == 0) {
            ret = -1;
        }
        else if (stats->nb_frames != 0) {
            uint64_t average = stats->sum_delays / stats->nb_frames;
            uint64_t variance = (stats->sum_square_delays / stats->nb_frames) - (average * average);
            uint64_t sigma = picoquic_sqrt_for_tests(variance);

            if (spec->latency_average == 0)
            {
                if (average > 25000 || sigma > 12500 || stats->max_delay > 100000) {
                    DBG_PRINTF("Latency average: %" PRIu64 ", sigma: %" PRIu64 ", max: %" PRIu64,
                        average, sigma, stats->max_delay);
                    ret = -1;
                }
            }
            else {
                if (average > spec->latency_average) {
                    DBG_PRINTF("Average latency expected: %" PRIu64 ", got %" PRIu64,
                        spec->latency_average, average);
                    ret = -1;
                }
                else if (spec->latency_max > 0 && stats->max_delay > spec->latency_max) {
                    DBG_PRINTF("Max latency expected: %" PRIu64 ", got %" PRIu64,
                        spec->latency_max, stats->max_delay);
                    ret = -1;
                }
            }
        }
    }

    return ret;
}


/* Receive stream data. This is composed of a set of messages.
 * All message received must have the same type
 * At the end of the message, compute and store delay statistics.
 * Messages are only received if not sender.
 * For sender, receiving FIN before sending it is an error.
 */
int mediatest_receive_stream_data(mediatest_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;
    size_t msg_read = 0;
    size_t available = 0;
    if (length > msg_read && ret == 0) {
        if (stream_ctx->is_sender) {
            picoquic_log_app_message(stream_ctx->cnx_ctx->cnx, "MEDIATEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
            DBG_PRINTF("MEDIATEST receive data on sending stream %" PRIu64, stream_ctx->stream_id);
            ret = -1;
        }
        else {
            /* Receive the message buffer. If at least 2 bytes, compute the size. */
            while (length > msg_read && ret == 0 && stream_ctx->message_received.bytes_received < MEDIATEST_HEADER_SIZE) {
                stream_ctx->message_received.header[stream_ctx->message_received.bytes_received++] = bytes[msg_read++];
                if (stream_ctx->message_received.bytes_received == MEDIATEST_HEADER_SIZE) {
                    stream_ctx->message_received.message_type = stream_ctx->message_received.header[0];
                    if (picoquic_frames_uint32_decode(stream_ctx->message_received.header + 1,
                        stream_ctx->message_received.header + MEDIATEST_HEADER_SIZE, &stream_ctx->message_received.message_size) == NULL ||
                        picoquic_frames_uint64_decode(stream_ctx->message_received.header + 5,
                            stream_ctx->message_received.header + MEDIATEST_HEADER_SIZE, &stream_ctx->message_received.sent_time) == NULL) {
                        ret = -1;
                    }
                    else if (stream_ctx->frames_received > 0) {
                        if (stream_ctx->message_received.message_type != stream_ctx->stream_type) {
                            ret = -1;
                        }
                    }
                    else {
                        stream_ctx->stream_type = stream_ctx->message_received.message_type;
                    }
                }
            }
            if (length > msg_read && ret == 0) {
                available = length - msg_read;
                if (stream_ctx->message_received.bytes_received > stream_ctx->message_received.message_size) {
                    ret = -1;
                }
                else {
                    size_t required = stream_ctx->message_received.message_size - stream_ctx->message_received.bytes_received;
                    if (required <= available) {
                        /* Message is fully received */
                        stream_ctx->bytes_received += stream_ctx->message_received.bytes_received;
                        stream_ctx->frames_received += 1;
                        length -= required;
                        /* Record statistics */
                        mediatest_record_stats(stream_ctx->cnx_ctx->mt_ctx, stream_ctx);
                        memset(&stream_ctx->message_received, 0, sizeof(mediatest_message_buffer_t));
                    }
                    else {
                        stream_ctx->message_received.bytes_received += available;
                        length = 0;
                    }
                }
            }
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

/* For the high speed video stream, check if the media is far behind. if
 * it is, mark the current state as "skipping". If the state is marked
 * "reset", abstain from sending any frame until the next I frame.
 */
void  mediatest_simulate_reset(mediatest_stream_ctx_t* stream_ctx, uint64_t current_time, uint64_t frame_duration, uint64_t cycle_length, uint64_t queue_limit)
{
    uint64_t frame_rank = stream_ctx->frames_sent % cycle_length;

    if (frame_rank > 0 && stream_ctx->frames_sent > queue_limit){
        if (((stream_ctx->frames_sent - queue_limit) * frame_duration) > current_time) {
            stream_ctx->is_reset = 1;
        }
        if (stream_ctx->is_reset) {
            for (uint64_t i = frame_rank; i < cycle_length; i++) {
                stream_ctx->next_frame_time += frame_duration;
                stream_ctx->frames_sent++;
                stream_ctx->frames_skipped++;
            }
        }
    }
    else {
        stream_ctx->is_reset = 0;
    }
}

/* Prepare next frame. Do this as soon as we know that a new frame can be sent. */
int mediatest_prepare_new_frame(mediatest_stream_ctx_t* stream_ctx, uint64_t current_time)
{
    int ret = 0;
    /* Is the high bandwidth stream reset? */
    if (stream_ctx->stream_type == media_test_video2) {
        mediatest_simulate_reset(stream_ctx, current_time, MEDIATEST_VIDEO2_PERIOD, 100, 20);
    }
    /* Is this the right time? */
    if (stream_ctx->next_frame_time <= current_time) {
        if (stream_ctx->frames_sent == 0) {
            stream_ctx->next_frame_time = current_time;
        }
        stream_ctx->message_sent.sent_time = stream_ctx->next_frame_time;

        stream_ctx->message_sent.message_type = stream_ctx->stream_type;
        switch (stream_ctx->stream_type) {
        case media_test_data:
            stream_ctx->message_sent.message_size = MEDIATEST_DATA_FRAME_SIZE;
            stream_ctx->next_frame_time = current_time;
            break;
        case media_test_audio:
            stream_ctx->message_sent.message_size = 32;
            stream_ctx->next_frame_time += MEDIATEST_AUDIO_PERIOD;
            break;
        case media_test_video:
            stream_ctx->message_sent.message_size = ((stream_ctx->frames_sent % 100) == 0) ? 0x8000 : 0x800;
            stream_ctx->next_frame_time += MEDIATEST_VIDEO_PERIOD;
             
            break;
        case media_test_video2:
            if ((stream_ctx->frames_sent % 100) == 0) {
                stream_ctx->next_iframe_time = stream_ctx->next_frame_time + 100 * MEDIATEST_VIDEO2_PERIOD;
            }
            stream_ctx->message_sent.message_size = ((stream_ctx->frames_sent % 100) == 0) ? 0x10000 : 0x1800;
            stream_ctx->next_frame_time += MEDIATEST_VIDEO2_PERIOD;
            break;
        default:
            ret = -1;
            break;
        }
        if (ret == 0) {
            stream_ctx->message_sent.header[0] = stream_ctx->stream_type;
            if (picoquic_frames_uint32_encode(stream_ctx->message_sent.header + 1,
                stream_ctx->message_sent.header + MEDIATEST_HEADER_SIZE, (uint32_t)stream_ctx->message_sent.message_size) == NULL ||
                picoquic_frames_uint64_encode(stream_ctx->message_sent.header + 5,
                    stream_ctx->message_sent.header + MEDIATEST_HEADER_SIZE, stream_ctx->message_sent.sent_time) == NULL) {
                ret = -1;
            }
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
int mediatest_prepare_to_send_on_stream(mediatest_stream_ctx_t* stream_ctx, void* context, size_t space, uint64_t current_time)
{
    int ret = 0;

    if (stream_ctx->is_sender) {
        /* If no ongoing message, try prepare a new one. */
        if (stream_ctx->message_sent.message_size == 0 && !stream_ctx->finished_sending) {
            ret = mediatest_prepare_new_frame(stream_ctx, current_time);
        }
        if (stream_ctx->message_sent.message_size > stream_ctx->message_sent.bytes_sent) {
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
                is_fin = (stream_ctx->frames_sent + 1 >= stream_ctx->frames_to_send);
                is_still_active = (current_time > stream_ctx->next_frame_time && !is_fin) ? 1 : 0;
            }
            buffer = (uint8_t*)picoquic_provide_stream_data_buffer(context, available, is_fin, is_still_active);
            if (buffer == NULL) {
                ret = -1;
            }
            else {
                stream_ctx->is_fin_sent = is_fin;
                /* fill the header bytes if needed */
                if (stream_ctx->message_sent.bytes_sent < MEDIATEST_HEADER_SIZE) {
                    header_bytes = MEDIATEST_HEADER_SIZE - stream_ctx->message_sent.bytes_sent;
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
                if (stream_ctx->message_sent.bytes_sent >= stream_ctx->message_sent.message_size) {
                    memset(&stream_ctx->message_sent, 0, sizeof(mediatest_message_buffer_t));
                    stream_ctx->frames_sent += 1;
                    stream_ctx->finished_sending = (stream_ctx->frames_sent >= stream_ctx->frames_to_send) ? 1 : 0;
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

/* Receive datagram data.
 * We only use datagrams to test conflicts between datagrams and streams,
 * deliberately causing bandwidth saturation with datagrams.
 */
int mediatest_receive_datagram(mediatest_cnx_ctx_t* cnx_ctx, size_t  length)
{
    cnx_ctx->mt_ctx->nb_datagrams_received++;
    cnx_ctx->mt_ctx->datagram_data_received += length;
    return 0;
}

int mediatest_prepare_to_send_datagram(mediatest_cnx_ctx_t* cnx_ctx, void * context, size_t length)
{
    int ret = 0;
    mediatest_ctx_t* mt_ctx = cnx_ctx->mt_ctx;
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
int mediatest_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{

    int ret = 0;
    mediatest_cnx_ctx_t* cnx_ctx = (mediatest_cnx_ctx_t*)callback_ctx;
    mediatest_stream_ctx_t* stream_ctx = (mediatest_stream_ctx_t*)v_stream_ctx;

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
            cnx_ctx = mediatest_create_cnx_context((mediatest_ctx_t*)callback_ctx, cnx);
            if (cnx_ctx == NULL) {
                /* cannot handle the connection */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                return -1;
            }
            else {
                cnx_ctx->is_server = 1;
                picoquic_set_callback(cnx, mediatest_callback, cnx_ctx);
            }
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Retrieve, or create and initialize stream context */
                stream_ctx = mediatest_find_or_create_stream(stream_id, cnx_ctx, 1);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void)picoquic_reset_stream(cnx, stream_id, MEDIATEST_ERROR_INTERNAL);
                ret = -1;
            }
            else {
                ret = mediatest_receive_stream_data(stream_ctx, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
                picoquic_log_app_message(cnx, "MEDIATEST callback returns %d, event %d", ret, fin_or_event);
                DBG_PRINTF("Prepare to send on NULL context, steam: %" PRIu64, stream_id);
                ret = -1;
            }
            else {
                ret = mediatest_prepare_to_send_on_stream(stream_ctx, bytes, length, cnx_ctx->mt_ctx->simulated_time);
            }
            break;
        case picoquic_callback_datagram:
            /* Receive data in a datagram */
            ret = mediatest_receive_datagram(cnx_ctx, length);
            break;
        case picoquic_callback_prepare_datagram:
            /* Prepare to send a datagram */
        {
            ret = mediatest_prepare_to_send_datagram(cnx_ctx, bytes, length);
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
            mediatest_delete_cnx_context(cnx_ctx);
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
#if 0
            ret = mediatest_handle_datagram_ack_nack(cnx_ctx, fin_or_event, stream_id /* encodes the send time!*/,
                bytes, length, picoquic_get_quic_time(cnx_ctx->mt_ctx->quic));
#else
            ret = 0;
#endif
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
        picoquic_log_app_message(cnx, "MEDIATEST callback returns %d, event %d", ret, fin_or_event);
        DBG_PRINTF("MEDIATEST callback returns %d, event %d", ret, fin_or_event);
    }


    return ret;
}


/* Process arrival of a packet from a link */
int mediatest_packet_arrival(mediatest_ctx_t* mt_ctx, int link_id, int is_losing_data, int * is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(mt_ctx->link[link_id], mt_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;

        if (!is_losing_data) {
            ret = picoquic_incoming_packet(mt_ctx->quic[link_id],
                packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
                mt_ctx->simulated_time);
        }

        free(packet);
    }

    return ret;
}


/* Packet departure from selected node */
int mediatest_packet_departure(mediatest_ctx_t* mt_ctx, int node_id, int* is_active)
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
int mediatest_step(mediatest_ctx_t* mt_ctx, int is_losing_data, int* is_active)
{
    int ret = 0;
    uint64_t next_arrival_time = UINT64_MAX;
    int arrival_index = -1;
    uint64_t next_departure_time = UINT64_MAX;
    int departure_index = -1;
    int need_frame_departure = 0;
    uint64_t next_frame_time = UINT64_MAX;
    uint64_t next_time;
    /* Check earliest packet arrival */
    for (int i = 0; i < 2; i++) {
        uint64_t arrival = picoquictest_sim_link_next_arrival(mt_ctx->link[i], next_arrival_time);
        if (arrival < next_arrival_time) {
            next_arrival_time = arrival;
            arrival_index = i;
        }
    }
    next_time = next_arrival_time;

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

    /* Check earliest media arrival */
    if (mt_ctx->client_cnx != NULL && mt_ctx->client_cnx->cnx != NULL && picoquic_get_cnx_state(mt_ctx->client_cnx->cnx) >= picoquic_state_ready) {
        mediatest_stream_ctx_t* stream_ctx = mt_ctx->client_cnx->first_stream;

        while (stream_ctx != NULL) {
            if (stream_ctx->is_sender && stream_ctx->message_sent.message_size == 0 &&
                stream_ctx->next_frame_time < next_frame_time && !stream_ctx->finished_sending) {
                next_frame_time = stream_ctx->next_frame_time;
            }
            stream_ctx = stream_ctx->next_stream;
        }

        if (next_frame_time <= next_time) {
            next_time = next_frame_time;
            need_frame_departure = 1;
        }
    }

    /* Update the time now, because the call to "active stream" reads the simulated time. */
    if (next_time > mt_ctx->simulated_time) {
        mt_ctx->simulated_time = next_time;
    }
    else {
        next_time = mt_ctx->simulated_time;
    }

    if (need_frame_departure) {
        mediatest_stream_ctx_t* stream_ctx = mt_ctx->client_cnx->first_stream;
        while (stream_ctx != NULL && ret == 0) {
            if (stream_ctx->is_sender && stream_ctx->message_sent.message_size == 0 &&
                stream_ctx->next_frame_time <= next_time && !stream_ctx->finished_sending) {
                ret = mediatest_prepare_new_frame(stream_ctx, next_time);
                picoquic_mark_active_stream(mt_ctx->client_cnx->cnx, stream_ctx->stream_id, 1, stream_ctx);
            }
            stream_ctx = stream_ctx->next_stream;
        }

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
            ret = mediatest_packet_arrival(mt_ctx, arrival_index, is_losing_data, is_active);
        }
        else {
            /* Prepare next packet from selected connection */
            ret = mediatest_packet_departure(mt_ctx, departure_index, is_active);
        }
    }
    if (ret < 0) {
        DBG_PRINTF("Simulation fails at T=%" PRIu64, mt_ctx->simulated_time);
    }

    return ret;
}

int mediatest_is_finished(mediatest_ctx_t* mt_ctx)
{
    int is_finished = 1;
    mediatest_cnx_ctx_t* cnx_ctx = mt_ctx->first_cnx;
    while(cnx_ctx != NULL && is_finished) {
        mediatest_stream_ctx_t* stream_ctx =  cnx_ctx->first_stream;
        while (stream_ctx != NULL && is_finished) {
            is_finished &= stream_ctx->is_fin_sent && stream_ctx->fin_received;
            stream_ctx = stream_ctx->next_stream;
        }
        cnx_ctx = cnx_ctx->next_cnx;
    }
    if (is_finished) {
        DBG_PRINTF("Media transmission finished at %" PRIu64, mt_ctx->simulated_time);
    }

    return is_finished;
}

/* Test configuration */
int mediatest_configure_stream(mediatest_cnx_ctx_t * cnx_ctx, media_test_type_enum stream_type, size_t data_size)
{
    int ret = 0;
    /* Find the next available stream id */
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx_ctx->cnx, 0);
    /* Create a stream context */
    mediatest_stream_ctx_t* stream_ctx = mediatest_create_stream_context(cnx_ctx, stream_id);
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        /* Set the media generation parameters */
        stream_ctx->is_sender = 1;
        stream_ctx->stream_type = stream_type;
        switch (stream_type) {
        case media_test_audio:
            stream_ctx->frames_to_send = MEDIATEST_DURATION / MEDIATEST_AUDIO_PERIOD;
            ret = picoquic_set_stream_priority(cnx_ctx->cnx, stream_ctx->stream_id, 2);
            break;
        case media_test_video:
            stream_ctx->frames_to_send = MEDIATEST_DURATION / MEDIATEST_VIDEO_PERIOD;
            ret = picoquic_set_stream_priority(cnx_ctx->cnx, stream_ctx->stream_id, 4);
            break;
        case media_test_video2:
            stream_ctx->frames_to_send = MEDIATEST_DURATION / MEDIATEST_VIDEO2_PERIOD;
            ret = picoquic_set_stream_priority(cnx_ctx->cnx, stream_ctx->stream_id, 6);
            break;
        case media_test_data:
        default:
            stream_ctx->frames_to_send = data_size / MEDIATEST_DATA_FRAME_SIZE;
            break;
        }
        if (ret == 0) {
            ret = picoquic_mark_active_stream(cnx_ctx->cnx, stream_id, 1, stream_ctx);
        }
    }
    return ret;
}

void mediatest_init_transport_parameters(picoquic_tp_t* tp, int client_mode)
{
    memset(tp, 0, sizeof(picoquic_tp_t));
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65635;
    tp->initial_max_stream_data_uni = 65535;
    tp->initial_max_data = 0x100000;
    tp->initial_max_stream_id_bidir = 512;
    tp->initial_max_stream_id_unidir = 512;
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

void mediatest_delete_ctx(mediatest_ctx_t* mt_ctx)
{
    /* Delete the connections */
    while (mt_ctx->first_cnx != NULL) {
        mediatest_delete_cnx_context(mt_ctx->first_cnx);
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

mediatest_ctx_t * mediatest_configure(int media_test_id,  mediatest_spec_t * spec)
{
    int ret = 0;
    mediatest_ctx_t* mt_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_connection_id_t icid = { { 0xed, 0x1a, 0x7e, 0x57, 0, 0, 0, 0}, 8 };
    icid.id[4] = media_test_id;

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
        mt_ctx = (mediatest_ctx_t*)malloc(sizeof(mediatest_ctx_t));
        if (mt_ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(mt_ctx, 0, sizeof(mediatest_ctx_t));
        /* Create the QUIC contexts */
        mt_ctx->quic[0] = picoquic_create(4, NULL, NULL, test_server_cert_store_file, NULL, mediatest_callback,
            (void*)mt_ctx, NULL, NULL, NULL, mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, NULL, 0);
        mt_ctx->quic[1] = picoquic_create(4,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            MEDIATEST_ALPN, mediatest_callback, (void*)mt_ctx, NULL, NULL, NULL,
            mt_ctx->simulated_time, &mt_ctx->simulated_time, NULL, mediatest_ticket_encrypt_key, sizeof(mediatest_ticket_encrypt_key));

        if (mt_ctx->quic[0] == NULL || mt_ctx->quic[1] == NULL) {
            ret = -1;
        }
        
        if (spec->ccalgo != NULL) {
            for (int i = 0; i < 2 && ret == 0; i++) {
                picoquic_set_default_congestion_algorithm(mt_ctx->quic[i], spec->ccalgo);
                ret = picoquic_set_binlog(mt_ctx->quic[i], ".");
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
            mt_ctx->link[i] = picoquictest_sim_link_create(0.01,
                (spec->link_latency == 0)?10000:spec->link_latency, NULL, 0, 0);
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
            (struct sockaddr*)&mt_ctx->addr[1], mt_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, MEDIATEST_ALPN, 1);
        /* Start the connection and create the context */
        if (cnx != NULL) {
            picoquic_tp_t client_parameters;
            mediatest_init_transport_parameters(&client_parameters, 1);
            picoquic_set_transport_parameters(cnx, &client_parameters);
            picoquic_set_feedback_loss_notification(cnx, 1);

            if (picoquic_start_client_cnx(cnx) != 0) {
                picoquic_delete_cnx(cnx);
                ret = -1;
            }
            if (cnx != NULL) {
                mt_ctx->client_cnx = mediatest_create_cnx_context(mt_ctx, cnx);
                if (mt_ctx->client_cnx == NULL) {
                    picoquic_delete_cnx(cnx);
                    ret = -1;
                }
                if (spec->data_size > 0 && ret == 0) {
                    ret = mediatest_configure_stream(mt_ctx->client_cnx, media_test_data, spec->data_size);
                }
                if (spec->do_audio && ret == 0) {
                    ret = mediatest_configure_stream(mt_ctx->client_cnx, media_test_audio, 0);
                }
                if (spec->do_video && ret == 0) {
                    ret = mediatest_configure_stream(mt_ctx->client_cnx, media_test_video, 0);
                }
                if (spec->do_video2 && ret == 0) {
                    ret = mediatest_configure_stream(mt_ctx->client_cnx, media_test_video2, 0);
                }
                if (spec->do_probe_up && ret == 0) {
                    picoquic_request_forced_probe_up(mt_ctx->client_cnx->cnx, 1);
                }
                if (spec->datagram_data_size > 0 && ret == 0) {
                    mt_ctx->datagram_data_requested = spec->datagram_data_size;
                }
                if (spec->priority_limit_for_bypass > 0) {
                    picoquic_set_priority_limit_for_bypass(mt_ctx->client_cnx->cnx, spec->priority_limit_for_bypass);
                }

            
                for (int i = 0; i < media_test_nb_types; i++) {
                    mt_ctx->media_stats[i].min_delay = UINT64_MAX;
                }
            }
        }
    }

    if (ret != 0 && mt_ctx != NULL) {
        mediatest_delete_ctx(mt_ctx);
        mt_ctx = NULL;
    }

    return mt_ctx;
}

int mediatest_loop(mediatest_ctx_t* mt_ctx, uint64_t simulated_time_max, int is_losing_data, int * is_finished)
{
    int ret = 0;
    int nb_steps = 0;
    int nb_inactive = 0;

    /* Run the simulation until done */
    while (ret == 0 && !(*is_finished) && nb_steps < 100000 && nb_inactive < 512 && mt_ctx->simulated_time < simulated_time_max) {
        int is_active = 0;
        nb_steps += 1;
        ret = mediatest_step(mt_ctx, is_losing_data, &is_active);
        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive += 1;
        }
        *is_finished = mediatest_is_finished(mt_ctx);
    }

    return ret;
}

/* One test */
int mediatest_one(mediatest_id_enum media_test_id, mediatest_spec_t * spec)
{
    int ret = 0;
    int is_finished = 0;

    /* set the configuration */
    mediatest_ctx_t* mt_ctx = mediatest_configure(media_test_id, spec);
    if (mt_ctx == NULL) {
        ret = -1;
    }

    /* Three special cases in which we manipulate the configuration
    * to simulate various downgrade or suspension patterns.
     */
    if (media_test_id == mediatest_worst) {
        /* Only collect statistics after expected end of disruption. */
        mt_ctx->disruption_clear = 2500000;
        /* Run the simulation for 1 second. */
        ret = mediatest_loop(mt_ctx, 1000000, 0, &is_finished);
        /* Lose data for 1 second */
        if (ret == 0) {
            ret = mediatest_loop(mt_ctx, 2000000, 1, &is_finished);
        }
    }
    else if (media_test_id == mediatest_video2_down ||
        media_test_id == mediatest_video2_back) {
        uint64_t picosec_per_byte_ref[2];
        uint64_t latency_ref[2];
        uint64_t down_time = (media_test_id == mediatest_video2_down) ? 4000000 : 2000000;
        uint64_t back_time = (media_test_id == mediatest_video2_down) ? 24000000 : 4000000;

        /* Run the simulation for the first period. */
        ret = mediatest_loop(mt_ctx, down_time, 0, &is_finished);
        /* Drop the bandwidth and increase latency for specified down time */
        for (int i = 0; i < 2; i++) {
            picosec_per_byte_ref[i] = mt_ctx->link[i]->picosec_per_byte;
            mt_ctx->link[i]->picosec_per_byte = 8000000; /* 8 us per byte, i.e., 1Mbps*/
            latency_ref[i] = mt_ctx->link[i]->microsec_latency;
        }
        if (ret == 0) {
            ret = mediatest_loop(mt_ctx, back_time, 0, &is_finished);
        }
        /* restore the bandwidth */
        for (int i = 0; i < 2; i++) {
            mt_ctx->link[i]->picosec_per_byte = picosec_per_byte_ref[i];
            mt_ctx->link[i]->microsec_latency = latency_ref[i];
        }
    }
    else if (spec->nb_suspensions > 0) {
        /* Set the time of the first suspension */
        uint64_t sim_time = spec->suspension_start_time;
        /* Execute the specified suspensions */
        for (int i = 0; ret == 0 && !is_finished && i < spec->nb_suspensions; i++) {
            /* Run the simulation until the beginning of the suspension */
            ret = mediatest_loop(mt_ctx, sim_time, 0, &is_finished);
            /* set the end of suspension time */
            sim_time += spec->suspension_down_time;
            /* program the suspension */
            picoquic_test_simlink_suspend(mt_ctx->link[0], sim_time, 0);
            picoquic_test_simlink_suspend(mt_ctx->link[1], sim_time, 1);
            /* Run the simulation until the end of the suspension */
            ret = mediatest_loop(mt_ctx, sim_time, 0, &is_finished);
            /* deliver the packets that were queued at the beginning of the suspension */
            if (spec->suspension_up_time == 0) {
                /* simulating back to back suspensions */
                picoquictest_sim_packet_t* packet;
                for (int i = 0; i < 2; i++) {
                    while ((packet = picoquictest_sim_link_dequeue(mt_ctx->link[i], sim_time)) != NULL && ret == 0) {
                        ret = picoquic_incoming_packet(mt_ctx->quic[i],
                            packet->bytes, (uint32_t)packet->length,
                            (struct sockaddr*)&packet->addr_from,
                            (struct sockaddr*)&packet->addr_to, 0, 0,
                            mt_ctx->simulated_time);
                        free(packet);
                    }
                }
            }
            /* Compute the time of the next suspension */
            sim_time += spec->suspension_up_time;
        }
        /* After that, continue running as specified. */
    }

    /* Run the simulation until done */
    if (ret == 0) {
        ret = mediatest_loop(mt_ctx, 30000000, 0, &is_finished);
    }

    /* Check that the simulation ran to the end. */
    if (ret == 0) {
        if (!is_finished) {
            ret = -1;
        }
        /* Check that the results are as expected. */
        if (ret == 0 && spec->do_audio) {
            ret = mediatest_check_stats(mt_ctx, spec, media_test_audio);
        }
        if (ret == 0 && spec->do_video) {
            ret = mediatest_check_stats(mt_ctx, spec, media_test_video);
        }
        if (ret == 0 && spec->do_video2 && !spec->do_not_check_video2) {
            ret = mediatest_check_stats(mt_ctx, spec, media_test_video2);
        }
    }
    if (ret == 0 && media_test_id == mediatest_wifi) {
        picoquic_path_quality_t quality = { 0 };
        picoquic_get_default_path_quality(mt_ctx->client_cnx->cnx, &quality);
        if (quality.lost == 0 || quality.spurious_losses == 0 || quality.timer_losses == 0) {
            /* Unexpected. the wifi tst should have triggered at least on spurious timer loss. */
            ret = -1;
        }
    }
    if (mt_ctx != NULL) {
        mediatest_delete_ctx(mt_ctx);
    }
    return ret;
}

/* Test cases */
int mediatest_video_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    ret = mediatest_one(mediatest_video, &spec);

    return ret;
}

int mediatest_video_audio_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    ret = mediatest_one(mediatest_video_audio, &spec);

    return ret;
}

int mediatest_video_data_audio_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    spec.data_size = 10000000;
    ret = mediatest_one(mediatest_video_data_audio, &spec);

    return ret;
}

int mediatest_video2_down_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.latency_average = 100000;
    spec.latency_max = 600000;
    spec.do_not_check_video2 = 1;
    ret = mediatest_one(mediatest_video2_down, &spec);

    return ret;
}

int mediatest_video2_back_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.latency_average = 80000;
    spec.latency_max = 500000;
    spec.do_not_check_video2 = 1;
    ret = mediatest_one(mediatest_video2_back, &spec);

    return ret;
}

int mediatest_video2_probe_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.1;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.latency_average = 25000;
    spec.latency_max = 150000;
    spec.do_probe_up = 1;
    ret = mediatest_one(mediatest_video2_probe, &spec);

    return ret;
}

int mediatest_worst_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_audio = 1;
    spec.data_size = 10000000;
    ret = mediatest_one(mediatest_worst, &spec);

    return ret;
}

int mediatest_wifi_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.01;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.link_latency = 15000;
    spec.latency_average = 60000;
    spec.latency_max = 350000;
    spec.priority_limit_for_bypass = 5;
    spec.do_not_check_video2 = 1;
    spec.nb_suspensions = 20;
    spec.suspension_start_time = 4000000;
    spec.suspension_down_time = 150000;
    spec.suspension_up_time = 0;

    ret = mediatest_one(mediatest_wifi, &spec);

    return ret;
}

int mediatest_suspension_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.1;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.latency_average = 50000;
    spec.latency_max = 300000;
    spec.do_not_check_video2 = 1;
    spec.nb_suspensions = 1;
    spec.suspension_start_time = 4000000;
    spec.suspension_down_time = 150000;
    spec.suspension_up_time = 50000;
    ret = mediatest_one(mediatest_suspension, &spec);

    return ret;
}

int mediatest_suspension2_test()
{
    int ret;
    mediatest_spec_t spec = { 0 };
    spec.ccalgo = picoquic_bbr_algorithm;
    spec.bandwidth = 0.1;
    spec.do_video = 1;
    spec.do_video2 = 1;
    spec.do_audio = 1;
    spec.data_size = 0;
    spec.latency_average = 50000;
    spec.latency_max = 300000;
    spec.do_not_check_video2 = 1;
    spec.do_probe_up = 1;
    ret = mediatest_one(mediatest_suspension2, &spec);

    return ret;
}