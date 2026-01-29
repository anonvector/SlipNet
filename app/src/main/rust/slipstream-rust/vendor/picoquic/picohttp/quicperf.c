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
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picosplay.h"
#include "quicperf.h"

/* management of scenarios by the quicperf client 
* scenario = stream_choice |  stream_choice ';' *scenario

id = alphanumeric-string

stream_choice = [ '=' id ':' ]['*' repeat_count ':'] { stream_description | media_stream | datagram_stream }

stream_description = [ stream_number ':'] post_size ':' response_size


media_stream = stream_media_description | datagram_media_description

stream_media_description = 's' media_description

datagram_media_description = 'd' media_description

media_description = priority ':' frequency ':' post_size ':' response_size
                    [ ':' nb_frames ':'  marks_size ':' mark_response_size ':' reset_delay ]
 */

size_t quicperf_parse_nb_stream(char const* text) {
    size_t n = 0;
    int after_semi = 1;

    while (*text != 0) {
        if (*text++ == ';') {
            n++;
            after_semi = 0;
        }
        else {
            after_semi = 1;
        }
    }

    n += after_semi;

    return n;
}

char const* quicperf_parse_stream_spaces(char const* text) {
    if (text != NULL) {
        while (*text == ' ' || *text == '\t' || *text == '\n' || *text == '\r') {
            text++;
        }
    }
    return text;
}

char const* quicperf_parse_number(char const* text, int *is_present, int* is_signed, uint64_t* number)
{
    *is_present = 0;
    *number = 0;
    if (is_signed != NULL) {
        *is_signed = 0;
        if (*text == '-') {
            *is_signed = 1;
            text++;
            *is_present = 1;
        }
    }
    while (text[0] >= '0' && text[0] <= '9') {
        int delta = *text++ - '0';
        *number *= 10;
        *number += delta;
        *is_present = 1;
    }

    text = quicperf_parse_stream_spaces(text);

    return text;
}

char const* quicperf_parse_alphanum(char const* text, int* is_present, char * s, size_t l)
{
    size_t nb_read = 0 ;
    *is_present = 0;

    while (nb_read + 1 < l){
        char c = *text;

        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z')) {
            s[nb_read++] = c;
            text++;
        }
        else {
            break;
        }
    }
    if (nb_read >= 0) {
        *is_present = 1;
        s[nb_read] = 0;
    }
    return text;
}

char const* quicperf_skip_colon_if_present(char const* text, int is_present)
{
    if (is_present && text != NULL) {
        text = quicperf_parse_stream_spaces(text);
        if (*text == ':') {
            text++;
            text = quicperf_parse_stream_spaces(text);
        }
        else if (*text != 0 && *text != ';'){
            text = NULL;
        }
    }
    return text;
}


char const* quicperf_parse_stream_id(char const* text, char * id, size_t id_size)
{
    int is_present = 0;
   
    id[0] = 0;

    if (*text == '=') {
        text = quicperf_parse_stream_spaces(text+1);
        text = quicperf_parse_alphanum(text, &is_present, id, id_size);
        if (text != NULL) {
            text = quicperf_skip_colon_if_present(text, 1);
        }
    }

    return text;
}

char const* quicperf_parse_stream_repeat(char const* text, uint64_t* number)
{
    int is_present = 0;

    if (*text == '*') {
        text = quicperf_parse_stream_spaces(text + 1);
        text = quicperf_parse_number(text, &is_present, NULL, number);
        if (!is_present) {
            text = NULL;
        }
        else {
            text = quicperf_skip_colon_if_present(text, 1);
        }
    }
    else {
        *number = 1;
    }

    return text;
}

char const* quicperf_parse_media_type(char const* text, quicperf_stream_desc_t* desc)
{
    if (*text == 's') {
        desc->media_type = quicperf_media_stream;
        text++;
    }
    else if (*text == 'd') {
        desc->media_type = quicperf_media_datagram;
        text++;
    }
    else if (*text == 'b') {
        desc->media_type = quicperf_media_batch;
        text++;
    }
    else {
        desc->media_type = quicperf_media_batch;
    }

    return text;
}

char const* quicperf_parse_post_size(char const* text, uint64_t default_number, uint64_t* number)
{
    int is_present = 0;
    int is_signed = 0;

    text = quicperf_parse_number(text, &is_present, &is_signed, number);

    if (!is_present) {
        text = NULL;
    }
    else if (is_signed) {
        if (*number == 0) {
            *number = default_number;
        }
        else {
            text = NULL;
        }
    }

    return quicperf_skip_colon_if_present(text, is_present);
}

char const* quicperf_parse_response_size(char const* text, int *is_signed, uint64_t* number)
{
    int is_present = 0;

    text = quicperf_parse_number(text, &is_present, is_signed, number);

    if (!is_present) {
        text = NULL;
    }

    return text;
}

char const* quicperf_parse_number_param(char const* text, uint64_t max_value, uint64_t* number)
{
    int is_present = 0;
    int is_signed = 0;

    text = quicperf_parse_number(text, &is_present, &is_signed, number);

    if (!is_present || is_signed || *number > max_value) {
        text = NULL;
    }

    return quicperf_skip_colon_if_present(text, is_present);
}

char const* quicperf_parse_frequency(char const* text, uint8_t* number)
{
    int is_present = 0;
    uint64_t number64;

    text = quicperf_parse_number(text, &is_present, NULL, &number64);

    if (!is_present || number64 > 255) {
        text = NULL;
    }
    else {
        *number = (uint8_t)number64;
        text = quicperf_skip_colon_if_present(text, is_present);
    }

    return text;
}

char const* quicperf_parse_letter_number_param(char const* text, char letter, uint64_t max_value, uint64_t* number)
{
    int is_present = 0;
    int is_signed = 0;

    if (*text == letter) {
        text = quicperf_parse_stream_spaces(text + 1);
        text = quicperf_parse_number(text, &is_present, &is_signed, number);

        if (!is_present || is_signed || (max_value != 0 && *number > max_value)) {
            text = NULL;
        }
        else {
            text = quicperf_skip_colon_if_present(text, is_present);
        }
    }

    return text;
}

char const* quicperf_parse_priority(char const* text, uint8_t* priority)
{
    uint64_t number = 0;

    text = quicperf_parse_letter_number_param(text, 'p', 255, &number);
    *priority = (uint8_t)number;

    return text;
}

char const* quicperf_parse_client_server(char const* text, int * is_client_media)
{
    if (*text == 'C') {
        *is_client_media = 1;
        text = quicperf_skip_colon_if_present(text+1, 1);
    }
    else if (*text == 'S') {
        *is_client_media = 0;
        text = quicperf_skip_colon_if_present(text+1, 1);
    }
    else {
        *is_client_media = 0;
    }

    return text;
}


char const* quicperf_parse_media_desc(char const* text, quicperf_stream_desc_t* desc)
{
    if (text != NULL) {
        text = quicperf_parse_frequency(quicperf_parse_stream_spaces(text), &desc->frequency);
    }

    if (text != NULL) {
        text = quicperf_parse_priority(quicperf_parse_stream_spaces(text), &desc->priority);
    }

    if (text != NULL) {
        text = quicperf_parse_client_server(quicperf_parse_stream_spaces(text), &desc->is_client_media);
    }

    if (text != NULL) {
        text = quicperf_parse_letter_number_param(text, 'n', 0, &desc->nb_frames);
    }

    if (text != NULL) {
        text = quicperf_parse_number_param(quicperf_parse_stream_spaces(text), 0xffffff, &desc->frame_size);
    }

    if (text != NULL) {
        text = quicperf_parse_letter_number_param(text, 'G', 0, &desc->group_size);
    }

    if (text != NULL) {
        text = quicperf_parse_letter_number_param(text, 'I', 0, &desc->first_frame_size);
    }

    if (text != NULL) {
        text = quicperf_parse_letter_number_param(text, 'D', 0, &desc->reset_delay);
    }

    return text;
}

char const* quicperf_parse_stream_desc(char const* text, quicperf_stream_desc_t* desc)
{

    if (text != NULL) {
        text = quicperf_parse_post_size(quicperf_parse_stream_spaces(text), 0, &desc->post_size);
    }

    if (text != NULL) {
        text = quicperf_parse_response_size(quicperf_parse_stream_spaces(text),
            &desc->is_infinite, &desc->response_size);
    }

    return text;
}

/* stream_choice = [ '=' id ':' ][ '=' previous_id ':' ]['*' repeat_count ':'] { stream_description | media_stream | datagram_stream } */
char const* quicperf_parse_stream_choice(char const* text, quicperf_stream_desc_t* desc)
{
    /* Parse the stream ID if present */
    text = quicperf_parse_stream_id(quicperf_parse_stream_spaces(text), desc->id, sizeof(desc->id));

    /* Parse the previous stream ID if present */
    if (text != NULL) {
        text = quicperf_parse_stream_id(quicperf_parse_stream_spaces(text), desc->previous_id, sizeof(desc->previous_id));
    }

    /* Parse the repeat count. */
    if (text != NULL) {
        text = quicperf_parse_stream_repeat(quicperf_parse_stream_spaces(text), &desc->repeat_count);
    }
    /* Check whether this is a media stream */
    if (text != NULL) {
        text = quicperf_parse_media_type(quicperf_parse_stream_spaces(text), desc);
    }
    /* Parse the stream or media description */
    if (desc->media_type == quicperf_media_batch) {
        text = quicperf_parse_stream_desc(text, desc);
    }
    else {
        text = quicperf_parse_media_desc(text, desc);
    }

    /* Skip the final ';' */
    if (text != NULL) {
        if (*text == ';') {
            text = quicperf_parse_stream_spaces(text + 1);
        }
        else if (*text != 0) {
            text = NULL;
        }
    }
    return text;
}


int quicperf_parse_scenario_desc(char const* text, size_t* nb_streams, quicperf_stream_desc_t** desc)
{
    int ret = 0;
    /* first count the number of streams and allocate memory */
    size_t nb_desc = quicperf_parse_nb_stream(text);

    *desc = (quicperf_stream_desc_t*)malloc(nb_desc * sizeof(quicperf_stream_desc_t));

    if (*desc == NULL) {
        *nb_streams = 0;
        ret = -1;
    }
    else {
        size_t i = 0;
        memset(*desc, 0, nb_desc * sizeof(quicperf_stream_desc_t));

        while (text != NULL && *text != 0 && i < nb_desc) {
            text = quicperf_parse_stream_choice(text, &(*desc)[i]);
            i++;
        }

        *nb_streams = i;

        if (text == NULL || i != nb_desc) {
            ret = -1;
        }
    }

    return ret;
}

/* Management of spay of stream contexts
 */
 /* Stream splay management */

static int64_t quicperf_stream_ctx_compare(void* l, void* r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((quicperf_stream_ctx_t*)l)->stream_id - ((quicperf_stream_ctx_t*)r)->stream_id;
}

static picosplay_node_t* quicperf_stream_ctx_create(void* value)
{
    return &((quicperf_stream_ctx_t*)value)->quicperf_stream_node;
}


static void* quicperf_stream_ctx_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_quicperf_stream_ctx, quicperf_stream_node));
}


static void quicperf_stream_ctx_delete(void* tree, picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    quicperf_stream_ctx_t* stream_ctx = quicperf_stream_ctx_value(node);

    free(stream_ctx);
}

/* Parsing and formating of the stream header sent in client requests.
 */

size_t quicperf_parse_request_header(picoquic_cnx_t * cnx, quicperf_stream_ctx_t* stream_ctx, uint8_t * bytes, size_t length)
{
    size_t byte_index = 0;

    while (stream_ctx->nb_post_bytes < 8 && byte_index < length) {
        if (stream_ctx->start_time == 0) {
            stream_ctx->start_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
        }
        stream_ctx->response_size = (stream_ctx->response_size << 8) + bytes[byte_index++];
        stream_ctx->nb_post_bytes++;
        /* check whether this is a media header */
        if (stream_ctx->nb_post_bytes == 8) {
            uint64_t high32 = stream_ctx->response_size >> 32;
            if (high32 >= 0xFFFFFFFD && high32 < 0xFFFFFFFF) {
                stream_ctx->is_media = 1;
                stream_ctx->is_datagram = ((high32 & 1) != 0);
                stream_ctx->frame_size = stream_ctx->response_size & 0xFFFFFFFF;
                stream_ctx->response_size = 0;
            }
        }
    }
    /* If this is a media header, parse the next 8 bytes */
    while (stream_ctx->is_media && stream_ctx->nb_post_bytes < 16) {
        uint8_t b = bytes[byte_index++];
        if (stream_ctx->nb_post_bytes == 8) {
            stream_ctx->priority = b;
            if (stream_ctx->priority != 0) {
                if (stream_ctx->is_datagram) {
                    picoquic_set_datagram_priority(cnx, stream_ctx->priority);
                }
                else {
                    picoquic_set_stream_priority(cnx, stream_ctx->stream_id, stream_ctx->priority);
                }
            }
        }
        else if (stream_ctx->nb_post_bytes == 9) {
            stream_ctx->frequency = b;
        }
        else if (stream_ctx->nb_post_bytes <= 12) {
            stream_ctx->nb_frames = (stream_ctx->nb_frames << 8) + b;
        }
        else {
            stream_ctx->first_frame_size = (stream_ctx->first_frame_size << 8) + b;
        }
        stream_ctx->nb_post_bytes++;
    }

    return byte_index;
}

size_t quicperf_prepare_media_request_bytes(quicperf_stream_ctx_t* stream_ctx, uint8_t* buffer, size_t available)
{
    size_t byte_index = 0;

    if (stream_ctx->frame_bytes_sent < 16) {
        uint8_t request[16];

        request[0] = 0xff;
        request[1] = 0xff;
        request[2] = 0xff;
        request[3] = (stream_ctx->is_datagram) ? 0xfd : 0xfe;
        request[4] = (uint8_t)((stream_ctx->frame_size >> 24) & 0xff);
        request[5] = (uint8_t)((stream_ctx->frame_size >> 16) & 0xff);
        request[6] = (uint8_t)((stream_ctx->frame_size >> 8) & 0xff);
        request[7] = (uint8_t)(stream_ctx->frame_size & 0xff);
        request[8] = stream_ctx->priority;
        request[9] = stream_ctx->frequency;
        request[10] = (uint8_t)((stream_ctx->nb_frames >> 16) & 0xff);
        request[11] = (uint8_t)((stream_ctx->nb_frames >> 8) & 0xff);
        request[12] = (uint8_t)(stream_ctx->nb_frames & 0xff);
        request[13] = (uint8_t)((stream_ctx->first_frame_size >> 16) & 0xff);
        request[14] = (uint8_t)((stream_ctx->first_frame_size >> 8) & 0xff);
        request[15] = (uint8_t)(stream_ctx->first_frame_size & 0xff);

        while (stream_ctx->frame_bytes_sent < 16 && byte_index < available) {
            buffer[byte_index] = request[stream_ctx->frame_bytes_sent];
            stream_ctx->frame_bytes_sent++;
            byte_index++;
        }
    }
    return byte_index;
}

/* Client work:
 * Integrate with context creation per client, on first reference.
 *
 * On start (ready), initialize the "initial" streams.
 * On fin of a stream, initialize the dependent stream.
 * In either of these cases, if nothing left, close the connection.
 *
 * On stream request: if stream is initialized, produce the required data, if all sent close stream. First 8 bytes
 * shall encode the number of bytes requested.
 * On stream data arrival: count the number arrived. If negative stream, reset stream if needed.
 *
 */

quicperf_stream_ctx_t* quicperf_find_stream_ctx(quicperf_ctx_t* ctx, uint64_t stream_id)
{
    quicperf_stream_ctx_t target;
    target.stream_id = stream_id;

    return (quicperf_stream_ctx_t*)picosplay_find(&ctx->quicperf_stream_tree, (void*)&target);
}

quicperf_ctx_t* quicperf_create_ctx(const char* scenario_text)
{
    quicperf_ctx_t* ctx = (quicperf_ctx_t*)malloc(sizeof(quicperf_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(quicperf_ctx_t));

        if (scenario_text != NULL) {
            if (quicperf_parse_scenario_desc(scenario_text, &ctx->nb_scenarios, &ctx->scenarios) == 0 &&
                (ctx->reports = (quicperf_stream_report_t*)malloc(sizeof(quicperf_stream_report_t) * ctx->nb_scenarios)) != NULL){
                memset(ctx->reports, 0, sizeof(quicperf_stream_report_t) * ctx->nb_scenarios);
                ctx->is_client = 1;
            }
            else {
                quicperf_delete_ctx(ctx);
                ctx = NULL;
            }
        }

        if (ctx != NULL) {
            picosplay_init_tree(&ctx->quicperf_stream_tree, quicperf_stream_ctx_compare, quicperf_stream_ctx_create,
                quicperf_stream_ctx_delete, quicperf_stream_ctx_value);
        }
    }

    return ctx;
}

void quicperf_delete_ctx(quicperf_ctx_t* ctx)
{
    picosplay_empty_tree(&ctx->quicperf_stream_tree);

    if (ctx->scenarios != NULL) {
        free(ctx->scenarios);
    }
    if (ctx->reports != NULL) {
        free(ctx->reports);
    }
    free(ctx);
}

quicperf_stream_ctx_t* quicperf_create_stream_ctx(quicperf_ctx_t* ctx, uint64_t stream_id)
{
    quicperf_stream_ctx_t* stream_ctx = (quicperf_stream_ctx_t*)malloc(sizeof(quicperf_stream_ctx_t));

    if (stream_ctx != NULL) {
        memset(stream_ctx, 0, sizeof(quicperf_stream_ctx_t));
        stream_ctx->stream_id = stream_id;
        picosplay_insert(&ctx->quicperf_stream_tree, stream_ctx);
    }
    return stream_ctx;
}

void quicperf_delete_stream_node(quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx)
{
    picosplay_delete_hint(&ctx->quicperf_stream_tree, &stream_ctx->quicperf_stream_node);
}

quicperf_stream_ctx_t* quicperf_init_batch_stream_from_scenario(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx,
    const quicperf_stream_desc_t * stream_desc, uint64_t rep_number)
{
    uint64_t stream_x = picoquic_get_next_local_stream_id(cnx, 0);
    quicperf_stream_ctx_t* stream_ctx = quicperf_create_stream_ctx(ctx, stream_x);

    if (stream_ctx != NULL) {
        stream_ctx->rep_number = rep_number;
        stream_ctx->post_size = stream_desc->post_size;
        stream_ctx->response_size = stream_desc->response_size;

        if (stream_desc->is_infinite) {
            stream_ctx->stop_for_fin = 1;
            for (int x = 0; x < 8; x++) {
                stream_ctx->length_header[x] = 0xFF;
            }
        }
        else {
            for (int x = 0; x < 8; x++) {
                stream_ctx->length_header[x] = (uint8_t)((stream_ctx->response_size >> ((7 - x) * 8)) & 0xFF);
            }
        }
    }
    return stream_ctx;
}

quicperf_stream_ctx_t* quicperf_request_media_stream_from_scenario(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx,  
    const quicperf_stream_desc_t* stream_desc, uint64_t rep_number, uint64_t group_id, uint64_t desc_start_time)
{
    uint64_t stream_x = picoquic_get_next_local_stream_id(cnx, 0);
    quicperf_stream_ctx_t* stream_ctx = quicperf_create_stream_ctx(ctx, stream_x);

    if (stream_ctx != NULL) {
        stream_ctx->rep_number = rep_number;
        stream_ctx->group_id = group_id;
        if (stream_desc->group_size == 0) {
            stream_ctx->nb_frames = stream_desc->nb_frames;
        }
        else if (stream_desc->group_size * (group_id + 1) > stream_desc->nb_frames) {
            stream_ctx->nb_frames = stream_desc->nb_frames - stream_desc->group_size * group_id;
        }
        else {
            stream_ctx->nb_frames = stream_desc->group_size;
        }
        stream_ctx->first_frame_size = stream_desc->first_frame_size;
        if (stream_ctx->first_frame_size == 0) {
            stream_ctx->first_frame_size = stream_desc->frame_size;
        }
        stream_ctx->frame_size = stream_desc->frame_size;
        stream_ctx->priority = stream_desc->priority;
        stream_ctx->frequency = stream_desc->frequency;
        stream_ctx->is_media = 1;
        stream_ctx->is_datagram = (stream_desc->media_type == quicperf_media_datagram);
        stream_ctx->start_time = desc_start_time;
        if (stream_desc->reset_delay > 0) {
            stream_ctx->reset_delay = stream_desc->reset_delay;
            stream_ctx->reset_time = stream_ctx->start_time + stream_ctx->reset_delay;
        }
    }
    return stream_ctx;
}

int quicperf_init_streams_from_scenario(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, char const *id)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
    picoquic_tp_t const* remote_tp = picoquic_get_transport_parameters(cnx, 0);

    for (size_t i = 0; ret == 0 && i < ctx->nb_scenarios; i++) {
        if (strcmp(id, ctx->scenarios[i].previous_id) == 0) {
            quicperf_stream_ctx_t* stream_ctx = NULL;
            uint64_t rep_number = 0;
            do {
                switch (ctx->scenarios[i].media_type) {
                case quicperf_media_batch:
                    stream_ctx = quicperf_init_batch_stream_from_scenario(cnx, ctx, &ctx->scenarios[i], rep_number);
                    break;
                case quicperf_media_stream:
                    if (ctx->scenarios[i].is_client_media) {
                        /* stream_ctx = quicperf_init_media_stream_from_scenario(cnx, ctx, &ctx->scenarios[i], repeat_nb, 0); */
                        /* TODO */
                        stream_ctx = NULL;
                    }
                    else {
                        stream_ctx = quicperf_request_media_stream_from_scenario(cnx, ctx, &ctx->scenarios[i], rep_number, 0, current_time);

                        if (stream_ctx != NULL && rep_number == 0) {
                            quicperf_stream_report_t* report = &ctx->reports[i];
                            report->is_activated = 1;
                            report->next_group_id = 1;
                            report->next_group_start_time = current_time;
                            if (stream_ctx->frequency > 0) {
                                report->next_group_start_time += (stream_ctx->nb_frames * 1000000) / stream_ctx->frequency;
                            }
                            if (report->next_group_start_time < ctx->next_group_start_time) {
                                ctx->next_group_start_time = report->next_group_start_time;
                            }
                            ctx->is_activated = 1;
                        }
                    }
                    break;
                case quicperf_media_datagram:
                    if (ctx->scenarios[i].is_client_media) {
                        /* TODO */
                        stream_ctx = NULL;
                    }
                    else if (ctx->scenarios[i].media_type == quicperf_media_datagram &&
                        ctx->scenarios[i].frame_size > remote_tp->max_datagram_frame_size) {
                        DBG_PRINTF("Datagram size %" PRIu64 " > max remote size: %u", ctx->scenarios[i].frame_size, remote_tp->max_datagram_frame_size);
                        ret = -1;
                    }
                    else {
                        stream_ctx = quicperf_request_media_stream_from_scenario(cnx, ctx, &ctx->scenarios[i], rep_number, 0, current_time);
                    }
                    break;
                default: 
                    stream_ctx = NULL;
                    break;
                }
                if (stream_ctx == NULL) {
                    ret = -1;
                } else {
                    rep_number++;
                    stream_ctx->stream_desc_index = i;
                    ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
                    ctx->nb_open_streams++;
                }
            } while (ret == 0 && rep_number < ctx->scenarios[i].repeat_count);
        }
        picoquic_set_app_wake_time(cnx, current_time);
    }

    return ret;
}


/* Send a datagram
 */
int quicperf_send_datagrams(picoquic_cnx_t* cnx, uint64_t current_time, quicperf_stream_ctx_t * stream_ctx)
{
    int ret = 0;
    uint8_t buffer[1024];
    uint64_t data_size = stream_ctx->frame_size;
    if (data_size > 1024) {
        data_size = 1024;
    }

    while (ret == 0 && current_time >= stream_ctx->next_frame_time && stream_ctx->nb_frames_sent < stream_ctx->nb_frames) {
        uint8_t* bytes = buffer;
        uint8_t* bytes_max = bytes + 1024;

        if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_ctx->stream_id)) == NULL ||
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_ctx->nb_frames_sent)) == NULL ||
            (bytes = picoquic_frames_uint64_encode(bytes, bytes_max, current_time)) == NULL) {
            ret = -1;
        }
        else {
            size_t encoded = (bytes - buffer);
            if (bytes < bytes_max && encoded < data_size) {
                memset(bytes, 0xaa, (size_t)data_size - encoded);
                encoded = (size_t) data_size;
            }
            ret = picoquic_queue_datagram_frame(cnx, encoded, buffer);
            stream_ctx->nb_frames_sent++;
            stream_ctx->next_frame_time = stream_ctx->start_time;
            if (stream_ctx->frequency > 0) {
                stream_ctx->next_frame_time += (stream_ctx->nb_frames_sent * 1000000) / stream_ctx->frequency;
            }
        }
    }

    return ret;
}

/* Receive a datagram
*/
void quicperf_receive_datagram(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, const uint8_t* bytes, size_t length)
{
    int ret = 0;
    uint64_t frame_id = 0;
    uint64_t timestamp = 0;
    const uint8_t* bytes_max = bytes + length;
    quicperf_stream_ctx_t target_stream_ctx = { 0 };
    quicperf_stream_ctx_t* stream_ctx = NULL;

    /* decode the datagram header */
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &target_stream_ctx.stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id)) == NULL ||
        (bytes = picoquic_frames_uint64_decode(bytes, bytes_max, &timestamp)) == NULL) {
        ret = -1;
    }

    /* Find the control stream */
    if (ret == 0) {
        /* Find the stream context for the frame id */
        picosplay_node_t* node = picosplay_find(&ctx->quicperf_stream_tree, &target_stream_ctx);
        if (node == NULL) {
            ret = -1;
        }
        else {
            stream_ctx = (quicperf_stream_ctx_t*)quicperf_stream_ctx_value(node);

            if (stream_ctx == NULL || stream_ctx->stream_desc_index >= ctx->nb_scenarios) {
                /* Do not use an invalid context ID */
                ret = 1;
            }
        }
    }
    /* Update the statistics */
    if (ret == 0) {
        /* Write media report on reporting file */
        uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
        quicperf_stream_report_t* report = &ctx->reports[stream_ctx->stream_desc_index];
        uint64_t expected_time = stream_ctx->start_time;
        uint64_t rtt;

        if (stream_ctx->frequency > 0) {
            expected_time += frame_id * 1000000 / stream_ctx->frequency;
        }
        report->nb_frames_received += 1;
        if (current_time <= expected_time) {
            rtt = 0;
        }
        else {
            rtt = current_time - expected_time;
        }

        report->sum_delays += rtt;
        if (report->min_delays == 0 || rtt < report->min_delays) {
            report->min_delays = rtt;
        }
        if (rtt > report->max_delays) {
            report->max_delays = rtt;
        }

        if (ctx->report_file != NULL) {
            if (ctx->scenarios[stream_ctx->stream_desc_index].id[0] != 0) {
                fprintf(ctx->report_file, "%s,", ctx->scenarios[stream_ctx->stream_desc_index].id);
            }
            else {
                fprintf(ctx->report_file, "#%" PRIu64 ", ", stream_ctx->stream_desc_index);
            }
            fprintf(ctx->report_file, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",\n",
                stream_ctx->rep_number, stream_ctx->group_id, frame_id, timestamp, current_time);
        }
    }
}

/*
* The scenario execution is driven by timers, from the client side.
*
* For the media scenario, the "next group" is started when the time has come,
* i.e., nb_frames/frequency after the start of the previous group. That requires
* keeping track of the description start time, how many groups have been
* requested so far, and what is the time for the next action. We keep
* these per descriptior variables in the "report" structure.
*
* The end of previous streams triggers that activation of batch streams in
* the "chaining" model. It triggers the marking of those streams as "available".
*/
void quicperf_activate_next_group( const quicperf_stream_desc_t* stream_desc, quicperf_stream_report_t* report)
{
    /* Compute the next group time. */
    report->next_group_id++;
    if (stream_desc->group_size < 1 || stream_desc->group_size * report->next_group_id >= stream_desc->nb_frames) {
        report->is_activated = 0;
    }
    if (stream_desc->frequency > 0) {
        report->next_group_start_time += (stream_desc->group_size * 1000000) / stream_desc->frequency;
    }
}

int quicperf_client_timer(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, uint64_t current_time)
{
    int ret = 0;

    ctx->next_group_start_time = UINT64_MAX;
    ctx->is_activated = 0;

    for (uint64_t i = 0; ret == 0 && i < ctx->nb_scenarios; i++) {
        const quicperf_stream_desc_t* stream_desc = &ctx->scenarios[i];
        if (stream_desc->media_type == quicperf_media_stream) {
            quicperf_stream_report_t* report = &ctx->reports[i];
            while (report->is_activated && current_time >= report->next_group_start_time) {
                if (stream_desc->media_type == quicperf_media_stream && stream_desc->group_size > 1 &&
                    stream_desc->group_size * report->next_group_id < stream_desc->nb_frames) {
                }
                for (uint64_t rep_number = 0; ret == 0 && rep_number < stream_desc->repeat_count; rep_number++) {
                    /* Need to start the next group */
                    quicperf_stream_ctx_t* stream_ctx = quicperf_request_media_stream_from_scenario(cnx, ctx, stream_desc, rep_number, report->next_group_id, report->next_group_start_time);
                    if (stream_ctx == 0) {
                        ret = -1;
                    }
                    else {
                        stream_ctx->stream_desc_index = i;
                        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
                        ctx->nb_open_streams++;
                    }
                }
                if (ret == 0) {
                    /* Compute the next group time and activate if needed */
                    quicperf_activate_next_group(stream_desc, report);
                }
            }
            if (report->is_activated && report->next_group_start_time < ctx->next_group_start_time) {
                ctx->next_group_start_time = report->next_group_start_time;
            }
            ctx->is_activated |= report->is_activated;
        }
    }

    if (ret == 0 && ctx->next_group_start_time != UINT64_MAX) {
        picoquic_set_app_wake_time(cnx, ctx->next_group_start_time);
    }

    return ret;
}

/* Upon stream completion, start the batch streams that have a dependency,
* and activate the media streams.
 */


int quicperf_init_streams_after_completion(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx,
    size_t stream_desc_index, uint64_t rep_number, uint64_t group_id)
{
    int ret = 0;
    const quicperf_stream_desc_t* stream_desc = &ctx->scenarios[stream_desc_index];
    /* Check whether this is the last group id */

    if (stream_desc->media_type == quicperf_media_stream && stream_desc->group_size > 1 &&
        stream_desc->group_size * (group_id + 1) < stream_desc->nb_frames) {
        /* Do nothing. The next group will be started in quicperf_client_timer */
    }
    else if (rep_number + 1 >= stream_desc->repeat_count &&
        stream_desc->id[0] != 0) {
        /* if this is a named stream, after the end of the last repeat, start the follow-up scenarios */
        ret = quicperf_init_streams_from_scenario(cnx, ctx, stream_desc->id);
    }
    return ret;
}

void quicperf_terminate_and_delete_stream(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    ctx->nb_open_streams--;
    if (ctx->is_client) {
        ret = quicperf_init_streams_after_completion(cnx, ctx, (size_t)stream_ctx->stream_desc_index, stream_ctx->rep_number, stream_ctx->group_id);
    }
    if (ret == 0) {
        picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 0, NULL);
        quicperf_delete_stream_node(ctx, stream_ctx);
    }
    if (ctx->is_client && ctx->nb_open_streams == 0 && !ctx->is_activated) {
        ret = picoquic_close(cnx, QUICPERF_NO_ERROR);
    }
}

int quicperf_receive_batch_data(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    size_t length, picoquic_call_back_event_t fin_or_event)
{
    int ret = 0;

    stream_ctx->nb_response_bytes += length;
    ctx->data_received += length;

    if (stream_ctx->stop_for_fin) {
        if (stream_ctx->nb_response_bytes >= stream_ctx->response_size) {
            if (!stream_ctx->is_stopped) {
                /* ask to send sending. This will stop all data notifications for the stream. */
                ret = picoquic_stop_sending(cnx, stream_ctx->stream_id, 0);
                stream_ctx->is_stopped = 1;
                stream_ctx->is_closed = 1;
            }
        }
        else if (fin_or_event == picoquic_callback_stream_fin) {
            /* closed too soon! */
            ret = picoquic_close(cnx, QUICPERF_ERROR_NOT_ENOUGH_DATA_SENT);
        }
    }
    else if (fin_or_event == picoquic_callback_stream_fin) {
        stream_ctx->is_closed = 1;
        if (stream_ctx->nb_response_bytes != stream_ctx->response_size) {
            /* Error, server did not send the expected number of bytes */
            ret = picoquic_close(cnx, QUICPERF_ERROR_NOT_ENOUGH_DATA_SENT);
        }
        else {
            picoquic_reset_stream_ctx(cnx,stream_ctx->stream_id);
        }
    }
    else if (stream_ctx->nb_response_bytes > stream_ctx->response_size) {
        /* error, too many bytes */
        ret = picoquic_close(cnx, QUICPERF_ERROR_TOO_MUCH_DATA_SENT);
    }
    return ret;
}

void quicperf_receive_media_data(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event)
{
    size_t byte_index = 0;
    uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));

    while (byte_index < length) {
        /* Consume the stream until the start of the next frame */
        size_t expected_bytes = (size_t)((stream_ctx->nb_frames_received == 0) ? stream_ctx->first_frame_size : stream_ctx->frame_size);

        if (stream_ctx->frames_bytes_received < 8) {
            stream_ctx->frame_start_stamp = (stream_ctx->frame_start_stamp << 8) + bytes[byte_index++];
            stream_ctx->frames_bytes_received++;
        }
        else {
            if (stream_ctx->frames_bytes_received < expected_bytes) {
                size_t available = expected_bytes - (size_t)stream_ctx->frames_bytes_received;
                if (available > length - byte_index) {
                    available = length - byte_index;
                }
                stream_ctx->frames_bytes_received += available;
                byte_index += available;
            }
        }
        if (stream_ctx->frames_bytes_received >= expected_bytes) {
            /* Write media report on reporting file */
            if (ctx->is_client) {
                quicperf_stream_report_t* report = &ctx->reports[stream_ctx->stream_desc_index];
                uint64_t expected_time = stream_ctx->start_time;
                uint64_t rtt ;

                if (stream_ctx->nb_frames_received > 0 && stream_ctx->frequency > 0) {
                    expected_time += (stream_ctx->nb_frames_received * 1000000) / stream_ctx->frequency;
                }
                report->nb_frames_received += 1;
                if (current_time <= expected_time) {
                    rtt = 0;
                }
                else {
                    rtt = current_time - expected_time;
                }
                report->sum_delays += rtt;
                if (report->min_delays == 0 || rtt < report->min_delays) {
                    report->min_delays = rtt;
                }
                if (rtt > report->max_delays) {
                    report->max_delays = rtt;
                }

                if (ctx->report_file != NULL) {
                    if (ctx->scenarios[stream_ctx->stream_desc_index].id[0] != 0) {
                        fprintf(ctx->report_file, "%s,", ctx->scenarios[stream_ctx->stream_desc_index].id);
                    }
                    else {
                        fprintf(ctx->report_file, "#%" PRIu64 ", ", stream_ctx->stream_desc_index);
                    }
                    fprintf(ctx->report_file, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",\n",
                        stream_ctx->rep_number, stream_ctx->group_id, stream_ctx->nb_frames_received,
                        stream_ctx->frame_start_stamp, current_time);
                }
            }

            stream_ctx->nb_frames_received++;
            stream_ctx->frames_bytes_received = 0;
            stream_ctx->frame_start_stamp = 0;

            if (stream_ctx->nb_frames_received >= stream_ctx->nb_frames) {
                stream_ctx->is_closed = 1;
            }
            else if (stream_ctx->stream_desc_index < ctx->nb_scenarios &&
                stream_ctx->reset_delay > 0 &&
                stream_ctx->frequency > 0) {
                stream_ctx->reset_time = stream_ctx->start_time + stream_ctx->reset_delay +
                    (stream_ctx->nb_frames_received * 1000000) / stream_ctx->frequency;
                if (current_time > stream_ctx->reset_time && fin_or_event != picoquic_callback_stream_fin) {
                    if (!stream_ctx->is_stopped) {
                        picoquic_stop_sending(cnx, stream_ctx->stream_id, QUICPERF_ERROR_DELAY_TOO_HIGH);
                    }
                    stream_ctx->is_stopped = 1;
                }
            }
        }
    }

    if (fin_or_event == picoquic_callback_stream_fin) {
        stream_ctx->is_closed = 1;
    }
}

int quicperf_receive_data_from_client(picoquic_cnx_t* cnx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event)
{
    /* TODO: something for client initiated stream. */
    int ret = 0;
    size_t byte_index = quicperf_parse_request_header(cnx, stream_ctx, bytes, length);
    stream_ctx->nb_post_bytes += (length - byte_index);

    if (fin_or_event == picoquic_callback_stream_fin) {
        if (stream_ctx->nb_post_bytes < 8 || (stream_ctx->is_media && stream_ctx->nb_post_bytes < 16)) {
            stream_ctx->response_size = 0;
            stream_ctx->is_media = 0;
            stream_ctx->is_datagram = 0;
        }
        else if (stream_ctx->is_datagram) {
            uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
            ret = quicperf_send_datagrams(cnx, current_time, stream_ctx);
            picoquic_set_app_wake_time(cnx, current_time);
        }
        else {
            ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
    }
    return ret;
}

int quicperf_process_stream_data(picoquic_cnx_t * cnx, quicperf_ctx_t * ctx, quicperf_stream_ctx_t* stream_ctx,
    uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event)
{
    int ret = 0;

    /* Data arrival on stream #x, maybe with fin mark */

    if (stream_ctx == NULL && !ctx->is_client) {
        stream_ctx = quicperf_find_stream_ctx(ctx, stream_id);
        if (stream_ctx == NULL) {
            /* If this is the first appearance of a stream on the server side, create it */
            stream_ctx = quicperf_create_stream_ctx(ctx, stream_id);
        }
    }

    if (stream_ctx == NULL) {
        if (!ctx->is_client) {
            /* Hard error! */
            ret = -1;
        }
    }
    else if (ctx->is_client) {
        if (!stream_ctx->is_closed) {
            if (stream_ctx->is_media) {
                if (stream_ctx->is_datagram && length > 0) {
                    /* TODO: Yell. This should not happen */
                }
                else {
                    quicperf_receive_media_data(cnx, ctx, stream_ctx, bytes, length, fin_or_event);
                }
            }
            else {
                ret = quicperf_receive_batch_data(cnx, ctx, stream_ctx, length, fin_or_event);
            }

            if (stream_ctx->is_closed || fin_or_event == picoquic_callback_stream_fin) {
                ctx->nb_streams++;
            }

            if (stream_ctx->is_closed) {
                quicperf_terminate_and_delete_stream(cnx, ctx, stream_ctx);
            }
        }
        else {
            /* Should never happen */
            ret = picoquic_close(cnx, QUICPERF_ERROR_TOO_MUCH_DATA_SENT);
        }
    }
    else if (!stream_ctx->is_closed) {
        ret = quicperf_receive_data_from_client(cnx, stream_ctx, bytes, length, fin_or_event);
    }
    else {
        /* Should never happen */
        ret = picoquic_close(cnx, QUICPERF_ERROR_TOO_MUCH_DATA_SENT);
    }
    return ret;
}

int quicperf_prepare_to_send_batch(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* context, size_t length)
{

    int ret = 0;
    uint64_t send_limit = (ctx->is_client) ? stream_ctx->post_size : stream_ctx->response_size;
    uint64_t sent_already = (ctx->is_client) ? stream_ctx->nb_post_bytes : stream_ctx->nb_response_bytes;
    size_t available = length;
    int is_fin = 0;
    uint8_t* buffer;

    /* To Do: for the server side, manage a succession of frames. If "finished to send",
    * set a wakeup time for the stream, and then for the connection.
     */

    if (!ctx->is_client && stream_ctx->is_stopped) {
        available = 0;
        is_fin = 1;
    } else if (sent_already + available > send_limit) {
        is_fin = 1;
        available = (size_t)(send_limit - sent_already);
    }
    if (ctx->is_client) {
        ctx->data_sent += available;
    }
    buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
    if (buffer != NULL) {
        while (ctx->is_client && stream_ctx->nb_post_bytes < 8 && available > 0) {
            *buffer++ = stream_ctx->length_header[stream_ctx->nb_post_bytes++];
            available--;
        }
        memset(buffer, 0x30, available);
        if (ctx->is_client) {
            stream_ctx->nb_post_bytes += available;
        }
        else {
            stream_ctx->nb_response_bytes += available;
        }

        if (is_fin && !ctx->is_client) {
            quicperf_delete_stream_node(ctx, stream_ctx);
        }
    } else if (available > 0) {
        ret = picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
    }

    return ret;
}

size_t quicperf_prepare_time_stamp(quicperf_stream_ctx_t* stream_ctx, uint8_t * buffer, size_t available)
{
    size_t byte_index = 0;
    if (stream_ctx->frame_bytes_sent < 8) {
        uint8_t time_stamp[8];
        (void)picoquic_frames_uint64_encode(buffer, buffer + 8, stream_ctx->frame_start_stamp);

        while (stream_ctx->frame_bytes_sent < 8 && byte_index < available) {
            buffer[byte_index] = time_stamp[stream_ctx->frame_bytes_sent];
            stream_ctx->frame_bytes_sent++;
            byte_index++;
        }
    }
    return byte_index;
}

int quicperf_prepare_to_send_media(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* context, size_t length)
{

    int ret = 0;
    uint64_t send_limit = (stream_ctx->nb_frames_sent > 0) ? stream_ctx->frame_size : stream_ctx->first_frame_size;
    size_t available = length;
    int is_fin = 0;
    uint8_t* buffer;

    stream_ctx->is_activated = 1; /* default value, may be overwritten next. */

    if (available + stream_ctx->frame_bytes_sent >= send_limit) {
        /* These will be the last bytes in this frame. */
        available = (size_t)(send_limit - stream_ctx->frame_bytes_sent);
        stream_ctx->nb_frames_sent++;

        if (stream_ctx->nb_frames_sent >= stream_ctx->nb_frames) {
            is_fin = 1;
            stream_ctx->is_activated = 0;
        }
        else {
            uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
            if (stream_ctx->frequency > 0) {
                stream_ctx->next_frame_time = stream_ctx->start_time + (stream_ctx->nb_frames_sent * 1000000) / stream_ctx->frequency;
            }
            if (current_time < stream_ctx->next_frame_time){
                stream_ctx->is_activated = 0;
                if (ctx->stream_wakeup_time == 0 || ctx->stream_wakeup_time > stream_ctx->next_frame_time) {
                    ctx->stream_wakeup_time = stream_ctx->next_frame_time;
                    picoquic_set_app_wake_time(cnx, ctx->stream_wakeup_time);
                    stream_ctx->is_activated = 0;
                }
            }
        }
    }

    buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, stream_ctx->is_activated);
    if (buffer != NULL) {
        size_t byte_index = 0;
        if (stream_ctx->frame_bytes_sent < 8) {
            uint8_t time_stamp[8];
            (void)picoquic_frames_uint64_encode(time_stamp, time_stamp + 8, stream_ctx->frame_start_stamp);

            while (stream_ctx->frame_bytes_sent < 8 && byte_index < available) {
                buffer[byte_index] = time_stamp[stream_ctx->frame_bytes_sent];
                stream_ctx->frame_bytes_sent++;
                byte_index++;
            }
        }
        if (byte_index < available) {
            memset(buffer + byte_index, 0x30, available - byte_index);
        }
        stream_ctx->frame_bytes_sent += available - byte_index;

        if (stream_ctx->frame_bytes_sent >= send_limit) {
            /* prepare for the next frame. */
            stream_ctx->frame_bytes_sent = 0;
        }

        if (is_fin) {
            quicperf_delete_stream_node(ctx, stream_ctx);
        }
    }
    else if (available > 0) {
        ret = picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
    }

    return ret;
}


int quicperf_prepare_media_request(picoquic_cnx_t* cnx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* context, size_t length)
{

    int ret = 0;
    size_t send_limit = 16;
    size_t available = length;
    int is_fin = 0;
    uint8_t* buffer;

    if (available + stream_ctx->frame_bytes_sent >= send_limit) {
        /* These will be the last bytes in this frame. */
        available = send_limit - (size_t)stream_ctx->frame_bytes_sent;
        stream_ctx->nb_frames_sent++;
        is_fin = 1;
    }

    buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
    if (buffer != NULL) {
        (void) quicperf_prepare_media_request_bytes(stream_ctx, buffer, available);
    }
    else if (available > 0) {
        ret = picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
    }

    return ret;
}

int quicperf_prepare_to_send(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* context, size_t length)
{
    int ret = 0;

    if (!stream_ctx->is_media) {
        ret = quicperf_prepare_to_send_batch(cnx, ctx, stream_ctx, context, length);
    }
    else if (ctx->is_client) {
        ret = quicperf_prepare_media_request(cnx, stream_ctx, context, length);
    }
    else if (!stream_ctx->is_datagram) {
        ret = quicperf_prepare_to_send_media(cnx, ctx, stream_ctx, context, length);
    }

    return ret;
}

/* On timer, mark active all the streams that
* need a time wakeup. Or, reset the stream timer to what is required.
* This is only needed for the "sleeping" streams, and maybe also for the datagram
* function.
*/
int quicperf_server_timer(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, uint64_t current_time)
{
    /* Naive implementation first. we may need to optimize that later. */
    int ret = 0;
    picosplay_node_t* to_delete = NULL;

    if (current_time >= ctx->stream_wakeup_time) {
        uint64_t next_wakeup_time = UINT64_MAX;
        picosplay_node_t* stream_node = picosplay_first(&ctx->quicperf_stream_tree);
        while (ret == 0 && stream_node != NULL) {
            quicperf_stream_ctx_t* stream_ctx = (quicperf_stream_ctx_t*)quicperf_stream_ctx_value(stream_node);

            if (stream_ctx->is_closed) {
                /* remove the stream context! */
                to_delete = stream_node;
            }
            else if (!stream_ctx->is_activated) {
                if (stream_ctx->is_datagram) {
                    while (stream_ctx->next_frame_time <= current_time && stream_ctx->nb_frames_sent < stream_ctx->nb_frames) {
                        ret = quicperf_send_datagrams(cnx, current_time, stream_ctx);
                    }
                    if (stream_ctx->nb_frames_sent >= stream_ctx->nb_frames && current_time >= stream_ctx->next_frame_time) {
                        /* Closing the stream context will trigger a cloture. */
                        picoquic_add_to_stream(cnx, stream_ctx->stream_id, NULL, 0, 1);
                    }
                    else if (stream_ctx->next_frame_time < next_wakeup_time) {
                        next_wakeup_time = stream_ctx->next_frame_time;
                    }
                }
                else {
                    if (stream_ctx->next_frame_time <= current_time) {
                        /* Activate the stream */
                        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
                        stream_ctx->is_activated = 1;
                    }
                    if (stream_ctx->next_frame_time < next_wakeup_time) {
                        next_wakeup_time = stream_ctx->next_frame_time;
                    }
                }
            }
            ctx->stream_wakeup_time = next_wakeup_time;
            stream_node = picosplay_next(stream_node);
        }
    }

    if (to_delete != NULL) {
        picosplay_delete(&ctx->quicperf_stream_tree, to_delete);
    }

    if (ret == 0) {
        picoquic_set_app_wake_time(cnx, ctx->stream_wakeup_time);
    }

    return ret;
}

int quicperf_timer(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, uint64_t current_time)
{
    int ret = 0;

    if (!ctx->is_client) {
        ret = quicperf_server_timer(cnx, ctx, current_time);
    }
    else {
        ret = quicperf_client_timer(cnx, ctx, current_time);
    }

    return ret;
}

int quicperf_reset_stream(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    if (stream_ctx == NULL) {
        /* Already closed, nothing to do */
    }
    else {
        /* Close the stream context, remove its association with the stream id, do not send any more */
        stream_ctx->is_closed = 1;
        quicperf_terminate_and_delete_stream(cnx, ctx, stream_ctx);
    }
    return ret;
}

int quicperf_stop_sending_stream(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx)
{
    if (stream_ctx != NULL) {
        stream_ctx->is_closed = 1;
        picoquic_reset_stream(cnx, stream_ctx->stream_id, QUICPERF_ERROR_STOPPED_BY_PEER);
        quicperf_terminate_and_delete_stream(cnx, ctx, stream_ctx);
    }
    return 0;
}

int quicperf_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    quicperf_ctx_t* ctx = (quicperf_ctx_t*)callback_ctx;
    quicperf_stream_ctx_t* stream_ctx = (quicperf_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        /* This will happen at the first call to  server */
        ctx = quicperf_create_ctx(NULL);
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, quicperf_callback, ctx);
        }
    }

    ctx->last_interaction_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
    ctx->progress_observed = 1;

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        ret = quicperf_process_stream_data(cnx, ctx, stream_ctx, stream_id, bytes, length, fin_or_event);
        break;
    case picoquic_callback_prepare_to_send:
        if (stream_ctx == NULL) {
            /* Unexpected */
            ret = -1;
        }
        else {
            ret = quicperf_prepare_to_send(cnx, ctx, stream_ctx, bytes, length);
        }
        break;
    case picoquic_callback_datagram:
        quicperf_receive_datagram(cnx, ctx, bytes, length);
        break;
    case picoquic_callback_prepare_datagram:
        /* ret = quicperf_prepare_datagram(cnx, ctx, bytes, length); */
        break;
    case picoquic_callback_stream_reset: /* Server reset stream #x */
        if (stream_ctx == NULL) {
            stream_ctx = quicperf_find_stream_ctx(ctx, stream_id);
        }
        ret = quicperf_reset_stream(cnx, ctx, stream_ctx);
        break;
    case picoquic_callback_stop_sending:
        if (stream_ctx == NULL) {
            stream_ctx = quicperf_find_stream_ctx(ctx, stream_id);
        }
        if (stream_ctx != NULL) {
            if (ctx->is_client) {
                /* Unexpected. Treat as protocol error */
                ret = -1;
            }
            else {
                ret = quicperf_stop_sending_stream(cnx, ctx, stream_ctx);
            }
        }
        break;
    case picoquic_callback_stateless_reset: /* Connection is unknown at peer */
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        if (!ctx->is_client) {
            quicperf_delete_ctx(ctx);
        }
        picoquic_set_callback(cnx, NULL, NULL);
        break;
    case picoquic_callback_version_negotiation: /* Not something we would want... */
        break;
    case picoquic_callback_stream_gap:
        /* TODO: Define what error. Stop sending? */
        break;
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        picoquic_cnx_set_pmtud_required(cnx, 1);
        if (ctx->is_client && ctx->quicperf_stream_tree.root == NULL) {
            ret = quicperf_init_streams_from_scenario(cnx, ctx, "");
            if (ret != 0 || ctx->nb_open_streams == 0) {
                picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
            }
        }
        break;
    case picoquic_callback_request_alpn_list:
        break;
    case picoquic_callback_set_alpn:
        break;
    case picoquic_callback_app_wakeup:
        /* Current time is passed in stream ID field! */
        ret = quicperf_timer(cnx, ctx, stream_id);
        break;
    default:
        /* unexpected */
        break;
    }

    /* that's it */
    return ret;
}

int quicperf_print_report(FILE* F, quicperf_ctx_t* quicperf_ctx)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < quicperf_ctx->nb_scenarios; i++) {
        quicperf_stream_report_t* report = &quicperf_ctx->reports[i];
        quicperf_stream_desc_t* desc = &quicperf_ctx->scenarios[i];
        uint64_t total_frames = desc->nb_frames * desc->repeat_count;
        char num_id[32];
        const char* id = NULL;

        if (desc->media_type == quicperf_media_batch) {
            continue;
        }
        
        if (desc->id[0] != 0) {
            id = desc->id;
        }
        else {
            size_t nb_chars = 0;
            (void)picoquic_sprintf(num_id, sizeof(num_id), &nb_chars, "#%zu", i);
            num_id[31] = 0;
            id = num_id;
        }
        ret |= fprintf(F, "Quicperf scenario %s: received %" PRIu64 "/ %" PRIu64 " frames",
            id, report->nb_frames_received, total_frames) <= 0;
        if (ret == 0 && report->nb_frames_received > 0) {
            uint64_t average_delay = report->sum_delays / report->nb_frames_received;
            ret |= fprintf(F, ", delay min/average/max = %" PRIu64 "/ %" PRIu64 "/ %" PRIu64,
                report->min_delays, average_delay, report->max_delays) <= 0;
        }
        if (ret == 0) {
            ret |= fprintf(F, ".\n");
        }
    }

    return ret;
}