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

/* Common code used by the server and the client implementations.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picotls.h>
#include "picosplay.h"
#include "picoquic.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"



 /* Stream context splay management */

static int64_t picohttp_stream_node_compare(void *l, void *r)
{
	/* Stream values are from 0 to 2^62-1, which means we are not worried with rollover */
	return ((h3zero_stream_ctx_t*)l)->stream_id - ((h3zero_stream_ctx_t*)r)->stream_id;
}

static picosplay_node_t * picohttp_stream_node_create(void * value)
{
	return &((h3zero_stream_ctx_t *)value)->http_stream_node;
}

void * picohttp_stream_node_value(picosplay_node_t * node)
{
	return (void*)((char*)node - offsetof(struct st_h3zero_stream_ctx_t, http_stream_node));
}

static void picohttp_clear_stream_ctx(h3zero_stream_ctx_t* stream_ctx)
{
	if (stream_ctx->file_path != NULL) {
		free(stream_ctx->file_path);
		stream_ctx->file_path = NULL;
	}
	if (stream_ctx->F != NULL) {
		stream_ctx->F = picoquic_file_close(stream_ctx->F);
	}

	if (stream_ctx->path_callback != NULL) {
		(void)stream_ctx->path_callback(stream_ctx->cnx, NULL, 0, picohttp_callback_free, stream_ctx, stream_ctx->path_callback_ctx);
	}

	if (stream_ctx->is_h3) {
		h3zero_delete_data_stream_state(&stream_ctx->ps.stream_state);
	}
	else {
		if (stream_ctx->ps.hq.path != NULL) {
			free(stream_ctx->ps.hq.path);
		}
	}
}

static void picohttp_stream_node_delete(void * tree, picosplay_node_t * node)
{
	h3zero_stream_ctx_t * stream_ctx = picohttp_stream_node_value(node);
	picohttp_clear_stream_ctx(stream_ctx);

	free(stream_ctx);
}

void h3zero_delete_stream(picoquic_cnx_t * cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx)
{
	if (cnx != NULL) {
		picoquic_unlink_app_stream_ctx(cnx, stream_ctx->stream_id);
	}
	picosplay_delete(&ctx->h3_stream_tree, &stream_ctx->http_stream_node);
}

h3zero_stream_ctx_t* h3zero_find_stream(h3zero_callback_ctx_t* ctx, uint64_t stream_id)
{
	h3zero_stream_ctx_t * ret = NULL;
	h3zero_stream_ctx_t target;
	target.stream_id = stream_id;
	picosplay_node_t * node = picosplay_find(&ctx->h3_stream_tree, (void*)&target);

	if (node != NULL) {
		ret = (h3zero_stream_ctx_t *)picohttp_stream_node_value(node);
	}

	return ret;
}

h3zero_stream_ctx_t * h3zero_find_or_create_stream(
	picoquic_cnx_t* cnx,
	uint64_t stream_id,
	h3zero_callback_ctx_t* ctx,
	int should_create,
	int is_h3)
{
	h3zero_stream_ctx_t * stream_ctx = h3zero_find_stream(ctx, stream_id);

	/* if stream is already present, check its state. New bytes? */

	if (stream_ctx == NULL && should_create) {
		stream_ctx = (h3zero_stream_ctx_t*)
			malloc(sizeof(h3zero_stream_ctx_t));
		if (stream_ctx == NULL) {
			/* Could not handle this stream */
			picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
		}
		else {
			memset(stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
			stream_ctx->stream_id = stream_id;
			stream_ctx->is_h3 = is_h3;
			stream_ctx->cnx = cnx;
			if (is_h3) {
				stream_ctx->ps.stream_state.h3_ctx = ctx;
				stream_ctx->ps.stream_state.stream_type = UINT64_MAX;
				stream_ctx->ps.stream_state.control_stream_id = UINT64_MAX;
				if (!IS_BIDIR_STREAM_ID(stream_id)) {
					if (IS_LOCAL_STREAM_ID(stream_id, picoquic_is_client(cnx))) {
						stream_ctx->ps.stream_state.is_fin_received = 1;
					}
					else {
						stream_ctx->ps.stream_state.is_fin_sent = 1;
					}
				}
			}
			picosplay_insert(&ctx->h3_stream_tree, stream_ctx);
		}
	}

	return stream_ctx;
}

void h3zero_init_stream_tree(picosplay_tree_t * h3_stream_tree)
{
	picosplay_init_tree(h3_stream_tree, picohttp_stream_node_compare, picohttp_stream_node_create, picohttp_stream_node_delete, picohttp_stream_node_value);
}


/* Declare a stream prefix, such as used by webtransport or masque
 */

h3zero_stream_prefix_t* h3zero_find_stream_prefix(h3zero_callback_ctx_t* ctx, uint64_t prefix)
{
	h3zero_stream_prefix_t* prefix_ctx = ctx->stream_prefixes.first;

	while (prefix_ctx != NULL) {
		if (prefix_ctx->prefix == prefix) {
			break;
		}
		prefix_ctx = prefix_ctx->next;
	}

	return prefix_ctx;
}

int h3zero_declare_stream_prefix(h3zero_callback_ctx_t* ctx, uint64_t prefix, picohttp_post_data_cb_fn function_call, void* function_ctx)
{
	int ret = 0;
	h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(ctx, prefix);

	if (prefix_ctx == NULL) {
		prefix_ctx = (h3zero_stream_prefix_t*)malloc(sizeof(h3zero_stream_prefix_t));
		if (prefix_ctx == NULL) {
			ret = -1;
		}
		else {
			memset(prefix_ctx, 0, sizeof(h3zero_stream_prefix_t));
			prefix_ctx->prefix = prefix;
			prefix_ctx->function_call = function_call;
			prefix_ctx->function_ctx = function_ctx;
			if (ctx->stream_prefixes.last == NULL) {
				ctx->stream_prefixes.first = prefix_ctx;
			}
			else {
				ctx->stream_prefixes.last->next = prefix_ctx;
			}
			prefix_ctx->previous = ctx->stream_prefixes.last;
			ctx->stream_prefixes.last = prefix_ctx;
		}
	}
	else {
		ret = -1;
	}
	return ret;
}

void h3zero_delete_stream_prefix(picoquic_cnx_t * cnx, h3zero_callback_ctx_t* ctx, uint64_t prefix)
{
	h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(ctx, prefix);
	if (prefix_ctx != NULL) {
		if (prefix_ctx->previous == NULL) {
			ctx->stream_prefixes.first = prefix_ctx->next;
		}
		else {
			prefix_ctx->previous->next = prefix_ctx->next;
		}
		if (prefix_ctx->next == NULL) {
			ctx->stream_prefixes.last = prefix_ctx->previous;
		}
		else {
			prefix_ctx->next->previous = prefix_ctx->previous;
		}
		/* find stream context */
		if (prefix_ctx->function_call != NULL) {
			/* Find the control stream context */
			h3zero_stream_ctx_t* stream_ctx = NULL;
		    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
			if (h3_ctx != NULL) {
				stream_ctx = h3zero_find_stream(h3_ctx, prefix_ctx->prefix);
			}
			if (stream_ctx != NULL) {
				prefix_ctx->function_call(cnx, NULL, 0, picohttp_callback_deregister, stream_ctx, prefix_ctx->function_ctx);
			}
		}
		free(prefix_ctx);
	}
	else {
		if (cnx != NULL) {
			picoquic_log_app_message(cnx, "Cannot find stream prefix %" PRIu64 " in table", prefix);
		}
	}
}

void h3zero_delete_all_stream_prefixes(picoquic_cnx_t * cnx, h3zero_callback_ctx_t* ctx)
{
	h3zero_stream_prefix_t* next;

	while ((next = ctx->stream_prefixes.first) != NULL) {
		if (ctx->stream_prefixes.first == next){
			/* the prefix was not deleted as part of app cleanup */
			h3zero_delete_stream_prefix(cnx, ctx, next->prefix);
		}
	}
}

uint64_t h3zero_parse_stream_prefix(uint8_t* buffer_8, size_t* nb_in_buffer, uint8_t* data, size_t data_length, size_t * nb_read)
{
	uint64_t prefix = UINT64_MAX;

	*nb_read = 0;
	while (*nb_read < data_length) {
		size_t v_len = (*nb_in_buffer > 0)?VARINT_LEN_T(buffer_8, size_t):8;
		if (*nb_in_buffer < v_len) {
			buffer_8[*nb_in_buffer] = data[*nb_read];
			*nb_read += 1;
			*nb_in_buffer += 1;
		}
		if (*nb_in_buffer >= v_len) {
			(void)picoquic_frames_uint64_decode(buffer_8, buffer_8 + 8, &prefix);
			break;
		}
	}

	return prefix;
}

int h3zero_protocol_init(picoquic_cnx_t* cnx)
{
	uint8_t decoder_stream_head = (uint8_t)h3zero_stream_type_qpack_decoder;
	uint8_t encoder_stream_head = (uint8_t)h3zero_stream_type_qpack_encoder;
	uint64_t settings_stream_id = picoquic_get_next_local_stream_id(cnx, 1);
	/* Some of the setting values depend on the presence of connection parameters */
	uint8_t settings_buffer[256];
	uint8_t* settings_last = 0;
	h3zero_settings_t settings = { 0 };
	int ret = 0;

	settings.enable_connect_protocol = 1;

	/* Web transport is only enabled if h3 datagrams are supported.
	 */
	if (cnx->local_parameters.max_datagram_frame_size > 0) {
		settings.h3_datagram = 1;
		settings.webtransport_max_sessions = 1;
	}

	settings_buffer[0] = (uint8_t)h3zero_stream_type_control;
	if ((settings_last = h3zero_settings_encode(settings_buffer + 1, settings_buffer + sizeof(settings_buffer), &settings)) == NULL) {
		ret = H3ZERO_INTERNAL_ERROR;
	}
	else {
		ret = picoquic_add_to_stream(cnx, settings_stream_id, settings_buffer, settings_last - settings_buffer, 0);
	}

	if (ret == 0) {
		/* set the settings stream the first stream to write! */
		ret = picoquic_set_stream_priority(cnx, settings_stream_id, 0);
	}

	if (ret == 0) {
		uint64_t encoder_stream_id = picoquic_get_next_local_stream_id(cnx, 1);
		/* set the encoder stream, although we do not actually create dynamic codes. */
		ret = picoquic_add_to_stream(cnx, encoder_stream_id, &encoder_stream_head, 1, 0);
		if (ret == 0) {
			ret = picoquic_set_stream_priority(cnx, encoder_stream_id, 1);
		}
	}

	if (ret == 0) {
		uint64_t decoder_stream_id = picoquic_get_next_local_stream_id(cnx, 1);
		/* set the the decoder stream, although we do not actually create dynamic codes. */
		ret = picoquic_add_to_stream(cnx, decoder_stream_id, &decoder_stream_head, 1, 0);
		if (ret == 0) {
			ret = picoquic_set_stream_priority(cnx, decoder_stream_id, 1);
		}
	}
	return ret;
}

uint8_t* h3zero_load_frame_content(uint8_t* bytes, uint8_t* bytes_max,
	h3zero_data_stream_state_t* stream_state, uint64_t* error_found)
{
	size_t available = bytes_max - bytes;

	if (stream_state->current_frame_length > 0x10000) {
		/* error, excessive load */
		*error_found = H3ZERO_INTERNAL_ERROR;
		return NULL;
	}
	else if (stream_state->current_frame == NULL) {
		stream_state->current_frame = (uint8_t*)malloc((size_t)stream_state->current_frame_length);
	}

	if (stream_state->current_frame == NULL) {
		/* error, internal error */
		*error_found = H3ZERO_INTERNAL_ERROR;
		return NULL;
	}
	if (stream_state->current_frame_read + available > stream_state->current_frame_length) {
		available = (size_t)(stream_state->current_frame_length - stream_state->current_frame_read);
	}
	memcpy(stream_state->current_frame + stream_state->current_frame_read, bytes, available);
	stream_state->current_frame_read += available;
	bytes += available;

	return bytes;
}

uint8_t* h3zero_skip_frame_content(uint8_t* bytes, uint8_t* bytes_max,
	h3zero_data_stream_state_t* stream_state, uint64_t* error_found)
{
	size_t available = bytes_max - bytes;

	if (stream_state->current_frame_read + available > stream_state->current_frame_length) {
		available = (size_t)(stream_state->current_frame_length - stream_state->current_frame_read);
	}
	stream_state->current_frame_read += available;
	bytes += available;

	return bytes;
}

/* Parsing a control stream.
* 
* This requires:
*     - read the frame type (bit "is_frame_type_read")
*     - read the frame length (bit "is_frame_length_known")
*     - check the the frame type is authorized for the stream.
*     - if recognized and processed, load the frame content,
*       then run the specific parser, which performs the specific
*       actions for the frame.
*     - else, just skip the content.
* 
* The settings frame must be the first on the control stream (property of H3 connection)
* There should be just one setting frames.
* 
* Ending the control stream closes the connection.
*/

static void h3zero_reset_control_stream_state(h3zero_data_stream_state_t* stream_state)
{
	stream_state->current_frame_type = UINT64_MAX;
	stream_state->current_frame_length = UINT64_MAX;
	stream_state->current_frame_read = 0;
	if (stream_state->current_frame != NULL) {
		free(stream_state->current_frame);
		stream_state->current_frame = NULL;
	}
}

static uint8_t* h3zero_parse_control_stream(uint8_t* bytes, uint8_t* bytes_max,
	h3zero_data_stream_state_t* stream_state, h3zero_callback_ctx_t* ctx, uint64_t* error_found)
{
	while (bytes != NULL && bytes < bytes_max) {
		/* If frame type not known yet, get it. */
		if (stream_state->current_frame_type == UINT64_MAX) {
			bytes = h3zero_varint_from_stream(bytes, bytes_max, &stream_state->current_frame_type, stream_state->frame_header, &stream_state->frame_header_read);
			if (stream_state->current_frame_type == UINT64_MAX) {
				/* frame type was not updated */
				continue;
			}
			else {
				if (ctx->settings.settings_received && stream_state->current_frame_type == h3zero_frame_settings) {
					*error_found = H3ZERO_FRAME_UNEXPECTED;
					bytes = NULL;
					continue;
				}
				else if (!ctx->settings.settings_received && stream_state->current_frame_type != h3zero_frame_settings) {
					*error_found = H3ZERO_MISSING_SETTINGS;
					bytes = NULL;
					continue;
				}
				/* Check that the type is acceptable, plus mark whether skipped or processed */
				else if (stream_state->current_frame_type == h3zero_frame_data ||
					stream_state->current_frame_type == h3zero_frame_header ||
					stream_state->current_frame_type == h3zero_frame_push_promise ||
					stream_state->current_frame_type == h3zero_frame_webtransport_stream) {
					*error_found = H3ZERO_INTERNAL_ERROR;
					bytes = NULL;
					continue;
				}
				else if (stream_state->current_frame_type != h3zero_frame_settings) {
					stream_state->is_current_frame_ignored = 1;
				}
			}
		}
		/* If frame length not known yet, get it. */
		if (stream_state->current_frame_length == UINT64_MAX) {
			bytes = h3zero_varint_from_stream(bytes, bytes_max, &stream_state->current_frame_length, stream_state->frame_header, &stream_state->frame_header_read);
			if (stream_state->current_frame_length == UINT64_MAX) {
				/* frame length was not updated */
				return bytes;
			}
		}
		if (stream_state->current_frame_length != UINT64_MAX) {
			/* Load the frame. May need to allocate memory. */
			if (stream_state->current_frame_read < stream_state->current_frame_length) {
				/* Process or skip the frame */
				if (stream_state->is_current_frame_ignored) {
					bytes = h3zero_skip_frame_content(bytes, bytes_max, stream_state, error_found);
				}
				else {
					bytes = h3zero_load_frame_content(bytes, bytes_max, stream_state, error_found);
				}
			}
			/* Process the frame if needed, or free it */
			if (stream_state->current_frame_read >= stream_state->current_frame_length) {
				if (stream_state->current_frame_type == h3zero_frame_settings) {
					/* TODO: actually parse the settings */
					const uint8_t* decoded_last = h3zero_settings_components_decode(stream_state->current_frame,
						stream_state->current_frame + stream_state->current_frame_length, &ctx->settings);
					if (decoded_last == NULL) {
						*error_found = H3ZERO_SETTINGS_ERROR;
						bytes = NULL;
					}
					else {
						ctx->settings.settings_received = 1;
					}
				}
				h3zero_reset_control_stream_state(stream_state);
			}
		}
	}
	return bytes;
}

uint8_t* h3zero_parse_control_stream_id(
	uint8_t* bytes, uint8_t* bytes_max,
	h3zero_data_stream_state_t* stream_state,
	h3zero_stream_ctx_t* stream_ctx,
	h3zero_callback_ctx_t* ctx)
{
	if (stream_state->control_stream_id == UINT64_MAX) {
		bytes = h3zero_varint_from_stream(bytes, bytes_max, &stream_state->control_stream_id, stream_state->frame_header, &stream_state->frame_header_read);
		if (stream_state->control_stream_id == UINT64_MAX) {
			/* Control stream ID not updated */
			return bytes;
		}
		/* Just found the control stream ID */
		h3zero_stream_prefix_t* stream_prefix;
		stream_prefix = h3zero_find_stream_prefix(ctx, stream_state->control_stream_id);
		if (stream_prefix == NULL) {
			bytes = NULL;
		}
		else {
			stream_ctx->path_callback = stream_prefix->function_call;
			stream_ctx->path_callback_ctx = stream_prefix->function_ctx;
		}
	}
	else {
		/* header was fully parsed. act as passthrough */
	}
	return bytes;
}

/* The only support for remote bidir stream is for
 * web transport. We expect the stream to start by a seb transport header:
 *  - type h3zero_frame_webtransport_stream
 *  - value control stream id.
 */
uint8_t* h3zero_parse_remote_bidir_stream(
	uint8_t* bytes, uint8_t* bytes_max,
	h3zero_stream_ctx_t* stream_ctx,
	h3zero_callback_ctx_t* ctx,
	uint64_t * error_found)
{
	h3zero_data_stream_state_t* stream_state = &stream_ctx->ps.stream_state;

	if (stream_state->stream_type == UINT64_MAX) {
		bytes = h3zero_varint_from_stream(bytes, bytes_max, &stream_state->stream_type, stream_state->frame_header, &stream_state->frame_header_read);
		if (stream_state->current_frame_type == UINT64_MAX) {
			/* frame type was not updated */
			return bytes;
		}
	}
	if (stream_state->stream_type == h3zero_frame_webtransport_stream) {
		bytes = h3zero_parse_control_stream_id(bytes, bytes_max, stream_state, stream_ctx, ctx);
	}
	else {
		/* Not and expected stream */
		bytes = NULL;
	}
	return bytes;
}

uint8_t* h3zero_parse_remote_unidir_stream(
	uint8_t* bytes, uint8_t* bytes_max,
	h3zero_stream_ctx_t* stream_ctx,
	h3zero_callback_ctx_t* ctx,
	uint64_t * error_found)
{
	h3zero_data_stream_state_t* stream_state = &stream_ctx->ps.stream_state;

	if (stream_state->stream_type == UINT64_MAX) {
		bytes = h3zero_varint_from_stream(bytes, bytes_max, &stream_state->stream_type, stream_state->frame_header, &stream_state->frame_header_read);
		if (stream_state->stream_type == UINT64_MAX) {
			/* stream type was not updated */
			return bytes;
		}
		if (stream_state->stream_type == h3zero_stream_type_control) {
			/* TODO: verify that there is just one control stream. */
			h3zero_reset_control_stream_state(stream_state);
		}
	}
	switch (stream_state->stream_type) {
	case h3zero_stream_type_control: /* used to send/receive setting frame and other control frames. */
		bytes = h3zero_parse_control_stream(bytes, bytes_max, stream_state, ctx, error_found);
		break;
	case h3zero_stream_type_push: /* Push type not supported in current implementation */
		bytes = bytes_max;
		break;
	case h3zero_stream_type_qpack_encoder: /* not required since not using dynamic table */
		bytes = bytes_max;
		break;
	case h3zero_stream_type_qpack_decoder: /* not required since not using dynamic table */
		bytes = bytes_max;
		break;
	case h3zero_stream_type_webtransport: /* unidir stream is used as specified in web transport */
		bytes = h3zero_parse_control_stream_id(bytes, bytes_max, stream_state, stream_ctx, ctx);
		break;
	default:
		/* Per section 6.2 of RFC 9114, unknown stream types are just ignored */
		bytes = bytes_max;
		break;
	}
	return bytes;
}

/* Parse the first bytes of a bidir or unidir stream, and determine what to do with that stream.
*/
uint8_t* h3zero_parse_incoming_remote_stream(
	uint8_t* bytes, uint8_t* bytes_max,
	h3zero_stream_ctx_t* stream_ctx,
	h3zero_callback_ctx_t* ctx)
{
	uint64_t error_found = 0;

	if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id)) {
		bytes = h3zero_parse_remote_bidir_stream(bytes, bytes_max, stream_ctx, ctx, &error_found);
	}
	else {
		bytes = h3zero_parse_remote_unidir_stream(bytes, bytes_max, stream_ctx, ctx, &error_found);
	}
	return bytes;
}

/* Parsing of a data stream. This is implemented as a filter, with a set of states:
* 
* - Reading frame length: obtaining the length and type of the next frame.
* - Reading header frame: obtaining the bytes of the header frame.
*   When all bytes are obtained, the header is parsed and the header
*   structure is documented. State moves back to initial, with header-read
*   flag set. Having two frame headers before a data frame is a bug.
* - Reading unknown frame: unknown frames can happen at any point in
*   the stream, and should just be ignored.
* - Reading data frame: the frame header indicated a data frame of
*   length N. Treat the following N bytes as data.
*/

uint8_t * h3zero_parse_data_stream(uint8_t * bytes, uint8_t * bytes_max,
	h3zero_data_stream_state_t * stream_state, size_t * available_data, uint64_t * error_found)
{
	*available_data = 0;
	*error_found = 0;

	if (bytes == NULL || bytes >= bytes_max) {
		*error_found = H3ZERO_INTERNAL_ERROR;
		return NULL;
	}

	if (!stream_state->frame_header_parsed) {
		size_t frame_type_length;
		size_t frame_header_length;

		if (stream_state->frame_header_read < 1) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}
		frame_type_length = h3zero_varint_skip(stream_state->frame_header);

		while (stream_state->frame_header_read < frame_type_length && bytes < bytes_max) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}

		if (stream_state->frame_header_read < frame_type_length) {
			/* No change in state, wait for more bytes */
			return bytes;
		}

		(void)h3zero_varint_decode(stream_state->frame_header, frame_type_length,
			&stream_state->current_frame_type);

		while (stream_state->frame_header_read < frame_type_length + 1 && bytes < bytes_max) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}

		frame_header_length = h3zero_varint_skip(stream_state->frame_header + frame_type_length) + frame_type_length;

		if (frame_header_length > sizeof(stream_state->frame_header)) {
			*error_found = H3ZERO_INTERNAL_ERROR;
			return NULL; /* This should never happen! */
		}

		while (stream_state->frame_header_read < frame_header_length && bytes < bytes_max) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}

		if (stream_state->frame_header_read >= frame_header_length) {
			(void)h3zero_varint_decode(stream_state->frame_header + frame_type_length, frame_header_length - frame_type_length,
				&stream_state->current_frame_length);
			stream_state->current_frame_read = 0;
			stream_state->frame_header_parsed = 1;

			if (stream_state->current_frame_type == h3zero_frame_data) {
				if (!stream_state->header_found || stream_state->trailer_found || stream_state->is_web_transport) {
					/* protocol error */
					*error_found = H3ZERO_FRAME_UNEXPECTED;
					bytes = NULL;
				}
			}
			else if (stream_state->current_frame_type == h3zero_frame_header) {
				if (stream_state->header_found && (!stream_state->data_found || stream_state->trailer_found || stream_state->is_web_transport)) {
					/* protocol error */
					*error_found = H3ZERO_FRAME_UNEXPECTED;
					bytes = NULL;
				}
				else if (stream_state->current_frame_length > 0x10000) {
					/* error, excessive load */
					*error_found = H3ZERO_INTERNAL_ERROR;
					bytes = NULL;
				}
			}
			else if (stream_state->current_frame_type == h3zero_frame_webtransport_stream) {
				if (stream_state->header_found) {
					/* protocol error */
					*error_found = H3ZERO_FRAME_UNEXPECTED;
					bytes = NULL;
				}
				else {
					stream_state->header_found = 1;
					stream_state->is_web_transport = 1;
					stream_state->control_stream_id = stream_state->current_frame_length;
					stream_state->current_frame_length = 0;
					stream_state->frame_header_parsed = 1;
				}
			}
			else if (stream_state->current_frame_type == h3zero_frame_cancel_push || 
				stream_state->current_frame_type == h3zero_frame_goaway ||
				stream_state->current_frame_type == h3zero_frame_max_push_id) {
				*error_found = H3ZERO_GENERAL_PROTOCOL_ERROR;
				bytes = NULL;
			}
			else if (stream_state->current_frame_type == h3zero_frame_settings) {
				*error_found = H3ZERO_FRAME_UNEXPECTED;
				bytes = NULL;
			}
		}
		return bytes;
	}
	else {
		size_t available = bytes_max - bytes;
		if (stream_state->is_web_transport) {
			/* Bypass all processing if using web transport */
			*available_data = (size_t) available;
		}
		else {
			if (stream_state->current_frame_read + available > stream_state->current_frame_length) {
				available = (size_t)(stream_state->current_frame_length - stream_state->current_frame_read);
			}

			if (stream_state->current_frame_type == h3zero_frame_header) {
			    if (stream_state->current_frame == NULL) {
					if (stream_state->current_frame_length <= 0x10000) {
						stream_state->current_frame = (uint8_t*)malloc((size_t)stream_state->current_frame_length);
					}
					if (stream_state->current_frame == NULL) {
						*error_found = H3ZERO_INTERNAL_ERROR;
						bytes = NULL;
					}
				}
				if (bytes != NULL) {
					memcpy(stream_state->current_frame + stream_state->current_frame_read, bytes, available);
					stream_state->current_frame_read += available;
					bytes += available;

					if (stream_state->current_frame_read >= stream_state->current_frame_length) {
						uint8_t* parsed;
						h3zero_header_parts_t* parts = (stream_state->header_found) ?
							&stream_state->trailer : &stream_state->header;
						stream_state->trailer_found = stream_state->header_found;
						stream_state->header_found = 1;
						/* parse */
						parsed = h3zero_parse_qpack_header_frame(stream_state->current_frame,
							stream_state->current_frame + stream_state->current_frame_length, parts);
						if (parsed == NULL || (size_t)(parsed - stream_state->current_frame) != stream_state->current_frame_length) {
							/* protocol error */
							*error_found = H3ZERO_FRAME_ERROR;
							bytes = NULL;
						}
						/* free resource */
						stream_state->frame_header_parsed = 0;
						stream_state->frame_header_read = 0;
						free(stream_state->current_frame);
						stream_state->current_frame = NULL;
					}
				}
			}
			else if (stream_state->current_frame_type == h3zero_frame_data) {
				*available_data = (size_t)available;
				stream_state->current_frame_read += available;
				if (stream_state->current_frame_read >= stream_state->current_frame_length) {
					stream_state->frame_header_parsed = 0;
					stream_state->frame_header_read = 0;
					stream_state->data_found = 1;
				}
			}
			else {
				/* Unknown frame type, should just be ignored */
				stream_state->current_frame_read += available;
				bytes += available;
				if (stream_state->current_frame_read >= stream_state->current_frame_length) {
					stream_state->frame_header_parsed = 0;
					stream_state->frame_header_read = 0;
				}
			}
		}
	}

	return bytes;
}

/*
* HTTP 3.0 common call back.
*/

/*
* Create and delete server side connection context
*/

h3zero_callback_ctx_t* h3zero_callback_create_context(picohttp_server_parameters_t* param)
{
	h3zero_callback_ctx_t* ctx = (h3zero_callback_ctx_t*)
		malloc(sizeof(h3zero_callback_ctx_t));

	if (ctx != NULL) {
		memset(ctx, 0, sizeof(h3zero_callback_ctx_t));

		h3zero_init_stream_tree(&ctx->h3_stream_tree);

		if (param != NULL) {
			ctx->path_table = param->path_table;
			ctx->path_table_nb = param->path_table_nb;
			ctx->web_folder = param->web_folder;
		}
	}

	return ctx;
}

void h3zero_callback_delete_context(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx)
{
	h3zero_delete_all_stream_prefixes(cnx, ctx);
	picosplay_empty_tree(&ctx->h3_stream_tree);
	free(ctx);
}

/* The picoquic callback bundles DATA and FIN. 
* We maintain this bundling, so the application has complete control on
* the stream context.
*/
int h3zero_post_data_or_fin(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event,
	h3zero_stream_ctx_t* stream_ctx)
{
	int ret = 0;

	if (stream_ctx != NULL && stream_ctx->path_callback != NULL) {
		ret = stream_ctx->path_callback(cnx, bytes, length, (fin_or_event == picoquic_callback_stream_fin) ?
			picohttp_callback_post_fin : picohttp_callback_post_data, stream_ctx, stream_ctx->path_callback_ctx);
	}

	return ret;
}

/* There are some streams, like unidir or server initiated bidir, that
* require extra processing, such as tying to web transport
* application.
*/

int h3zero_process_remote_stream(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event,
	h3zero_stream_ctx_t* stream_ctx,
	h3zero_callback_ctx_t* ctx)
{
	int ret = 0;
	uint64_t error_found = 0;

	if (stream_ctx == NULL) {
		ret = -1;
	}
	else {
		uint8_t* bytes_max = bytes + length;

		if (IS_BIDIR_STREAM_ID(stream_id)) {
			bytes = h3zero_parse_remote_bidir_stream(bytes, bytes_max, stream_ctx, ctx, &error_found);
		}
		else {
			bytes = h3zero_parse_remote_unidir_stream(bytes, bytes_max, stream_ctx, ctx, &error_found);
		}

		if (bytes == NULL) {
			picoquic_log_app_message(cnx, "Cannot parse incoming stream: %" PRIu64", error: %" PRIu64,
				stream_id, error_found);
			ret = picoquic_stop_sending(cnx, stream_id, error_found);
		}
		else if (bytes < bytes_max || fin_or_event == picoquic_callback_stream_fin) {
			ret = h3zero_post_data_or_fin(cnx, bytes, bytes_max - bytes, fin_or_event, stream_ctx);
		}
	}
	return ret;
}

/* Forget stream: terminate the stream if necessary, 
 * remove its references, and dispose of the context.
 */
void h3zero_forget_stream(picoquic_cnx_t* cnx,
	h3zero_stream_ctx_t* stream_ctx)
{
	if (stream_ctx != NULL){
		if (!stream_ctx->ps.stream_state.is_fin_sent) {
			stream_ctx->ps.stream_state.is_fin_sent = 1;
			picoquic_reset_stream(cnx, stream_ctx->stream_id, 0);
		}
		picoquic_unlink_app_stream_ctx(cnx, stream_ctx->stream_id);
	}
}

char const * h3zero_server_default_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic HTTP 3 service\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>Simple HTTP 3 Responder</h1>\r\n\
<p>GET / or GET /index.html returns this text</p>\r\n\
<p>Get /NNNNN returns txt document of length NNNNN bytes(decimal)</p>\r\n\
<p>Any other command will result in an error, and an empty response.</p>\r\n\
<h1>Enjoy!</h1>\r\n\
</BODY></HTML>\r\n";

char const * h3zero_server_post_response_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic POST Response\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>POST successful</h1>\r\n\
<p>Received %d bytes.\r\n\
</BODY></HTML>\r\n";

int h3zero_server_parse_path(const uint8_t* path, size_t path_length, uint64_t* echo_size,
	char** file_path, char const* web_folder, int* file_error);

int h3zero_find_path_item(const uint8_t * path, size_t path_length, const picohttp_server_path_item_t * path_table, size_t path_table_nb)
{
	size_t i = 0;

	while (i < path_table_nb) {
		if (path_length >= path_table[i].path_length && memcmp(path, path_table[i].path, path_table[i].path_length) == 0){
			if (path_length == path_table[i].path_length || path[path_table[i].path_length] == (uint8_t)'?')
				return (int)i;
		}
		i++;
	}
	return -1;
}

/* TODO find a better place. */
h3zero_content_type_enum h3zero_get_content_type_by_path(const char *path) {
	if (path != NULL) {
		/* Dots in paths allowed.
		 * https://datatracker.ietf.org/doc/html/rfc1738
		 * path -> segment -> xpalphas -> xalpha -> alpha | digit | safe | extra | escape -> safe = $ | - | _ | @ | . |
		 */

		const char *dot = strrchr(path, '.'); /* recursive to get the last occuraence. */
		/* if dot is found. */
		if(dot && dot != path) {
			const char *ext = dot + 1;

			/*
			* h3zero_content_type_none = 0,
			* h3zero_content_type_not_supported,
			* h3zero_content_type_text_html,
			* h3zero_content_type_text_plain,
			* h3zero_content_type_image_gif,
			* h3zero_content_type_image_jpeg,
			* h3zero_content_type_image_png,
			* h3zero_content_type_dns_message,
			* h3zero_content_type_javascript,
			* h3zero_content_type_json,
			* h3zero_content_type_www_form_urlencoded,
			* h3zero_content_type_text_css
			*/
			if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0) {
				return h3zero_content_type_text_html;
			} else if (strcmp(ext, "gif") == 0) {
				return h3zero_content_type_image_gif;
			} else if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0) {
				return h3zero_content_type_image_jpeg;
			} else if (strcmp(ext, "png") == 0) {
				return h3zero_content_type_image_png;
			} else if (strcmp(ext, "js") == 0) {
				return h3zero_content_type_javascript;
			} else if (strcmp(ext, "json") == 0) {
				return h3zero_content_type_json;
			} else if (strcmp(ext, "css") == 0) {
				return h3zero_content_type_text_css;
			}
		}
	}

	/* PATH == NULL OR dot not found OR unknown extension. */
	return h3zero_content_type_text_plain;
}

/* Processing of the request frame.
* This function is called after the client's stream is closed,
* after verifying that a request was received */

int h3zero_process_request_frame(
	picoquic_cnx_t* cnx,
	h3zero_stream_ctx_t * stream_ctx,
	h3zero_callback_ctx_t * app_ctx)
{
	/* Prepare response header */
	uint8_t buffer[1024];
	uint8_t post_response[512];
	uint8_t * o_bytes = &buffer[0];
	uint8_t * o_bytes_max = o_bytes + sizeof(buffer);
	uint64_t response_length = 0;
	int ret = 0;
	int file_error = 0;

	*o_bytes++ = h3zero_frame_header;
	o_bytes += 2; /* reserve two bytes for frame length */

	if (stream_ctx->ps.stream_state.header.method == h3zero_method_get) {
		/* Manage GET */
		if (h3zero_server_parse_path(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length,
			&stream_ctx->echo_length, &stream_ctx->file_path, app_ctx->web_folder, &file_error) != 0) {
			char log_text[256];
			picoquic_log_app_message(cnx, "Cannot find file for path: <%s> in folder <%s>, error: 0x%x",
				picoquic_uint8_to_str(log_text, 256, stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length),
				(app_ctx->web_folder == NULL) ? "NULL" : app_ctx->web_folder, file_error);
			/* If unknown, 404 */
			o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
			/* TODO: consider known-url?data construct */
		}
		else {
			response_length = (stream_ctx->echo_length == 0) ?
				strlen(h3zero_server_default_page) : stream_ctx->echo_length;
			o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
				(stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
				h3zero_get_content_type_by_path(stream_ctx->file_path));
			/* TODO handle query string
			 * Currently picoquic doesn't support query strings.
			 */
		}
	}
	else if (stream_ctx->ps.stream_state.header.method == h3zero_method_post) {
		/* Manage Post. */
		if (stream_ctx->path_callback == NULL && stream_ctx->post_received == 0) {
			int path_item = h3zero_find_path_item(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, app_ctx->path_table, app_ctx->path_table_nb);
			if (path_item >= 0) {
				/* TODO-POST: move this code to post-fin callback.*/
				stream_ctx->path_callback = app_ctx->path_table[path_item].path_callback;
				stream_ctx->path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post,
					stream_ctx, stream_ctx->path_callback_ctx);
			}
		}

		if (stream_ctx->path_callback != NULL) {
			response_length = stream_ctx->path_callback(cnx, post_response, sizeof(post_response), picohttp_callback_post_fin, stream_ctx, stream_ctx->path_callback_ctx);
		}
		else {
			/* Prepare generic POST response */
			size_t message_length = 0;
			(void)picoquic_sprintf((char*)post_response, sizeof(post_response), &message_length, h3zero_server_post_response_page, (int)stream_ctx->post_received);
			response_length = message_length;
		}

		/* If known, create response header frame */
		/* POST-TODO: provide content type of response as part of context */
		o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
			(stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
			h3zero_content_type_text_plain);
	}
	else if (stream_ctx->ps.stream_state.header.method == h3zero_method_connect) {
		/* The connect handling depends on the requested protocol */

		if (stream_ctx->path_callback == NULL) {
			int path_item = h3zero_find_path_item(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, app_ctx->path_table, app_ctx->path_table_nb);
			if (path_item >= 0) {
				stream_ctx->path_callback = app_ctx->path_table[path_item].path_callback;
				if (stream_ctx->path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_connect,
					stream_ctx, app_ctx->path_table[path_item].path_app_ctx) != 0) {
					/* This callback is not supported */
					picoquic_log_app_message(cnx, "Unsupported callback on stream: %"PRIu64 ", path:%s", stream_ctx->stream_id, app_ctx->path_table[path_item].path);
					o_bytes = h3zero_create_error_frame(o_bytes, o_bytes_max, "501", H3ZERO_USER_AGENT_STRING);
				}
				else {
					/* Create a connect accept frame */
					picoquic_log_app_message(cnx, "Connect accepted on stream: %"PRIu64 ", path:%s", stream_ctx->stream_id, app_ctx->path_table[path_item].path);
					o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max, h3zero_content_type_none);
					stream_ctx->is_upgraded = 1;
				}
			}
			else {
				/* No such connect path */
				char log_text[256];
				picoquic_log_app_message(cnx, "cannot find path context on stream: %"PRIu64 ", path:%s", stream_ctx->stream_id,
					picoquic_uint8_to_str(log_text, 256, stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length));
				o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
			}
		}
		else {
			/* Duplicate request? Bytes after connect? Should they just be sent to the app? */
			picoquic_log_app_message(cnx, "Duplicate request on stream: %"PRIu64, stream_ctx->stream_id);
			ret = -1;
		}
	}
	else
	{
		/* unsupported method */
		picoquic_log_app_message(cnx, "Unsupported method on stream: %"PRIu64, stream_ctx->stream_id);
		o_bytes = h3zero_create_error_frame(o_bytes, o_bytes_max, "501", H3ZERO_USER_AGENT_STRING);
	}

	if (o_bytes == NULL) {
		picoquic_log_app_message(cnx, "Error, resetting stream: %"PRIu64, stream_ctx->stream_id);
		ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
	}
	else {
		size_t header_length = o_bytes - &buffer[3];
		int is_fin_stream = (stream_ctx->echo_length == 0) ? (1 - stream_ctx->is_upgraded) : 0;
		buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
		buffer[2] = (uint8_t)(header_length & 0xFF);

		if (response_length > 0) {
			size_t ld = 0;

			if (o_bytes + 2 < o_bytes_max) {
				*o_bytes++ = h3zero_frame_data;
				ld = picoquic_varint_encode(o_bytes, o_bytes_max - o_bytes, response_length);
			}

			if (ld == 0) {
				o_bytes = NULL;
			}
			else {
				o_bytes += ld; 

				if (stream_ctx->echo_length == 0) {
					if (response_length <= sizeof(post_response)) {
						if (o_bytes + (size_t)response_length <= o_bytes_max) {
							memcpy(o_bytes, (stream_ctx->ps.stream_state.header.method == h3zero_method_post) ? post_response : (uint8_t*)h3zero_server_default_page, (size_t)response_length);
							o_bytes += (size_t)response_length;
						}
						else {
							o_bytes = NULL;
						}
					}
					else {
						/* Large post responses are not concatenated here, but will be pulled from the data */
						is_fin_stream = 0;
					}
				}
			}
		}

		if (o_bytes != NULL) {
			if (is_fin_stream && stream_ctx->ps.stream_state.header.method == h3zero_method_connect) {
				picoquic_log_app_message(cnx, "Setting FIN in connect response on stream: %"PRIu64, stream_ctx->stream_id);
			}
			ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id,
				buffer, o_bytes - buffer, is_fin_stream, stream_ctx);
			if (ret != 0) {
				o_bytes = NULL;
			}
		}

		if (o_bytes == NULL) {
			ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
		}
		else if (stream_ctx->echo_length != 0 || response_length > sizeof(post_response)) {
			ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
		}
	}

	return ret;
}

int h3zero_client_open_stream_file(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx)
{
	int ret = 0;

	if (!stream_ctx->is_file_open && ctx->no_disk == 0) {
		int last_err = 0;
		stream_ctx->F = picoquic_file_open_ex(stream_ctx->f_name, "wb", &last_err);
		if (stream_ctx->F == NULL) {
			picoquic_log_app_message(cnx,
				"Could not open file <%s> for stream %" PRIu64 ", error %d (0x%x)\n", stream_ctx->f_name, stream_ctx->stream_id, last_err, last_err);
			DBG_PRINTF("Could not open file <%s> for stream %" PRIu64 ", error %d (0x%x)", stream_ctx->f_name, stream_ctx->stream_id, last_err, last_err);
			ret = -1;
		}
		else {
			stream_ctx->is_file_open = 1;
			ctx->nb_open_files++;
		}
	}

	return ret;
}


int h3zero_client_close_stream(picoquic_cnx_t * cnx,
	h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx)
{
	int ret = 0;
	if (stream_ctx != NULL && stream_ctx->is_open) {
		picoquic_unlink_app_stream_ctx(cnx, stream_ctx->stream_id);
		if (stream_ctx->f_name != NULL) {
			free(stream_ctx->f_name);
			stream_ctx->f_name = NULL;
		}
		stream_ctx->F = picoquic_file_close(stream_ctx->F);
		if (stream_ctx->is_file_open) {
			ctx->nb_open_files--;
			stream_ctx->is_file_open = 0;
		}
		stream_ctx->is_open = 0;
		ctx->nb_open_streams--; 
		ret = 1;
	}
	return ret;
}

int h3zero_process_h3_server_data(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, h3zero_callback_ctx_t* ctx,
	h3zero_stream_ctx_t* stream_ctx, uint64_t* fin_stream_id)
{
	int ret = 0;
	int process_complete = 0;
	size_t available_data = 0;
	uint64_t error_found = 0;
	uint8_t* bytes_max = bytes + length;

	while (bytes < bytes_max) {
		bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->ps.stream_state, &available_data, &error_found);
		if (bytes == NULL) {
			ret = picoquic_close(cnx, error_found);
			break;
		}
		else if (available_data > 0) {
			if (stream_ctx->ps.stream_state.is_web_transport) {
				if (stream_ctx->path_callback == NULL) {
					h3zero_stream_prefix_t* stream_prefix;
					stream_prefix = h3zero_find_stream_prefix(ctx, stream_ctx->ps.stream_state.control_stream_id);
					if (stream_prefix == NULL) {
						ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_WEBTRANSPORT_BUFFERED_STREAM_REJECTED);
					}
					else {
						stream_ctx->path_callback = stream_prefix->function_call;
						stream_ctx->path_callback_ctx = stream_prefix->function_ctx;
						(void)picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
					}
				}
			}
			else if (stream_ctx->ps.stream_state.header_found && stream_ctx->post_received == 0) {
				int path_item = h3zero_find_path_item(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, ctx->path_table, ctx->path_table_nb);
				if (path_item >= 0) {
					stream_ctx->path_callback = ctx->path_table[path_item].path_callback;
					stream_ctx->path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post,
						stream_ctx, ctx->path_table[path_item].path_app_ctx);
				}
				(void)picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
			}

			/* Received data for a POST or CONNECT command. */
			if (stream_ctx->path_callback != NULL) {
				/* if known URL, pass the data to URL specific callback.
				* Little oddity there. For the 'connect" method, we need to pass the data and the FIN mark.
				* For the "post" method, the "fin" call is supposed to come from within the
				* `h3zero_process_request_frame` call, and return the size of the post response.
				*
				* The web transport callbacks may result in the stream context being deleted. That
				* means we really should not reuse the pointer "stream_ctx" after that. But the "post"
				* usage relies on the stack maintaining a "post_received" variable, so we need
				* to handle that. The "process complete" flag is used to bypass the processing of
				* the FIN bit in the following code block, because the FIN bit is already handled in this call.
				*/
				int is_post = stream_ctx->ps.stream_state.header.method == h3zero_method_post;

				ret = stream_ctx->path_callback(cnx, bytes, available_data,
					(fin_or_event == picoquic_callback_stream_fin && !is_post) ?
					picohttp_callback_post_fin : picohttp_callback_post_data, stream_ctx, stream_ctx->path_callback_ctx);
				if (is_post) {
					stream_ctx->post_received += available_data;
				}
				else {
					process_complete = 1;
				}
			}
			else {
				stream_ctx->post_received += available_data;
			}
			bytes += available_data;
		}
	}
	/* Process the header if necessary */
	if (ret == 0 && !process_complete) {
		if (stream_ctx->ps.stream_state.is_web_transport) {
			if (fin_or_event == picoquic_callback_stream_fin && available_data == 0 && stream_ctx->path_callback != NULL) {
				ret = stream_ctx->path_callback(cnx, NULL, 0, picohttp_callback_post_fin, stream_ctx, stream_ctx->path_callback_ctx);
			}
		}
		else {
			if (fin_or_event == picoquic_callback_stream_fin || stream_ctx->ps.stream_state.header.method == h3zero_method_connect) {
				/* Process the request header. */
				if (stream_ctx->ps.stream_state.header_found) {
					ret = h3zero_process_request_frame(cnx, stream_ctx, ctx);
				}
				else {
					/* Unexpected end of stream before the header is received */
					ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_FRAME_ERROR);
				}
			}
		}
	}
	return ret;
}

int h3zero_process_h3_client_data(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, h3zero_callback_ctx_t* ctx,
	h3zero_stream_ctx_t* stream_ctx, uint64_t* fin_stream_id)
{
	int ret = 0;
	if (!stream_ctx->is_file_open && ctx->no_disk == 0 && stream_ctx->file_path != NULL) {
		ret = h3zero_client_open_stream_file(cnx, ctx, stream_ctx);
	}
	if (ret == 0 && length > 0) {
		uint64_t error_found = 0;
		size_t available_data = 0;
		uint8_t* bytes_max = bytes + length;
		int header_required = !stream_ctx->ps.stream_state.header_found;
		while (bytes < bytes_max) {
			bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->ps.stream_state, &available_data, &error_found);
			if (bytes == NULL) {
				ret = picoquic_close(cnx, error_found);
				if (ret != 0) {
					picoquic_log_app_message(cnx,
						"Could not parse incoming data from stream %" PRIu64 ", error 0x%x", stream_id, error_found);
				}
				break;
			}
			else {
				if (header_required && stream_ctx->ps.stream_state.header_found && picoquic_is_client(cnx)) {
					int is_success = (stream_ctx->ps.stream_state.header.status >= 200 &&
						stream_ctx->ps.stream_state.header.status < 300);
					if (stream_ctx->ps.stream_state.is_upgrade_requested) {
						stream_ctx->is_upgraded = is_success;
					}
					if (stream_ctx->path_callback != NULL) {
						stream_ctx->path_callback(cnx, NULL, 0, (is_success) ?
							picohttp_callback_connect_accepted : picohttp_callback_connect_refused,
							stream_ctx, stream_ctx->path_callback_ctx);
					}
				}
				if (available_data > 0) {
					if (!stream_ctx->flow_opened) {
						if (stream_ctx->ps.stream_state.current_frame_length < 0x100000) {
							stream_ctx->flow_opened = 1;
						}
						else if (cnx->cnx_state == picoquic_state_ready) {
							stream_ctx->flow_opened = 1;
							ret = picoquic_open_flow_control(cnx, stream_id, stream_ctx->ps.stream_state.current_frame_length);
						}
					}
					if (ret == 0 && ctx->no_disk == 0) {
						ret = (fwrite(bytes, 1, available_data, stream_ctx->F) > 0) ? 0 : -1;
						if (ret != 0) {
							picoquic_log_app_message(cnx,
								"Could not write data from stream %" PRIu64 ", error 0x%x", stream_id, ret);
						}
					}
					stream_ctx->received_length += available_data;
					bytes += available_data;
				}
			}
		}
	}

	if (fin_or_event == picoquic_callback_stream_fin) {
		if (stream_ctx->path_callback != NULL) {
			stream_ctx->path_callback(cnx, NULL, 0, picohttp_callback_post_fin, stream_ctx, stream_ctx->path_callback_ctx);
		}
		else {
			if (h3zero_client_close_stream(cnx, ctx, stream_ctx)) {
				*fin_stream_id = stream_id;
				if (stream_id <= 64 && !ctx->no_print) {
					fprintf(stdout, "Stream %" PRIu64 " ended after %" PRIu64 " bytes\n",
						stream_id, stream_ctx->received_length);
				}
				if (stream_ctx->received_length == 0) {
					picoquic_log_app_message(cnx, "Stream %" PRIu64 " ended after %" PRIu64 " bytes, ret=0x%x",
						stream_id, stream_ctx->received_length, ret);
				}
			}
		}
	}

	return ret;
}

int h3zero_callback_data(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, h3zero_callback_ctx_t* ctx,
	h3zero_stream_ctx_t* stream_ctx, uint64_t* fin_stream_id)
{

	int ret = 0;

	/* Data arrival on stream #x, maybe with fin mark */
	if (stream_ctx == NULL) {
		/* If the stream is not found, we have different treatments based on direction:
		*   - Local stream must always be created locally, thus need to be present before
		*     data arrives.
		*   - For remote streams, we create a context upon arrival.
		*/
		if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
			stream_ctx = h3zero_find_stream(ctx, stream_id);
		}
		else {
			stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 1, 1);
		}
		if (stream_ctx == NULL) {
			if (fin_or_event == picoquic_callback_stream_fin) {
				if (length > 0) {
					DBG_PRINTF("Received %zu bytes & FIN after stream %" PRIu64 " was discarded\n", length, stream_id);
				}
			}
			else {
				ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);

				if (ret == 0 && IS_BIDIR_STREAM_ID(stream_id)) {
					ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
				}
				ret = -1;
			}
		}
		else {
			picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
		}
	}
	if (ret == 0 && stream_ctx != NULL) {
		if (stream_ctx->is_upgraded) {
			ret = h3zero_post_data_or_fin(cnx, bytes, length, fin_or_event, stream_ctx);
		}
		else if (IS_BIDIR_STREAM_ID(stream_id)) {
			if (IS_CLIENT_STREAM_ID(stream_id)) {
				/* If nothing is known about the stream, it is treated by default as an H3 stream
				 */
				if (stream_ctx == NULL) {
					fprintf(stdout, "unexpected data on local stream context: %" PRIu64 ".\n", stream_id);
					ret = -1;
				}
				else if (cnx->client_mode) {
					if (stream_ctx->is_open) {
						/* Process incoming H3 client data */
						ret = h3zero_process_h3_client_data(cnx, stream_id, bytes, length, fin_or_event, ctx,
							stream_ctx, fin_stream_id);
					}
					else {
						/* Perform application callback */
						ret = h3zero_post_data_or_fin(cnx, bytes, length, fin_or_event, stream_ctx);
					}
				}
				else {
					/* Process incoming H3 server data */
					ret = h3zero_process_h3_server_data(cnx, stream_id, bytes, length, fin_or_event, ctx,
						stream_ctx, fin_stream_id);
				}
			}
			else {
				/* Non client streams are only expected if using web transport
				 */
				ret = h3zero_process_remote_stream(cnx, stream_id, bytes, length,
					fin_or_event, stream_ctx, ctx);
			}
		}
		else {
			ret = h3zero_process_remote_stream(cnx, stream_id, bytes, length,
				fin_or_event, stream_ctx, ctx);
		}
	}
	return ret;
}


/* Prepare to send. This is the same code as on the client side, except for the
* delayed opening of the data file */
int h3zero_prepare_to_send_buffer(void* context, size_t space,
	uint64_t echo_length, uint64_t* echo_sent, FILE* F)
{
	int ret = 0;

	if (*echo_sent < echo_length) {
		uint8_t * buffer;
		uint64_t available = echo_length - *echo_sent;
		int is_fin = 1;

		if (available > space) {
			available = space;
			is_fin = 0;
		}

		buffer = picoquic_provide_stream_data_buffer(context, (size_t)available, is_fin, !is_fin);
		if (buffer != NULL) {
			if (F) {
				size_t nb_read = fread(buffer, 1, (size_t)available, F);

				if (nb_read != available) {
					ret = -1;
				}
				else {
					*echo_sent += available;
					ret = 0;
				}
			}
			else {
				/* TODO: fill buffer with some text */
				memset(buffer, 0x5A, (size_t)available);
				*echo_sent += available;
				ret = 0;
			}
		}
		else {
			ret = -1;
		}
	}

	return ret;
}

int h3zero_prepare_to_send(int client_mode, void* context, size_t space,
	h3zero_stream_ctx_t* stream_ctx)
{
	int ret = 0;

	if (!client_mode && stream_ctx->F == NULL && stream_ctx->file_path != NULL) {
		stream_ctx->F = picoquic_file_open(stream_ctx->file_path, "rb");
		if (stream_ctx->F == NULL) {
			ret = -1;
		}
	}

	if (ret == 0) {
		if (client_mode) {
			ret = h3zero_prepare_to_send_buffer(context, space, stream_ctx->post_size, &stream_ctx->post_sent, NULL);
		}
		else {
			ret = h3zero_prepare_to_send_buffer(context, space, stream_ctx->echo_length, &stream_ctx->echo_sent,
				stream_ctx->F);
		}
	}
	return ret;
}

int h3zero_callback_prepare_to_send(picoquic_cnx_t* cnx,
	uint64_t stream_id, h3zero_stream_ctx_t * stream_ctx,
	void * context, size_t space, h3zero_callback_ctx_t* ctx)
{
	int ret = -1;

	if (stream_ctx == NULL) {
		stream_ctx = h3zero_find_stream(ctx, stream_id);
	}

	if (stream_ctx == NULL) {
		ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
	}
	else {
		if (stream_ctx->path_callback != NULL) {
			/* TODO: should we do that in the case of "post" ? */
			/* Get data from callback context of specific URL */
			ret = stream_ctx->path_callback(cnx, context, space, picohttp_callback_provide_data, stream_ctx, stream_ctx->path_callback_ctx);
		}
		else {
			/* default reply for known URL */
			ret = h3zero_prepare_to_send(cnx->client_mode, context, space, stream_ctx);
			/* if finished sending on server, delete stream */
			if (!cnx->client_mode) {
				if (stream_ctx->echo_sent >= stream_ctx->echo_length) {
					h3zero_delete_stream(cnx, ctx, stream_ctx);
				}
			}
		}
	}

	return ret;
}

/* Handling of HTTP3 Datagrams. Per RFC 9297 the Datagram Data field of QUIC DATAGRAM
*  frames uses the following format:
*
*   HTTP/3 Datagram {
*     Quarter Stream ID (i),
*     HTTP Datagram Payload (..),
*   }
*
*  The "quarter stream ID" is a variable-length integer that contains the value
*  of the client-initiated bidirectional stream that this datagram is
*  associated with divided by four. The implementation searchs for the stream-ID
*  in the table of stream prefixes. If it finds a prefix, if tries to execute
*  the corresponding callback. If that callback fail, or if the prefix is not
*  registered, it returns an error.
* 
*  Sending of callback is by polling the prefixes that are marked active for
*  datagrams, in round robin fashion. If the datagram can be sent, the code
*  automatically include the quarter stream ID corresponding to the context.
*/

int h3zero_callback_datagram(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, h3zero_callback_ctx_t* h3_ctx)
{
	int ret = 0;
	uint64_t quarter_stream_id = UINT64_MAX;
	const uint8_t* bytes_max = bytes + length;

	/* Find the control stream identifier */
	bytes = (uint8_t*)picoquic_frames_varint_decode(bytes, bytes_max, &quarter_stream_id);
	if (bytes != NULL) {
		/* find the control stream context, using the full stream ID */
		h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(h3_ctx, quarter_stream_id*4);

		if (prefix_ctx == NULL || prefix_ctx->function_call == NULL) {
			/* Should signal the error HTTP_DATAGRAM_ERROR */
		} else {
			h3zero_stream_ctx_t* stream_ctx = h3zero_find_stream(h3_ctx, prefix_ctx->prefix);
			if (stream_ctx == NULL) {
				/* Application is not yet ready -- just ignore the datagram */
			} else {
				prefix_ctx->function_call(cnx, bytes, bytes_max - bytes, picohttp_callback_post_datagram, stream_ctx, prefix_ctx->function_ctx);
			}
		}
	}
	return ret;
}

/* Arrival of a datagram capsule */
void h3zero_receive_datagram_capsule(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx, h3zero_capsule_t* capsule, h3zero_callback_ctx_t* h3_ctx)
{
	if (stream_ctx == NULL) {
		/* Application is not yet ready -- just ignore the datagram */
	}
	else {
		h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(h3_ctx, stream_ctx->stream_id);
		if ( prefix_ctx == NULL || prefix_ctx->function_call == NULL) {
			/* Should signal the error HTTP_DATAGRAM_ERROR */
		}
		else {
			prefix_ctx->function_call(cnx, capsule->capsule_buffer, capsule->capsule_length, picohttp_callback_post_datagram, stream_ctx, prefix_ctx->function_ctx);
		}
	}
}

typedef struct st_h3zero_prepare_datagram_ctx_t {
	void* picoquic_context;
	size_t picoquic_space;
	uint64_t quarter_stream_id;
	size_t stream_id_encoding_length;
	uint8_t buffer[8];
	size_t application_length;
	int application_ready;
} h3zero_prepare_datagram_ctx_t;

uint8_t* h3zero_provide_datagram_buffer(void* context, size_t length, int ready_to_send)
{
	uint8_t* ret_buffer = NULL;
	h3zero_prepare_datagram_ctx_t* pdg_ctx = (h3zero_prepare_datagram_ctx_t*)context;
	pdg_ctx->application_length = length;
	pdg_ctx->application_ready = ready_to_send;
	if (length > 0) {
		if (length + pdg_ctx->stream_id_encoding_length <= pdg_ctx->picoquic_space) {
			uint8_t* buffer = picoquic_provide_datagram_buffer(pdg_ctx->picoquic_context, length + pdg_ctx->stream_id_encoding_length);
			if (buffer != NULL) {
				ret_buffer = (uint8_t*)picoquic_frames_varint_encode(buffer, buffer + pdg_ctx->stream_id_encoding_length, pdg_ctx->quarter_stream_id);
			}
		}
	}
	return ret_buffer;
}

static int h3zero_callback_prepare_datagram_in_context(picoquic_cnx_t* cnx, void* context, size_t space, h3zero_callback_ctx_t* h3_ctx, h3zero_stream_prefix_t* prefix_ctx)
{
	/* Poll this prefix. Intercept the data writing callback so the quarter stream ID can be inserted.
	 * Remember how many bytes were actually posted. Complete the call to picoquic.
	 * The call to picoquic is: 
	 * buffer = picoquic_provide_datagram_buffer(context, length);
	 */
	int data_sent = 0;
	if (prefix_ctx->ready_to_send_datagrams && prefix_ctx->function_call != NULL) {
		h3zero_prepare_datagram_ctx_t pdg_ctx = { 0 };
		uint8_t* next_byte;
		prefix_ctx->ready_to_send_datagrams = 0;
		pdg_ctx.picoquic_context = context;
		pdg_ctx.picoquic_space = space;
		pdg_ctx.quarter_stream_id = (prefix_ctx->prefix) >> 2;
		if ((next_byte = picoquic_frames_varint_encode(pdg_ctx.buffer, pdg_ctx.buffer + 8, pdg_ctx.quarter_stream_id)) == NULL) {
			/* error !*/
		}
		else {
			h3zero_stream_ctx_t* stream_ctx = h3zero_find_stream(h3_ctx, prefix_ctx->prefix);
			pdg_ctx.stream_id_encoding_length = next_byte - pdg_ctx.buffer;
			if (space > pdg_ctx.stream_id_encoding_length) {
				/* Call the application */
				prefix_ctx->function_call(cnx, (uint8_t *)&pdg_ctx, space - pdg_ctx.stream_id_encoding_length, picohttp_callback_provide_datagram, stream_ctx, prefix_ctx->function_ctx);
				/* the application might have called the mark active API, so we use an OR here */
				prefix_ctx->ready_to_send_datagrams |= pdg_ctx.application_ready;
				if (pdg_ctx.application_length > 0) {
					h3_ctx->last_datagram_prefix = prefix_ctx->prefix;
					data_sent = 1;
				}
			}
		}
	}
	return data_sent;
}

int h3zero_callback_prepare_datagram(picoquic_cnx_t* cnx, void* context, size_t space, h3zero_callback_ctx_t* h3_ctx)
{
	/* First pass will start just after the last datagram prefix polled, then next pass until that prefix  */
	h3zero_stream_prefix_t * previous_prefix_ctx = h3zero_find_stream_prefix(h3_ctx, h3_ctx->last_datagram_prefix);
	h3zero_stream_prefix_t * prefix_ctx = (previous_prefix_ctx == NULL) ? NULL : previous_prefix_ctx->next;
	int data_sent = 0;
	int still_active = 0;
	int all_checked = 0;
	/* checked the prefixes after the last sent one. */
	while (prefix_ctx != NULL) {
		data_sent = h3zero_callback_prepare_datagram_in_context(cnx, context, space, h3_ctx, prefix_ctx);
		still_active |= prefix_ctx->ready_to_send_datagrams;
		if (data_sent) {
			break;
		}
		else {
			prefix_ctx = prefix_ctx->next;
		}
	}
	if (!data_sent) {
		/* The previous loop only checked the prefixes after the last sent one. Now test the other ones. */
		prefix_ctx = h3_ctx->stream_prefixes.first;
		while (prefix_ctx != NULL) {
			data_sent = h3zero_callback_prepare_datagram_in_context(cnx, context, space, h3_ctx, prefix_ctx);
			still_active |= prefix_ctx->ready_to_send_datagrams;
			if (data_sent) {
				break;
			}
			else if (prefix_ctx == previous_prefix_ctx) {
				all_checked = 1;
				break;
			} else {
				prefix_ctx = prefix_ctx->next;
			}
		}
	}
	if (!all_checked) {
		/* The previous loops concluded without checking all prefixes, so recheck */
		prefix_ctx = h3_ctx->stream_prefixes.first;
		while (prefix_ctx != NULL && !still_active) {
			still_active |= prefix_ctx->ready_to_send_datagrams;
			prefix_ctx = prefix_ctx->next;
		}
	}
	picoquic_mark_datagram_ready(cnx, still_active);
	return 0;
}

int h3zero_set_datagram_ready(picoquic_cnx_t* cnx, uint64_t stream_id)
{
	int ret = -1;
	h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);

	if (h3_ctx != NULL) {
		/* Find the control stream. */
		h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(h3_ctx, stream_id);
		if (prefix_ctx != NULL) {
			/* mark this control stream as ready for sending datagrams. */
			prefix_ctx->ready_to_send_datagrams = 1;
			/* declare readiness to picoquic. */
			ret = picoquic_mark_datagram_ready(cnx, 1);
		}
	}

	return ret;
}

/* Picoquic callback for H3 connections.
 */
int h3zero_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	h3zero_callback_ctx_t* ctx = NULL;
	h3zero_stream_ctx_t* stream_ctx = (h3zero_stream_ctx_t*)v_stream_ctx;
	uint64_t fin_stream_id = UINT64_MAX;

	if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(cnx->quic)) {
		ctx = h3zero_callback_create_context((picohttp_server_parameters_t *)callback_ctx);
		if (ctx == NULL) {
			/* cannot handle the connection */
			picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
			return -1;
		}
		else {
			picoquic_set_callback(cnx, h3zero_callback, ctx);
			ret = h3zero_protocol_init(cnx);
		}
	} else{
		ctx = (h3zero_callback_ctx_t*)callback_ctx;
	}

	if (ret == 0) {
		switch (fin_or_event) {
		case picoquic_callback_stream_data:
		case picoquic_callback_stream_fin:
			/* Data arrival on stream #x, maybe with fin mark */
			ret = h3zero_callback_data(cnx, stream_id, bytes, length,
				fin_or_event, ctx, stream_ctx, &fin_stream_id);
			break;
		case picoquic_callback_stream_reset: /* Peer reset stream #x */
		case picoquic_callback_stop_sending: /* Peer asks server to reset stream #x */
											 /* TODO: special case for uni streams. */
			if (stream_ctx == NULL) {
				stream_ctx = h3zero_find_stream(ctx, stream_id);
			}
			if (stream_ctx != NULL) {
				if (stream_ctx->path_callback != NULL) {
					/* reset post callback. */
					ret = stream_ctx->path_callback(cnx, NULL, 0, picohttp_callback_reset, stream_ctx, stream_ctx->path_callback_ctx);
				}
				else {
					/* If a file is open on a client, close and do the accounting. */
					ret = h3zero_client_close_stream(cnx, ctx, stream_ctx);
				}
			}
			if (IS_BIDIR_STREAM_ID(stream_id)) {
				picoquic_reset_stream(cnx, stream_id, 0);
			}
			break;
		case picoquic_callback_stateless_reset:
		case picoquic_callback_close: /* Received connection close */
		case picoquic_callback_application_close: /* Received application close */
			if (cnx->client_mode) {
				if (!ctx->no_print) {
					fprintf(stdout, "Received a %s\n",
						(fin_or_event == picoquic_callback_close) ? "connection close request" : (
							(fin_or_event == picoquic_callback_application_close) ?
							"request to close the application" :
							"stateless reset"));
				}
				ctx->connection_closed = 1;
				break;
			}
			else {
				picoquic_log_app_message(cnx, "Clearing context on connection close (%d)", fin_or_event);
				h3zero_callback_delete_context(cnx, ctx);
				picoquic_set_callback(cnx, NULL, NULL);
			}
			break;
		case picoquic_callback_version_negotiation:
			if (cnx->client_mode && !ctx->no_print) {
				fprintf(stdout, "Received a version negotiation request:");
				for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4) {
					uint32_t vn = PICOPARSE_32(bytes + byte_index);
					fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
				}
				fprintf(stdout, "\n");
			}
			break;
		case picoquic_callback_stream_gap:
			/* Gap indication, when unreliable streams are supported */
			ret = -1;
			break;
		case picoquic_callback_prepare_to_send:
			ret = h3zero_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx);
			break;
		case picoquic_callback_datagram: /* Datagram frame has been received */
			ret = h3zero_callback_datagram(cnx, bytes, length, ctx);
			break;
		case picoquic_callback_prepare_datagram: /* Prepare the next datagram */
			ret = h3zero_callback_prepare_datagram(cnx, bytes, length, ctx);
			break;
		case picoquic_callback_datagram_acked: /* Ack for packet carrying datagram-frame received from peer */
		case picoquic_callback_datagram_lost: /* Packet carrying datagram-frame probably lost */
		case picoquic_callback_datagram_spurious: /* Packet carrying datagram-frame was not really lost */
			/* datagram acknowledgements are not visible for now at the H3 layer, just ignore. */
			break;
		case picoquic_callback_almost_ready:
		case picoquic_callback_ready:
			/* TODO: Check that the transport parameters are what Http3 expects */
			break;
		default:
			/* unexpected -- just ignore. */
			break;
		}
	}

	/* TODO: this is the plug-in for demo scenario manager.
	 * Add code here so scenarios can play out.
	 */

	return ret;
}

/* Parse the settings frame.
 * Since this is done by reading a stream, the parsing state is
 * included in the setting frames, as follow:
 * 
 * - as long as the stream header length is not read, the header size is zero
 * - if the header length is read, the reader accumulates all the required
 *   bytes in a buffer, then does a regular decoding.
 */

uint8_t* h3zero_settings_component_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t setting_key, uint64_t setting_value, const uint64_t default_value)
{
	if (setting_value != default_value) {
		if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, setting_key)) != NULL) {
			bytes = picoquic_frames_varint_encode(bytes, bytes_max, setting_value);
		}
	}
	return bytes;
}

uint8_t* h3zero_settings_encode(uint8_t* bytes, const uint8_t* bytes_max, const h3zero_settings_t* settings)
{
	/* reserve enough bytes for the encoding length */
	size_t length_max = bytes_max - bytes;

	if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, h3zero_frame_settings)) != NULL) {
		uint8_t* bytes_of_length = bytes;
		if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, length_max)) != NULL) {
			/* remember how many bytes were used to encode the length */
			uint8_t* bytes_after_length = bytes;
			/* encode the various components, as needed */
			if ((bytes = h3zero_settings_component_encode(bytes, bytes_max, h3zero_setting_header_table_size, settings->table_size, UINT64_MAX)) != NULL &&
				(bytes = h3zero_settings_component_encode(bytes, bytes_max, h3zero_qpack_blocked_streams, settings->blocked_streams, UINT64_MAX)) != NULL &&
				(bytes = h3zero_settings_component_encode(bytes, bytes_max, h3zero_settings_enable_connect_protocol, settings->enable_connect_protocol, 0)) != NULL &&
				(bytes = h3zero_settings_component_encode(bytes, bytes_max, h3zero_setting_h3_datagram, settings->h3_datagram, 0)) != NULL &&
				(bytes = h3zero_settings_component_encode(bytes, bytes_max, h3zero_settings_webtransport_max_sessions, settings->webtransport_max_sessions, 0)) != NULL) {
				size_t actual_length = bytes - bytes_after_length;
				uint8_t* bytes_final_length = picoquic_frames_varint_encode(bytes_of_length, bytes_after_length, actual_length);
				if (bytes_final_length == NULL) {
					/* Final length is longer than buffer size, which should be impossible */
					bytes = NULL;
				}
				else if (bytes_final_length != bytes_after_length) {
					/* Final length is shorter than predicted length */
					memmove(bytes_final_length, bytes_after_length, actual_length);
					bytes = bytes_final_length + actual_length;
				}
			}
		}
	}
	return bytes;
}

const uint8_t* h3zero_settings_components_decode(const uint8_t* bytes, const uint8_t* bytes_max, h3zero_settings_t* settings)
{
	uint64_t component_key;
	uint64_t component_value;
	while (bytes != NULL &&
		bytes < bytes_max &&
		(bytes = picoquic_frames_varint_decode(bytes, bytes_max, &component_key)) != NULL &&
		(bytes = picoquic_frames_varint_decode(bytes, bytes_max, &component_value)) != NULL) {
		switch (component_key) {
		case h3zero_setting_header_table_size:
			settings->table_size = component_value;
			break;
		case h3zero_qpack_blocked_streams:
			settings->blocked_streams = component_value;
			break;
		case h3zero_settings_enable_connect_protocol:
			settings->enable_connect_protocol = (unsigned int)component_value;
			break;
		case h3zero_setting_h3_datagram:
			settings->h3_datagram = (unsigned int)component_value;
			break;
		case h3zero_settings_webtransport_max_sessions:
			settings->webtransport_max_sessions = component_value;
			break;
		default:
			break;
		}
	}
	return bytes;
}

const uint8_t* h3zero_settings_decode(const uint8_t* bytes, const uint8_t* bytes_max, h3zero_settings_t* settings)
{
	size_t header_length = 0;
	memset(settings, 0, sizeof(h3zero_settings_t));
	if (*bytes != 0x04) {
		/* not a settings frame */
		bytes = NULL;
	} else {
		bytes++;
		/* get the decoding length */
		if ((bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &header_length)) != NULL) {
			const uint8_t* settings_end = bytes + header_length;
			if (settings_end > bytes_max) {
				bytes = NULL;
			}
			else {
				bytes = h3zero_settings_components_decode(bytes, settings_end, settings);
			}
		}
	}
	return bytes;
}


/* TLV buffer accumulator.
* This is commonly used when parsing data streams.
*/

void h3zero_release_capsule(h3zero_capsule_t* capsule)
{
	if (capsule->capsule_buffer != NULL) {
		free(capsule->capsule_buffer);
	}
	memset(capsule, 0, sizeof(h3zero_capsule_t));
}

const uint8_t* h3zero_accumulate_capsule(const uint8_t* bytes, const uint8_t* bytes_max, h3zero_capsule_t* capsule)
{
	if (capsule->is_stored) {
		/* reset the fields to expected value */
		capsule->header_length = 0;
		capsule->header_read = 0;
		capsule->capsule_type = 0;
		capsule->capsule_length = 0;
		capsule->is_stored = 0;
	}
	if (!capsule->is_length_known) {
		size_t length_of_type = 0;
		size_t length_of_length = 0;

		/* Decode T and L from input buffer */
		if (capsule->header_read < 1) {
			capsule->header_buffer[capsule->header_read++] = *bytes++;
		}
		length_of_type = VARINT_LEN_T(capsule->header_buffer, size_t);

		if (length_of_type + 1 > H3ZERO_CAPSULE_HEADER_SIZE_MAX) {
			bytes = NULL;
		}
		else {
			while (capsule->header_read < length_of_type && bytes < bytes_max) {
				capsule->header_buffer[capsule->header_read++] = *bytes++;
			}
			if (capsule->header_read >= length_of_type) {
				(void)picoquic_frames_varint_decode(capsule->header_buffer, capsule->header_buffer + length_of_type,
					&capsule->capsule_type);

				while (capsule->header_read < length_of_type + 1 && bytes < bytes_max) {
					capsule->header_buffer[capsule->header_read++] = *bytes++;
				}

				if (capsule->header_read >= length_of_type + 1) {
					/* No change in state, wait for more bytes */
					length_of_length = VARINT_LEN_T((capsule->header_buffer + length_of_type), size_t);

					capsule->header_length = length_of_type + length_of_length;
					if (capsule->header_length > H3ZERO_CAPSULE_HEADER_SIZE_MAX) {
						bytes = NULL;
					}
					else {
						while (capsule->header_read < capsule->header_length && bytes < bytes_max) {
							capsule->header_buffer[capsule->header_read++] = *bytes++;
						}
						if (capsule->header_read >= capsule->header_length) {
							(void)picoquic_frames_varlen_decode(capsule->header_buffer + length_of_type,
								capsule->header_buffer + length_of_type + length_of_length,
								&capsule->capsule_length);
							capsule->is_length_known = 1;
						}
					}
				}
			}
		}
	}
	if (capsule->is_length_known) {
		if (capsule->capsule_buffer_size < capsule->capsule_length) {
			uint8_t* capsule_buffer = (uint8_t*)malloc(capsule->capsule_length);
			if (capsule_buffer != NULL && capsule->value_read > 0) {
				memcpy(capsule_buffer, capsule->capsule_buffer, capsule->value_read);
			}
			if (capsule->capsule_buffer != NULL) {
				free(capsule->capsule_buffer);
			}
			capsule->capsule_buffer = capsule_buffer;
			capsule->capsule_buffer_size = capsule->capsule_length;
		}
		if (capsule->capsule_buffer == NULL) {
			capsule->value_read = 0;
			capsule->capsule_buffer_size = 0;
			bytes = NULL;
		} else {
			size_t available = bytes_max - bytes;
			if (capsule->value_read + available > capsule->capsule_length) {
				available = capsule->capsule_length - capsule->value_read;
			}
			memcpy(capsule->capsule_buffer + capsule->value_read, bytes, available);
			bytes += available;
			capsule->value_read += available;
			if (capsule->value_read >= capsule->capsule_length) {
				capsule->is_stored = 1;
			}
		}
	}
	return bytes;
}

/* Default response to a "prepare to send" call on a test stream 
* for an H3zero server or client connection. 
* 
* void * context, size_t space: values provided by picoquic in "prepare to send" callback
* uint64_t send_total_length: target length of the content
* uint64_t * sent_length: amount of data already sent
* FILE * F: data file from which the content will be read.
* 
* If the file pointer F is null, the program will send a set of meaningless bytes
* of the desired length. This "meaningless" data function is often used when
* testing or when measuring performance.
*/
int h3zero_prepare_and_send_data(void * context, size_t space, uint64_t send_total_length, uint64_t * sent_length, FILE * F)
{
	int ret = 0;

	if (*sent_length < send_total_length) {
		uint8_t * buffer;
		uint64_t available = send_total_length - *sent_length;
		int is_fin = 1;

		if (available > space) {
			available = space;
			is_fin = 0;
		}

		buffer = picoquic_provide_stream_data_buffer(context, (size_t)available, is_fin, !is_fin);
		if (buffer != NULL) {
			if (F) {
				size_t nb_read = fread(buffer, 1, (size_t)available, F);

				if (nb_read != available) {
					ret = -1;
				}
				else {
					*sent_length += available;
					ret = 0;
				}
			}
			else {
				/* TODO: fill buffer with some text */
				memset(buffer, 0x5A, (size_t)available);
				*sent_length += available;
				ret = 0;
			}
		}
		else {
			ret = -1;
		}
	}

	return ret;
}