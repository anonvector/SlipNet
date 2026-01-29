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
#ifndef H3ZERO_H
#define H3ZERO_H

#ifdef __cplusplus
extern "C" {
#endif

#define H3ZERO_NO_ERROR 0x0100 /* No error */
#define H3ZERO_GENERAL_PROTOCOL_ERROR  0x0101 /* Protocol violation, or no more specific information */
#define H3ZERO_INTERNAL_ERROR 0x0102 /* Internal error */
#define H3ZERO_STREAM_CREATION_ERROR 0x0103 /* Stream creation error */
#define H3ZERO_CLOSED_CRITICAL_STREAM 0x0104 /* Critical stream was closed */
#define H3ZERO_FRAME_UNEXPECTED 0x0105 /* Frame not permitted in the current state */
#define H3ZERO_FRAME_ERROR 0x0106 /* Frame violated layout or size rules */
#define H3ZERO_EXCESSIVE_LOAD 0x0107 /* Peer generating excessive load */
#define H3ZERO_ID_ERROR 0x0108 /* An identifier was used incorrectly */
#define H3ZERO_SETTINGS_ERROR 0x0109 /* SETTINGS frame contained invalid values */
#define H3ZERO_MISSING_SETTINGS 0x010A /* No SETTINGS frame received */
#define H3ZERO_REQUEST_REJECTED 0x010B /* Request not processed */
#define H3ZERO_REQUEST_CANCELLED 0x010C /* Data no longer needed */
#define H3ZERO_REQUEST_INCOMPLETE 0x010D /* Stream terminated early */
#define H3_MESSAGE_ERROR 0x010E /* HTTP message was malformed and cannot be processed */
#define H3ZERO_CONNECT_ERROR 0x010F /* TCP reset or error on CONNECT request */
#define H3ZERO_VERSION_FALLBACK 0x0110 /* Retry over  H3ZERO/1.1 */
#define H3ZERO_QPACK_DECOMPRESSION_FAILED 0x0200 /* Decoding of a field section failed. */
#define H3ZERO_QPACK_ENCODER_STREAM_ERROR 0x0201 /* Error on the encoder stream */
#define H3ZERO_QPACK_DECODER_STREAM_ERROR 0x0202 /* Error on the decoder stream */
#define H3ZERO_WEBTRANSPORT_BUFFERED_STREAM_REJECTED 0x3994bd84 /* Stream arrived before webtransport session established */
#define H3ZERO_WEBTRANSPORT_SESSION_GONE 0x170d7b68 /* Stream arrived after web transport session closed */
#define H3ZERO_WEBTRANSPORT_APPLICATION_ERROR(code) (0x52e4a40fa8dbull + code) /* see spec for skipping grease points when mapping codes */
#define H3ZERO_USER_AGENT_STRING "H3Zero/1.0"

#define H3ZERO_CAPSULE_CLOSE_WEBTRANSPORT_SESSION 0x2843
#define H3ZERO_CAPSULE_DRAIN_WEBTRANSPORT_SESSION 0x78ae

typedef enum {
	h3zero_frame_data = 0,
    h3zero_frame_header = 1,
    h3zero_frame_cancel_push = 3,
    h3zero_frame_settings = 4,
    h3zero_frame_push_promise = 5,
    h3zero_frame_goaway = 7,
    h3zero_frame_max_push_id = 0xd,
    h3zero_frame_reserved_base = 0xb,
    h3zero_frame_reserved_delta = 0x1f,
    h3zero_frame_webtransport_stream = 0x41
} h3zero_frame_type_enum_t;

typedef enum {
    h3zero_stream_type_control = 0,
    h3zero_stream_type_push = 1, /* Push type not supported in h3zero settings */
    h3zero_stream_type_qpack_encoder = 2, /* not required since not using dynamic table */
    h3zero_stream_type_qpack_decoder = 3, /* not required since not using dynamic table */
    h3zero_stream_type_webtransport = 0x54 /* unidir stream is used as specified in web transport */
} h3zero_stream_type_enum;

typedef enum {
    http_header_unknown = 0,
    http_pseudo_header_authority,
    http_pseudo_header_path,
    http_header_age,
    http_header_content_disposition,
    http_header_content_length,
    http_header_cookie,
    http_header_date,
    http_header_etag,
    http_header_if_modified_since,
    http_header_if_none_match,
    http_header_last_modified,
    http_header_link,
    http_header_location,
    http_header_referer,
    http_header_set_cookie,
    http_pseudo_header_method,
    http_pseudo_header_scheme,
    http_pseudo_header_status,
    http_pseudo_header_protocol,
    http_header_accept,
    http_header_accept_encoding,
    http_header_accept_ranges,
    http_header_access_control_allow_headers,
    http_header_access_control_allow_origin,
    http_header_cache_control,
    http_header_content_encoding,
    http_header_content_type,
    http_header_range,
    http_header_strict_transport_security,
    http_header_vary,
    http_header_x_content_type_options,
    http_header_x_xss_protection,
    http_header_accept_language,
    http_header_access_control_allow_credentials,
    http_header_access_control_allow_methods,
    http_header_access_control_expose_headers,
    http_header_access_control_request_headers,
    http_header_access_control_request_method,
    http_header_alt_svc,
    http_header_authorization,
    http_header_content_security_policy,
    http_header_early_data,
    http_header_expect_ct,
    http_header_forwarded,
    http_header_if_range,
    http_header_origin,
    http_header_purpose,
    http_header_server,
    http_header_timing_allow_origin,
    http_header_upgrade_insecure_requests,
    http_header_user_agent,
    http_header_x_forwarded_for,
    http_header_x_frame_options,
	http_header_max
} http_header_enum_t;

#define H3ZERO_QPACK_CODE_CONNECT 15
#define H3ZERO_QPACK_CODE_GET 17
#define H3ZERO_QPACK_CODE_POST 20
#define H3ZERO_QPACK_CODE_PATH 1
#define H3ZERO_QPACK_CODE_404 27
#define H3ZERO_QPACK_CODE_200 25
#define H3ZERO_QPACK_ALLOW_GET 76
#define H3ZERO_QPACK_AUTHORITY 0
#define H3ZERO_QPACK_SCHEME_HTTPS 23
#define H3ZERO_QPACK_TEXT_PLAIN 53
#define H3ZERO_QPACK_RANGE 55
#define H3ZERO_QPACK_USER_AGENT 95
#define H3ZERO_QPACK_ORIGIN 90
#define H3ZERO_QPACK_SERVER 92

typedef struct st_h3zero_qpack_static_t {
    int index;
    http_header_enum_t header;
    char const * content;
    int enum_as_int; /* Documented for some interesting values */
} h3zero_qpack_static_t;

typedef enum {
    h3zero_content_type_none = 0,
    h3zero_content_type_not_supported,
    h3zero_content_type_text_html,
    h3zero_content_type_text_plain,
    h3zero_content_type_image_gif,
    h3zero_content_type_image_jpeg,
    h3zero_content_type_image_png,
    h3zero_content_type_dns_message,
    h3zero_content_type_javascript,
    h3zero_content_type_json,
    h3zero_content_type_www_form_urlencoded,
    h3zero_content_type_text_css
} h3zero_content_type_enum;

typedef enum {
    h3zero_method_none = 0,
    h3zero_method_not_supported,
    h3zero_method_connect,
    h3zero_method_delete,
    h3zero_method_get,
    h3zero_method_head,
    h3zero_method_options,
    h3zero_method_post,
    h3zero_method_put
} h3zero_method_enum;

typedef struct st_h3zero_header_parts_t {
    h3zero_method_enum method;
    uint8_t const * path;
    size_t path_length;
    uint8_t const * range;
    size_t range_length;
    int status;
    h3zero_content_type_enum content_type;
    uint8_t const * protocol;
    size_t protocol_length;
    unsigned int path_is_huffman : 1;
} h3zero_header_parts_t;

/* Setting codes.
* This list includes the "extension" settings for datagrams and web
* transport, because we want to have common functions for coding and
* decoding setting values.
 */
#define h3zero_setting_reserved = 0x0
#define h3zero_setting_header_table_size 0x1
#define h3zero_setting_max_header_list_size 0x6
#define h3zero_qpack_blocked_streams 0x07
#define h3zero_setting_grease_signature 0x0a0a
#define h3zero_setting_grease_mask 0x0f0f
#define h3zero_settings_enable_connect_protocol 0x8
#define h3zero_setting_h3_datagram 0x33
#define h3zero_settings_webtransport_max_sessions 0xc671706aull

typedef struct st_h3zero_settings_t {
    uint64_t webtransport_max_sessions;
    uint64_t table_size;
    uint64_t max_header_list_size;
    uint64_t blocked_streams;
    unsigned int enable_connect_protocol : 1;
    unsigned int h3_datagram : 1;
    unsigned int settings_received : 1;
} h3zero_settings_t;

extern uint8_t const * h3zero_default_setting_frame;

extern const size_t h3zero_default_setting_frame_size;

uint8_t * h3zero_qpack_int_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t val);
uint8_t * h3zero_qpack_int_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t *val);

uint8_t * h3zero_parse_qpack_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_header_parts_t * parts);
uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host);
uint8_t* h3zero_create_request_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max,
    uint8_t const* path, size_t path_length, uint8_t const* range, size_t range_length,
    char const* host, char const* ua_string);
uint8_t * h3zero_create_post_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host,
    h3zero_content_type_enum content_type);
uint8_t* h3zero_create_request_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max,
    uint8_t const* path, size_t path_length, uint8_t const* range, size_t range_length,
    char const* host, char const* ua_string);
uint8_t* h3zero_create_connect_header_frame(uint8_t* bytes, uint8_t* bytes_max,
    char const* authority, uint8_t const* path, size_t path_length, char const* protocol,
    char const* origin, char const* ua_string);
uint8_t* h3zero_create_post_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max,
    uint8_t const* path, size_t path_length, uint8_t const* range, size_t range_length,
    char const* host, h3zero_content_type_enum content_type, char const* ua_string);
uint8_t * h3zero_create_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type);
uint8_t* h3zero_create_error_frame(uint8_t* bytes, uint8_t* bytes_max, char const* error_code, char const* server_string);
uint8_t* h3zero_create_response_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max,
    h3zero_content_type_enum doc_type, char const* server_string);
uint8_t * h3zero_create_not_found_header_frame(uint8_t * bytes, uint8_t * bytes_max);
uint8_t* h3zero_create_not_found_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max, char const* server_string);
uint8_t * h3zero_create_bad_method_header_frame(uint8_t * bytes, uint8_t * bytes_max);
uint8_t* h3zero_create_bad_method_header_frame_ex(uint8_t* bytes, uint8_t* bytes_max, char const* server_string);

typedef struct st_h3zero_data_stream_state_t {
    struct st_h3zero_callback_ctx_t* h3_ctx;
    h3zero_header_parts_t header;
    h3zero_header_parts_t trailer;
    uint64_t stream_type;
    uint8_t * current_frame;
    uint64_t current_frame_type;
    uint64_t current_frame_length;
    uint64_t current_frame_read;
    uint64_t control_stream_id;
    uint8_t frame_header[16];
    size_t frame_header_read;
    unsigned int is_upgrade_requested:1;
    unsigned int is_web_transport : 1;
    unsigned int frame_header_parsed : 1;
    unsigned int header_found : 1;
    unsigned int data_found : 1;
    unsigned int trailer_found : 1;
    unsigned int is_h3_control : 1;
    unsigned int is_current_frame_ignored : 1;
    /* Keeping track of FIN sent and FIN received, so applications can delete stream contexts that are not useful */
    unsigned int is_fin_received : 1; 
    unsigned int is_fin_sent : 1;
} h3zero_data_stream_state_t;

/* Parsing of a data stream. This is implemented as a filter, with a set of states:
*
* - Reading frame length: obtaining the length and type of the next frame.
* - Reading header frame: obtaining the bytes of the data frame.
*   When all bytes are obtained, the header is parsed and the header
*   structure is documented. State moves back to initial, with header-read
*   flag set. Having two frame headers before a data frame is a bug.
* - Reading data frame: the frame header indicated a data frame of
*   length N. Treat the following N bytes as data.
*
* There may be several data frames in a stream. The application will pick
* the bytes and treat them as data.
*/

size_t h3zero_varint_skip(const uint8_t* bytes);
size_t h3zero_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64);
uint8_t* h3zero_varint_from_stream(uint8_t* bytes, uint8_t* bytes_max, uint64_t* result, uint8_t* buffer, size_t* buffer_length);
void h3zero_release_header_parts(h3zero_header_parts_t* header);

int hzero_qpack_huffman_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t * decoded, size_t max_decoded, size_t * nb_decoded);

/* TLV_Buffer_accumulator 
*/
#ifdef __cplusplus
}
#endif

#endif /* H3ZERO_H */