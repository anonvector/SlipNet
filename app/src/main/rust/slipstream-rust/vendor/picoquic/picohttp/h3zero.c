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
 * Basic implementation of HTTP3, suitable for a minimal test responder.
 * The traffic generation is similar to that of the http0dot9 test:
 * - Receive a get request on a client bidir stream.
 * - Parse the header to find the required document
 * - Generate the corresponding document in memory
 * The "request" is expected to be an H3 request header frame, encoded with QPACK
 * The "response" will include a response header frame and one or several data frames.
 * QPACK encoding only uses the static dictionary.
 * The server will start the connection by sending a setting frame, which will
 * specify a zero-length dynamic dictionary for QPACK.
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "h3zero.h"

/*
 * Transport parameters.
 * HTTP/3 does not use server-initiated bidirectional streams;
 * clients MUST omit or specify a value of zero for the QUIC
 * transport parameter initial_max_bidi_streams.
 * Both clients and servers SHOULD send a value of three or
 * greater for the QUIC transport parameter initial_max_uni_streams.
 */

/* Varint are used in many frame encodings. We want to ensure that h3zero can be used without
 * referencing the picoquic libraries, and thus we have to duplicate here two utility
 * functions: h3zeo_varint_decode and h3zero_varint_skip. */

size_t h3zero_varint_skip(const uint8_t* bytes)
{
    return ((size_t)1u) << ((bytes[0] & 0xC0) >> 6);
}

size_t h3zero_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64)
{
    size_t length = h3zero_varint_skip(bytes);

    if (length > max_bytes) {
        length = 0;
        *n64 = 0;
    }
    else {
        uint64_t v = *bytes++ & 0x3F;

        for (size_t i = 1; i < length; i++) {
            v <<= 8;
            v += *bytes++;
        }

        *n64 = v;
    }

    return length;
}


/*
 * Prefixed integers are used throughout QPACK encoding. This is 
 * defined in RFC 7541.
 *
 * If the value is small enough, the encoding uses a single byte:
 *      0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | ? | ? | ? |       Value       |
 *   +---+---+---+-------------------+
 * If the value is long, use a multibyte encoding:
 *     0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | ? | ? | ? | 1   1   1   1   1 |
 *   +---+---+---+-------------------+
 *   | 1 |    Value-(2^N-1) LSB      |
 *   +---+---------------------------+
 *                  ...
 *   +---+---------------------------+
 *   | 0 |    Value-(2^N-1) MSB      |
 *   +---+---------------------------+
 * Integers can be up to 62 bit longs.
 */

uint8_t * h3zero_qpack_int_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask,  uint64_t val)
{
    if (bytes == NULL || bytes >= bytes_max) {
        return NULL;
    }

    if (val < mask) {
        *bytes++ |= val;
    }
    else {
        val -= mask;
        *bytes++ |= mask;
        while (val >= 0x80 && bytes < bytes_max) {
            *bytes++ = 0x80 | (val & 0x7F);
            val >>= 7;
        }

        if (bytes < bytes_max) {
            *bytes++ = (uint8_t) val;
        }
        else {
            bytes = NULL;
        }
    }

    return bytes;
}

uint8_t * h3zero_qpack_int_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t *val)
{

    if (bytes == NULL || bytes >= bytes_max) {
        *val = 0;
        return NULL;
    }

    *val = *bytes++ & mask;

    if (*val == mask) {
        int shift = 0;
        int complete = 0;
        uint64_t v = 0;

        while (bytes < bytes_max && shift < 62) {
            v |= (((uint64_t)bytes[0]) & 0x7Full) << shift;
            if (((*bytes++) & 0x80) == 0) {
                complete = 1;
                break;
            }
            shift += 7;
        }

        if (shift >= 62 || bytes > bytes_max || !complete) {
            bytes = NULL;
        }
        else {
            *val = v + mask;
        }
    }

    return bytes;
}

/*
 * Table of QPACK static code
 */

h3zero_qpack_static_t qpack_static[] = {
    { 0, http_pseudo_header_authority, NULL, 0},
    { 1, http_pseudo_header_path, "/", 0},
    { 2, http_header_age, "0", 0},
    { 3, http_header_content_disposition, NULL, 0},
    { 4, http_header_content_length, "0", 0},
    { 5, http_header_cookie, NULL, 0},
    { 6, http_header_date, NULL, 0},
    { 7, http_header_etag, NULL, 0},
    { 8, http_header_if_modified_since, NULL, 0},
    { 9, http_header_if_none_match, NULL, 0},
    { 10, http_header_last_modified, NULL, 0},
    { 11, http_header_link, NULL, 0},
    { 12, http_header_location, NULL, 0},
    { 13, http_header_referer, NULL, 0},
    { 14, http_header_set_cookie, NULL, 0},    
    { 15, http_pseudo_header_method, "CONNECT", h3zero_method_connect},
    { 16, http_pseudo_header_method, "DELETE", h3zero_method_delete},
    { 17, http_pseudo_header_method, "GET", h3zero_method_get},
    { 18, http_pseudo_header_method, "HEAD", h3zero_method_head},
    { 19, http_pseudo_header_method, "OPTIONS", h3zero_method_options},
    { 20, http_pseudo_header_method, "POST", h3zero_method_post},
    { 21, http_pseudo_header_method, "PUT", h3zero_method_put},
    { 22, http_pseudo_header_scheme, "http", 0},
    { 23, http_pseudo_header_scheme, "https", 0},
    { 24, http_pseudo_header_status, "103", 103},
    { 25, http_pseudo_header_status, "200", 200},
    { 26, http_pseudo_header_status, "304", 304},
    { 27, http_pseudo_header_status, "404", 404},
    { 28, http_pseudo_header_status, "503", 503},
    { 29, http_header_accept, "*/*", 0},
    { 30, http_header_accept, "application/dns-message", 0},
    { 31, http_header_accept_encoding, "gzip, deflate, br", 0},
    { 32, http_header_accept_ranges, "bytes", 0},
    { 33, http_header_access_control_allow_headers, "cache-control", 0},
    { 34, http_header_access_control_allow_headers, "content-type", 0},
    { 35, http_header_access_control_allow_origin, "*", 0},
    { 36, http_header_cache_control, "max-age=0", 0},
    { 37, http_header_cache_control, "max-age=2592000", 0},
    { 38, http_header_cache_control, "max-age=604800", 0},
    { 39, http_header_cache_control, "no-cache", 0},
    { 40, http_header_cache_control, "no-store", 0},
    { 41, http_header_cache_control, "public, max-age=31536000", 0},
    { 42, http_header_content_encoding, "br", 0},
    { 43, http_header_content_encoding, "gzip", 0},
    { 44, http_header_content_type, "application/dns-message", h3zero_content_type_dns_message},
    { 45, http_header_content_type, "application/javascript", h3zero_content_type_javascript},
    { 46, http_header_content_type, "application/json", h3zero_content_type_json},
    { 47, http_header_content_type, "application/x-www-form-urlencoded", h3zero_content_type_www_form_urlencoded},
    { 48, http_header_content_type, "image/gif", h3zero_content_type_image_gif},
    { 49, http_header_content_type, "image/jpeg", h3zero_content_type_image_jpeg},
    { 50, http_header_content_type, "image/png", h3zero_content_type_image_png},
    { 51, http_header_content_type, "text/css", h3zero_content_type_text_css},
    { 52, http_header_content_type, "text/html; charset=utf-8", h3zero_content_type_text_html},
    { 53, http_header_content_type, "text/plain", h3zero_content_type_text_plain},
    { 54, http_header_content_type, "text/plain;charset=utf-8", h3zero_content_type_text_plain},
    { 55, http_header_range, "bytes=0-", 0},
    { 56, http_header_strict_transport_security, "max-age=31536000", 0},
    { 57, http_header_strict_transport_security, "max-age=31536000; includesubdomains", 0},
    { 58, http_header_strict_transport_security, "max-age=31536000; includesubdomains; preload", 0},
    { 59, http_header_vary, "accept-encoding", 0},
    { 60, http_header_vary, "origin", 0},
    { 61, http_header_x_content_type_options, "nosniff", 0},
    { 62, http_header_x_xss_protection, "1; mode=block", 0},
    { 63, http_pseudo_header_status, "100", 100},
    { 64, http_pseudo_header_status, "204", 204},
    { 65, http_pseudo_header_status, "206", 206},
    { 66, http_pseudo_header_status, "302", 302},
    { 67, http_pseudo_header_status, "400", 400},
    { 68, http_pseudo_header_status, "403", 403},
    { 69, http_pseudo_header_status, "421", 421},
    { 70, http_pseudo_header_status, "425", 425},
    { 71, http_pseudo_header_status, "500", 500},
    { 72, http_header_accept_language, NULL, 0},
    { 73, http_header_access_control_allow_credentials, "FALSE", 0},
    { 74, http_header_access_control_allow_credentials, "TRUE", 0},
    { 75, http_header_access_control_allow_headers, "*", 0},
    { 76, http_header_access_control_allow_methods, "get", 0},
    { 77, http_header_access_control_allow_methods, "get, post, options", 0},
    { 78, http_header_access_control_allow_methods, "options", 0},
    { 79, http_header_access_control_expose_headers, "content-length", 0},
    { 80, http_header_access_control_request_headers, "content-type", 0},
    { 81, http_header_access_control_request_method, "get", 0},
    { 82, http_header_access_control_request_method, "post", 0},
    { 83, http_header_alt_svc, "clear", 0},
    { 84, http_header_authorization, NULL, 0},
    { 85, http_header_content_security_policy, "script-src 'none'; object-src 'none'; base-uri 'none'", 0},
    { 86, http_header_early_data, "1", 0},
    { 87, http_header_expect_ct, NULL, 0},
    { 88, http_header_forwarded, NULL, 0},
    { 89, http_header_if_range, NULL, 0},
    { 90, http_header_origin, NULL, 0},
    { 91, http_header_purpose, "prefetch", 0},
    { 92, http_header_server, NULL, 0},
    { 93, http_header_timing_allow_origin, "*", 0},
    { 94, http_header_upgrade_insecure_requests, "1", 0},
    { 95, http_header_user_agent, NULL, 0},
    { 96, http_header_x_forwarded_for, NULL, 0},
    { 97, http_header_x_frame_options, "deny", 0},
    { 98, http_header_x_frame_options, "sameorigin", 0}
};

size_t h3zero_qpack_nb_static = sizeof(qpack_static) / sizeof(h3zero_qpack_static_t);

/* 
 * Minimal QPACK parsing.
 *
 * This is used for header frames, which start with:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |   Required Insert Count (8+)  |
 * +---+---------------------------+
 * | S |      Delta Base (7+)      |
 * +---+---------------------------+
 *
 * followed by 
 * +---+---------------------------+
 * |      Compressed Headers     ...
 * +-------------------------------+
 *
 * Since H3zero only support static entries, we expect the required
 * Insert count to be zero, and we always ignore the Base delta.
 * The Base is encoded as sign-and-modulus integer (on 1 byte?)
 *
 * We expect the following types of compressed content:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | S |      Index (6+)       |
 * +---+---+-----------------------+
 *
 * Index reference with static bit S set to 1, and the index describing an entry
 * in the static table.
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | N | S |Name Index (4+)|
 * +---+---+---+---+---------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Literal header field with name reference, expecting S bit to 1. Set N bits
 * to 0, ignore on read. 
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 | N | H |NameLen(3+)|
 * +---+---+---+---+---+-----------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Literal Header Field Without Name Reference. The N bit is set to zero on write,
 * ignored on read. The H bit is always zero, since we do not implement Huffman
 * encoding.
 */

h3zero_method_enum h3zero_get_method_by_name(uint8_t * name, size_t name_length) {
    int const method_index[] = { 15, 16, 17, 18, 19, 20, 21, -1 };
    h3zero_method_enum method = h3zero_method_not_supported;

    for (int i = 0; method_index[i] >= 0; i++) {
        if (strlen(qpack_static[method_index[i]].content) == name_length &&
            memcmp(qpack_static[method_index[i]].content, name, name_length) == 0) {
            method = (h3zero_method_enum)qpack_static[method_index[i]].enum_as_int;
            break;
        }
    }

    return method;
}

h3zero_content_type_enum h3zero_get_content_type_by_name(uint8_t * name, size_t name_length) {
    int const content_type_index[] = { 
        44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, -1 };
    h3zero_content_type_enum content_type = h3zero_content_type_not_supported;

    for (int i = 0; content_type_index[i] >= 0; i++) {
        if (strlen(qpack_static[content_type_index[i]].content) == name_length &&
            memcmp(qpack_static[content_type_index[i]].content, name, name_length) == 0) {
            content_type = (h3zero_content_type_enum)
                qpack_static[content_type_index[i]].enum_as_int;
            break;
        }
    }

    return content_type;
}

int h3zero_parse_status(uint8_t * content, size_t content_length)
{
    int val = 0;

    for (size_t i = 0; i < content_length; i++) {
        if (content[i] >= '0' && content[i] <= '9') {
            val *= 10;
            val += content[i] - '0';
        }
        else {
            val = -1;
            break;
        }
    }

    return val;
}

uint8_t* h3zero_parse_qpack_header_value_string(uint8_t * bytes, uint8_t* decoded,
    size_t decoded_length, const uint8_t ** field, size_t * length)
{
    if (*field != NULL) {
        /* Duplicate field! */
        bytes = NULL;
    }
    else {
        *field = malloc(decoded_length + 1);
        if (*field == NULL) {
            bytes = 0;
            *length = 0;
        }
        else {
            memcpy((void*)*field, decoded, decoded_length);
            ((uint8_t*)(*field))[decoded_length] = 0;
            *length = (size_t)decoded_length;
        }
    }
    return bytes;
}

uint8_t * h3zero_parse_qpack_header_value(uint8_t * bytes, uint8_t * bytes_max,
    http_header_enum_t header, h3zero_header_parts_t * parts)
{
    uint64_t v_length = 0;
    int is_huffman = 0;
    uint8_t * decoded = NULL;
    size_t decoded_length;
    uint8_t deHuff[256];

    if (bytes >= bytes_max || bytes == NULL) {
        bytes = NULL;
    }
    else {
        is_huffman = (bytes[0] >> 7) & 1;
        bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x7F, &v_length);
    }
    if (bytes != NULL) {
        if (bytes + v_length > bytes_max) {
            bytes = NULL;
        } else {
            if (is_huffman && hzero_qpack_huffman_decode(
                bytes, bytes + v_length, deHuff, sizeof(deHuff), &decoded_length) == 0)
            {
                decoded = deHuff;
            }
            else {
                decoded = bytes;
                decoded_length = (size_t) v_length;
            }

            switch (header) {
            case http_pseudo_header_method:
                if (parts->method != h3zero_method_none) {
                    /* Duplicate method! */
                    bytes = 0;
                }
                else {
                    parts->method = h3zero_get_method_by_name(decoded, decoded_length);
                }
                break;
            case http_header_content_type:
                if (parts->content_type != h3zero_content_type_none) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    parts->content_type = h3zero_get_content_type_by_name(decoded, decoded_length);
                }
                break;
            case http_pseudo_header_status:
                if (parts->status != 0) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    /* TODO: decimal to binary */
                    parts->status = h3zero_parse_status(decoded, decoded_length);
                }
                break;
            case http_pseudo_header_path:
                if (parts->path != NULL) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    bytes = h3zero_parse_qpack_header_value_string(bytes, decoded,
                        decoded_length, &parts->path, &parts->path_length);
                }
                break;
            case http_header_range:
                if (parts->range != NULL) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    bytes = h3zero_parse_qpack_header_value_string(bytes, decoded,
                        decoded_length, &parts->range, &parts->range_length);
                }
                break;
            case http_pseudo_header_protocol:
                if (parts->protocol != NULL) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    bytes = h3zero_parse_qpack_header_value_string(bytes, decoded,
                        decoded_length, &parts->protocol, &parts->protocol_length);
                }
                break;
            default:
                break;
            }

            if (bytes != NULL) {
                bytes += v_length;
            }
        }
    }

    return bytes;
}

int h3zero_get_interesting_header_type(uint8_t * name, size_t name_length, int is_huffman)
{
    char const  * interesting_header_name[] = {
     ":method", ":path", ":status", "content-type", ":protocol", "origin", "range", NULL};
    const http_header_enum_t interesting_header[] = {
        http_pseudo_header_method, http_pseudo_header_path,
        http_pseudo_header_status, http_header_content_type,
        http_pseudo_header_protocol, http_header_origin,
        http_header_range
    };
    http_header_enum_t val = http_header_unknown;
    uint8_t deHuff[256];

    if (is_huffman) {
        size_t nb_decoded = 0;
        if (hzero_qpack_huffman_decode(name, name + name_length, deHuff, sizeof(deHuff), &nb_decoded) == 0){
            name = deHuff;
            name_length = nb_decoded;
        }
    }

    for (int i = 0; interesting_header_name[i] != NULL; i++) {
        if (strlen(interesting_header_name[i]) == name_length &&
            memcmp(interesting_header_name[i], name, name_length) == 0) {
            val = interesting_header[i];
            break;
        }
    }

    return val;
}

uint8_t * h3zero_parse_qpack_header_frame(uint8_t * bytes, uint8_t * bytes_max, 
    h3zero_header_parts_t * parts)
{
    memset(parts, 0, sizeof(h3zero_header_parts_t));

    if (bytes == NULL || bytes >= bytes_max) {
        return NULL;
    }

    /* parse base, expect 0 insert */
    if (bytes[0] != 0) {
        /* unexpected value */
        bytes = NULL;
    }
    else {
        uint64_t delta_base;
        bytes = h3zero_qpack_int_decode(bytes + 1, bytes_max, 0x7F, &delta_base);
    }

    while (bytes != NULL && bytes < bytes_max) {
        if ((bytes[0] & 0xC0) == 0xC0) {
            /* Index reference with static encoding */
            uint64_t s_index;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x3F, &s_index);

            if (s_index > h3zero_qpack_nb_static) {
                /* Index out of range */
                bytes = NULL;
            }
            else {
                switch (qpack_static[s_index].header) {
                case http_pseudo_header_method:
                    if (parts->method != h3zero_method_none) {
                        /* Duplicate method! */
                        bytes = 0;
                    }
                    else {
                        parts->method = (h3zero_method_enum) qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_header_content_type:
                    if (parts->content_type != h3zero_content_type_none) {
                        /* Duplicate content type! */
                        bytes = NULL;
                    }
                    else {
                        parts->content_type = (h3zero_content_type_enum)qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_status:
                    if (parts->status != 0) {
                        /* Duplicate content type! */
                        bytes = NULL;
                    }
                    else {
                        parts->status = qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_path:
                    if (parts->path != NULL) {
                        /* Duplicate path! */
                        bytes = NULL;
                    }
                    else {
                        parts->path_length = strlen(qpack_static[s_index].content);
                        parts->path = malloc(parts->path_length + 1);
                        if (parts->path == NULL) {
                            /* internal error */
                            bytes = NULL;
                            parts->path_length = 0;
                        }
                        else {
                            memcpy((uint8_t *)parts->path, qpack_static[s_index].content, parts->path_length);
                            ((uint8_t*)parts->path)[parts->path_length] = 0;
                        }
                    }
                    break;
                case http_header_origin:
                    /* TODO: parse origin value? */
                case http_pseudo_header_protocol:
                    /* TODO: parse protocol value? */
                default:
                    break;
                }
            }
        }
        else if ((bytes[0] & 0xD0) == 0x50) {
            /* Literal header field with name reference, static encoding */
            uint64_t s_index;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x0F, &s_index);
            if (bytes != NULL) {
                if (s_index > h3zero_qpack_nb_static) {
                    /* Index out of range */
                    bytes = NULL;
                } else {
                    bytes = h3zero_parse_qpack_header_value(bytes, bytes_max,
                        qpack_static[s_index].header, parts);
                }
            }
        }
        else if ((bytes[0] & 0xE0) == 0x20) {
            /* Literal Header Field Without Name Reference */
            uint64_t n_length;
            int is_huffman = (bytes[0] >> 3) & 1;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x07, &n_length);
            if (bytes != NULL) {
                if (bytes + n_length > bytes_max) {
                    bytes = NULL;
                }
                else {
                    http_header_enum_t header_type = h3zero_get_interesting_header_type(bytes, (size_t)n_length, is_huffman);
                    bytes += n_length;
                    bytes = h3zero_parse_qpack_header_value(bytes, bytes_max,
                        header_type, parts);
                }
            }
        }
        else {
            /* unexpected encoding */
            bytes = NULL;
        }
    }

    return bytes;
}

/*
 * Header frame.
 * The HEADERS frame (type=0x1) is used to carry a header block,
 * compressed using QPACK.
 * It is always the first frame sent on the stream, whether by the client or
 * by the server.
 *
 * On the client side, this will include the minimal required frames for
 * a request according to
 * https://developers.google.com/web/fundamentals/performance/http2/:
 *      :method: GET
 *        :path: /index.html
 *     :version: HTTP/3.0
 *      :scheme: HTTPS
 *   user-agent: Picoquic-H3zero/0.1
 * On the server side, this should be:
 *     :status: 200
 *    :version: HTTP/3.0
 *    server: Picoquic-H3zero/0.1
 * Plus one of:
 *  http_header_content_type: "text/html; charset=utf-8"
 *  http_header_content_type: "text/plain;charset=utf-8"
 *  http_header_content_type: "image/gif"
 *  http_header_content_type: "image/jpeg"
 *  http_header_content_type: "image/png"
 *
 * Followed by a series of data frames.
 *
 * If the path does not exist, the server will return an error:
 *   :status: 404
 * Followed by nothing.
 * If the method is not supported, the server will return error
 * 405, with header "allow GET"
 */

static uint8_t * h3zero_qpack_code_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t prefix, uint8_t mask, uint64_t code) 
{
    if (bytes != NULL) {
        if (bytes + 1 > bytes_max) {
            bytes = NULL;
        }
        else {
            *bytes = prefix;
            bytes = h3zero_qpack_int_encode(bytes, bytes_max, mask, code);
        }
    }

    return bytes;
}

static uint8_t * h3zero_qpack_literal_plus_ref_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint64_t code, uint8_t const * val, size_t val_length)
{
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x50, 0x0F, code);
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x00, 0x7F, val_length);
    if (bytes != NULL && val_length > 0) {
        if (bytes + val_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, val, val_length);
            bytes += val_length;
        }
    }

    return bytes;
}

/* Example of literal plus literal: 
0x20 | QPACK_TEST_HEADER_PATH_LEN, QPACK_TEST_HEADER_PATH,
QPACK_TEST_HEADER_INDEX_HTML_LEN, QPACK_TEST_HEADER_INDEX_HTML
This supposes that the literal is less than 127 bytes.

*   0   1   2   3   4   5   6   7
* +---+---+---+---+---+---+---+---+
* | 0 | 0 | 1 | N | H |NameLen(3+)|
* +---+---+---+---+---+-----------+
* |  Name String (Length bytes)   |
* +---+---------------------------+
* | H |     Value Length (7+)     |
* +---+---------------------------+
* |  Value String (Length bytes)  |
* +-------------------------------+
*/

static uint8_t * h3zero_qpack_name_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t prefix, uint8_t mask, uint8_t const * name, size_t name_length) 
{
    if (bytes != NULL) {
        if (bytes + 1 > bytes_max) {
            bytes = NULL;
        }
        else {
            *bytes = prefix;
            bytes = h3zero_qpack_int_encode(bytes, bytes_max, mask, name_length);
            if (bytes != NULL && name_length > 0) {
                if (bytes + name_length > bytes_max) {
                    bytes = NULL;
                }
                else {
                    memcpy(bytes, name, name_length);
                    bytes += name_length;
                }
            }
        }
    }

    return bytes;
}

static uint8_t * h3zero_qpack_literal_plus_name_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * name, size_t name_length, uint8_t const * val, size_t val_length)
{

    bytes = h3zero_qpack_name_encode(bytes, bytes_max, 0x20, 0x07, name, name_length);
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x00, 0x7F, val_length);
    if (bytes != NULL && val_length > 0) {
        if (bytes + val_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, val, val_length);
            bytes += val_length;
        }
    }

    return bytes;
}

uint8_t * h3zero_encode_content_type(uint8_t * bytes, uint8_t * bytes_max, h3zero_content_type_enum content_type)
{
    /* Content type header */
    if (bytes != NULL) {
        int code = -1;
        for (size_t i = 0; i < h3zero_qpack_nb_static; i++) {
            if (qpack_static[i].header == http_header_content_type &&
                qpack_static[i].enum_as_int == content_type) {
                code = qpack_static[i].index;
                break;
            }
        }

        if (code < 0) {
            /* Error, no such content */
            bytes = NULL;
        }
        else {
            bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, code);
        }
    }

    return bytes;
}

uint8_t* h3zero_create_connect_header_frame(uint8_t* bytes, uint8_t* bytes_max,
    char const * authority, uint8_t const* path, size_t path_length, char const* protocol,
    char const * origin, char const* ua_string)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_CONNECT);
    /* Scheme: HTTPS */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_SCHEME_HTTPS);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_CODE_PATH, path, path_length);
    /* Protocol. Use literal plus name format */
    if (protocol != NULL) {
        bytes = h3zero_qpack_literal_plus_name_encode(bytes, bytes_max, (uint8_t*)":protocol", 9, (uint8_t*)protocol, strlen(protocol));
    }
    /* Authority. Use literal plus reference format */
    if (authority != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_AUTHORITY, (uint8_t const*)authority, strlen(authority));
    }
    /* Origin. Use literal plus ref format */
    if (origin != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_ORIGIN, (uint8_t*)origin, strlen(origin));
    }
    /* User Agent */
    if (ua_string != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_USER_AGENT, (uint8_t const*)ua_string, strlen(ua_string));
    }
    return bytes;
}

uint8_t * h3zero_create_post_header_frame_ex(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, uint8_t const * range, size_t range_length, char const* host,
    h3zero_content_type_enum content_type, char const* ua_string)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_POST);
    /* Scheme: HTTPS */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_SCHEME_HTTPS);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_CODE_PATH, path, path_length);
    /* Authority: host. Use literal plus reference format */
    if (host != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_AUTHORITY, (uint8_t const *)host, strlen(host));
    }
    /* Optional: range. Use literal plus reference format */
    if (range_length > 0) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_RANGE, (uint8_t const *)range, range_length);
    }
    /* User Agent */
    if (ua_string != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_USER_AGENT, (uint8_t const*)ua_string, strlen(ua_string));
    }
    /* Document type */
    bytes = h3zero_encode_content_type(bytes, bytes_max, content_type);

    return bytes;
}

uint8_t* h3zero_create_post_header_frame(uint8_t* bytes, uint8_t* bytes_max,
    uint8_t const* path, size_t path_length, char const* host, h3zero_content_type_enum content_type)
{
    return h3zero_create_post_header_frame_ex(bytes, bytes_max, path, path_length, NULL, 0, host,
        content_type, H3ZERO_USER_AGENT_STRING);
}

uint8_t * h3zero_create_request_header_frame_ex(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, uint8_t const * range, size_t range_length,
    char const * host, char const* ua_string)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method: GET */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_GET);
    /* Scheme: HTTPS */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_SCHEME_HTTPS);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_CODE_PATH, path, path_length);
    /* Authority: host. Use literal plus reference format */
    if (host != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_AUTHORITY, (uint8_t const *)host, strlen(host));
    }
    /* Optional: range. Use literal plus reference format */
    if (range_length > 0) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_RANGE, (uint8_t const *)range, range_length);
    }
    /* User Agent */
    if (ua_string != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_USER_AGENT, (uint8_t const*)ua_string, strlen(ua_string));
    }
    return bytes;
}

uint8_t* h3zero_create_request_header_frame(uint8_t* bytes, uint8_t* bytes_max,
    uint8_t const* path, size_t path_length, char const* host)
{
    return h3zero_create_request_header_frame_ex(bytes, bytes_max, path, path_length,
        NULL, 0, host, H3ZERO_USER_AGENT_STRING);
}

uint8_t * h3zero_create_response_header_frame_ex(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type, char const* server_string)
{

    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;

    /* Status = 200 */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_200);

    /* Server string */
    if (server_string != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_SERVER, (uint8_t const*)server_string, strlen(server_string));
    }

    if (doc_type != h3zero_content_type_none) {
        /* Content type header */
        bytes = h3zero_encode_content_type(bytes, bytes_max, doc_type);
    }

    return bytes;
}

uint8_t* h3zero_create_response_header_frame(uint8_t* bytes, uint8_t* bytes_max,
    h3zero_content_type_enum doc_type)
{
    return h3zero_create_response_header_frame_ex(bytes, bytes_max, doc_type, H3ZERO_USER_AGENT_STRING);
}

uint8_t* h3zero_create_error_frame(uint8_t* bytes, uint8_t* bytes_max, char const* error_code, char const* server_string)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Status = 404 */
    if (strcmp(error_code, "404") == 0) {
        bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_404);
    }
    else {
        bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x50, 0x0F, H3ZERO_QPACK_CODE_404);
        if (bytes != NULL && bytes + 4 <= bytes_max) {
            *bytes++ = 3;
            *bytes++ = error_code[0];
            *bytes++ = error_code[1];
            *bytes++ = error_code[2];
        }
    }

    /* Server string */
    if (server_string != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_SERVER, (uint8_t const*)server_string, strlen(server_string));
    }
    /* Allowed methods */
    if (strcmp(error_code, "405") == 0 && bytes != NULL) {
        char const* allowed = "GET, POST, CONNECT";
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_ALLOW_GET, (uint8_t*)allowed, strlen(allowed));
    }
    return bytes;
}

uint8_t * h3zero_create_not_found_header_frame_ex(uint8_t * bytes, uint8_t * bytes_max, char const* server_string)
{
    return h3zero_create_error_frame(bytes, bytes_max, "404", server_string);
}

uint8_t* h3zero_create_not_found_header_frame(uint8_t* bytes, uint8_t* bytes_max)
{
    return h3zero_create_not_found_header_frame_ex(bytes, bytes_max, H3ZERO_USER_AGENT_STRING);
}

uint8_t * h3zero_create_bad_method_header_frame_ex(uint8_t * bytes, uint8_t * bytes_max, char const* server_string)
{
    return h3zero_create_error_frame(bytes, bytes_max, "405", server_string);
}

uint8_t* h3zero_create_bad_method_header_frame(uint8_t* bytes, uint8_t* bytes_max)
{
    return h3zero_create_bad_method_header_frame_ex(bytes, bytes_max, H3ZERO_USER_AGENT_STRING);
}

/* Read varint from stream.
 * The H3 streams data structures often include series of varint for
 * encoding of types, lengths, or property values. The size of
 * the messages is not known in advance. Instead, the parser is called
 * when bytes are received from the network.
 * 
 * The parser retains as state the number of bytes accumulated in 
 * a buffer. If the first byte is read, this byte provides the
 * length of the encoding. If there are zero bytes, the first byte
 * to be read will be placed in the buffer.
 */
uint8_t * h3zero_varint_from_stream(uint8_t* bytes, uint8_t* bytes_max, uint64_t * result, uint8_t * buffer, size_t* buffer_length)
{
    uint8_t* bp = buffer + *buffer_length;
    uint8_t* be;

    if (bytes == bytes_max){
        return bytes; /* continuing */
    }
    if (bp == buffer) {
        *bp++ = *bytes++;
        *buffer_length += 1;
    }
    be = buffer + h3zero_varint_skip(buffer);

    while (bytes < bytes_max && bp < be) {
        *bp++ = *bytes++;
        *buffer_length += 1;
    }

    if (bp >= be) {
        (void)h3zero_varint_decode(buffer, bp - buffer, result);
        if ((*buffer_length = bp - be) > 0) {
            memmove(buffer, be, *buffer_length);
        }
    }
    return bytes;
}

void h3zero_release_header_parts(h3zero_header_parts_t* header)
{
    if (header->path != NULL) {
        free((uint8_t*)header->path);
        *((uint8_t**)&header->path) = NULL;
        header->path_length = 0;
    }
    if (header->range != NULL) {
        free((uint8_t*)header->range);
        *((uint8_t**)&header->range) = NULL;
        header->range_length = 0;
    }
    if (header->protocol != NULL) {
        free((uint8_t*)header->protocol);
        *((uint8_t**)&header->protocol) = NULL;
        header->protocol_length = 0;
    }
}

void h3zero_delete_data_stream_state(h3zero_data_stream_state_t * stream_state)
{
    if (stream_state->header_found){
        h3zero_release_header_parts(&stream_state->header);
    }

    if (stream_state->trailer_found){
        h3zero_release_header_parts(&stream_state->trailer);
    }

    if (stream_state->current_frame != NULL) {
        free(stream_state->current_frame);
        stream_state->current_frame = NULL;
    }
}

/*
 * Setting frame.
 * The setting frame is encoded as as set of 16 bit identifiers and varint values.
 * For convenience, we set the first byte to the integer 0 that identifies
 * a control stream.
 */

static uint8_t const h3zero_default_setting_frame_val[] = {
    0, /* Control Stream ID, varint = 0 */
    (uint8_t)h3zero_frame_settings, /* var int frame type ( < 64) */
    17, /* Length of setting frame content */
    (uint8_t)h3zero_setting_header_table_size, 0, /* var int type ( < 64), then var int value (0) */
    (uint8_t)h3zero_qpack_blocked_streams, 0, /* var int type ( < 64),  then var int value (0) Control*/
    /* enable_connect_protocol = 0x8 */
    (uint8_t)h3zero_settings_enable_connect_protocol, 1,
    /* datagram support */
    (uint8_t)h3zero_setting_h3_datagram, 1,
    /* Declare max 1 web transport session */
    (uint8_t)0xC0, 0, 0, 0,
    ((h3zero_settings_webtransport_max_sessions >> 24)&0xff)|0x80,
    (uint8_t)((h3zero_settings_webtransport_max_sessions >> 16)&0xff),
    (uint8_t)((h3zero_settings_webtransport_max_sessions >> 8)&0xff),
    (uint8_t)((h3zero_settings_webtransport_max_sessions)&0xff), 1
};

uint8_t const * h3zero_default_setting_frame = h3zero_default_setting_frame_val;

const size_t h3zero_default_setting_frame_size = sizeof(h3zero_default_setting_frame_val);

/* There is no way in QPACK to prevent sender from using Huffman 
 * encoding. We use a simple decoding function with two tables:
 * - h3zero_qpack_huffman_bit, 64 bytes, 512 bits
 * - h3zero_qpack_huffman_val, 512 bytes.
 * If the bit at position "i" is set in the "bit" table, the code decoded so
 * far is an index. Increase "i" by one if the input byte is zero, by the
 * value in the "val" table if 1.
 * If the bit at position "i" is set in the "bit" table, the code decoded so
 * far is a terminal. Add the value in "val" to the decoded octet list, and
 * reset the index "i" to zero.
 */

const uint8_t h3zero_qpack_huffman_bit[64] = {
    249,
    50,
    115,
    39,
    38,
    79,
    147,
    39,
    38,
    100,
    249,
    50,
    114,
    100,
    242,
    100,
    228,
    228,
    206,
    77,
    52,
    228,
    204,
    203,
    202,
    114,
    102,
    79,
    147,
    39,
    76,
    156,
    153,
    62,
    76,
    156,
    156,
    153,
    62,
    76,
    156,
    153,
    60,
    154,
    100,
    242,
    102,
    79,
    147,
    39,
    38,
    83,
    228,
    201,
    201,
    147,
    211,
    39,
    38,
    79,
    38,
    78,
    76,
    178
};

const uint8_t h3zero_qpack_huffman_val[512] = {
    /* 0: |  X: 44 */ 44,
    /* 1: |0  X: 17 */ 16,
    /* 2: |00  X: 10 */ 8,
    /* 3: |000  X: 7 */ 4,
    /* 4: |0000  X: 6 */ 2,
    /* 5: |00000  V: 48 */ 48,
    /* 6: |00001  V: 49 */ 49,
    /* 7: |0001  X: 9 */ 2,
    /* 8: |00010  V: 50 */ 50,
    /* 9: |00011  V: 97 */ 97,
    /* 10: |001  X: 14 */ 4,
    /* 11: |0010  X: 13 */ 2,
    /* 12: |00100  V: 99 */ 99,
    /* 13: |00101  V: 101 */ 101,
    /* 14: |0011  X: 16 */ 2,
    /* 15: |00110  V: 105 */ 105,
    /* 16: |00111  V: 111 */ 111,
    /* 17: |01  X: 29 */ 12,
    /* 18: |010  X: 22 */ 4,
    /* 19: |0100  X: 21 */ 2,
    /* 20: |01000  V: 115 */ 115,
    /* 21: |01001  V: 116 */ 116,
    /* 22: |0101  X: 26 */ 4,
    /* 23: |01010  X: 25 */ 2,
    /* 24: |010100  V: 32 */ 32,
    /* 25: |010101  V: 37 */ 37,
    /* 26: |01011  X: 28 */ 2,
    /* 27: |010110  V: 45 */ 45,
    /* 28: |010111  V: 46 */ 46,
    /* 29: |011  X: 37 */ 8,
    /* 30: |0110  X: 34 */ 4,
    /* 31: |01100  X: 33 */ 2,
    /* 32: |011000  V: 47 */ 47,
    /* 33: |011001  V: 51 */ 51,
    /* 34: |01101  X: 36 */ 2,
    /* 35: |011010  V: 52 */ 52,
    /* 36: |011011  V: 53 */ 53,
    /* 37: |0111  X: 41 */ 4,
    /* 38: |01110  X: 40 */ 2,
    /* 39: |011100  V: 54 */ 54,
    /* 40: |011101  V: 55 */ 55,
    /* 41: |01111  X: 43 */ 2,
    /* 42: |011110  V: 56 */ 56,
    /* 43: |011111  V: 57 */ 57,
    /* 44: |1  X: 80 */ 36,
    /* 45: |10  X: 61 */ 16,
    /* 46: |100  X: 54 */ 8,
    /* 47: |1000  X: 51 */ 4,
    /* 48: |10000  X: 50 */ 2,
    /* 49: |100000  V: 61 */ 61,
    /* 50: |100001  V: 65 */ 65,
    /* 51: |10001  X: 53 */ 2,
    /* 52: |100010  V: 95 */ 95,
    /* 53: |100011  V: 98 */ 98,
    /* 54: |1001  X: 58 */ 4,
    /* 55: |10010  X: 57 */ 2,
    /* 56: |100100  V: 100 */ 100,
    /* 57: |100101  V: 102 */ 102,
    /* 58: |10011  X: 60 */ 2,
    /* 59: |100110  V: 103 */ 103,
    /* 60: |100111  V: 104 */ 104,
    /* 61: |101  X: 69 */ 8,
    /* 62: |1010  X: 66 */ 4,
    /* 63: |10100  X: 65 */ 2,
    /* 64: |101000  V: 108 */ 108,
    /* 65: |101001  V: 109 */ 109,
    /* 66: |10101  X: 68 */ 2,
    /* 67: |101010  V: 110 */ 110,
    /* 68: |101011  V: 112 */ 112,
    /* 69: |1011  X: 73 */ 4,
    /* 70: |10110  X: 72 */ 2,
    /* 71: |101100  V: 114 */ 114,
    /* 72: |101101  V: 117 */ 117,
    /* 73: |10111  X: 77 */ 4,
    /* 74: |101110  X: 76 */ 2,
    /* 75: |1011100  V: 58 */ 58,
    /* 76: |1011101  V: 66 */ 66,
    /* 77: |101111  X: 79 */ 2,
    /* 78: |1011110  V: 67 */ 67,
    /* 79: |1011111  V: 68 */ 68,
    /* 80: |11  X: 112 */ 32,
    /* 81: |110  X: 97 */ 16,
    /* 82: |1100  X: 90 */ 8,
    /* 83: |11000  X: 87 */ 4,
    /* 84: |110000  X: 86 */ 2,
    /* 85: |1100000  V: 69 */ 69,
    /* 86: |1100001  V: 70 */ 70,
    /* 87: |110001  X: 89 */ 2,
    /* 88: |1100010  V: 71 */ 71,
    /* 89: |1100011  V: 72 */ 72,
    /* 90: |11001  X: 94 */ 4,
    /* 91: |110010  X: 93 */ 2,
    /* 92: |1100100  V: 73 */ 73,
    /* 93: |1100101  V: 74 */ 74,
    /* 94: |110011  X: 96 */ 2,
    /* 95: |1100110  V: 75 */ 75,
    /* 96: |1100111  V: 76 */ 76,
    /* 97: |1101  X: 105 */ 8,
    /* 98: |11010  X: 102 */ 4,
    /* 99: |110100  X: 101 */ 2,
    /* 100: |1101000  V: 77 */ 77,
    /* 101: |1101001  V: 78 */ 78,
    /* 102: |110101  X: 104 */ 2,
    /* 103: |1101010  V: 79 */ 79,
    /* 104: |1101011  V: 80 */ 80,
    /* 105: |11011  X: 109 */ 4,
    /* 106: |110110  X: 108 */ 2,
    /* 107: |1101100  V: 81 */ 81,
    /* 108: |1101101  V: 82 */ 82,
    /* 109: |110111  X: 111 */ 2,
    /* 110: |1101110  V: 83 */ 83,
    /* 111: |1101111  V: 84 */ 84,
    /* 112: |111  X: 128 */ 16,
    /* 113: |1110  X: 121 */ 8,
    /* 114: |11100  X: 118 */ 4,
    /* 115: |111000  X: 117 */ 2,
    /* 116: |1110000  V: 85 */ 85,
    /* 117: |1110001  V: 86 */ 86,
    /* 118: |111001  X: 120 */ 2,
    /* 119: |1110010  V: 87 */ 87,
    /* 120: |1110011  V: 89 */ 89,
    /* 121: |11101  X: 125 */ 4,
    /* 122: |111010  X: 124 */ 2,
    /* 123: |1110100  V: 106 */ 106,
    /* 124: |1110101  V: 107 */ 107,
    /* 125: |111011  X: 127 */ 2,
    /* 126: |1110110  V: 113 */ 113,
    /* 127: |1110111  V: 118 */ 118,
    /* 128: |1111  X: 136 */ 8,
    /* 129: |11110  X: 133 */ 4,
    /* 130: |111100  X: 132 */ 2,
    /* 131: |1111000  V: 119 */ 119,
    /* 132: |1111001  V: 120 */ 120,
    /* 133: |111101  X: 135 */ 2,
    /* 134: |1111010  V: 121 */ 121,
    /* 135: |1111011  V: 122 */ 122,
    /* 136: |11111  X: 144 */ 8,
    /* 137: |111110  X: 141 */ 4,
    /* 138: |1111100  X: 140 */ 2,
    /* 139: |11111000  V: 38 */ 38,
    /* 140: |11111001  V: 42 */ 42,
    /* 141: |1111101  X: 143 */ 2,
    /* 142: |11111010  V: 44 */ 44,
    /* 143: |11111011  V: 59 */ 59,
    /* 144: |111111  X: 148 */ 4,
    /* 145: |1111110  X: 147 */ 2,
    /* 146: |11111100  V: 88 */ 88,
    /* 147: |11111101  V: 90 */ 90,
    /* 148: |1111111  X: 156 */ 8,
    /* 149: |11111110  X: 153 */ 4,
    /* 150: |11111110|0  X: 152 */ 2,
    /* 151: |11111110|00  V: 33 */ 33,
    /* 152: |11111110|01  V: 34 */ 34,
    /* 153: |11111110|1  X: 155 */ 2,
    /* 154: |11111110|10  V: 40 */ 40,
    /* 155: |11111110|11  V: 41 */ 41,
    /* 156: |11111111|  X: 162 */ 6,
    /* 157: |11111111|0  X: 159 */ 2,
    /* 158: |11111111|00  V: 63 */ 63,
    /* 159: |11111111|01  X: 161 */ 2,
    /* 160: |11111111|010  V: 39 */ 39,
    /* 161: |11111111|011  V: 43 */ 43,
    /* 162: |11111111|1  X: 168 */ 6,
    /* 163: |11111111|10  X: 165 */ 2,
    /* 164: |11111111|100  V: 124 */ 124,
    /* 165: |11111111|101  X: 167 */ 2,
    /* 166: |11111111|1010  V: 35 */ 35,
    /* 167: |11111111|1011  V: 62 */ 62,
    /* 168: |11111111|11  X: 176 */ 8,
    /* 169: |11111111|110  X: 173 */ 4,
    /* 170: |11111111|1100  X: 172 */ 2,
    /* 171: |11111111|11000  V: 0 */ 0,
    /* 172: |11111111|11001  V: 36 */ 36,
    /* 173: |11111111|1101  X: 175 */ 2,
    /* 174: |11111111|11010  V: 64 */ 64,
    /* 175: |11111111|11011  V: 91 */ 91,
    /* 176: |11111111|111  X: 180 */ 4,
    /* 177: |11111111|1110  X: 179 */ 2,
    /* 178: |11111111|11100  V: 93 */ 93,
    /* 179: |11111111|11101  V: 126 */ 126,
    /* 180: |11111111|1111  X: 184 */ 4,
    /* 181: |11111111|11110  X: 183 */ 2,
    /* 182: |11111111|111100  V: 94 */ 94,
    /* 183: |11111111|111101  V: 125 */ 125,
    /* 184: |11111111|11111  X: 188 */ 4,
    /* 185: |11111111|111110  X: 187 */ 2,
    /* 186: |11111111|1111100  V: 60 */ 60,
    /* 187: |11111111|1111101  V: 96 */ 96,
    /* 188: |11111111|111111  X: 190 */ 2,
    /* 189: |11111111|1111110  V: 123 */ 123,
    /* 190: |11111111|1111111  X: 220 */ 30,
    /* 191: |11111111|11111110|  X: 201 */ 10,
    /* 192: |11111111|11111110|0  X: 196 */ 4,
    /* 193: |11111111|11111110|00  X: 195 */ 2,
    /* 194: |11111111|11111110|000  V: 92 */ 92,
    /* 195: |11111111|11111110|001  V: 195 */ 195,
    /* 196: |11111111|11111110|01  X: 198 */ 2,
    /* 197: |11111111|11111110|010  V: 208 */ 208,
    /* 198: |11111111|11111110|011  X: 200 */ 2,
    /* 199: |11111111|11111110|0110  V: 128 */ 128,
    /* 200: |11111111|11111110|0111  V: 130 */ 130,
    /* 201: |11111111|11111110|1  X: 209 */ 8,
    /* 202: |11111111|11111110|10  X: 206 */ 4,
    /* 203: |11111111|11111110|100  X: 205 */ 2,
    /* 204: |11111111|11111110|1000  V: 131 */ 131,
    /* 205: |11111111|11111110|1001  V: 162 */ 162,
    /* 206: |11111111|11111110|101  X: 208 */ 2,
    /* 207: |11111111|11111110|1010  V: 184 */ 184,
    /* 208: |11111111|11111110|1011  V: 194 */ 194,
    /* 209: |11111111|11111110|11  X: 213 */ 4,
    /* 210: |11111111|11111110|110  X: 212 */ 2,
    /* 211: |11111111|11111110|1100  V: 224 */ 224,
    /* 212: |11111111|11111110|1101  V: 226 */ 226,
    /* 213: |11111111|11111110|111  X: 217 */ 4,
    /* 214: |11111111|11111110|1110  X: 216 */ 2,
    /* 215: |11111111|11111110|11100  V: 153 */ 153,
    /* 216: |11111111|11111110|11101  V: 161 */ 161,
    /* 217: |11111111|11111110|1111  X: 219 */ 2,
    /* 218: |11111111|11111110|11110  V: 167 */ 167,
    /* 219: |11111111|11111110|11111  V: 172 */ 172,
    /* 220: |11111111|11111111|  X: 266 */ 46,
    /* 221: |11111111|11111111|0  X: 237 */ 16,
    /* 222: |11111111|11111111|00  X: 230 */ 8,
    /* 223: |11111111|11111111|000  X: 227 */ 4,
    /* 224: |11111111|11111111|0000  X: 226 */ 2,
    /* 225: |11111111|11111111|00000  V: 176 */ 176,
    /* 226: |11111111|11111111|00001  V: 177 */ 177,
    /* 227: |11111111|11111111|0001  X: 229 */ 2,
    /* 228: |11111111|11111111|00010  V: 179 */ 179,
    /* 229: |11111111|11111111|00011  V: 209 */ 209,
    /* 230: |11111111|11111111|001  X: 234 */ 4,
    /* 231: |11111111|11111111|0010  X: 233 */ 2,
    /* 232: |11111111|11111111|00100  V: 216 */ 216,
    /* 233: |11111111|11111111|00101  V: 217 */ 217,
    /* 234: |11111111|11111111|0011  X: 236 */ 2,
    /* 235: |11111111|11111111|00110  V: 227 */ 227,
    /* 236: |11111111|11111111|00111  V: 229 */ 229,
    /* 237: |11111111|11111111|01  X: 251 */ 14,
    /* 238: |11111111|11111111|010  X: 244 */ 6,
    /* 239: |11111111|11111111|0100  X: 241 */ 2,
    /* 240: |11111111|11111111|01000  V: 230 */ 230,
    /* 241: |11111111|11111111|01001  X: 243 */ 2,
    /* 242: |11111111|11111111|010010  V: 129 */ 129,
    /* 243: |11111111|11111111|010011  V: 132 */ 132,
    /* 244: |11111111|11111111|0101  X: 248 */ 4,
    /* 245: |11111111|11111111|01010  X: 247 */ 2,
    /* 246: |11111111|11111111|010100  V: 133 */ 133,
    /* 247: |11111111|11111111|010101  V: 134 */ 134,
    /* 248: |11111111|11111111|01011  X: 250 */ 2,
    /* 249: |11111111|11111111|010110  V: 136 */ 136,
    /* 250: |11111111|11111111|010111  V: 146 */ 146,
    /* 251: |11111111|11111111|011  X: 259 */ 8,
    /* 252: |11111111|11111111|0110  X: 256 */ 4,
    /* 253: |11111111|11111111|01100  X: 255 */ 2,
    /* 254: |11111111|11111111|011000  V: 154 */ 154,
    /* 255: |11111111|11111111|011001  V: 156 */ 156,
    /* 256: |11111111|11111111|01101  X: 257 */ 2,
    /* 257: |11111111|11111111|011010  V: 160 */ 160,
    /* 258: |11111111|11111111|011011  V: 163 */ 163,
    /* 259: |11111111|11111111|0111  X: 263 */ 4,
    /* 260: |11111111|11111111|01110  X: 262 */ 2,
    /* 261: |11111111|11111111|011100  V: 164 */ 164,
    /* 262: |11111111|11111111|011101  V: 169 */ 169,
    /* 263: |11111111|11111111|01111  X: 265 */ 2,
    /* 264: |11111111|11111111|011110  V: 170 */ 170,
    /* 265: |11111111|11111111|011111  V: 173 */ 173,
    /* 266: |11111111|11111111|1  X: 306 */ 40,
    /* 267: |11111111|11111111|10  X: 283 */ 16,
    /* 268: |11111111|11111111|100  X: 276 */ 8,
    /* 269: |11111111|11111111|1000  X: 273 */ 4,
    /* 270: |11111111|11111111|10000  X: 272 */ 2,
    /* 271: |11111111|11111111|100000  V: 178 */ 178,
    /* 272: |11111111|11111111|100001  V: 181 */ 181,
    /* 273: |11111111|11111111|10001  X: 275 */ 2,
    /* 274: |11111111|11111111|100010  V: 185 */ 185,
    /* 275: |11111111|11111111|100011  V: 186 */ 186,
    /* 276: |11111111|11111111|1001  X: 280 */ 4,
    /* 277: |11111111|11111111|10010  X: 279 */ 2,
    /* 278: |11111111|11111111|100100  V: 187 */ 187,
    /* 279: |11111111|11111111|100101  V: 189 */ 189,
    /* 280: |11111111|11111111|10011  X: 282 */ 2,
    /* 281: |11111111|11111111|100110  V: 190 */ 190,
    /* 282: |11111111|11111111|100111  V: 196 */ 196,
    /* 283: |11111111|11111111|101  X: 291 */ 8,
    /* 284: |11111111|11111111|1010  X: 288 */ 4,
    /* 285: |11111111|11111111|10100  X: 287 */ 2,
    /* 286: |11111111|11111111|101000  V: 198 */ 198,
    /* 287: |11111111|11111111|101001  V: 228 */ 228,
    /* 288: |11111111|11111111|10101  X: 290 */ 2,
    /* 289: |11111111|11111111|101010  V: 232 */ 232,
    /* 290: |11111111|11111111|101011  V: 233 */ 233,
    /* 291: |11111111|11111111|1011  X: 299 */ 8,
    /* 292: |11111111|11111111|10110  X: 296 */ 4,
    /* 293: |11111111|11111111|101100  X: 295 */ 2,
    /* 294: |11111111|11111111|1011000  V: 1 */ 1,
    /* 295: |11111111|11111111|1011001  V: 135 */ 135,
    /* 296: |11111111|11111111|101101  X: 298 */ 2,
    /* 297: |11111111|11111111|1011010  V: 137 */ 137,
    /* 298: |11111111|11111111|1011011  V: 138 */ 138,
    /* 299: |11111111|11111111|10111  X: 303 */ 4,
    /* 300: |11111111|11111111|101110  X: 302 */ 2,
    /* 301: |11111111|11111111|1011100  V: 139 */ 139,
    /* 302: |11111111|11111111|1011101  V: 140 */ 140,
    /* 303: |11111111|11111111|101111  X: 305 */ 2,
    /* 304: |11111111|11111111|1011110  V: 141 */ 141,
    /* 305: |11111111|11111111|1011111  V: 143 */ 143,
    /* 306: |11111111|11111111|11  X: 338 */ 32,
    /* 307: |11111111|11111111|110  X: 323 */ 16,
    /* 308: |11111111|11111111|1100  X: 316 */ 8,
    /* 309: |11111111|11111111|11000  X: 313 */ 4,
    /* 310: |11111111|11111111|110000  X: 312 */ 2,
    /* 311: |11111111|11111111|1100000  V: 147 */ 147,
    /* 312: |11111111|11111111|1100001  V: 149 */ 149,
    /* 313: |11111111|11111111|110001  X: 315 */ 2,
    /* 314: |11111111|11111111|1100010  V: 150 */ 150,
    /* 315: |11111111|11111111|1100011  V: 151 */ 151,
    /* 316: |11111111|11111111|11001  X: 320 */ 4,
    /* 317: |11111111|11111111|110010  X: 319 */ 2,
    /* 318: |11111111|11111111|1100100  V: 152 */ 152,
    /* 319: |11111111|11111111|1100101  V: 155 */ 155,
    /* 320: |11111111|11111111|110011  X: 322 */ 2,
    /* 321: |11111111|11111111|1100110  V: 157 */ 157,
    /* 322: |11111111|11111111|1100111  V: 158 */ 158,
    /* 323: |11111111|11111111|1101  X: 331 */ 8,
    /* 324: |11111111|11111111|11010  X: 328 */ 4,
    /* 325: |11111111|11111111|110100  X: 327 */ 2,
    /* 326: |11111111|11111111|1101000  V: 165 */ 165,
    /* 327: |11111111|11111111|1101001  V: 166 */ 166,
    /* 328: |11111111|11111111|110101  X: 330 */ 2,
    /* 329: |11111111|11111111|1101010  V: 168 */ 168,
    /* 330: |11111111|11111111|1101011  V: 174 */ 174,
    /* 331: |11111111|11111111|11011  X: 335 */ 4,
    /* 332: |11111111|11111111|110110  X: 334 */ 2,
    /* 333: |11111111|11111111|1101100  V: 175 */ 175,
    /* 334: |11111111|11111111|1101101  V: 180 */ 180,
    /* 335: |11111111|11111111|110111  X: 337 */ 2,
    /* 336: |11111111|11111111|1101110  V: 182 */ 182,
    /* 337: |11111111|11111111|1101111  V: 183 */ 183,
    /* 338: |11111111|11111111|111  X: 360 */ 22,
    /* 339: |11111111|11111111|1110  X: 347 */ 8,
    /* 340: |11111111|11111111|11100  X: 344 */ 4,
    /* 341: |11111111|11111111|111000  X: 343 */ 2,
    /* 342: |11111111|11111111|1110000  V: 188 */ 188,
    /* 343: |11111111|11111111|1110001  V: 191 */ 191,
    /* 344: |11111111|11111111|111001  X: 346 */ 2,
    /* 345: |11111111|11111111|1110010  V: 197 */ 197,
    /* 346: |11111111|11111111|1110011  V: 231 */ 231,
    /* 347: |11111111|11111111|11101  X: 353 */ 6,
    /* 348: |11111111|11111111|111010  X: 350 */ 2,
    /* 349: |11111111|11111111|1110100  V: 239 */ 239,
    /* 350: |11111111|11111111|1110101  X: 352 */ 2,
    /* 351: |11111111|11111111|11101010  V: 9 */ 9,
    /* 352: |11111111|11111111|11101011  V: 142 */ 142,
    /* 353: |11111111|11111111|111011  X: 357 */ 4,
    /* 354: |11111111|11111111|1110110  X: 356 */ 2,
    /* 355: |11111111|11111111|11101100  V: 144 */ 144,
    /* 356: |11111111|11111111|11101101  V: 145 */ 145,
    /* 357: |11111111|11111111|1110111  X: 359 */ 2,
    /* 358: |11111111|11111111|11101110  V: 148 */ 148,
    /* 359: |11111111|11111111|11101111  V: 159 */ 159,
    /* 360: |11111111|11111111|1111  X: 380 */ 20,
    /* 361: |11111111|11111111|11110  X: 369 */ 8,
    /* 362: |11111111|11111111|111100  X: 366 */ 4,
    /* 363: |11111111|11111111|1111000  X: 365 */ 2,
    /* 364: |11111111|11111111|11110000  V: 171 */ 171,
    /* 365: |11111111|11111111|11110001  V: 206 */ 206,
    /* 366: |11111111|11111111|1111001  X: 368 */ 2,
    /* 367: |11111111|11111111|11110010  V: 215 */ 215,
    /* 368: |11111111|11111111|11110011  V: 225 */ 225,
    /* 369: |11111111|11111111|111101  X: 373 */ 4,
    /* 370: |11111111|11111111|1111010  X: 372 */ 2,
    /* 371: |11111111|11111111|11110100  V: 236 */ 236,
    /* 372: |11111111|11111111|11110101  V: 237 */ 237,
    /* 373: |11111111|11111111|1111011  X: 377 */ 4,
    /* 374: |11111111|11111111|11110110|  X: 376 */ 2,
    /* 375: |11111111|11111111|11110110|0  V: 199 */ 199,
    /* 376: |11111111|11111111|11110110|1  V: 207 */ 207,
    /* 377: |11111111|11111111|11110111|  X: 379 */ 2,
    /* 378: |11111111|11111111|11110111|0  V: 234 */ 234,
    /* 379: |11111111|11111111|11110111|1  V: 235 */ 235,
    /* 380: |11111111|11111111|11111  X: 414 */ 34,
    /* 381: |11111111|11111111|111110  X: 397 */ 16,
    /* 382: |11111111|11111111|1111100  X: 390 */ 8,
    /* 383: |11111111|11111111|11111000|  X: 387 */ 4,
    /* 384: |11111111|11111111|11111000|0  X: 386 */ 2,
    /* 385: |11111111|11111111|11111000|00  V: 192 */ 192,
    /* 386: |11111111|11111111|11111000|01  V: 193 */ 193,
    /* 387: |11111111|11111111|11111000|1  X: 389 */ 2,
    /* 388: |11111111|11111111|11111000|10  V: 200 */ 200,
    /* 389: |11111111|11111111|11111000|11  V: 201 */ 201,
    /* 390: |11111111|11111111|11111001|  X: 394 */ 4,
    /* 391: |11111111|11111111|11111001|0  X: 393 */ 2,
    /* 392: |11111111|11111111|11111001|00  V: 202 */ 202,
    /* 393: |11111111|11111111|11111001|01  V: 205 */ 205,
    /* 394: |11111111|11111111|11111001|1  X: 396 */ 2,
    /* 395: |11111111|11111111|11111001|10  V: 210 */ 210,
    /* 396: |11111111|11111111|11111001|11  V: 213 */ 213,
    /* 397: |11111111|11111111|1111101  X: 405 */ 8,
    /* 398: |11111111|11111111|11111010|  X: 402 */ 4,
    /* 399: |11111111|11111111|11111010|0  X: 401 */ 2,
    /* 400: |11111111|11111111|11111010|00  V: 218 */ 218,
    /* 401: |11111111|11111111|11111010|01  V: 219 */ 219,
    /* 402: |11111111|11111111|11111010|1  X: 404 */ 2,
    /* 403: |11111111|11111111|11111010|10  V: 238 */ 238,
    /* 404: |11111111|11111111|11111010|11  V: 240 */ 240,
    /* 405: |11111111|11111111|11111011|  X: 409 */ 4,
    /* 406: |11111111|11111111|11111011|0  X: 408 */ 2,
    /* 407: |11111111|11111111|11111011|00  V: 242 */ 242,
    /* 408: |11111111|11111111|11111011|01  V: 243 */ 243,
    /* 409: |11111111|11111111|11111011|1  X: 411 */ 2,
    /* 410: |11111111|11111111|11111011|10  V: 255 */ 255,
    /* 411: |11111111|11111111|11111011|11  X: 413 */ 2,
    /* 412: |11111111|11111111|11111011|110  V: 203 */ 203,
    /* 413: |11111111|11111111|11111011|111  V: 204 */ 204,
    /* 414: |11111111|11111111|111111  X: 446 */ 32,
    /* 415: |11111111|11111111|1111110  X: 431 */ 16,
    /* 416: |11111111|11111111|11111100|  X: 424 */ 8,
    /* 417: |11111111|11111111|11111100|0  X: 421 */ 4,
    /* 418: |11111111|11111111|11111100|00  X: 420 */ 2,
    /* 419: |11111111|11111111|11111100|000  V: 211 */ 211,
    /* 420: |11111111|11111111|11111100|001  V: 212 */ 212,
    /* 421: |11111111|11111111|11111100|01  X: 423 */ 2,
    /* 422: |11111111|11111111|11111100|010  V: 214 */ 214,
    /* 423: |11111111|11111111|11111100|011  V: 221 */ 221,
    /* 424: |11111111|11111111|11111100|1  X: 428 */ 4,
    /* 425: |11111111|11111111|11111100|10  X: 427 */ 2,
    /* 426: |11111111|11111111|11111100|100  V: 222 */ 222,
    /* 427: |11111111|11111111|11111100|101  V: 223 */ 223,
    /* 428: |11111111|11111111|11111100|11  X: 430 */ 2,
    /* 429: |11111111|11111111|11111100|110  V: 241 */ 241,
    /* 430: |11111111|11111111|11111100|111  V: 244 */ 244,
    /* 431: |11111111|11111111|11111101|  X: 439 */ 8,
    /* 432: |11111111|11111111|11111101|0  X: 436 */ 4,
    /* 433: |11111111|11111111|11111101|00  X: 435 */ 2,
    /* 434: |11111111|11111111|11111101|000  V: 245 */ 245,
    /* 435: |11111111|11111111|11111101|001  V: 246 */ 246,
    /* 436: |11111111|11111111|11111101|01  X: 438 */ 2,
    /* 437: |11111111|11111111|11111101|010  V: 247 */ 247,
    /* 438: |11111111|11111111|11111101|011  V: 248 */ 248,
    /* 439: |11111111|11111111|11111101|1  X: 443 */ 4,
    /* 440: |11111111|11111111|11111101|10  X: 442 */ 2,
    /* 441: |11111111|11111111|11111101|100  V: 250 */ 250,
    /* 442: |11111111|11111111|11111101|101  V: 251 */ 251,
    /* 443: |11111111|11111111|11111101|11  X: 445 */ 2,
    /* 444: |11111111|11111111|11111101|110  V: 252 */ 252,
    /* 445: |11111111|11111111|11111101|111  V: 253 */ 253,
    /* 446: |11111111|11111111|1111111  X: 476 */ 30,
    /* 447: |11111111|11111111|11111110|  X: 461 */ 14,
    /* 448: |11111111|11111111|11111110|0  X: 454 */ 6,
    /* 449: |11111111|11111111|11111110|00  X: 451 */ 2,
    /* 450: |11111111|11111111|11111110|000  V: 254 */ 254,
    /* 451: |11111111|11111111|11111110|001  X: 453 */ 2,
    /* 452: |11111111|11111111|11111110|0010  V: 2 */ 2,
    /* 453: |11111111|11111111|11111110|0011  V: 3 */ 3,
    /* 454: |11111111|11111111|11111110|01  X: 458 */ 4,
    /* 455: |11111111|11111111|11111110|010  X: 457 */ 2,
    /* 456: |11111111|11111111|11111110|0100  V: 4 */ 4,
    /* 457: |11111111|11111111|11111110|0101  V: 5 */ 5,
    /* 458: |11111111|11111111|11111110|011  X: 460 */ 2,
    /* 459: |11111111|11111111|11111110|0110  V: 6 */ 6,
    /* 460: |11111111|11111111|11111110|0111  V: 7 */ 7,
    /* 461: |11111111|11111111|11111110|1  X: 469 */ 8,
    /* 462: |11111111|11111111|11111110|10  X: 466 */ 4,
    /* 463: |11111111|11111111|11111110|100  X: 465 */ 2,
    /* 464: |11111111|11111111|11111110|1000  V: 8 */ 8,
    /* 465: |11111111|11111111|11111110|1001  V: 11 */ 11,
    /* 466: |11111111|11111111|11111110|101  X: 468 */ 2,
    /* 467: |11111111|11111111|11111110|1010  V: 12 */ 12,
    /* 468: |11111111|11111111|11111110|1011  V: 14 */ 14,
    /* 469: |11111111|11111111|11111110|11  X: 473 */ 4,
    /* 470: |11111111|11111111|11111110|110  X: 472 */ 2,
    /* 471: |11111111|11111111|11111110|1100  V: 15 */ 15,
    /* 472: |11111111|11111111|11111110|1101  V: 16 */ 16,
    /* 473: |11111111|11111111|11111110|111  X: 475 */ 2,
    /* 474: |11111111|11111111|11111110|1110  V: 17 */ 17,
    /* 475: |11111111|11111111|11111110|1111  V: 18 */ 18,
    /* 476: |11111111|11111111|11111111|  X: 492 */ 16,
    /* 477: |11111111|11111111|11111111|0  X: 485 */ 8,
    /* 478: |11111111|11111111|11111111|00  X: 482 */ 4,
    /* 479: |11111111|11111111|11111111|000  X: 481 */ 2,
    /* 480: |11111111|11111111|11111111|0000  V: 19 */ 19,
    /* 481: |11111111|11111111|11111111|0001  V: 20 */ 20,
    /* 482: |11111111|11111111|11111111|001  X: 484 */ 2,
    /* 483: |11111111|11111111|11111111|0010  V: 21 */ 21,
    /* 484: |11111111|11111111|11111111|0011  V: 23 */ 23,
    /* 485: |11111111|11111111|11111111|01  X: 489 */ 4,
    /* 486: |11111111|11111111|11111111|010  X: 488 */ 2,
    /* 487: |11111111|11111111|11111111|0100  V: 24 */ 24,
    /* 488: |11111111|11111111|11111111|0101  V: 25 */ 25,
    /* 489: |11111111|11111111|11111111|011  X: 491 */ 2,
    /* 490: |11111111|11111111|11111111|0110  V: 26 */ 26,
    /* 491: |11111111|11111111|11111111|0111  V: 27 */ 27,
    /* 492: |11111111|11111111|11111111|1  X: 500 */ 8,
    /* 493: |11111111|11111111|11111111|10  X: 497 */ 4,
    /* 494: |11111111|11111111|11111111|100  X: 496 */ 2,
    /* 495: |11111111|11111111|11111111|1000  V: 28 */ 28,
    /* 496: |11111111|11111111|11111111|1001  V: 29 */ 29,
    /* 497: |11111111|11111111|11111111|101  X: 499 */ 2,
    /* 498: |11111111|11111111|11111111|1010  V: 30 */ 30,
    /* 499: |11111111|11111111|11111111|1011  V: 31 */ 31,
    /* 500: |11111111|11111111|11111111|11  X: 504 */ 4,
    /* 501: |11111111|11111111|11111111|110  X: 503 */ 2,
    /* 502: |11111111|11111111|11111111|1100  V: 127 */ 127,
    /* 503: |11111111|11111111|11111111|1101  V: 220 */ 220,
    /* 504: |11111111|11111111|11111111|111  X: 506 */ 2,
    /* 505: |11111111|11111111|11111111|1110  V: 249 */ 249,
    /* 506: |11111111|11111111|11111111|1111  X: 510 */ 4,
    /* 507: |11111111|11111111|11111111|11110  X: 509 */ 2,
    /* 508: |11111111|11111111|11111111|111100  V: 10 */ 10,
    /* 509: |11111111|11111111|11111111|111101  V: 13 */ 13,
    /* 510: |11111111|11111111|11111111|11111  X: 512 */ 2,
    /* 511: |11111111|11111111|11111111|111110  V: 22 */ 22
};

int hzero_qpack_huffman_decode(uint8_t* bytes, uint8_t* bytes_max, uint8_t* decoded, size_t max_decoded, size_t* nb_decoded)
{
    int ret = 0;
    uint64_t val_in = 0;
    int bits_in = 0;
    size_t decoded_index = 0;
    int index = 0;
    int was_all_ones = 1;

    while (1) {
        /* Refill the registry */
        int bit;
        int index_64 = index >> 3;
        int b_index = 7 - (index & 7);

        while (bits_in < 57 && bytes < bytes_max) {
            uint64_t added = *bytes++;
            int shift = 64 - bits_in - 8;
            added <<= shift;
            val_in |= added;
            bits_in += 8;
        }

        if ((h3zero_qpack_huffman_bit[index_64] >> b_index) & 1) {
            /* This is an index location */
            if (bits_in <= 0) {
                /* Reached the end of the input! */
                break;
            }
            bit = (val_in >> 63) & 1;
            val_in <<= 1;
            bits_in--;
            if (bit) {
                index += h3zero_qpack_huffman_val[index];
            }
            else {
                index++;
                was_all_ones = 0;
            }
            if (index >= 512) {
                /* End of string marked by all ones */
                break;
            }
        }
        else if (decoded_index < max_decoded){
            decoded[decoded_index++] = h3zero_qpack_huffman_val[index];
            index = 0;
            was_all_ones = 1;
        }
        else
        {
            /* input is too long */
            was_all_ones = 1;
            break;
        }
    }

    /* Error if break and not all ones before that */
    if (!was_all_ones) {
        ret = -1;
    }

    *nb_decoded = decoded_index;

    return ret;
}
