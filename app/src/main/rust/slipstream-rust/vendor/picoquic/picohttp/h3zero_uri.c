#include "h3zero_uri.h"
#include "h3zero_uri.h"
#include "h3zero_uri.h"
#include "h3zero_uri.h"
#include "h3zero_uri.h"
/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/* Implement parsing of URI and Path, per RFC 3986
* 
* 
    URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

    hier-part     = "//" authority path-abempty
    / path-absolute
    / path-rootless
    / path-empty

    URI-reference = URI / relative-ref

    absolute-URI  = scheme ":" hier-part [ "?" query ]

    relative-ref  = relative-part [ "?" query ] [ "#" fragment ]

    relative-part = "//" authority path-abempty
    / path-absolute
    / path-noscheme
    / path-empty

    scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

    authority     = [ userinfo "@" ] host [ ":" port ]
    userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
    host          = IP-literal / IPv4address / reg-name
    port          = *DIGIT

    IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"

    IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

    IPv6address   =                            6( h16 ":" ) ls32
    /                       "::" 5( h16 ":" ) ls32
    / [               h16 ] "::" 4( h16 ":" ) ls32
    / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
    / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
    / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
    / [ *4( h16 ":" ) h16 ] "::"              ls32
    / [ *5( h16 ":" ) h16 ] "::"              h16
    / [ *6( h16 ":" ) h16 ] "::"

    h16           = 1*4HEXDIG
    ls32          = ( h16 ":" h16 ) / IPv4address
    IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet

    dec-octet     = DIGIT                 ; 0-9
    / %x31-39 DIGIT         ; 10-99
    / "1" 2DIGIT            ; 100-199
    / "2" %x30-34 DIGIT     ; 200-249
    / "25" %x30-35          ; 250-255

    reg-name      = *( unreserved / pct-encoded / sub-delims )

    path          = path-abempty    ; begins with "/" or is empty
    / path-absolute   ; begins with "/" but not "//"
    / path-noscheme   ; begins with a non-colon segment
    / path-rootless   ; begins with a segment
    / path-empty      ; zero characters

    path-abempty  = *( "/" segment )
    path-absolute = "/" [ segment-nz *( "/" segment ) ]
    path-noscheme = segment-nz-nc *( "/" segment )
    path-rootless = segment-nz *( "/" segment )
    path-empty    = 0<pchar>

    segment       = *pchar
    segment-nz    = 1*pchar
    segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
    ; non-zero-length segment without any colon ":"

    pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

    query         = *( pchar / "/" / "?" )

    fragment      = *( pchar / "/" / "?" )

    pct-encoded   = "%" HEXDIG HEXDIG

    unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    reserved      = gen-delims / sub-delims
    gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
    sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
    / "*" / "+" / "," / ";" / "="

* The first priority is to implement the parsing of "path-abempty",
* which is used for example in web transport.
 */

#include <string.h>
#include <stdlib.h>
#include "h3zero_uri.h"

size_t h3zero_pathabempty_length(const uint8_t* path, size_t path_length)
{
    size_t l = 0;
    while (l < path_length) {
        if (path[l] == (uint8_t)'?') {
            break;
        }
        l++;
    }
    return l;
}


size_t h3zero_query_offset(const uint8_t* path, size_t path_length)
{
    size_t query_offset = path_length;
    size_t pathabempty_length = h3zero_pathabempty_length(path, path_length);

    if (pathabempty_length < path_length && path[pathabempty_length] == (uint8_t)'?') {
        query_offset = pathabempty_length + 1;
    }

    return query_offset;
}

size_t h3zero_query_parameter_position(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length)
{
    size_t parameter_position = 0;
    size_t begin_index = 0;
    while (begin_index < queries_length) {
        size_t tentative_position = begin_index + parameter_id_length;
        if (tentative_position <= queries_length &&
            memcmp(queries + begin_index, parameter_id, parameter_id_length) == 0 && (
                tentative_position == queries_length ||
                queries[tentative_position] == '=' ||
                queries[tentative_position] == '&')) {
            parameter_position = tentative_position;
            if (tentative_position < queries_length &&
                queries[tentative_position] == '=') {
                parameter_position += 1;
            }
            break;
        } else {
            while (begin_index < queries_length && queries[begin_index] != '&') {
                begin_index++;
            }
            if (begin_index < queries_length) {
                /* Skip the & delimiter */
                begin_index++;
            }
        }
    }
    return parameter_position;
}

size_t h3zero_query_parameter_length(const uint8_t* parameter_value, size_t max_length)
{
    size_t next_char_index = 0;

    while (next_char_index < max_length && parameter_value[next_char_index] != (uint8_t)'&') {
        next_char_index++;
    }

    return(next_char_index);
}

size_t h3zero_query_parameter_pchar(const uint8_t* bytes, size_t length, size_t next_char_index, uint8_t* p, int * err)
{
    uint8_t v = bytes[next_char_index];
    
    next_char_index++;

    if (v == (uint8_t)'%') {
        int i = 0;

        *err = 0;

        for (; next_char_index < length && i < 2; i++) {
            uint8_t x = bytes[next_char_index];

            next_char_index++;
            v <<= 4;
            if (x >= (uint8_t)'0' && x <= (uint8_t)'9') {
                v += x - (uint8_t)'0';
            }
            else if (x >= (uint8_t)'a' && x <= (uint8_t)'f') {
                v += x - (uint8_t)'a' + 10;
            }
            else if (x >= (uint8_t)'A' && x <= (uint8_t)'F') {
                v += x - (uint8_t)'A' + 10;
            }
            else {
                break;
            }
        }
        if (i < 2) {
            *err = -1;
        } 
    }

    *p = v;
    return next_char_index;
}

int h3zero_query_bytes_to_string(const uint8_t* bytes, size_t length, uint8_t* buffer, size_t buffer_max, size_t* parsed_length)
{
    size_t string_length = 0;
    size_t next_char_index = 0;
    int ret = 0;
    while (ret == 0 && next_char_index < length) {
        uint8_t v;
        next_char_index = h3zero_query_parameter_pchar(bytes, length, next_char_index, &v, &ret);

        if (string_length < buffer_max) {
            buffer[string_length] = v;
            string_length++;
        }
        else {
            ret = -1;
        }
    }
    if (string_length < buffer_max) {
        buffer[string_length] = 0;
    }
    *parsed_length = string_length;

    return ret;
}

int h3zero_query_bytes_to_uint64(const uint8_t* bytes, size_t length, uint64_t* number)
{
    size_t next_char_index = 0;
    int ret = 0;
    uint64_t x = 0;

    while (next_char_index < length && ret == 0) {
        uint8_t v;
        next_char_index = h3zero_query_parameter_pchar(bytes, length, next_char_index, &v, &ret);

        if (ret == 0) {
            if (v >= (uint8_t)'0' && v <= (uint8_t)'9') {
                if (x >= (UINT64_MAX / 10)) {
                    ret = -1;
                } else {
                    uint64_t dv = v - (uint8_t)'0';
                    x = x * 10;
                    if (x > UINT64_MAX - dv) {
                        ret = -1;
                    }
                    else {
                        x += dv;
                    }
                }
            }
            else {
                /* improper character */
                ret = -1;
            }
        }
    }

    *number = x;

    return ret;
}

int h3zero_query_parameter_string(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length, uint8_t * buffer, size_t buffer_size, size_t * parsed_length)
{
    int ret = 0;
    size_t parameter_position = h3zero_query_parameter_position(queries, queries_length, parameter_id, parameter_id_length);

    if (parameter_position != 0) {
        size_t parameter_length = h3zero_query_parameter_length(queries + parameter_position, queries_length - parameter_position);
        ret = h3zero_query_bytes_to_string(queries + parameter_position, parameter_length, buffer, buffer_size, parsed_length);
    }

    return ret;
}

int h3zero_query_parameter_number(const uint8_t* queries, size_t queries_length, const char* parameter_id, size_t parameter_id_length, uint64_t* number, uint64_t default_number)
{

    int ret = 0;
    size_t parameter_length = 0;
    size_t parameter_position = h3zero_query_parameter_position(queries, queries_length, parameter_id, parameter_id_length);


    if (parameter_position != 0) {
        parameter_length = h3zero_query_parameter_length(queries + parameter_position, queries_length - parameter_position);
        ret = h3zero_query_bytes_to_uint64(queries + parameter_position, parameter_length, number);
    }
    if (parameter_length == 0 || ret != 0) {
        *number = default_number;
    }

    return ret;
}
