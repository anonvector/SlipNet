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

/* clang-format off */

/* Simple set of utilities */
#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <Ws2def.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif
#include "picoquic_internal.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_utils.h"

/* clang-format on */

char* picoquic_string_create(const char* original, size_t len)
{
    size_t allocated = len + 1;
    char * str = NULL;

    /* tests to protect against integer overflow */
    if (allocated > 0) {
        str = (char*)malloc(allocated);

        if (str != NULL) {
            if (original == NULL || len == 0) {
                str[0] = 0;
            }
            else if (allocated > len) {
                memcpy(str, original, len);
                str[allocated - 1] = 0;
            }
            else {
                /* This could happen only in case of integer overflow */
                free(str);
                str = NULL;
            }
        }
    }

    return str;
}

char* picoquic_string_duplicate(const char* original)
{
    char* str = NULL;

    if (original != NULL) {
        size_t len = strlen(original);

        str = picoquic_string_create(original, len);
    }

    return str;
}

char* picoquic_string_free(char* str)
{
    if (str != NULL) {
        free(str);
    }

    return NULL;
}

char* picoquic_strip_endofline(char* buf, size_t bufmax, char const* line)
{
    for (size_t i = 0; i < bufmax; i++) {
        int c = line[i];

        if (c == 0 || c == '\r' || c == '\n') {
            buf[i] = 0;
            break;
        }
        else {
            buf[i] = (char) c;
        }
    }

    buf[bufmax - 1] = 0;
    return buf;
}

static FILE* debug_out = NULL;
void (*debug_callback)(const char *msg, void *arg) = NULL;
void *debug_callback_argp = NULL;
static int debug_suspended = 0;

void debug_set_stream(FILE *F)
{
    debug_out = F;
    debug_callback = NULL;
    debug_callback_argp = NULL;
}

void debug_set_callback(void (*cb)(const char *msg, void *argp), void *argp)
{
    debug_callback = cb;
    debug_callback_argp = argp;
    debug_out = NULL;
}

void debug_printf(const char* fmt, ...)
{
    if (debug_suspended == 0 && (debug_out != NULL || debug_callback != NULL)) {
        if (debug_out) {
            va_list args;
            va_start(args, fmt);
            vfprintf(debug_out, fmt, args);
            va_end(args);
        } else {
            char message[1024];
            size_t message_length;
            va_list args;
            va_start(args, fmt);
            vsnprintf(message, sizeof(message), fmt, args);
            va_end(args);
            message_length = strnlen(message, sizeof(message));
            if (message_length > 0) {
                // Strip any trailing newline
                if (message[message_length - 1] == '\n') {
                    message[message_length - 1] = '\0';
                }
            }
            debug_callback(message, debug_callback_argp);
        }
    }
}

void debug_dump(const void * x, int len)
{
    if (debug_suspended == 0 && (debug_out != NULL || debug_callback != NULL)) {
        char msg[64];
        size_t mlen;
        uint8_t * bytes = (uint8_t *)x;

        for (int i = 0; i < len;) {
            snprintf(msg, sizeof(msg), "%04x:  ", (int) i);
            mlen = strnlen(msg, sizeof(msg));

            for (int j = 0; j < 16 && i < len; j++, i++) {
                snprintf(msg + mlen, sizeof(msg) - mlen, "%02x ", bytes[i]);
                mlen = strnlen(msg, sizeof(msg));
            }
            if (debug_out) {
                fprintf(debug_out, "%s\n", msg);
            } else {
                debug_callback(msg, debug_callback_argp);
            }
        }
    }
}

void debug_printf_push_stream(FILE* f)
{
    if (debug_out) {
        fprintf(stderr, "Nested err out not supported\n");
        exit(1);
    }
    debug_out = f;
}

void debug_printf_pop_stream(void)
{
    if (debug_out == NULL) {
        fprintf(stderr, "No current err out\n");
        exit(1);
    }
    debug_out = NULL;
}

void debug_printf_suspend(void)
{
    debug_suspended = 1;
}

void debug_printf_resume(void)
{
    debug_suspended = 0;
}

int debug_printf_reset(int suspended)
{
    int ret = debug_suspended;
    debug_suspended = suspended;
    return ret;
}

int picoquic_sprintf(char* buf, size_t buf_len, size_t * nb_chars, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
#ifdef _WINDOWS
    int res = vsnprintf_s(buf, buf_len, _TRUNCATE, fmt, args);
#else
    int res = vsnprintf(buf, buf_len, fmt, args);
#endif
    va_end(args);

    if (nb_chars != NULL) {
        *nb_chars = res;
    }

    // vsnprintf returns <0 for errors and >=0 for nb of characters required.
    // We return 0 when printing was successful.
    return res >= 0 ? ((size_t)res >= buf_len) : res;
}

int picoquic_print_connection_id_hexa(char* buf, size_t buf_len, const picoquic_connection_id_t * cnxid)
{
    static const char hex_to_char[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    if (buf_len < ((size_t)cnxid->id_len) * 2u + 1u) {
        return -1;  
    }

    for (unsigned i = 0; i < cnxid->id_len; i++) {
        buf[i * 2u] = hex_to_char[cnxid->id[i] >> 4];
        buf[i * 2u + 1u] = hex_to_char[cnxid->id[i] & 0x0f];
    }

    buf[cnxid->id_len * 2u] = 0;

    return 0;
}

int picoquic_parse_hexa_digit(char x) {
    int ret = -1;

    if (x >= '0' && x <= '9') {
        ret = x - '0';
    }
    else if (x >= 'A' && x <= 'F') {
        ret = x - 'A' + 10;
    }
    else if (x >= 'a' && x <= 'f') {
        ret = x - 'a' + 10;
    }

    return ret;
}

size_t picoquic_parse_hexa(char const * hex_input, size_t input_length, uint8_t * bin_output, size_t output_max)
{
    size_t ret = 0;
    if (input_length > 0 && (input_length & 1) == 0 && 2*output_max >= input_length) {
        size_t offset = 0;

        while (offset < input_length) {
            int a = picoquic_parse_hexa_digit(hex_input[offset++]);
            int b = picoquic_parse_hexa_digit(hex_input[offset++]);

            if (a < 0 || b < 0) {
                ret = 0;
                break;
            }
            else {
                bin_output[ret++] = (uint8_t)((a << 4) | b);
            }
        }
    }

    return ret;
}

uint8_t picoquic_parse_connection_id_hexa(char const * hex_input, size_t input_length, picoquic_connection_id_t * cnx_id)
{
    memset(cnx_id, 0, sizeof(picoquic_connection_id_t));
    cnx_id->id_len = (uint8_t) picoquic_parse_hexa(hex_input, input_length, cnx_id->id, 18);

    if (cnx_id->id_len == 0) {
        memset(cnx_id, 0, sizeof(picoquic_connection_id_t));
    }

    return (cnx_id->id_len);
}

uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len)
{
    uint8_t ret;

    ret = (dest_len < 4) ? 0 : (dest_len - 3);
    ret <<= 4;
    ret |= (srce_len < 4) ? 0 : (srce_len - 3);

    return ret;
}

uint8_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id)
{
    uint8_t copied = cnx_id.id_len;
    if (copied > bytes_max || copied == 0) {
        copied = 0;
    } else {
        memcpy(bytes, cnx_id.id, copied);
    }

    return copied;
}

uint8_t picoquic_parse_connection_id(const uint8_t * bytes, uint8_t len, picoquic_connection_id_t * cnx_id)
{
    if (len <= PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        cnx_id->id_len = len;
        memcpy(cnx_id->id, bytes, len);
    } else {
        len = 0;
        cnx_id->id_len = 0;
    }
    return len;
}

const picoquic_connection_id_t picoquic_null_connection_id = { 
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0 };

int picoquic_is_connection_id_null(const picoquic_connection_id_t * cnx_id)
{
    return (cnx_id->id_len == 0) ? 1 : 0;
}

int picoquic_compare_connection_id(const picoquic_connection_id_t * cnx_id1, const picoquic_connection_id_t * cnx_id2)
{
    int ret = -1;

    if (cnx_id1->id_len == cnx_id2->id_len) {
        ret = memcmp(cnx_id1->id, cnx_id2->id, cnx_id1->id_len);
    }
    else if (cnx_id1->id_len > cnx_id2->id_len) {
        ret = 1;
    }

    return ret;
}

/* Hash connection ids for picohash_table's */
uint64_t picoquic_connection_id_hash(const picoquic_connection_id_t * cid)
{
    uint64_t val64 = 0;
    size_t i = 0;

    for (; i < cid->id_len && i < 8; i++) {
        val64 <<= 8;
        val64 += cid->id[i];
    }

    for (; i < cid->id_len; i++) {
        uint64_t top = val64 >> 56;
        val64 <<= 8;
        val64 += cid->id[i];
        val64 += top * 0x10001;
    }

    return val64;
}

uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id)
{
    uint64_t val64 = 0;

    if (cnx_id.id_len < 8)
    {
        for (size_t i = 0; i < cnx_id.id_len; i++) {
            val64 <<= 8;
            val64 |= cnx_id.id[i];
        }
        for (size_t i = cnx_id.id_len; i < 8; i++) {
            val64 <<= 8;
        }
    } else {
        for (size_t i = 0; i < 8; i++) {
            val64 <<= 8;
            val64 |= cnx_id.id[i];
        }
    }

    return val64;
}

void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64)
{
    for (int i = 7; i >= 0; i--) {
        cnx_id->id[i] = (uint8_t)(val64 & 0xFF);
        val64 >>= 8;
    }
    for (size_t i = 8; i < sizeof(cnx_id->id); i++) {
        cnx_id->id[i] = 0;
    }
    cnx_id->id_len = 8;
}

uint64_t picoquic_hash_addr(const struct sockaddr* addr)
{
    uint64_t h;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* a4 = (struct sockaddr_in*)addr;
        h = picohash_bytes((uint8_t*)&a4->sin_addr , 4);
        h += 128ull * a4->sin_port;
    }
    else {
        struct sockaddr_in6* a6 = (struct sockaddr_in6*)addr;
        h = picohash_bytes((uint8_t*)& a6->sin6_addr, 16);
        h += 128ull * a6->sin6_port;
    }

    return h;
}

int picoquic_compare_addr(const struct sockaddr * expected, const struct sockaddr * actual)
{
    int ret = -1;

    if (expected->sa_family == actual->sa_family) {
        if (expected->sa_family == AF_INET) {
            struct sockaddr_in * ex = (struct sockaddr_in *)expected;
            struct sockaddr_in * ac = (struct sockaddr_in *)actual;
            if (ex->sin_port == ac->sin_port &&
#ifdef _WINDOWS
                ex->sin_addr.S_un.S_addr == ac->sin_addr.S_un.S_addr) {
#else
                ex->sin_addr.s_addr == ac->sin_addr.s_addr){
#endif
                ret = 0;
            }
        } else {
            struct sockaddr_in6 * ex = (struct sockaddr_in6 *)expected;
            struct sockaddr_in6 * ac = (struct sockaddr_in6 *)actual;


            if (ex->sin6_port == ac->sin6_port &&
                memcmp(&ex->sin6_addr, &ac->sin6_addr, 16) == 0) {
                ret = 0;
            }
        }
    }

    return ret;
}


int picoquic_compare_ip_addr(const struct sockaddr* expected, const struct sockaddr* actual)
{
    int ret = -1;

    if (expected->sa_family == actual->sa_family) {
        if (expected->sa_family == AF_INET6) {
            struct sockaddr_in6* ex = (struct sockaddr_in6*)expected;
            struct sockaddr_in6* ac = (struct sockaddr_in6*)actual;

            ret = memcmp(&ex->sin6_addr, &ac->sin6_addr, 16);
        }
        else {
            struct sockaddr_in* ex = (struct sockaddr_in*)expected;
            struct sockaddr_in* ac = (struct sockaddr_in*)actual;
#ifdef _WINDOWS
            ret = (ex->sin_addr.S_un.S_addr == ac->sin_addr.S_un.S_addr) ? 0 : -1;
#else
            ret = (ex->sin_addr.s_addr == ac->sin_addr.s_addr) ? 0 : -1;
#endif
        }
    }
    return ret;
}

uint16_t picoquic_get_addr_port(const struct sockaddr* addr)
{
    uint16_t port = (addr->sa_family == AF_INET6) ? ((struct sockaddr_in6*)addr)->sin6_port : ((struct sockaddr_in*)addr)->sin_port;

    return port;
}

void picoquic_set_addr_port(const struct sockaddr* addr, uint16_t port)
{
    if (addr->sa_family == AF_INET6) {
        ((struct sockaddr_in6*)addr)->sin6_port = port;
    }
    else {
        ((struct sockaddr_in*)addr)->sin_port = port;
    }
}

int picoquic_addr_length(const struct sockaddr* addr)
{
    int len = 0;
    if (addr->sa_family == AF_INET) {
        len = (int)sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        len = (int)sizeof(struct sockaddr_in6);
    }
    return len;
}
/* Copy a sockaddr to a storage value, and return the copied address length */
void picoquic_store_addr(struct sockaddr_storage * stored_addr, const struct sockaddr * addr)
{
    int len = 0;

    if (addr == NULL || (len = picoquic_addr_length(addr)) == 0) {
        stored_addr->ss_family = 0;
    }
    else {
        memcpy(stored_addr, addr, len);
    }
}

/* Return a pointer to the IP address and IP length in a sockaddr */
void picoquic_get_ip_addr(struct sockaddr * addr, uint8_t ** ip_addr, uint8_t * ip_addr_len)
{
    if (addr->sa_family == AF_INET) {
        *ip_addr = (uint8_t *)&((struct sockaddr_in *)addr)->sin_addr;
        *ip_addr_len = 4;
    }
    else if(addr->sa_family == AF_INET6) {
        *ip_addr = (uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr;
        *ip_addr_len = 16;
    }
    else {
        *ip_addr = NULL;
        *ip_addr_len = 0;
    }
}

/* Store a test address */
int picoquic_store_text_addr(struct sockaddr_storage* stored_addr, const char* ip_address_text, uint16_t port)
{
    int ret = 0;
    struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)stored_addr;
    struct sockaddr_in6* ipv6_addr = (struct sockaddr_in6*)stored_addr;

    /* get the IP address of the server */
    memset(stored_addr, 0, sizeof(struct sockaddr_storage));

    if (inet_pton(AF_INET, ip_address_text, &ipv4_addr->sin_addr) == 1) {
        /* Valid IPv4 address */
        ipv4_addr->sin_family = AF_INET;
        ipv4_addr->sin_port = htons((unsigned short)port);
    }
    else if (inet_pton(AF_INET6, ip_address_text, &ipv6_addr->sin6_addr) == 1) {
        /* Valid IPv6 address */
        ipv6_addr->sin6_family = AF_INET6;
        ipv6_addr->sin6_port = htons((unsigned short)port);
    }
    else {
        ret = -1;
    }

    return ret;
}

/* Get text string for address and port */
char const* picoquic_addr_text(const struct sockaddr* addr, char* text, size_t text_size)
{
    char addr_buffer[128];
    char const* addr_text;
    char const* ret_text = "?:?";

    if (addr != NULL) {
        switch (addr->sa_family) {
        case AF_INET:
            addr_text = inet_ntop(AF_INET,
                (const void*)(&((struct sockaddr_in*)addr)->sin_addr),
                addr_buffer, sizeof(addr_buffer));
            if (picoquic_sprintf(text, text_size, NULL, "%s:%d", addr_text, ntohs(((struct sockaddr_in*)addr)->sin_port)) == 0) {
                ret_text = text;
            }
            break;
        case AF_INET6:
            addr_text = inet_ntop(AF_INET6,
                (const void*)(&((struct sockaddr_in6*)addr)->sin6_addr),
                addr_buffer, sizeof(addr_buffer));
            if (picoquic_sprintf(text, text_size, NULL, "[%s]:%d", addr_text, ntohs(((struct sockaddr_in6*)addr)->sin6_port)) == 0) {
                ret_text = text;
            }
        default:
            break;
        }
    }

    return ret_text;
}

/* get a loopback address of the required type */
int picoquic_store_loopback_addr(struct sockaddr_storage* stored_addr, int addr_family, uint16_t port)
{
    int ret = -1;
    if (addr_family == AF_INET) {
        ret = picoquic_store_text_addr(stored_addr, "127.0.0.1", port);
    }
    else if (addr_family == AF_INET6) {
        ret = picoquic_store_text_addr(stored_addr, "::1", port);
    }
    return ret;
}

/* Return a directory path based on solution dir and file name */
char const* picoquic_solution_dir = NULL;

void picoquic_set_solution_dir(char const* solution_dir)
{
    picoquic_solution_dir = solution_dir;
}

int picoquic_get_input_path(char * target_file_path, size_t file_path_max, const char * solution_path, const char * file_name)
{
    if (solution_path == NULL) {
        solution_path = PICOQUIC_DEFAULT_SOLUTION_DIR;
    }

    const char * separator = PICOQUIC_FILE_SEPARATOR;
    size_t solution_path_length = strlen(solution_path);
    if (solution_path_length != 0 && solution_path[solution_path_length - 1] == separator[0]) {
        separator = "";
    }

    int ret = picoquic_sprintf(target_file_path, file_path_max, NULL, "%s%s%s",
        solution_path, separator, file_name);

    return ret;
}

/* Safely open files in a portable way */
FILE * picoquic_file_open_ex(char const * file_name, char const * flags, int * last_err)
{
    FILE * F;

#ifdef _WINDOWS
    errno_t err = fopen_s(&F, file_name, flags);
    if (err != 0){
        if (last_err != NULL) {
            *last_err = err;
        }
        if (F != NULL) {
            fclose(F);
            F = NULL;
        }
    }
#else
    F = fopen(file_name, flags);
    if (F == NULL && last_err != NULL) {
        *last_err = errno;
    }
#endif

    return F;
}
FILE* picoquic_file_open(char const* file_name, char const* flags)
{
    return picoquic_file_open_ex(file_name, flags, NULL);
}

/* Safely close files in a portable way */
FILE * picoquic_file_close(FILE * F)
{
    if (F != NULL) {
        (void)fclose(F);
    }
    return NULL;
}

/* Safely delete file in a portable way */
int picoquic_file_delete(char const * file_name, int * last_err)
{
    int ret;

#ifdef _WINDOWS
    ret = _unlink(file_name);
    if (last_err != NULL && ret != 0) {
        *last_err = errno;
    }
#else
    ret = unlink(file_name);
    if (last_err != NULL && ret != 0) {
        *last_err = errno;
    }
#endif
    return ret;
}

 /* Skip and decode function.
  * These functions return NULL in case of a failure (insufficient buffer).
  */

const uint8_t* picoquic_frames_fixed_skip(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t size)
{
    /* Write this test so as to avoid integer overflows, especially on 32 bit arch. */
    return size <= (uint64_t)(bytes_max - bytes) ? (bytes + size) : NULL;
}


const uint8_t* picoquic_frames_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes < bytes_max) {
        uint8_t v_len = VARINT_LEN(bytes);
        return  picoquic_frames_fixed_skip(bytes, bytes_max, v_len);
    }
    else {
        return NULL;
    }
}


/* Parse a varint. In case of an error, *n64 is unchanged, and NULL is returned */
const uint8_t* picoquic_frames_varint_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    uint8_t length;

    if (bytes < bytes_max && bytes + (length = VARINT_LEN_T(bytes, uint8_t)) <= bytes_max) {
        uint64_t v = *bytes++ & 0x3F;

        while (--length > 0) {
            v <<= 8;
            v += *bytes++;
        }

        *n64 = v;
    }
    else {
        bytes = NULL;
    }

    return bytes;
}

const uint8_t* picoquic_frames_varlen_decode(const uint8_t* bytes, const uint8_t* bytes_max, size_t* n)
{
    uint64_t len = 0;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &len);
    *n = (size_t)len;
    return (*n == len) ? bytes : NULL;
}

const uint8_t* picoquic_frames_uint8_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n)
{
    if (bytes < bytes_max) {
        *n = *bytes++;
    }
    else {
        bytes = NULL;
    }
    return bytes;
}


const uint8_t* picoquic_frames_uint16_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint16_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_16(bytes);
        bytes += sizeof(*n);
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

const uint8_t* picoquic_frames_uint32_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint32_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_32(bytes);
        bytes += sizeof(*n);
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

const uint8_t* picoquic_frames_uint64_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_64(bytes);
        bytes += sizeof(*n);
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

const uint8_t* picoquic_frames_length_data_skip(const uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t length;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL) {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, length);
    }
    return bytes;
}

const uint8_t* picoquic_frames_cid_decode(const uint8_t* bytes, const uint8_t* bytes_max, picoquic_connection_id_t* cid)
{
    bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &cid->id_len);

    if (cid->id_len > PICOQUIC_CONNECTION_ID_MAX_SIZE ||
        bytes + cid->id_len > bytes_max) {
        bytes = NULL;
    }
    else {
        memset(cid->id, 0, sizeof(cid->id));
        memcpy(cid->id, bytes, cid->id_len);
        bytes += cid->id_len;
    }

    return bytes;
}

/* Predict length of a varint encoding */
size_t picoquic_frames_varint_encode_length(uint64_t n64)
{
    size_t len = 8;

    if (n64 < 16384) {
        if (n64 < 64) {
            len = 1;
        }
        else {
            len = 2;
        }
    }
    else if (n64 < 1073741824) {
        len = 4;
    }

    return len;
}

/* Encoding functions of the form uint8_t * picoquic_frame_XXX_encode(uint8_t * bytes, uint8_t * bytes-max, ...)
 */
uint8_t* picoquic_frames_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64)
{
    if (n64 < 16384) {
        if (n64 < 64) {
            if (bytes + 1 <= bytes_max) {
                *bytes++ = (uint8_t)(n64);
            }
            else {
                bytes = NULL;
            }
        }
        else {
            if (bytes + 2 <= bytes_max) {
                *bytes++ = (uint8_t)((n64 >> 8) | 0x40);
                *bytes++ = (uint8_t)(n64);
            }
            else {
                bytes = NULL;
            }
        }
    }
    else if (n64 < 1073741824) {
        if (bytes + 4 <= bytes_max) {
            *bytes++ = (uint8_t)((n64 >> 24) | 0x80);
            *bytes++ = (uint8_t)(n64 >> 16);
            *bytes++ = (uint8_t)(n64 >> 8);
            *bytes++ = (uint8_t)(n64);
        }
        else {
            bytes = NULL;
        }
    }
    else {
        if (bytes + 8 <= bytes_max) {
            *bytes++ = (uint8_t)((n64 >> 56) | 0xC0);
            *bytes++ = (uint8_t)(n64 >> 48);
            *bytes++ = (uint8_t)(n64 >> 40);
            *bytes++ = (uint8_t)(n64 >> 32);
            *bytes++ = (uint8_t)(n64 >> 24);
            *bytes++ = (uint8_t)(n64 >> 16);
            *bytes++ = (uint8_t)(n64 >> 8);
            *bytes++ = (uint8_t)(n64);
        }
        else {
            bytes = NULL;
        }
    }

    return bytes;
}

uint8_t* picoquic_frames_varlen_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t n)
{
    return picoquic_frames_varint_encode(bytes, bytes_max, n);
}

uint8_t* picoquic_frames_uint8_encode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t n)
{
    if (bytes + sizeof(n) > bytes_max) {
        bytes = NULL;
    }
    else {
        *bytes++ = n;
    }

    return (bytes);
}

uint8_t* picoquic_frames_uint16_encode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t n)
{
    if (bytes + sizeof(n) > bytes_max) {
        bytes = NULL;
    }
    else {
        *bytes++ = (uint8_t)(n >> 8);
        *bytes++ = (uint8_t)n;
    }
    return (bytes);
}

uint8_t* picoquic_frames_uint24_encode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t n)
{
    if (bytes + 3 > bytes_max) {
        bytes = NULL;
    }
    else {
        *bytes++ = (uint8_t)(n >> 16);
        *bytes++ = (uint8_t)(n >> 8);
        *bytes++ = (uint8_t)n;
    }
    return (bytes);
}

uint8_t* picoquic_frames_uint32_encode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t n)
{
    if (bytes + sizeof(n) > bytes_max) {
        bytes = NULL;
    }
    else {
        *bytes++ = (uint8_t)(n >> 24);
        *bytes++ = (uint8_t)(n >> 16);
        *bytes++ = (uint8_t)(n >> 8);
        *bytes++ = (uint8_t)n;
    }
    return (bytes);
}

uint8_t* picoquic_frames_uint64_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n)
{
    if (bytes + sizeof(n) > bytes_max) {
        bytes = NULL;
    }
    else {
        *bytes++ = (uint8_t)(n >> 56);
        *bytes++ = (uint8_t)(n >> 48);
        *bytes++ = (uint8_t)(n >> 40);
        *bytes++ = (uint8_t)(n >> 32);
        *bytes++ = (uint8_t)(n >> 24);
        *bytes++ = (uint8_t)(n >> 16);
        *bytes++ = (uint8_t)(n >> 8);
        *bytes++ = (uint8_t)n;
    }
    return (bytes);

}

uint8_t* picoquic_frames_length_data_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t l, const uint8_t* v)
{
    if ((bytes = picoquic_frames_varlen_encode(bytes, bytes_max, l)) != NULL &&
        (bytes + l) <= bytes_max) {
        memcpy(bytes, v, l);
        bytes += l;
    }
    else {
        bytes = NULL;
    }

    return bytes;
}

uint8_t* picoquic_frames_cid_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_connection_id_t* cid)
{
    return picoquic_frames_length_data_encode(bytes, bytes_max, cid->id_len, cid->id);
}

uint8_t* picoquic_frames_charz_encode(uint8_t* bytes, const uint8_t* bytes_max, char const * s)
{
    if (s == NULL) {
        bytes = picoquic_frames_varlen_encode(bytes, bytes_max, 0);
    }
    else {
        size_t l = strlen(s);
        bytes = picoquic_frames_length_data_encode(bytes, bytes_max, l, (const uint8_t*)s);
    }
    return bytes;
}


/* Constant time memory comparison. This is only required now for
 * the comparison of 16 bytes long stateless reset secrets, so we have
 * only minimal requriements for performance, and privilege portability.
 *
 * Returns uint64_t value so the code works for arbitrary length.
 * Value is zero if strings match.
 */

int picoquic_constant_time_memcmp(const uint8_t* x, const uint8_t* y, size_t l)
{
    uint64_t ret = 0;

    while (l > 0) {
        ret += (*x++ ^ *y++);
        l--;
    }

    return (ret == 0)?0:-1;
}

/* Minimal support for threads.
 */

#ifndef _WINDOWS
static void picoquic_set_abs_delay(struct timespec* ts, uint64_t microsec_wait) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += (unsigned long)(microsec_wait / 1000000);
    ts->tv_nsec += (unsigned long)((microsec_wait % 1000000)*1000);
    if (ts->tv_nsec > 1000000000) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000;
    }
}
#endif

int picoquic_create_thread(picoquic_thread_t * thread, picoquic_thread_fn thread_fn, void * arg)
{
#ifdef _WINDOWS
    int ret = 0;
    *thread = CreateThread(NULL, 0, thread_fn, arg, 0, NULL);
    if (*thread == NULL) {
        ret = GetLastError();
    }
#else
    int ret = pthread_create(thread, NULL, thread_fn, arg);
#endif
    return ret;
}

int picoquic_wait_thread(picoquic_thread_t thread)
{
    int ret = 0;
#ifdef _WINDOWS
    if (WaitForSingleObject(thread, INFINITE) == WAIT_TIMEOUT) {
        ret = -1;
    }
#else
    ret = pthread_join(thread, NULL);
#endif
    return ret;
}

void picoquic_delete_thread(picoquic_thread_t * thread)
{
#ifdef _WINDOWS
    /* Wait until background thread has terminated, or timeout in milliseconds */
    if (WaitForMultipleObjects(1, thread, TRUE, 1000) == WAIT_TIMEOUT) {
        /* if soft wait fails, then hard cancel */
        TerminateThread(*thread, 0);
    }
    /* Close the thread handle */
    CloseHandle(*thread);
    *thread = NULL;
#else
    if (pthread_join(*thread, NULL) != 0) {
# ifdef _POSIX_THREAD_PROCESS_SHARED
        pthread_kill(*thread, SIGTERM);
# else
        (void)pthread_cancel(*thread);
# endif
    }
#endif
}


int picoquic_create_mutex(picoquic_mutex_t * mutex)
{
#ifdef _WINDOWS
    int ret = 0;
    *mutex = CreateMutex(NULL, FALSE, NULL);
    if (*mutex == NULL) {
        ret = -1;
    }
#else
    int ret = pthread_mutex_init(mutex, NULL);
#endif
    return ret;
}

int picoquic_delete_mutex(picoquic_mutex_t* mutex)
{
#ifdef _WINDOWS
    int ret = 0;
    CloseHandle(*mutex);
    *mutex = NULL;
#else
    int ret = pthread_mutex_destroy(mutex);
#endif
    return ret;
}

int picoquic_lock_mutex(picoquic_mutex_t  * mutex)
{
#ifdef _WINDOWS
    int ret = 0;
    DWORD w_ret = WaitForSingleObject(*mutex, INFINITE);
    if (w_ret != WAIT_OBJECT_0) {
        ret = -1;
    }
#else 
    int ret = pthread_mutex_lock(mutex);
#endif
    return ret;
}

int picoquic_unlock_mutex(picoquic_mutex_t * mutex)
{
#ifdef _WINDOWS
    int ret = 0;
    if (!ReleaseMutex(*mutex)) {
        ret = -1;
    }
#else 
    int ret = pthread_mutex_unlock(mutex);
#endif
    return ret;
}

int picoquic_create_event(picoquic_event_t* event)
{
#ifdef _WINDOWS
    int ret = 0;
    *event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (*event == NULL) {
        ret = -1;
    }
#else
    int ret;

    memset(event, 0, sizeof(picoquic_event_t));
    ret = pthread_mutex_init(&event->mutex, NULL);
    if (ret == 0) {
        ret = pthread_cond_init(&event->cond, NULL);
    }
#endif
    return ret;
}

void picoquic_delete_event(picoquic_event_t* event)
{
#ifdef _WINDOWS
    CloseHandle(*event);
    *event = NULL;
#else 
    (void)pthread_mutex_destroy(&event->mutex);
    (void)pthread_cond_destroy(&event->cond);
    memset(event, 0, sizeof(picoquic_event_t));
#endif
}

int picoquic_signal_event(picoquic_event_t* event)
{
#ifdef _WINDOWS
    int ret = 0;
    if (!SetEvent(*event)){
        ret = -1;
    }
#else 
    int ret;
    (void)pthread_mutex_lock(&event->mutex);
    ret = pthread_cond_broadcast(&event->cond);
    (void)pthread_mutex_unlock(&event->mutex);
#endif
    return ret;
}

int picoquic_wait_for_event(picoquic_event_t* event, uint64_t microsec_wait)
{
#ifdef _WINDOWS
    int ret = 0;
    DWORD dwWaitResult;
    DWORD millisec_wait = (microsec_wait == UINT64_MAX) ? INFINITE : (DWORD)(microsec_wait / 1000);
    dwWaitResult = WaitForSingleObject(*event, millisec_wait);
    if (dwWaitResult == WAIT_OBJECT_0) {
        (void)ResetEvent(*event);
    } else {
        ret = -1;
    }
#else
    int ret;
    (void)pthread_mutex_lock(&event->mutex);
    if (microsec_wait == UINT64_MAX) {
        ret = pthread_cond_wait(&event->cond, &event->mutex);
    }
    else {
        struct timespec abstime;
        picoquic_set_abs_delay(&abstime, microsec_wait);
        ret = pthread_cond_timedwait(&event->cond, &event->mutex, &abstime);
    }
    (void)pthread_mutex_unlock(&event->mutex);
#endif
    return ret;
}


/* Pseudo random generation suitable for tests. Guaranties that the
* same seed will produce the same sequence, allows for specific
* random sequence for a given test.
* Adapted from http://xoroshiro.di.unimi.it/splitmix64.c,
* Written in 2015 by Sebastiano Vigna (vigna@acm.org)  */

uint64_t picoquic_test_random(uint64_t* random_context)
{
    uint64_t z;
    *random_context += 0x9e3779b97f4a7c15;
    z = *random_context;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

void picoquic_test_random_bytes(uint64_t* random_context, uint8_t* bytes, size_t bytes_max)
{
    size_t byte_index = 0;

    while (byte_index < bytes_max) {
        uint64_t v = picoquic_test_random(random_context);

        for (int i = 0; i < 8 && byte_index < bytes_max; i++) {
            bytes[byte_index++] = v & 0xFF;
            v >>= 8;
        }
    }
}

uint64_t picoquic_test_uniform_random(uint64_t* random_context, uint64_t rnd_max)
{
    uint64_t rnd = 0;

    if (rnd_max > 0) {
        uint64_t rnd_min = UINT64_MAX % rnd_max;

        do {
            rnd = picoquic_test_random(random_context);
        } while (rnd < rnd_min);
        rnd %= rnd_max;
    }

    return rnd;
}

double picoquic_test_gauss_random(uint64_t* random_context)
{
    double dx = 0;

    /* Sum of 12 variables in [0..1], provides
     * average = 6.0, stdev = 3.0 */
    for (int i = 0; i < 12; i++) {
        double d;
        uint64_t r = picoquic_test_random(random_context);
        r ^= r >> 17;
        r ^= r >> 34;
        d = (double)(r & 0x1ffff) + 0.5;
        d /= (double)(0x20000);
        dx += d;
    }

    dx -= 6.0;

    return dx;
}

/* Convert binary string to test string for logging purposes.
 */
char* picoquic_uint8_to_str(char* text, size_t text_len, const uint8_t* data, size_t data_len)
{
    size_t render_length = data_len;
    size_t rendered;

    if (render_length + 1 > text_len) {
        if (text_len > 4) {
            render_length = text_len - 4;
        }
        else {
            render_length = 0;
        }
    }

    for (rendered = 0; rendered < render_length; rendered++) {
        int c = data[rendered];
        if (c < ' ' || c >= 127) {
            c = '?';
        }
        text[rendered] = (char)c;
    }

    if (rendered < data_len) {
        for (size_t i = 0; i < 3 && rendered + 1 < text_len; i++, rendered++) {
            text[rendered] = '.';
        }
    }
    text[rendered] = 0;

    return text;
}
