/*
* Author: Igor Lubashev
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

#ifndef PICOQUIC_UTILS_H
#define PICOQUIC_UTILS_H

#include <stdio.h>
#include <inttypes.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define PRIst "Iu"
#ifndef PRIu64
#define PRIu64 "I64u"
#endif
#ifndef PRIx64
#define PRIx64 "I64x"
#endif
#else
#define PRIst "zu"
#endif

#ifdef _WINDOWS
#ifndef _WINDOWS64
#ifndef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#define PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#endif
#endif
#endif

#ifdef __APPLE__
#ifndef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#define PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#endif
#endif

/* File identifiers in simple tracing functions */
#define PICOQUIC_SENDER 1
#define PICOQUIC_PACKET 2
#define PICOQUIC_QUICCTX 3
#define PICOQUIC_FRAME 4
#define PICOQUIC_LOSS_RECOVERY 5
#define SET_LAST_WAKE(quic, file_id) ((quic)->wake_file = file_id, (quic)->wake_line = __LINE__)


void debug_set_stream(FILE *F);
void debug_set_callback(void (*cb)(const char *msg, void *argp), void *argp);
void debug_printf(const char* fmt, ...);
void debug_printf_push_stream(FILE* f);
void debug_printf_pop_stream(void);
void debug_printf_suspend(void);
void debug_printf_resume(void);
int debug_printf_reset(int suspended);
void debug_dump(const void * x, int len);

/* utilities */
char* picoquic_string_create(const char* original, size_t len);
char* picoquic_string_duplicate(const char* original);
char* picoquic_string_free(char* str);
int picoquic_sprintf(char* buf, size_t buf_len, size_t * nb_chars, const char* fmt, ...);

extern const picoquic_connection_id_t picoquic_null_connection_id;
uint8_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id);
uint8_t picoquic_parse_connection_id(const uint8_t* bytes, uint8_t len, picoquic_connection_id_t *cnx_id);
int picoquic_is_connection_id_null(const picoquic_connection_id_t * cnx_id);
int picoquic_compare_connection_id(const picoquic_connection_id_t * cnx_id1, const picoquic_connection_id_t * cnx_id2);
uint64_t picoquic_connection_id_hash(const picoquic_connection_id_t * cid);
uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id);
void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64);
uint64_t picoquic_hash_addr(const struct sockaddr* addr);
size_t picoquic_parse_hexa(char const* hex_input, size_t input_length, uint8_t* bin_output, size_t output_max);
uint8_t picoquic_parse_connection_id_hexa(char const * hex_input, size_t input_length, picoquic_connection_id_t * cnx_id);
int picoquic_print_connection_id_hexa(char* buf, size_t buf_len, const picoquic_connection_id_t* cnxid);
uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len);

int picoquic_compare_addr(const struct sockaddr* expected, const struct sockaddr* actual);
int picoquic_compare_ip_addr(const struct sockaddr* expected, const struct sockaddr* actual);
uint16_t picoquic_get_addr_port(const struct sockaddr* addr);
void picoquic_set_addr_port(const struct sockaddr* addr, uint16_t port);

int picoquic_addr_length(const struct sockaddr* addr);
void picoquic_store_addr(struct sockaddr_storage * stored_addr, const struct sockaddr * addr);
void picoquic_get_ip_addr(struct sockaddr * addr, uint8_t ** ip_addr, uint8_t * ip_addr_len);
int picoquic_store_text_addr(struct sockaddr_storage* stored_addr, const char* ip_address_text, uint16_t port);
char const* picoquic_addr_text(const struct sockaddr* addr, char* text, size_t text_size);
int picoquic_store_loopback_addr(struct sockaddr_storage* stored_addr, int addr_family, uint16_t port);

/* Setting the solution dir when not executing from default location */
void picoquic_set_solution_dir(char const* solution_dir);
int picoquic_get_input_path(char * target_file_path, size_t file_path_max, const char * solution_path, const char * file_name);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef _WINDOWS
#define PICOQUIC_FILE_SEPARATOR "\\"
#ifdef _WINDOWS64
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\"
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\"
#endif
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "./"
#define PICOQUIC_FILE_SEPARATOR "/"
#endif

#ifndef DISABLE_DEBUG_PRINTF

#define DBG_PRINTF_FILENAME_MAX 24
#define DBG_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        &__FILE__[MAX(DBG_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_PRINTF_FILENAME_MAX], \
        __LINE__, __func__ , __VA_ARGS__)

#define DBG_FATAL_PRINTF(fmt, ...)                    \
    do {                                              \
        DBG_PRINTF("(FATAL) " fmt "\n", __VA_ARGS__); \
        exit(1);                                      \
    } while (0)

#else

#define DBG_PRINTF(fmt, ...)
#define DBG_FATAL_PRINTF(fmt, ...)

#endif //#ifdef DISABLE_DEBUG_PRINTF

/* Safely open files in a portable way */
FILE * picoquic_file_open_ex(char const * file_name, char const * flags, int * last_err);
FILE * picoquic_file_open(char const * file_name, char const * flags);
FILE * picoquic_file_close(FILE * F);

int picoquic_file_delete(char const* file_name, int* last_err);

/* Skip and decoding functions */
const uint8_t* picoquic_frames_fixed_skip(const uint8_t * bytes, const uint8_t * bytes_max, uint64_t size);
const uint8_t* picoquic_frames_varint_skip(const uint8_t * bytes, const uint8_t * bytes_max);
const uint8_t* picoquic_frames_varint_decode(const uint8_t * bytes, const uint8_t * bytes_max, uint64_t * n64);
const uint8_t* picoquic_frames_varlen_decode(const uint8_t * bytes, const uint8_t * bytes_max, size_t * n);
const uint8_t* picoquic_frames_uint8_decode(const uint8_t * bytes, const uint8_t * bytes_max, uint8_t * n);
const uint8_t* picoquic_frames_uint16_decode(const uint8_t * bytes, const uint8_t * bytes_max, uint16_t * n);
const uint8_t* picoquic_frames_uint32_decode(const uint8_t * bytes, const uint8_t * bytes_max, uint32_t * n);
const uint8_t* picoquic_frames_uint64_decode(const uint8_t * bytes, const uint8_t * bytes_max, uint64_t * n);
const uint8_t* picoquic_frames_length_data_skip(const uint8_t * bytes, const uint8_t * bytes_max);
const uint8_t* picoquic_frames_cid_decode(const uint8_t * bytes, const uint8_t * bytes_max, picoquic_connection_id_t * cid);

#define VARINT_LEN(bytes) (((uint8_t)1) << ((bytes[0] >> 6)&3))
#define VARINT_LEN_T(bytes, t_len) (((t_len)1) << ((bytes[0] >> 6)&3))

/* Predict length of a varint encoding */
size_t picoquic_frames_varint_encode_length(uint64_t n64);

/* Encoding functions of the form uint8_t * picoquic_frame_XXX_encode(uint8_t * bytes, uint8_t * bytes-max, ...)
 */
uint8_t* picoquic_frames_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64);
uint8_t* picoquic_frames_varlen_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t n);
uint8_t* picoquic_frames_uint8_encode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t n);
uint8_t* picoquic_frames_uint16_encode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t n);
uint8_t* picoquic_frames_uint24_encode(uint8_t * bytes, const uint8_t * bytes_max, uint32_t n);
uint8_t* picoquic_frames_uint32_encode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t n);
uint8_t* picoquic_frames_uint64_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n);
uint8_t* picoquic_frames_length_data_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t l, const uint8_t* v);
uint8_t* picoquic_frames_cid_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_connection_id_t* cid);
uint8_t* picoquic_frames_charz_encode(uint8_t * bytes, const uint8_t * bytes_max, char const* s);

/* Constant time memory comparison may be required on some platforms for testing reset secrets */
int picoquic_constant_time_memcmp(const uint8_t* x, const uint8_t* y, size_t l);

/* A set of portable function enables minimal support for
 * thread, mutex and event in Windows and Linux
 */
#ifdef _WINDOWS
#define picoquic_thread_t HANDLE
#define picoquic_thread_return_t DWORD WINAPI
typedef DWORD (WINAPI* picoquic_thread_fn)(LPVOID lpParam);
#define picoquic_mutex_t HANDLE
#define picoquic_event_t HANDLE
#define picoquic_thread_do_return return 0
#else
 /* Linux routine returns */
#define picoquic_thread_t pthread_t
#define picoquic_thread_return_t void*
typedef void* (*picoquic_thread_fn) (void* lpParam);
#define picoquic_mutex_t pthread_mutex_t 
#define picoquic_thread_do_return return (void *)NULL

typedef struct st_picoquic_event_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} picoquic_event_t;
#endif

int picoquic_create_thread(picoquic_thread_t* thread, picoquic_thread_fn thread_fn, void* arg);
int picoquic_wait_thread(picoquic_thread_t thread);
void picoquic_delete_thread(picoquic_thread_t* thread);

int picoquic_create_mutex(picoquic_mutex_t* mutex);
int picoquic_delete_mutex(picoquic_mutex_t* mutex);
int picoquic_lock_mutex(picoquic_mutex_t* mutex);
int picoquic_unlock_mutex(picoquic_mutex_t* mutex);

int picoquic_create_event(picoquic_event_t* event);
void picoquic_delete_event(picoquic_event_t* event);
int picoquic_signal_event(picoquic_event_t* event);
int picoquic_wait_for_event(picoquic_event_t* event, uint64_t microsec_wait);

/* Simple portable random number generation
 */
uint64_t picoquic_uniform_random(uint64_t rnd_max);

/* Set of random number generation functions, designed for tests.
 * The random numbers are defined by a 64 bit context, initialized to a seed.
 * The same seed will always generate the same sequence.
 */

uint64_t picoquic_test_random(uint64_t* random_context);
void picoquic_test_random_bytes(uint64_t* random_context, uint8_t* bytes, size_t bytes_max);
uint64_t picoquic_test_uniform_random(uint64_t* random_context, uint64_t rnd_max);
double picoquic_test_gauss_random(uint64_t* random_context); /* random gaussian of variance 1.0, average 0 */

/* Convert text carried in uint8_t arrays to text string
 * suitable for logs */
char* picoquic_uint8_to_str(char* text, size_t text_len, const uint8_t* data, size_t data_len);

/* Really basic network simulator, only simulates a simple link using a
 * packet structure.
 * Init: link creation. Returns a link structure with defined bandwidth,
 * latency, loss pattern and initial time. The link is empty. The loss
 * pattern is a 64 bit bit mask.
 * Submit packet of length L at time t. The packet is queued to the link.
 * Get packet out of link at time T + L + Queue.
 */

typedef struct st_picoquictest_sim_packet_t {
    struct st_picoquictest_sim_packet_t* next_packet;
    uint64_t arrival_time;
    size_t length;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    uint8_t ecn_mark;
    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquictest_sim_packet_t;

typedef struct st_picoquictest_sim_link_t {
    uint64_t next_send_time;
    uint64_t queue_time;
    uint64_t resume_time;
    uint64_t queue_delay_max;
    uint64_t picosec_per_byte;
    uint64_t microsec_latency;
    uint64_t* loss_mask;
    uint64_t packets_dropped;
    uint64_t packets_sent;
    uint64_t jitter;
    uint64_t jitter_seed;
    size_t path_mtu;
    picoquictest_sim_packet_t* first_packet;
    picoquictest_sim_packet_t* last_packet;
    /* Variables for random early drop simulation */
    uint64_t red_drop_mask;
    uint64_t red_queue_max;
    /* L4S MAX sets the ECN mark threshold if doing L4S or DCTCP style ECN marking. */
    uint64_t l4s_max;
    /* Variables for rate limiter simulation */
    double bucket_increase_per_microsec;
    uint64_t bucket_max;
    double bucket_current;
    uint64_t bucket_arrival_last;
    /* Variable for multipath simulation */
    int is_switched_off;
    int is_unreachable;
} picoquictest_sim_link_t;

picoquictest_sim_link_t* picoquictest_sim_link_create(double data_rate_in_gps,
    uint64_t microsec_latency, uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t current_time);

void picoquictest_sim_link_delete(picoquictest_sim_link_t* link);

picoquictest_sim_packet_t* picoquictest_sim_link_create_packet();

uint64_t picoquictest_sim_link_next_arrival(picoquictest_sim_link_t* link, uint64_t current_time);

picoquictest_sim_packet_t* picoquictest_sim_link_dequeue(picoquictest_sim_link_t* link,
    uint64_t current_time);

void picoquictest_sim_link_submit(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time);

/* picoquic_test_simlink_suspend simulates and interuption of transmission until the
* specified "end of interval" time. There are two modes:
* 
* - simulate_receive = 1: receive side. Simulate suspension of reception until the
*   specified end of interval. All rpending packets are delivered at this point.
* - simulate_receive = 0: sender side. Simulate suspension of transmission until the
*   specified end of interval. Packets are queued as if transmitted in sequence
*   after that interval.
 */
void picoquic_test_simlink_suspend(picoquictest_sim_link_t* link, uint64_t time_end_of_interval, int simulate_receive);

/* SNI, Stores and Certificates used for test
 */

#define PICOQUIC_TEST_SNI "test.example.com"

#ifdef _WINDOWS
#define PICOQUIC_TEST_FILE_SERVER_CERT "certs\\cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_BAD_CERT "certs\\badcert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY "certs\\key.pem"
#define PICOQUIC_TEST_FILE_CERT_STORE "certs\\test-ca.crt"
#define PICOQUIC_TEST_FILE_SERVER_CERT_ECDSA "certs\\ecdsa\\cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY_ECDSA "certs\\ecdsa\\key.pem"
#else
#define PICOQUIC_TEST_FILE_SERVER_CERT "certs/cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_BAD_CERT "certs/badcert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY "certs/key.pem"
#define PICOQUIC_TEST_FILE_CERT_STORE "certs/test-ca.crt"
#define PICOQUIC_TEST_FILE_SERVER_CERT_ECDSA "certs/ecdsa/cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY_ECDSA "certs/ecdsa/key.pem"
#endif

 /* To set the solution directory for tests */
extern char const* picoquic_solution_dir;
#ifdef __cplusplus
}
#endif
#endif
