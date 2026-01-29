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

#ifndef PICOQUIC_INTERNAL_H
#define PICOQUIC_INTERNAL_H

#ifdef _MSC_VER
#pragma warning(disable: 4100) // unreferenced formal parameter
#endif

#include "picohash.h"
#include "picosplay.h"
#include "picoquic.h"
#include "picoquic_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PICOQUIC_MAX_PACKET_SIZE
#define PICOQUIC_MAX_PACKET_SIZE 1536
#endif
#define PICOQUIC_MIN_SEGMENT_SIZE 32
#define PICOQUIC_ENFORCED_INITIAL_MTU 129 /* TODO: MTU */
#define PICOQUIC_ENFORCED_INITIAL_CID_LENGTH 8
#define PICOQUIC_PRACTICAL_MAX_MTU 1440
#define PICOQUIC_RETRY_SECRET_SIZE 64
#define PICOQUIC_RETRY_TOKEN_PAD_SIZE 26
#define PICOQUIC_DEFAULT_0RTT_WINDOW (10*PICOQUIC_ENFORCED_INITIAL_MTU)
#define PICOQUIC_NB_PATH_TARGET 8
#define PICOQUIC_NB_PATH_DEFAULT 2
#define PICOQUIC_MAX_PACKETS_IN_POOL 0x2000
#define PICOQUIC_STORED_IP_MAX 16

#define PICOQUIC_INITIAL_RTT 250000ull /* 250 ms */
#define PICOQUIC_TARGET_RENO_RTT 100000ull /* 100 ms */
#define PICOQUIC_TARGET_SATELLITE_RTT 610000ull /* 610 ms, practical maximum for non-pathological RTT */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 250000ull /* 250 ms */
#define PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER 1000000ull /* one second */
#define PICOQUIC_LARGE_RETRANSMIT_TIMER 2000000ull /* two seconds */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000ull /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 100000ull /* 10 ms */
#define PICOQUIC_ACK_DELAY_MAX_DEFAULT 25000ull /* 25 ms, per protocol spec */
#define PICOQUIC_ACK_DELAY_MIN 1000ull /* 1 ms */
#define PICOQUIC_ACK_DELAY_MIN_MAX_VALUE 0xFFFFFFull /* max value that can be negotiated by peers */
#define PICOQUIC_RACK_DELAY 300000ull /* 100 ms */
#define PICOQUIC_MAX_ACK_DELAY_MAX_MS 0x4000ull /* 2<14 ms */
#define PICOQUIC_TOKEN_DELAY_LONG (24*60*60*1000000ull) /* 24 hours */
#define PICOQUIC_TOKEN_DELAY_SHORT (2*60*1000000ull) /* 2 minutes */
#define PICOQUIC_CID_REFRESH_DELAY (5*1000000ull) /* if idle for 5 seconds, refresh the CID */
#define PICOQUIC_MTU_LOSS_THRESHOLD 10 /* if threshold of full MTU packetlost, reset MTU */

#define PICOQUIC_BANDWIDTH_ESTIMATE_MAX 10000000000ull /* 10 GB per second */
#define PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN 1000
#define PICOQUIC_BANDWIDTH_MEDIUM 2000000 /* 16 Mbps, threshold for coalescing 10 packets per ACK with long delays */
#define PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MIN 1000
#define PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX 15000

#define PICOQUIC_MINRTT_MARGIN 128 /* Typical uncertainty on RTT measurement, caused for example by process scheduling */
#define PICOQUIC_MINRTT_THRESHOLD 128 /* RTT MIN value under which congestion control should not be driven by RTT changes */

#define PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX 1000000ull /* one second */

#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000ull /* 120 seconds for now */
#define PICOQUIC_MICROSEC_HANDSHAKE_MAX 30000000ull /* 30 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000ull /* 10 seconds for now */

#define PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT 100000ull /* max 10 stateless reset by second by default */

#define PICOQUIC_CWIN_INITIAL (10 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_PATH_CWIN_INITIAL (10 * path_x->send_mtu)
#define PICOQUIC_CWIN_MINIMUM (2 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_PATH_CWIN_MINIMUM (2 * path_x->send_mtu)

#define PICOQUIC_PRIORITY_BYPASS_MAX_RATE 125000
#define PICOQUIC_PRIORITY_BYPASS_QUANTUM 2560

#define PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH (1<<22)

#define PICOQUIC_DEFAULT_SIMULTANEOUS_LOGS 32
#define PICOQUIC_DEFAULT_HALF_OPEN_RETRY_THRESHOLD 64

#define PICOQUIC_PN_RANDOM_MIN 0xffff
#define PICOQUIC_PN_RANDOM_RANGE 0x10000

#define PICOQUIC_SPIN_RESERVE_MOD_256 17

#define PICOQUIC_CHALLENGE_REPEAT_MAX 3

#define PICOQUIC_ALPN_NUMBER_MAX 32

#define PICOQUIC_CC_ALGO_NUMBER_NEW_RENO 1
#define PICOQUIC_CC_ALGO_NUMBER_CUBIC 2
#define PICOQUIC_CC_ALGO_NUMBER_DCUBIC 3
#define PICOQUIC_CC_ALGO_NUMBER_FAST 4
#define PICOQUIC_CC_ALGO_NUMBER_BBR 5
#define PICOQUIC_CC_ALGO_NUMBER_PRAGUE 6
#define PICOQUIC_CC_ALGO_NUMBER_BBR1 7

#define PICOQUIC_MAX_ACK_RANGE_REPEAT 4
#define PICOQUIC_MIN_ACK_RANGE_REPEAT 2

#define PICOQUIC_DEFAULT_HOLE_PERIOD 256

/*
 * Types of frames.
 */
typedef enum {
    picoquic_frame_type_padding = 0,
    picoquic_frame_type_ping = 1,
    picoquic_frame_type_poll = 0x20,
    picoquic_frame_type_ack = 0x02,
    picoquic_frame_type_ack_ecn = 0x03,
    picoquic_frame_type_reset_stream = 0x04,
    picoquic_frame_type_stop_sending = 0x05,
    picoquic_frame_type_crypto_hs = 0x06,
    picoquic_frame_type_new_token = 0x07,
    picoquic_frame_type_stream_range_min = 0x08,
    picoquic_frame_type_stream_range_max = 0x0f,
    picoquic_frame_type_max_data = 0x10,
    picoquic_frame_type_max_stream_data = 0x11,
    picoquic_frame_type_max_streams_bidir = 0x12,
    picoquic_frame_type_max_streams_unidir = 0x13,
    picoquic_frame_type_data_blocked = 0x14,
    picoquic_frame_type_stream_data_blocked = 0x15,
    picoquic_frame_type_streams_blocked_bidir = 0x16,
    picoquic_frame_type_streams_blocked_unidir = 0x17,
    picoquic_frame_type_new_connection_id = 0x18,
    picoquic_frame_type_path_new_connection_id = 0x15228c09,
    picoquic_frame_type_retire_connection_id = 0x19,
    picoquic_frame_type_path_retire_connection_id = 0x15228c0a,
    picoquic_frame_type_path_challenge = 0x1a,
    picoquic_frame_type_path_response = 0x1b,
    picoquic_frame_type_connection_close = 0x1c,
    picoquic_frame_type_application_close = 0x1d,
    picoquic_frame_type_handshake_done = 0x1e,
    picoquic_frame_type_datagram = 0x30,
    picoquic_frame_type_datagram_l = 0x31,
    picoquic_frame_type_ack_frequency = 0xAF,
    picoquic_frame_type_immediate_ack = 0x1F,
    picoquic_frame_type_time_stamp = 757,
    picoquic_frame_type_path_ack = 0x15228c00,
    picoquic_frame_type_path_ack_ecn =  0x15228c01,
    picoquic_frame_type_path_abandon =  0x15228c05,
    picoquic_frame_type_path_backup =  0x15228c07,
    picoquic_frame_type_path_available =  0x15228c08,
    picoquic_frame_type_bdp = 0xebd9,
    picoquic_frame_type_max_path_id = 0x15228c0c,
    picoquic_frame_type_path_blocked = 0x15228c0d,
    picoquic_frame_type_observed_address_v4 = 0x9f81a6,
    picoquic_frame_type_observed_address_v6 = 0x9f81a7
} picoquic_frame_type_enum_t;

/* PMTU discovery requirement status */

typedef enum {
    picoquic_pmtu_discovery_not_needed = 0,
    picoquic_pmtu_discovery_optional,
    picoquic_pmtu_discovery_required
} picoquic_pmtu_discovery_status_enum;

/*
 * Efficient range operations that assume range containing bitfields.
 * Namely, it assumes max&min==min, min&bits==0, max&bits==bits.
 */
#define PICOQUIC_IN_RANGE(v, min, max)                  (((v) & ~((min)^(max))) == (min))
     // Is v between min and max and has all given bits set/clear?
#define PICOQUIC_BITS_SET_IN_RANGE(  v, min, max, bits) (((v) & ~((min)^(max)^(bits))) == ((min)^(bits)))
#define PICOQUIC_BITS_CLEAR_IN_RANGE(v, min, max, bits) (((v) & ~((min)^(max)^(bits))) == (min))


/*
 * Supported versions
 */
#if 0
#define PICOQUIC_FIRST_INTEROP_VERSION 0xFF000005
#define PICOQUIC_SECOND_INTEROP_VERSION 0xFF000007
#define PICOQUIC_THIRD_INTEROP_VERSION 0xFF000008
#define PICOQUIC_FOURTH_INTEROP_VERSION 0xFF000009
#define PICOQUIC_FIFTH_INTEROP_VERSION 0xFF00000B
#define PICOQUIC_SIXTH_INTEROP_VERSION 0xFF00000C
#define PICOQUIC_SEVENTH_INTEROP_VERSION 0xFF00000D
#define PICOQUIC_EIGHT_INTEROP_VERSION 0xFF00000E
#define PICOQUIC_NINTH_INTEROP_VERSION 0xFF00000F
#define PICOQUIC_NINTH_BIS_INTEROP_VERSION 0xFF000010
#define PICOQUIC_TENTH_INTEROP_VERSION 0xFF000011
#define PICOQUIC_ELEVENTH_INTEROP_VERSION 0xFF000012
#define PICOQUIC_TWELFTH_INTEROP_DRAFT19 0xFF000013
#define PICOQUIC_TWELFTH_INTEROP_VERSION 0xFF000014
#define PICOQUIC_THIRTEENTH_INTEROP_VERSION 0xFF000016
#define PICOQUIC_FOURTEENTH_INTEROP_VERSION 0xFF000017
#define PICOQUIC_FIFTEENTH_INTEROP_VERSION 0xFF000018
#define PICOQUIC_SIXTEENTH_INTEROP_VERSION 0xFF000019
#endif
#define PICOQUIC_SEVENTEENTH_INTEROP_VERSION 0xFF00001B
#define PICOQUIC_EIGHTEENTH_INTEROP_VERSION 0xFF00001C
#define PICOQUIC_NINETEENTH_INTEROP_VERSION 0xFF00001D
#define PICOQUIC_NINETEENTH_BIS_INTEROP_VERSION 0xFF00001E
#define PICOQUIC_TWENTIETH_PRE_INTEROP_VERSION 0xFF00001F
#define PICOQUIC_TWENTIETH_INTEROP_VERSION 0xFF000020
#define PICOQUIC_TWENTYFIRST_INTEROP_VERSION 0xFF000021
#define PICOQUIC_POST_IESG_VERSION 0xFF000022
#define PICOQUIC_V1_VERSION 0x00000001
#define PICOQUIC_V2_VERSION 0x6b3343cf
#define PICOQUIC_V2_VERSION_DRAFT 0x709a50c4
#define PICOQUIC_INTERNAL_TEST_VERSION_1 0x50435130
#define PICOQUIC_INTERNAL_TEST_VERSION_2 0x50435131

#define PICOQUIC_INTEROP_VERSION_INDEX 0

#define PICOQUIC_INTEROP_VERSION_LATEST PICOQUIC_NINETEENTH_INTEROP_VERSION


typedef struct st_picoquic_version_parameters_t {
    uint32_t version;
    size_t version_aead_key_length;
    uint8_t* version_aead_key;
    size_t version_retry_key_length;
    uint8_t* version_retry_key;
    char* tls_prefix_label;
    char* tls_traffic_update_label;
    uint32_t packet_type_version;
    uint32_t* upgrade_from;
} picoquic_version_parameters_t;

extern const picoquic_version_parameters_t picoquic_supported_versions[];
extern const size_t picoquic_nb_supported_versions;

int picoquic_get_version_index(uint32_t proposed_version);

/* Quic defines 4 epochs, which are used for managing the
 * crypto contexts
 */
#define PICOQUIC_NUMBER_OF_EPOCHS 4
#define PICOQUIC_NUMBER_OF_EPOCH_OFFSETS (PICOQUIC_NUMBER_OF_EPOCHS+1)

typedef enum {
    picoquic_epoch_initial = 0,
    picoquic_epoch_0rtt = 1,
    picoquic_epoch_handshake = 2,
    picoquic_epoch_1rtt = 3
} picoquic_epoch_enum;

/*
* Nominal packet types. These are the packet types used internally by the
* implementation. The wire encoding depends on the version.
*/
typedef enum {
    picoquic_packet_error = 0,
    picoquic_packet_version_negotiation,
    picoquic_packet_initial,
    picoquic_packet_retry,
    picoquic_packet_handshake,
    picoquic_packet_0rtt_protected,
    picoquic_packet_1rtt_protected,
    picoquic_packet_type_max
} picoquic_packet_type_enum;

/* Packet header structure.
 * This structure is used internally when parsing or
 * formatting the header of a Quic packet.
 */

typedef struct st_picoquic_packet_header_t {
    picoquic_connection_id_t dest_cnx_id;
    picoquic_connection_id_t srce_cnx_id;
    uint32_t pn;
    uint32_t vn;
    size_t offset; /* offset to the first byte of the payload.*/
    size_t pn_offset; /* offset to the first byte of the packet number */
    picoquic_packet_type_enum ptype;
    uint64_t pnmask; 
    uint64_t pn64;
    size_t payload_length;
    int version_index;
    picoquic_epoch_enum epoch;
    picoquic_packet_context_enum pc;

    unsigned int key_phase : 1;
    unsigned int spin : 1;
    unsigned int has_spin_bit : 1;
    unsigned int has_reserved_bit_set : 1;
    unsigned int has_loss_bits : 1;
    unsigned int loss_bit_Q : 1;
    unsigned int loss_bit_L : 1;
    unsigned int quic_bit_is_zero : 1;

    size_t token_length;
    const uint8_t* token_bytes;
    size_t pl_val;
    struct st_picoquic_local_cnxid_t* l_cid;
} picoquic_packet_header;

/* There are two loss bits in the packet header. On is used
 * to report errors, the other to build an observable square
 * wave, of half period Q defined below.
 */
#define PICOQUIC_LOSS_BIT_Q_HALF_PERIOD 64

/*
 * Management of the spin bit in the packet header.
 * We envisage different spin bit policies, and implement
 * each policy by 2 function pointers for processing incoming and
 * outgoing packets.
 */
typedef void(*picoquic_spinbit_incoming_fn)(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_header* ph);
typedef uint8_t(*picoquic_spinbit_outgoing_fn)(picoquic_cnx_t* cnx);

typedef struct st_picoquic_spinbit_def_t {
    picoquic_spinbit_incoming_fn spinbit_incoming;
    picoquic_spinbit_outgoing_fn spinbit_outgoing;
} picoquic_spinbit_def_t;

extern picoquic_spinbit_def_t picoquic_spin_function_table[];

/*
* The stateless packet structure is used to temporarily store
* stateless packets before they can be sent by servers.
*/

typedef struct st_picoquic_stateless_packet_t {
    struct st_picoquic_stateless_packet_t* next_packet;
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_local;
    int if_index_local;
    unsigned char received_ecn;
    size_t length;
    uint64_t receive_time;
    uint64_t cnxid_log64;
    picoquic_connection_id_t initial_cid;
    picoquic_packet_type_enum ptype;

    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquic_stateless_packet_t;

/* Handling of stateless packets */
picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic);
void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp);
picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(picoquic_quic_t* quic);
void picoquic_delete_stateless_packet(picoquic_stateless_packet_t* sp);

/* Data structure used to hold chunk of stream data before in sequence delivery */
typedef struct st_picoquic_stream_data_node_t {
    picosplay_node_t stream_data_node;
    picoquic_quic_t* quic;
    struct st_picoquic_stream_data_node_t* next_stream_data;
    uint64_t offset;  /* Stream offset of the first octet in "bytes" */
    size_t length;    /* Number of octets in "bytes" */
    const uint8_t* bytes;
    uint8_t data[PICOQUIC_MAX_PACKET_SIZE];
} picoquic_stream_data_node_t;

/* Data structure used to hold chunk of stream data queued by application */
typedef struct st_picoquic_stream_queue_node_t {
    picoquic_quic_t* quic;
    struct st_picoquic_stream_queue_node_t* next_stream_data;
    uint64_t offset;  /* Stream offset of the first octet in "bytes" */
    size_t length;    /* Number of octets in "bytes" */
    uint8_t* bytes;
} picoquic_stream_queue_node_t;

/*
 * The simple packet structure is used to store packets that
 * have been sent but are not yet acknowledged.
 * Packets are stored in unencrypted format.
 * The checksum length is the difference between encrypted and unencrypted.
 */

typedef struct st_picoquic_packet_t {
    struct st_picoquic_packet_t* packet_next;
    struct st_picoquic_packet_t* packet_previous;
    struct st_picoquic_path_t* send_path;
    picosplay_node_t queue_data_repeat_node;
    uint64_t sequence_number;
    uint64_t send_time;
    uint64_t delivered_prior;
    uint64_t delivered_time_prior;
    uint64_t delivered_sent_prior;
    uint64_t lost_prior;
    uint64_t inflight_prior;
    size_t data_repeat_frame;
    size_t data_repeat_index;

    /* Handling of data repeat queue requires sorting by priority,
    * stream_id, stream_offset, data_length
    */
    uint64_t data_repeat_priority;
    uint64_t data_repeat_stream_id;
    uint64_t data_repeat_stream_offset;
    size_t data_repeat_stream_data_length;

    size_t length;
    size_t checksum_overhead;
    size_t offset;
    picoquic_packet_type_enum ptype;
    picoquic_packet_context_enum pc;
    unsigned int is_evaluated : 1;
    unsigned int is_ack_eliciting : 1;
    unsigned int is_mtu_probe : 1;
    unsigned int is_multipath_probe : 1;
    unsigned int is_ack_trap : 1;
    unsigned int delivered_app_limited : 1;
    unsigned int sent_cwin_limited : 1;
    unsigned int is_preemptive_repeat : 1;
    unsigned int was_preemptively_repeated : 1;
    unsigned int is_queued_to_path : 1;
    unsigned int is_queued_for_retransmit : 1;
    unsigned int is_queued_for_spurious_detection : 1;
    unsigned int is_queued_for_data_repeat : 1;

    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquic_packet_t;

picoquic_packet_t* picoquic_create_packet(picoquic_quic_t* quic);
void picoquic_recycle_packet(picoquic_quic_t* quic, picoquic_packet_t* packet);

/* Definition of the token register used to prevent repeated usage of
 * the same new token, retry token, or session ticket.
 */

typedef struct st_picoquic_registered_token_t {
    picosplay_node_t registered_token_node;
    uint64_t token_time;
    uint64_t token_hash; /* The last 8 bytes of the token, normally taken from AEAD checksum */
    int count;
} picoquic_registered_token_t;

/*
 * Definition of the session ticket store and connection token
 * store that can be associated with a
 * client context.
 */

typedef enum {
    picoquic_tp_0rtt_max_data = 0,
    picoquic_tp_0rtt_max_stream_data_bidi_local = 1,
    picoquic_tp_0rtt_max_stream_data_bidi_remote = 2,
    picoquic_tp_0rtt_max_stream_data_uni = 3,
    picoquic_tp_0rtt_max_streams_id_bidir = 4,
    picoquic_tp_0rtt_max_streams_id_unidir = 5,
    picoquic_tp_0rtt_rtt_local = 6,
    picoquic_tp_0rtt_cwin_local = 7,
    picoquic_tp_0rtt_rtt_remote = 8,
    picoquic_tp_0rtt_cwin_remote = 9
} picoquic_tp_0rtt_enum;
#define PICOQUIC_NB_TP_0RTT 10

typedef struct st_picoquic_stored_ticket_t {
    struct st_picoquic_stored_ticket_t* next_ticket;
    char* sni;
    char* alpn;
    uint8_t* ip_addr;
    uint64_t tp_0rtt[PICOQUIC_NB_TP_0RTT];
    uint8_t* ticket;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t alpn_length;
    uint32_t version;
    uint16_t ticket_length;
    uint8_t ip_addr_length;
    uint8_t ip_addr_client_length;
    uint8_t* ip_addr_client;
    unsigned int was_used : 1;
} picoquic_stored_ticket_t;

int picoquic_store_ticket(picoquic_quic_t* quic,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint32_t version, const uint8_t* ip_addr, uint8_t ip_addr_length,
    const uint8_t* ip_addr_client, uint8_t ip_addr_client_length,
    uint8_t* ticket, uint16_t ticket_length, picoquic_tp_t const* tp);
picoquic_stored_ticket_t* picoquic_get_stored_ticket(picoquic_quic_t* quic,
    char const* sni, uint16_t sni_length,
    char const* alpn, uint16_t alpn_length, uint32_t version, int need_unused, uint64_t ticket_id);
int picoquic_get_ticket(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint32_t version,
    uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t * tp, int mark_used);
int picoquic_get_ticket_and_version(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint32_t version, uint32_t* ticket_version,
    uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t* tp, int mark_used);
int picoquic_save_tickets(const picoquic_stored_ticket_t* first_ticket,
    uint64_t current_time, char const* ticket_file_name);
int picoquic_load_tickets(picoquic_quic_t* quic, char const* ticket_file_name);
void picoquic_free_tickets(picoquic_stored_ticket_t** pp_first_ticket);
void picoquic_seed_ticket(picoquic_cnx_t* cnx, picoquic_path_t* path_x);


typedef struct st_picoquic_stored_token_t {
    struct st_picoquic_stored_token_t* next_token;
    char const* sni;
    uint8_t const* token;
    uint8_t const* ip_addr;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t token_length;
    uint8_t ip_addr_length;
    unsigned int was_used : 1;
} picoquic_stored_token_t;

int picoquic_store_token(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t const* token, uint16_t token_length);
int picoquic_get_token(picoquic_quic_t * quic,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t** token, uint16_t* token_length, int mark_used);

int picoquic_save_tokens(picoquic_quic_t* quic,
    char const* token_file_name);
int picoquic_load_tokens(picoquic_quic_t* quic, char const* token_file_name);
void picoquic_free_tokens(picoquic_stored_token_t** pp_first_token);

/* Remember the tickets issued by a server, and the last
 * congestion control parameters for the corresponding connection
 */

typedef struct st_picoquic_issued_ticket_t {
    struct st_picoquic_issued_ticket_t* next_ticket;
    struct st_picoquic_issued_ticket_t* previous_ticket;
    picohash_item hash_item;
    uint64_t ticket_id;
    uint64_t creation_time;
    uint64_t rtt;
    uint64_t cwin;
    uint8_t ip_addr[16];
    uint8_t ip_addr_length;
} picoquic_issued_ticket_t;

int picoquic_remember_issued_ticket(picoquic_quic_t* quic,
    uint64_t ticket_id,
    uint64_t rtt,
    uint64_t cwin,
    const uint8_t* ip_addr,
    uint8_t ip_addr_length);

picoquic_issued_ticket_t* picoquic_retrieve_issued_ticket(picoquic_quic_t* quic,
    uint64_t ticket_id);

/*
 * Transport parameters, as defined by the QUIC transport specification.
 * The initial code defined the type as an enum, but the binary representation
 * of the enum type is not strictly defined in C. Values like "0xff02de1"
 * could end up represented as a negative integer, and then converted to
 * the 64 bit representation "0xffffffffff02de1", which is not good.
 * We changed that to using macro for definition.
 */
typedef uint64_t picoquic_tp_enum;
#define picoquic_tp_original_connection_id 0 
#define picoquic_tp_idle_timeout 1 
#define picoquic_tp_stateless_reset_token 2 
#define picoquic_tp_max_packet_size 3 
#define picoquic_tp_initial_max_data 4 
#define picoquic_tp_initial_max_stream_data_bidi_local 5 
#define picoquic_tp_initial_max_stream_data_bidi_remote 6 
#define picoquic_tp_initial_max_stream_data_uni 7 
#define picoquic_tp_initial_max_streams_bidi 8 
#define picoquic_tp_initial_max_streams_uni 9 
#define picoquic_tp_ack_delay_exponent 10 
#define picoquic_tp_max_ack_delay 11 
#define picoquic_tp_disable_migration 12 
#define picoquic_tp_server_preferred_address 13 
#define picoquic_tp_active_connection_id_limit 14 
#define picoquic_tp_handshake_connection_id 15 
#define picoquic_tp_retry_connection_id 16 
#define picoquic_tp_max_datagram_frame_size 32 /* per draft-pauly-quic-datagram-05 */ 
#define picoquic_tp_test_large_chello 3127 
#define picoquic_tp_enable_loss_bit 0x1057 
#define picoquic_tp_min_ack_delay 0xff04de1bull 
#define picoquic_tp_enable_time_stamp 0x7158  /* x&1 */
#define picoquic_tp_grease_quic_bit 0x2ab2
#define picoquic_tp_version_negotiation 0x11
#define picoquic_tp_enable_bdp_frame 0xebd9 /* per draft-kuhn-quic-0rtt-bdp-09 */
#define picoquic_tp_initial_max_path_id  0x0f739bbc1b666d11ull /* per draft quic multipath 11 */
#define picoquic_tp_address_discovery 0x9f81a176 /* per draft-seemann-quic-address-discovery */

/* Callback for converting binary log to quic log at the end of a connection. 
 * This is kept private for now; and will only be set through the "set quic log"
 * API.
 */
typedef int (*picoquic_autoqlog_fn)(picoquic_cnx_t * cnx);

/* Callback used for the performance log
 */
typedef int (*picoquic_performance_log_fn)(picoquic_quic_t* quic, picoquic_cnx_t* cnx, int should_delete);

/* QUIC context, defining the tables of connections,
 * open sockets, etc.
 */
typedef struct st_picoquic_quic_t {
    void* tls_master_ctx;
    picoquic_stream_data_cb_fn default_callback_fn;
    void* default_callback_ctx;
    picoquic_stream_direct_receive_fn default_direct_receive_fn;
    void* default_direct_receive_ctx;
    char const* default_alpn;
    picoquic_alpn_select_fn alpn_select_fn;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
    uint8_t retry_seed[PICOQUIC_RETRY_SECRET_SIZE];
    uint64_t* p_simulated_time;
    char const* ticket_file_name;
    char const* token_file_name;
    picoquic_stored_ticket_t * p_first_ticket;
    picoquic_stored_token_t * p_first_token;
    picosplay_tree_t token_reuse_tree; /* detection of token reuse */
    uint8_t local_cnxid_length;
    uint8_t default_stream_priority;
    uint8_t default_datagram_priority;
    uint64_t local_cnxid_ttl; /* Max time to live of Connection ID in microsec, init to "forever" */
    uint32_t mtu_max;
    uint32_t initial_send_mtu_ipv4;
    uint32_t initial_send_mtu_ipv6;
    uint32_t padding_multiple_default;
    uint32_t padding_minsize_default;
    uint32_t sequence_hole_pseudo_period; /* Optimistic ack defense */
    picoquic_pmtud_policy_enum default_pmtud_policy;
    picoquic_spinbit_version_enum default_spin_policy;
    picoquic_lossbit_version_enum default_lossbit_policy;
    uint32_t default_multipath_option;
    uint64_t default_handshake_timeout;
    uint64_t crypto_epoch_length_max; /* Default packet interval between key rotations */
    uint32_t max_simultaneous_logs;
    uint32_t current_number_of_open_logs;
    uint32_t max_half_open_before_retry;
    uint32_t current_number_half_open;
    uint32_t current_number_connections;
    uint32_t tentative_max_number_connections;
    uint32_t max_number_connections;
    uint64_t stateless_reset_next_time; /* Next time Stateless Reset or VN packet can be sent */
    uint64_t stateless_reset_min_interval; /* Enforced interval between two stateless reset packets */
    uint64_t cwin_max; /* max value of cwin per connection */
    /* Flags */
    unsigned int check_token : 1;
    unsigned int force_check_token : 1;
    unsigned int provide_token : 1;
    unsigned int unconditional_cnx_id : 1;
    unsigned int client_zero_share : 1;
    unsigned int server_busy : 1;
    unsigned int is_cert_store_not_empty : 1;
    unsigned int use_long_log : 1;
    unsigned int should_close_log : 1;
    unsigned int enable_sslkeylog : 1; /* Enable the SSLKEYLOG feature */
    unsigned int use_unique_log_names : 1; /* Add 64 bit random number to log names for uniqueness */
    unsigned int dont_coalesce_init : 1; /* test option to turn of packet coalescing on server */
    unsigned int one_way_grease_quic_bit : 1; /* Grease of QUIC bit, but do not announce support */
    unsigned int log_pn_dec : 1; /* Log key hashes on key changes to debug crypto */
    unsigned int random_initial : 2; /* Randomize the initial PN number */
    unsigned int packet_train_mode : 1; /* Tune pacing for sending packet trains */
    unsigned int use_constant_challenges : 1; /* Use predictable challenges when producing constant logs. */
    unsigned int use_low_memory : 1; /* if possible, use low memory alternatives, e.g. for AES */
    unsigned int is_preemptive_repeat_enabled : 1; /* enable premptive repeat on new connections */
    unsigned int default_send_receive_bdp_frame : 1; /* enable sending and receiving BDP frame */
    unsigned int enforce_client_only : 1; /* Do not authorize incoming connections */
    unsigned int test_large_server_flight : 1; /* Use TP to ensure server flight is at least 8K */
    unsigned int is_port_blocking_disabled : 1; /* Do not check client port on incoming connections */
    unsigned int are_path_callbacks_enabled : 1; /* Enable path specific callbacks by default */
    unsigned int use_predictable_random : 1; /* For logging tests */
    unsigned int defer_stream_data_consumption : 1; /* Defer stream data consumption to application */
    picoquic_stateless_packet_t* pending_stateless_packet;

    picoquic_congestion_algorithm_t const* default_congestion_alg;
    uint64_t wifi_shadow_rtt;
    double bbr_quantum_ratio;

    struct st_picoquic_cnx_t* cnx_list;
    struct st_picoquic_cnx_t* cnx_last;
    picosplay_tree_t cnx_wake_tree;

    struct st_picoquic_cnx_t* cnx_in_progress;

    picohash_table* table_cnx_by_id;
    picohash_table* table_cnx_by_net;
    picohash_table* table_cnx_by_icid;
    picohash_table* table_cnx_by_secret;

    picohash_table* table_issued_tickets;
    picoquic_issued_ticket_t* table_issued_tickets_first;
    picoquic_issued_ticket_t* table_issued_tickets_last;
    size_t table_issued_tickets_nb;

    picoquic_packet_t * p_first_packet;
    int nb_packets_in_pool;
    int nb_packets_allocated;
    int nb_packets_allocated_max;

    picoquic_stream_data_node_t* p_first_data_node;
    int nb_data_nodes_in_pool;
    int nb_data_nodes_allocated;
    int nb_data_nodes_allocated_max;

    picoquic_connection_id_cb_fn cnx_id_callback_fn;
    void* cnx_id_callback_ctx;

    void* aead_encrypt_ticket_ctx;
    void* aead_decrypt_ticket_ctx;
    void ** retry_integrity_sign_ctx;
    void ** retry_integrity_verify_ctx;

    struct st_ptls_verify_certificate_t * verify_certificate_callback;
    picoquic_free_verify_certificate_ctx free_verify_certificate_callback_fn;

    picoquic_tp_t default_tp;

    picoquic_fuzz_fn fuzz_fn;
    void* fuzz_ctx;
    int wake_file;
    int wake_line;

    /* Global flow control enforcement */
    uint64_t max_data_limit;

    /* Path quality callback. These variables store the default values
    * of the min deltas required to perform path quality signaling.
    */ 
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;

    /* Logging APIS */
    void* F_log;
    char* binlog_dir;
    char* qlog_dir;
    picoquic_autoqlog_fn autoqlog_fn;
    struct st_picoquic_unified_logging_t* text_log_fns;
    struct st_picoquic_unified_logging_t* bin_log_fns;
    struct st_picoquic_unified_logging_t* qlog_fns;
    picoquic_performance_log_fn perflog_fn;
    void* v_perflog_ctx;

#ifdef BBRExperiment
    bbr_exp bbr_exp_flags;
#endif

} picoquic_quic_t;

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch);

int picoquic_registered_token_check_reuse(picoquic_quic_t* quic, const uint8_t* token, size_t token_length, uint64_t expiry_time);

void picoquic_registered_token_clear(picoquic_quic_t* quic, uint64_t expiry_time_max);

/*
 * SACK dashboard item, part of connection context. Each item
 * holds a range of packet numbers that have been received.
 * The same structured is reused in stream management to hold
 * a range of bytes that have been received.
 */

typedef struct st_picoquic_sack_item_t {
    picosplay_node_t node;
    uint64_t start_of_sack_range;
    uint64_t end_of_sack_range;
    uint64_t time_created;
    int nb_times_sent[2];
} picoquic_sack_item_t;

typedef struct st_picoquic_sack_range_count_t {
    int range_counts[PICOQUIC_MAX_ACK_RANGE_REPEAT];
} picoquic_sack_range_count_t;

typedef struct st_picoquic_sack_list_t {
    picosplay_tree_t ack_tree;
    uint64_t ack_horizon;
    int64_t horizon_delay;
    picoquic_sack_range_count_t rc[2];
} picoquic_sack_list_t;

/*
 * Stream head.
 * Stream contains bytes of data, which are not always delivered in order.
 * When in order data is available, the application can read it,
 * or a callback can be set.
 *
 * Streams are maintained in the context of connections, which includes:
 *
 * - a list of open streams, managed as a "splay"
 * - a subset of "output" streams, managed as a double linked list
 *
 * For each stream, the code maintains a list of received stream segments, managed as
 * a "splay" of "stream data nodes".
 *
 * Two input modes are supported. If streams are marked active, the application receives
 * a callback and provides data "just in time". Other streams can just push data using
 * "picoquic_add_to_stream", and the data segments will be listed in the "send_queue".
 * Segments in the send queue will be sent in order, and the "active" poll for data
 * will only happen when all segments are sent.
 *
 * The stream structure holds a variety of parameters about the state of the stream.
 */

typedef struct st_picoquic_stream_head_t {
    picosplay_node_t stream_node; /* splay of streams in connection context */
    struct st_picoquic_stream_head_t * next_output_stream; /* link in the list of output streams */
    struct st_picoquic_stream_head_t * previous_output_stream;
    picoquic_cnx_t * cnx;
    uint64_t stream_id;
    struct st_picoquic_path_t * affinity_path; /* Path for which affinity is set, or NULL if none */
    uint64_t consumed_offset; /* amount of data consumed by the application */
    uint64_t delivered_offset; /* amount of data delivered to the application */
    uint64_t fin_offset; /* If the fin mark is received, index of the byte after last */
    uint64_t maxdata_local; /* flow control limit of how much the peer is authorized to send */
    uint64_t maxdata_local_acked; /* highest value in max stream data frame acked by the peer */
    uint64_t maxdata_remote; /* flow control limit of how much we authorize the peer to send */
    uint64_t local_error;
    uint64_t remote_error;
    uint64_t local_stop_error;
    uint64_t remote_stop_error;
    uint64_t last_time_data_sent;
    picosplay_tree_t stream_data_tree; /* splay of received stream segments */
    uint64_t sent_offset; /* Amount of data sent in the stream */
    picoquic_stream_queue_node_t* send_queue; /* if the stream is not "active", list of data segments ready to send */
    void * app_stream_ctx;
    picoquic_stream_direct_receive_fn direct_receive_fn; /* direct receive function, if not NULL */
    void* direct_receive_ctx; /* direct receive context */
    picoquic_sack_list_t sack_list; /* Track which parts of the stream were acknowledged by the peer */
    /* Stream priority -- lowest is most urgent */
    uint8_t stream_priority;
    /* Flags describing the state of the stream */
    unsigned int is_active : 1; /* The application is actively managing data sending through callbacks */
    unsigned int fin_requested : 1; /* Application has requested Fin of sending stream */
    unsigned int fin_sent : 1; /* Fin sent to peer */
    unsigned int fin_received : 1; /* Fin received from peer */
    unsigned int fin_signalled : 1; /* After Fin was received from peer, Fin was signalled to the application */
    unsigned int reset_requested : 1; /* Application has requested to reset the stream */
    unsigned int reset_sent : 1; /* Reset stream sent to peer */
    unsigned int reset_acked : 1; /* Reset stream acked by the peer */
    unsigned int reset_received : 1; /* Reset stream received from peer */
    unsigned int reset_signalled : 1; /* After Reset stream received from peer, application was notified */
    unsigned int stop_sending_requested : 1; /* Application has requested to stop sending */
    unsigned int stop_sending_sent : 1; /* Stop sending was sent to peer */
    unsigned int stop_sending_received : 1; /* Stop sending received from peer */
    unsigned int stop_sending_signalled : 1; /* After stop sending received from peer, application was notified */
    unsigned int max_stream_updated : 1; /* After stream was closed in both directions, the max stream id number was updated */
    unsigned int stream_data_blocked_sent : 1; /* If stream_data_blocked has been sent to peer, and no data sent on stream since */
    unsigned int is_output_stream : 1; /* If stream is listed in the output list */
    unsigned int is_closed : 1; /* Stream is closed, closure is accouted for */
    unsigned int is_discarded : 1; /* There should be no more callback for that stream, the application has discarded it */
} picoquic_stream_head_t;

#define IS_CLIENT_STREAM_ID(id) (unsigned int)(((id) & 1) == 0)
#define IS_BIDIR_STREAM_ID(id)  (unsigned int)(((id) & 2) == 0)
#define IS_LOCAL_STREAM_ID(id, client_mode)  (unsigned int)(((id)^(client_mode)) & 1)
#define STREAM_ID_FROM_RANK(rank, client_mode, is_unidir) ((((uint64_t)(rank)-(uint64_t)1)<<2)|(((uint64_t)is_unidir)<<1)|((uint64_t)(client_mode^1)))
#define STREAM_RANK_FROM_ID(id) ((id + 4)>>2)
#define STREAM_TYPE_FROM_ID(id) ((id)&3)
#define NEXT_STREAM_ID_FOR_TYPE(id) ((id)+4)

/*
 * Frame queue. This is used for miscellaneous packets. It is also used for
 * various tests, allowing for fault injection. 
 *
 * Misc frames are sent at the next opportunity. 
 * TODO: consider flagging MISC frames with expected packet type or epoch,
 * to avoid creating unexpected protocol errors.
 *
 * The misc frame are allocated in meory as blobs, starting with the
 * misc_frame_header, followed by the misc frame content.
 */

typedef struct st_picoquic_misc_frame_header_t {
    struct st_picoquic_misc_frame_header_t* next_misc_frame;
    struct st_picoquic_misc_frame_header_t* previous_misc_frame;
    size_t length;
    picoquic_packet_context_enum pc;
    int is_pure_ack;
} picoquic_misc_frame_header_t;

/* Per epoch sequence/packet context.
* There are three such contexts:
* 0: Application (0-RTT and 1-RTT)
* 1: Handshake
* 2: Initial
* The context holds all the data required to manage sending and
* resending of packets.
*/

typedef struct st_picoquic_packet_context_t {
    uint64_t send_sequence; /* picoquic_decode_ack_frame */
    uint64_t next_sequence_hole;
    uint64_t retransmit_sequence;
    uint64_t highest_acknowledged;
    uint64_t latest_time_acknowledged; /* time at which the highest acknowledged was sent */
    uint64_t highest_acknowledged_time; /* time at which the highest ack was received */
    picoquic_packet_t* pending_last;
    picoquic_packet_t* pending_first;
    picoquic_packet_t* retransmitted_newest;
    picoquic_packet_t* retransmitted_oldest;
    picoquic_packet_t* preemptive_repeat_ptr;
    /* monitor size of queues */
    uint64_t retransmitted_queue_size;
    /* ECN Counters */
    uint64_t ecn_ect0_total_remote;
    uint64_t ecn_ect1_total_remote;
    uint64_t ecn_ce_total_remote;
    /* Flags */
    unsigned int ack_of_ack_requested : 1; /* TODO: Initialized, unused */
} picoquic_packet_context_t;

/* Per epoch ack context.
* There are three such contexts:
* 0: Application (0-RTT and 1-RTT)
* 1: Handshake
* 2: Initial
* The context holds all the data required to manage acknowledgments
*/
typedef struct st_picoquic_ack_context_track_t {
    uint64_t highest_ack_sent; /* picoquic_format_ack_frame */
    uint64_t highest_ack_sent_time; /* picoquic_format_ack_frame */
    uint64_t time_oldest_unack_packet_received; /* picoquic_is_ack_needed: first packet that has not been acked yet */

    unsigned int ack_needed : 1; /* picoquic_format_ack_frame */
    unsigned int ack_after_fin : 1; /* picoquic_format_ack_frame */
    unsigned int out_of_order_received : 1; /* picoquic_is_ack_needed */
    unsigned int is_immediate_ack_required : 1;
} picoquic_ack_context_track_t;

typedef struct st_picoquic_ack_context_t {
    picoquic_sack_list_t sack_list; /* picoquic_format_ack_frame */
    uint64_t time_stamp_largest_received; /* picoquic_format_ack_frame */
    picoquic_ack_context_track_t act[2];
    uint64_t crypto_rotation_sequence; /* Lowest sequence seen with current key */

    /* ECN Counters */
    uint64_t ecn_ect0_total_local; /* picoquic_format_ack_frame */
    uint64_t ecn_ect1_total_local; /* picoquic_format_ack_frame */
    uint64_t ecn_ce_total_local; /* picoquic_format_ack_frame */
    /* Flags */
    unsigned int sending_ecn_ack : 1; /* picoquic_format_ack_frame, picoquic_ecn_accounting */
} picoquic_ack_context_t;

/* Local CID.
 * Local CID are created on demand, and stashed in the CID list.
 * When the CID is created, it is registered in the QUIC context as 
 * pointing to the local connection. We manage collisions, so two
 * connections do not use the same context.
 * When a CID is associated with a path, we set a pointer from the
 * path to the entry in the CID list. If a CID is retired, these pointers
 * are nullified.
*/
typedef struct st_picoquic_local_cnxid_t {
    struct st_picoquic_local_cnxid_t* next;
    picoquic_cnx_t* registered_cnx;
    picohash_item hash_item;
    uint64_t path_id;
    uint64_t sequence;
    uint64_t create_time;
    picoquic_connection_id_t cnx_id;
    unsigned int is_acked;
} picoquic_local_cnxid_t;

typedef struct st_picoquic_local_cnxid_list_t {
    struct st_picoquic_local_cnxid_list_t * next_list;
    uint64_t unique_path_id;
    uint64_t local_cnxid_sequence_next;
    uint64_t local_cnxid_retire_before;
    uint64_t local_cnxid_oldest_created;
    int nb_local_cnxid;
    int nb_local_cnxid_expired;
    unsigned int is_demoted : 1;
    uint64_t demotion_time;
    picoquic_local_cnxid_t* local_cnxid_first;
} picoquic_local_cnxid_list_t;

/* Remote CID.
 * Remote CID are received from the peer. RCID #0 is received during the 
 * handshake, RCID#1 MAY be received as part of server's transport parameters,
 * all other RCID are received in New CID frames. */
typedef struct st_picoquic_remote_cnxid_t {
    struct st_picoquic_remote_cnxid_t* next;
    uint64_t sequence;
    picoquic_connection_id_t cnx_id;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    int nb_path_references;
    unsigned int needs_removal : 1;
    unsigned int retire_sent : 1;
    unsigned int retire_acked : 1;
    picoquic_packet_context_t pkt_ctx;
} picoquic_remote_cnxid_t;

typedef struct st_picoquic_remote_cnxid_stash_t {
    struct st_picoquic_remote_cnxid_stash_t* next_stash;
    uint64_t unique_path_id;
    uint64_t retire_cnxid_before;
    picoquic_remote_cnxid_t* cnxid_stash_first;
    unsigned int is_in_use : 1;
} picoquic_remote_cnxid_stash_t;

/*
* Pacing uses a set of per path variables:
* - rate: bytes per second.
* - evaluation_time: last time the path was evaluated.
* - bucket_max: maximum value (capacity) of the leaky bucket.
* - packet_time_microsec: max of (packet_time_nano_sec/1024, 1) microsec.
* Internal variables:
* - bucket_nanosec: number of nanoseconds of transmission time that are allowed.
* - packet_time_nanosec: number of nanoseconds required to send a full size packet.
*/
typedef struct st_picoquic_pacing_t {
    uint64_t rate;
    uint64_t evaluation_time;
    int64_t bucket_max;
    uint64_t packet_time_microsec;
    uint64_t quantum_max;
    uint64_t rate_max;
    int bandwidth_pause;
    /* High precision variables should only be used inside pacing.c */
    int64_t bucket_nanosec;
    int64_t packet_time_nanosec;
} picoquic_pacing_t;

/*
* Per path context.
* Path contexts are created:
* - At the beginning of the connection for path[0]
* - When sending or receiving packets to a or from new addresses and ports.
* 
* When a path is created, it is assigned a local connection idand a remote connection ID.
* After that, the path has to be validated by a successful challenge/response.
*
* If multipath is supported, paths remain in the list until they are abandoned.
* 
* As soon as a path is validated, it moves to position 0. The old path[0] moves to the
* last position, and is marked as deprecated. After about 1 RTT, the path resource
* are freed. (TODO: once we actually support multipath, change that behavior.)
* (TODO: servers should only validate the path after receiving non-probing frames from
* the client.)
*
* Congestion control and spin bit management are path specific.
* Packet numbering is global, see packet context.
*/
typedef struct st_picoquic_path_t {
    picoquic_local_cnxid_t* p_local_cnxid; 
    picoquic_remote_cnxid_t* p_remote_cnxid;
    struct sockaddr_storage registered_peer_addr;
    picohash_item net_id_hash_item;
    struct st_picoquic_cnx_t* cnx;
    uint64_t unique_path_id;

    void* app_path_ctx;
    /* If using unique path id multipath */
    picoquic_ack_context_t ack_ctx;
    picoquic_packet_context_t pkt_ctx;
    /* Peer address. */
    struct sockaddr_storage peer_addr;
    /* Local address, on the local network */
    struct sockaddr_storage local_addr;
    unsigned long if_index_dest;
    /* Address observed by the peer */
    struct sockaddr_storage observed_addr;
    /* Manage the reception of observed addresses */
    uint64_t observed_address_received;
    /* Manage the publishing of observed addresses */
    unsigned int observed_addr_acked:1;
    int nb_observed_repeat;
    uint64_t observed_sequence_sent;
    uint64_t observed_time;
    /* Manage path probing logic */
    uint64_t last_non_path_probing_pn;
    /* Challenge used for this path */
    uint64_t challenge_response;
    uint64_t challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t challenge_time;
    uint64_t demotion_time;
    uint64_t challenge_time_first;
    uint8_t challenge_repeat_count;
    /* NAT Challenge for this path, if using unique path id */
    uint64_t nat_challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t nat_challenge_time;
    uint64_t nat_challenge_repeat_count;
    picoquic_remote_cnxid_t* p_remote_nat_cnxid;
    unsigned long if_index_nat_dest;
    struct sockaddr_storage nat_peer_addr;
    struct sockaddr_storage nat_local_addr;
    /* Last time a packet was sent on this path. */
    uint64_t last_sent_time;
    uint64_t status_sequence_to_receive_next;
    uint64_t status_sequence_sent_last;
    /* Last 1-RTT "non path validating" packet received on this path */
    /* flags */
    unsigned int mtu_probe_sent : 1;
    unsigned int path_is_published : 1;
    unsigned int challenge_required : 1;
    unsigned int challenge_verified : 1;
    unsigned int challenge_failed : 1;
    unsigned int response_required : 1;
    unsigned int nat_challenge_required : 1;
    unsigned int path_is_standby : 1;
    unsigned int path_is_demoted : 1;
    unsigned int path_abandon_received : 1;
    unsigned int path_abandon_sent : 1;
    unsigned int current_spin : 1;
    unsigned int last_bw_estimate_path_limited : 1;
    unsigned int path_cid_rotated : 1;
    unsigned int path_is_preferred_path : 1;
    unsigned int is_nat_challenge : 1;
    unsigned int is_cc_data_updated : 1;
    unsigned int is_multipath_probe_needed : 1;
    unsigned int was_local_cnxid_retired : 1;
    unsigned int is_ssthresh_initialized : 1;
    unsigned int is_token_published : 1;
    unsigned int is_ticket_seeded : 1; /* Whether the current ticket has been updated with RTT and CWIN */
    unsigned int is_bdp_sent : 1;
    unsigned int is_nominal_ack_path : 1;
    unsigned int is_ack_lost : 1;
    unsigned int is_ack_expected : 1;
    unsigned int is_datagram_ready : 1;
    unsigned int is_pto_required : 1; /* Should send PTO probe */
    unsigned int is_probing_nat : 1; /* When path transmission is scheduled only for NAT probing */
    unsigned int is_lost_feedback_notified : 1; /* Lost feedback has been notified */
    unsigned int is_cca_probing_up : 1; /* congestion control algorithm is seeking more bandwidth */
    unsigned int rtt_is_initialized : 1; /* RTT was measured at least once. */
    unsigned int slipstream_path_mode : 2; /* 0=unknown, 1=recursive, 2=authoritative */
    unsigned int slipstream_no_ack_delay : 1; /* Disable delayed ACK for this path */
    
    /* Management of retransmissions in a path.
     * The "path_packet" variables are used for the RACK algorithm, per path, to avoid
     * declaring packets lost just because another path is delivering them faster.
     * The "number of retransmit" counts the number of unsuccessful retransmissions; it
     * is reset to zero if a new packet is acknowledged.
     */
    uint64_t last_packet_received_at;
    uint64_t last_loss_event_detected;
    uint64_t nb_retransmit; /* Number of timeout retransmissions since last ACK */
    uint64_t total_bytes_lost; /* Sum of length of packet lost on this path */
    uint64_t nb_losses_found;
    uint64_t nb_timer_losses;
    uint64_t nb_spurious; /* Number of spurious retransmissions for the path */
                                         
    /* Loss bit data */
    uint64_t nb_losses_reported;
    uint64_t q_square;
    /* Time measurement */
    uint64_t max_ack_delay;
    uint64_t rtt_sample;
    uint64_t one_way_delay_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_variant;
    uint64_t retransmit_timer;
    uint64_t rtt_min;
    uint64_t rtt_max;
    uint64_t max_spurious_rtt;
    uint64_t max_reorder_delay;
    uint64_t max_reorder_gap;
    uint64_t latest_sent_time;
    uint64_t rtt_packet_previous_period;
    uint64_t rtt_time_previous_period;
    uint64_t nb_rtt_estimate_in_period;
    uint64_t sum_rtt_estimate_in_period;
    uint64_t max_rtt_estimate_in_period;
    uint64_t min_rtt_estimate_in_period;


    /* MTU */
    size_t send_mtu;
    size_t send_mtu_max_tried;

    /* Bandwidth measurement */
    uint64_t delivered; /* The total amount of data delivered so far on the path */
    uint64_t delivered_last; /* Amount delivered by last bandwidth estimation */
    uint64_t delivered_time_last; /* time last delivered packet was delivered */
    uint64_t delivered_sent_last; /* time last delivered packet was sent */
    uint64_t delivered_limited_index;
    uint64_t delivered_last_packet;
    uint64_t bandwidth_estimate; /* In bytes per second */
    uint64_t bandwidth_estimate_max; /* Maximum of bandwidth estimate over life of path */
    uint64_t max_sample_acked_time; /* Time max sample was delivered */
    uint64_t max_sample_sent_time; /* Time max sample was sent */
    uint64_t max_sample_delivered; /* Delivered value at time of max sample */
    uint64_t peak_bandwidth_estimate; /* In bytes per second, measured on short interval with highest bandwidth */

    uint64_t bytes_sent; /* Total amount of bytes sent on the path */
    uint64_t received; /* Total amount of bytes received from the path */
    uint64_t receive_rate_epoch; /* Time of last receive rate measurement */
    uint64_t received_prior; /* Total amount received at start of epoch */
    uint64_t receive_rate_estimate; /* In bytes per second */
    uint64_t receive_rate_max; /* In bytes per second */

    /* Congestion control state */
    uint64_t cwin;
    uint64_t bytes_in_transit;
    uint64_t last_sender_limited_time;
    uint64_t last_cwin_blocked_time;
    uint64_t last_time_acked_data_frame_sent;
    void* congestion_alg_state;
    picoquic_pacing_t pacing;

    /* MTU safety tracking */
    uint64_t nb_mtu_losses;

    /* Debug MP */
    int lost_after_delivered;
    int responder;
    int challenger;
    int polled;
    int paced;
    int congested;
    int selected;
    int nb_delay_outliers;

    /* Path quality callback. These variables store the delta set for signaling
     * and the threshold computed based on these deltas and the latest published value.
     */ 
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;
    uint64_t rtt_threshold_low;
    uint64_t rtt_threshold_high;
    uint64_t pacing_rate_threshold_low;
    uint64_t pacing_rate_threshold_high;
    uint64_t receive_rate_threshold_low;
    uint64_t receive_rate_threshold_high;

    /* BDP parameters sent by the server to be stored at client */
    uint64_t rtt_min_remote;
    uint64_t cwin_remote;
    uint8_t ip_client_remote[16];
    uint8_t ip_client_remote_length;
    
} picoquic_path_t;

/* Crypto context. There are four such contexts:
* 0: Initial context, with encryption based on a version dependent key,
* 1: 0-RTT context
* 2: Handshake context
* 3: Application data
*/
typedef struct st_picoquic_crypto_context_t {
    void* aead_encrypt;
    void* aead_decrypt;
    void* pn_enc; /* Used for PN encryption */
    void* pn_dec; /* Used for PN decryption */
} picoquic_crypto_context_t;

/*
* Per connection context.
*/
typedef struct st_picoquic_cnx_t {
    picoquic_quic_t* quic;

    /* Management of context retrieval tables */

    struct st_picoquic_cnx_t* next_in_table;
    struct st_picoquic_cnx_t* previous_in_table;

    /* Proposed version, may be zero if there is no reference.
     * Rejected version that triggered reception of a Version negotiation packet, zero by default.
     * Desired version, target of possible compatible negotiation.
     */
    uint32_t proposed_version;
    uint32_t rejected_version;
    uint32_t desired_version;
    int version_index;

    /* Series of flags showing the state or choices of the connection */
    unsigned int is_0RTT_accepted : 1; /* whether 0-RTT is accepted */
    unsigned int remote_parameters_received : 1; /* whether remote parameters where received */
    unsigned int client_mode : 1; /* Is this connection the client side? */
    unsigned int key_phase_enc : 1; /* Key phase used in outgoing packets */
    unsigned int key_phase_dec : 1; /* Key phase expected in incoming packets */
    unsigned int zero_rtt_data_accepted : 1; /* Peer confirmed acceptance of zero rtt data */
    unsigned int sending_ecn_ack : 1; /* ECN data has been received, should be copied in acks */
    unsigned int sent_blocked_frame : 1; /* Blocked frame has been sent */
    unsigned int stream_blocked_bidir_sent : 1; /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int stream_blocked_unidir_sent : 1; /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int max_stream_data_needed : 1; /* If at least one stream needs more data */
    unsigned int path_demotion_needed : 1; /* If at least one path was recently demoted */
    unsigned int alt_path_challenge_needed : 1; /* If at least one alt path challenge is needed or in progress */
    unsigned int is_handshake_finished : 1; /* If there are no more packets to ack or retransmit in initial  or handshake contexts */
    unsigned int is_handshake_done_acked : 1; /* If the peer has acked the handshake done packet */
    unsigned int is_new_token_acked : 1; /* Has the peer acked a new token? This assumes at most one new token sent per connection */
    unsigned int is_1rtt_received : 1; /* If at least one 1RTT packet has been received */
    unsigned int is_1rtt_acked : 1; /* If at least one 1RTT packet has been acked by the peer */
    unsigned int has_successful_probe : 1; /* At least one probe was successful */
    unsigned int grease_transport_parameters : 1; /* Exercise greasing of transport parameters */
    unsigned int test_large_chello : 1; /* Add a greasing parameter to test sending CHello on multiple packets */
    unsigned int initial_validated : 1; /* Path has been validated, DOS amplification protection is lifted */
    unsigned int initial_repeat_needed : 1; /* Path has not been validated, repeated initial was received */
    unsigned int is_loss_bit_enabled_incoming : 1; /* Read the loss bits in incoming packets */
    unsigned int is_loss_bit_enabled_outgoing : 1; /* Insert the loss bits in outgoing packets */
    unsigned int is_ack_frequency_negotiated : 1; /* Ack Frequency extension negotiated */
    unsigned int is_ack_frequency_updated : 1; /* Should send an ack frequency frame asap. */
    unsigned int recycle_sooner_needed : 1; /* There may be a need to recycle "sooner" packets */
    unsigned int is_time_stamp_enabled : 1; /* Read time stamp on on incoming */
    unsigned int is_time_stamp_sent : 1; /* Send time stamp with ACKS */
    unsigned int is_pacing_update_requested : 1; /* Whether the application subscribed to pacing updates */
    unsigned int is_path_quality_update_requested : 1; /* Whether the application subscribed to path quality updates */
    unsigned int is_hcid_verified : 1; /* Whether the HCID was received from the peer */
    unsigned int do_grease_quic_bit : 1; /* Negotiated grease of QUIC bit */
    unsigned int quic_bit_greased : 1; /* Indicate whether the quic bit was greased at least once */
    unsigned int quic_bit_received_0 : 1; /* Indicate whether the quic bit was received as zero at least once */
    unsigned int is_half_open : 1; /* for server side connections, created but not yet complete */
    unsigned int did_receive_short_initial : 1; /* whether peer sent unpadded initial packet */
    unsigned int ack_ignore_order_local : 1; /* Request peer to not generate immediate ack if out of order packet received */
    unsigned int ack_ignore_order_remote : 1; /* Peer requested no immediate ack if out of order packet received */
    unsigned int are_path_callbacks_enabled : 1; /* Enable path specific callbacks */
    unsigned int is_sending_large_buffer : 1; /* Buffer provided by application is sufficient for PMTUD */
    unsigned int is_preemptive_repeat_enabled : 1; /* Preemptive repat of packets to reduce transaction latency */
    unsigned int do_version_negotiation : 1; /* Whether compatible version negotiation is activated */
    unsigned int send_receive_bdp_frame : 1; /* enable sending and receiving BDP frame */
    unsigned int cwin_notified_from_seed : 1; /* cwin was reset from a seeded value */
    unsigned int is_datagram_ready : 1; /* Active polling for datagrams */
    unsigned int is_immediate_ack_required : 1; /* Should send an ACK asap */
    unsigned int is_multipath_enabled : 1; /* Unique path ID extension has been negotiated */
    unsigned int is_lost_feedback_notification_required : 1; /* CC algorithm requests lost feedback notification */
    unsigned int is_forced_probe_up_required : 1; /* application wants "probe up" if CC requests it */
    unsigned int is_address_discovery_provider : 1; /* send the address discovery extension */
    unsigned int is_address_discovery_receiver : 1; /* receive the address discovery extension */

    /* Requesting polls */
    unsigned int is_poll_requested : 1; /* Whether the application requested to poll */

    /* Disable ack delay */
    unsigned int no_ack_delay : 1; /* Whether the ack delay is disabled, no impact on transport parameters */

    /* PMTUD policy */
    picoquic_pmtud_policy_enum pmtud_policy;
    /* Spin bit policy */
    picoquic_spinbit_version_enum spin_policy;
    /* Idle timeout in microseconds */
    uint64_t idle_timeout;
    /* Local and remote parameters */
    picoquic_tp_t local_parameters;
    picoquic_tp_t remote_parameters;
    /* Padding policy */
    uint32_t padding_multiple;
    uint32_t padding_minsize;
    /* Value of RTT and CWIN remembered from previous connections */
    uint8_t seed_ip_addr[PICOQUIC_STORED_IP_MAX];
    uint8_t seed_ip_addr_length;
    uint64_t seed_rtt_min;
    uint64_t seed_cwin;
    /* Identification of ticket issued to the current connection,
     * and if present of the ticket used to resume the connection.
     * On server this is the unique sequence number of the ticket.
     * On client this is the creation time of the ticket.
     */
    uint64_t issued_ticket_id;
    uint64_t resumed_ticket_id;

    /* On clients, document the SNI and ALPN expected from the server */
    /* TODO: there may be a need to propose multiple ALPN */
    char const* sni;
    char const* alpn;
    /* On clients, receives the maximum 0RTT size accepted by server */
    size_t max_early_data_size;
    /* Call back function and context */
    picoquic_stream_data_cb_fn callback_fn;
    void* callback_ctx;

    /* connection state, ID, etc. Todo: allow for multiple cnxid */
    picoquic_state_enum cnx_state;
    picoquic_connection_id_t initial_cnxid;
    picoquic_connection_id_t original_cnxid;
    struct sockaddr_storage registered_icid_addr;
    picohash_item registered_icid_item;
    struct sockaddr_storage registered_secret_addr;
    uint8_t registered_reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picohash_item registered_reset_secret_item;

    uint64_t start_time;
    int64_t phase_delay;
    uint64_t application_error;
    uint64_t local_error;
    char const * local_error_reason;
    uint64_t remote_application_error;
    uint64_t remote_error;
    uint64_t offending_frame_type;
    uint16_t retry_token_length;
    uint8_t * retry_token;

    /* Next time sending data is expected */
    uint64_t next_wake_time;
    picosplay_node_t cnx_wake_node;
    /* Wakeup time requested by the application */
    uint64_t app_wake_time;
    /* TLS context, TLS Send Buffer, streams, epochs */
    void* tls_ctx;
    uint64_t crypto_epoch_length_max;
    uint64_t crypto_epoch_sequence;
    uint64_t crypto_rotation_time_guard;
    struct st_ptls_buffer_t* tls_sendbuf;
    uint16_t psk_cipher_suite_id;

    picoquic_stream_head_t tls_stream[PICOQUIC_NUMBER_OF_EPOCHS]; /* Separate input/output from each epoch */
    picoquic_crypto_context_t crypto_context[PICOQUIC_NUMBER_OF_EPOCHS]; /* Encryption and decryption objects */
    picoquic_crypto_context_t crypto_context_old; /* Old encryption and decryption context after key rotation */
    picoquic_crypto_context_t crypto_context_new; /* New encryption and decryption context just before key rotation */
    uint64_t crypto_failure_count;
    /* Liveness detection */
    uint64_t latest_progress_time; /* last local time at which the connection progressed */
    uint64_t latest_receive_time; /* last time something was received from the peer */
    /* Close connection management */
    uint64_t last_close_sent;
    /* Sequence and retransmission state */
    picoquic_packet_context_t pkt_ctx[picoquic_nb_packet_context];
    /* Acknowledgement state */
    picoquic_ack_context_t ack_ctx[picoquic_nb_packet_context];
    /* Sequence number of the next observed address frame */
    uint64_t observed_number;
    /* Statistics */
    uint64_t nb_bytes_queued;
    uint32_t nb_zero_rtt_sent;
    uint32_t nb_zero_rtt_acked;
    uint32_t nb_zero_rtt_received;
    size_t max_mtu_sent;
    size_t max_mtu_received;
    uint64_t nb_packets_received;
    uint64_t nb_trains_sent;
    uint64_t nb_trains_short;
    uint64_t nb_trains_blocked_cwin;
    uint64_t nb_trains_blocked_pacing;
    uint64_t nb_trains_blocked_others;
    uint64_t nb_packets_sent;
    uint64_t nb_packets_logged;
    uint64_t nb_retransmission_total;
    uint64_t nb_preemptive_repeat;
    uint64_t nb_spurious;
    uint64_t nb_crypto_key_rotations;
    uint64_t nb_packet_holes_inserted;
    uint64_t max_ack_delay_remote;
    uint64_t max_ack_gap_remote;
    uint64_t max_ack_delay_local;
    uint64_t max_ack_gap_local;
    uint64_t min_ack_delay_remote;
    uint64_t min_ack_delay_local;
    unsigned int cwin_blocked : 1;
    unsigned int flow_blocked : 1;
    unsigned int stream_blocked : 1;
    /* Congestion algorithm */
    picoquic_congestion_algorithm_t const* congestion_alg;
    /* Management of quality signalling updates */
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;
    uint64_t pacing_rate_signalled;
    uint64_t pacing_increase_threshold;
    uint64_t pacing_decrease_threshold;
    uint64_t pacing_change_threshold;

    /* Data accounting for limiting amplification attacks */
    uint64_t initial_data_received;
    uint64_t initial_data_sent;

    /* Flow control information */
    uint64_t data_sent;
    uint64_t data_received;
    uint64_t data_consumed;
    uint64_t maxdata_local; /* Highest value sent to the peer */
    uint64_t maxdata_local_acked; /* Highest value acked by the peer */
    uint64_t maxdata_remote; /* Highest value received from the peer */
    uint64_t max_stream_data_local;
    uint64_t max_stream_data_remote;
    uint64_t max_stream_id_bidir_local; /* Highest value sent to the peer */
    uint64_t max_stream_id_bidir_rank_acked; /* Highest rank value acked by the peer */
    uint64_t max_stream_id_bidir_local_computed; /* Value computed from stream FIN but not yet sent */
    uint64_t max_stream_id_bidir_remote; /* Highest value received from the peer */
    uint64_t max_stream_id_unidir_local; /* Highest value sent to the peer */
    uint64_t max_stream_id_unidir_rank_acked; /* Highest rank value acked by the peer */
    uint64_t max_stream_id_unidir_local_computed;  /* Value computed from stream FIN but not yet sent */
    uint64_t max_stream_id_unidir_remote; /* Highest value received from the peer */

    /* Queue for frames waiting to be sent */
    picoquic_misc_frame_header_t* first_misc_frame;
    picoquic_misc_frame_header_t* last_misc_frame;

    /* Management of streams */
    picosplay_tree_t stream_tree;
    picoquic_stream_head_t * first_output_stream;
    picoquic_stream_head_t * last_output_stream;
    uint64_t high_priority_stream_id;
    uint64_t next_stream_id[4];
    uint64_t priority_limit_for_bypass; /* Bypass CC if dtagram or stream priority lower than this, 0 means never */
    picoquic_pacing_t priority_bypass_pacing;

    /* Repeat queue contains packets with data frames that should be
     * sent according to priority when congestion window opens. */
    picosplay_tree_t queue_data_repeat_tree;

    /* Management of datagram queue (see also active datagram flag)
     * The "conflict" count indicates how many datagrams have been sent while
     * stream data was also waiting. If this passes the max value
     * picoquic will try sending stream data before the next datagram.
     * This is provisional -- we need to consider managing datagram
     * priorities in a way similar to stream priorities.
     */
    picoquic_misc_frame_header_t* first_datagram;
    picoquic_misc_frame_header_t* last_datagram;
    uint64_t datagram_priority;
    int datagram_conflicts_count;
    int datagram_conflicts_max;

    /* If not `0`, the connection will send keep alive messages in the given interval. */
    uint64_t keep_alive_interval;

    /* Management of paths */
    picoquic_path_t ** path;
    int nb_paths;
    int nb_path_alloc;
    int last_path_polled;
    uint64_t unique_path_id_next;
    picoquic_path_t* nominal_path_for_ack;
    uint64_t status_sequence_to_send_next;
    uint64_t max_path_id_local;
    uint64_t max_path_id_acknowledged;
    uint64_t max_path_id_remote;
    uint64_t path_blocked_acknowledged;
    /* Management of the CNX-ID stash */
    picoquic_remote_cnxid_stash_t * first_remote_cnxid_stash;
    /* management of local CID stash.
    * the number of lists represents the number of list already created,
    * minus the number of lists deleted.
    * */
    uint64_t nb_local_cnxid_lists;
    uint64_t next_path_id_in_lists;
    picoquic_local_cnxid_list_t * first_local_cnxid_list;

    /* Management of ACK frequency */
    uint64_t ack_frequency_sequence_local;
    uint64_t ack_gap_local;
    uint64_t ack_frequency_delay_local;
    uint64_t ack_frequency_sequence_remote;
    uint64_t ack_gap_remote;
    uint64_t ack_delay_remote;
    uint64_t ack_reordering_threshold_remote;

    /* Copies of packets received too soon */
    picoquic_stateless_packet_t* first_sooner;
    picoquic_stateless_packet_t* last_sooner;

    /* Log handling */
    uint16_t log_unique;
    FILE* f_binlog;
    char* binlog_file_name;
#ifdef PICOQUIC_MEMORY_LOG
    void (*memlog_call_back)(picoquic_cnx_t* cnx, picoquic_path_t* path, void* v_memlog, int op_code, uint64_t current_time);
    void *memlog_ctx;
#endif
} picoquic_cnx_t;

typedef struct st_picoquic_packet_data_t {
    uint64_t last_time_stamp_received;
    uint64_t last_ack_delay; /* ACK Delay in ACK frame */
    int nb_path_ack;
    struct {
        picoquic_path_t* acked_path; /* path for which ACK was received */
        uint64_t largest_sent_time; /* Send time of ACKed packet (largest number acked) */
        uint64_t delivered_prior; /* Amount delivered prior to that packet */
        uint64_t delivered_time_prior; /* Time last delivery before acked packet sent */
        uint64_t delivered_sent_prior; /* Time this last delivery packet was sent */
        uint64_t lost_prior; /* Value of nb_bytes_lost when packet was sent */
        uint64_t inflight_prior; /* Value of bytes_in_flight when packet was sent */
        unsigned int rs_is_path_limited; /* Whether the path was app limited when packet was sent */
        unsigned int rs_is_cwnd_limited;
        unsigned int is_set;
        uint64_t data_acked;
    } path_ack[PICOQUIC_NB_PATH_TARGET];
} picoquic_packet_data_t;

/* Load the stash of retry tokens. */
int picoquic_load_token_file(picoquic_quic_t* quic, char const * token_file_name);

/* Init of transport parameters */
void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode);

/* Registration of per path connection ID in server context */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid);

/* Register or update default address and reset secret */
int picoquic_register_net_secret(picoquic_cnx_t* cnx);

/* Registration of initial connection ID and peer IP */
int picoquic_register_net_icid(picoquic_cnx_t* cnx);

void picoquic_create_local_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t* cnx_id, uint8_t id_length, picoquic_connection_id_t cnx_id_remote);

/* Management of path */
int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time,
    const struct sockaddr* local_addr, const struct sockaddr* peer_addr,
    uint64_t unique_path_id);
void picoquic_register_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x);
int picoquic_renew_connection_id(picoquic_cnx_t* cnx, int path_id);
void picoquic_delete_path(picoquic_cnx_t* cnx, int path_index);
void picoquic_demote_path(picoquic_cnx_t* cnx, int path_index, uint64_t current_time, uint64_t reason, char const * phrase);
void picoquic_retransmit_demoted_path(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time);
void picoquic_queue_retransmit_on_ack(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time);
void picoquic_promote_path_to_default(picoquic_cnx_t* cnx, int path_index, uint64_t current_time);
void picoquic_delete_abandoned_paths(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time);
void picoquic_set_path_challenge(picoquic_cnx_t* cnx, int path_id, uint64_t current_time);
int picoquic_find_path_by_address(picoquic_cnx_t* cnx, const struct sockaddr* addr_local, const struct sockaddr* addr_peer, int* partial_match);
int picoquic_find_path_by_unique_id(picoquic_cnx_t* cnx, uint64_t unique_path_id);
int picoquic_assign_peer_cnxid_to_path(picoquic_cnx_t* cnx, int path_id);
void picoquic_reset_path_mtu(picoquic_path_t* path_x);
int picoquic_get_path_id_from_unique(picoquic_cnx_t* cnx, uint64_t unique_path_id);

picoquic_remote_cnxid_stash_t* picoquic_find_or_create_remote_cnxid_stash(picoquic_cnx_t* cnx, uint64_t unique_path_id, int do_create);

/* Management of the CNX-ID stash */
int picoquic_init_cnxid_stash(picoquic_cnx_t* cnx);

uint64_t picoquic_add_remote_cnxid_to_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* remote_cnxid_stash, uint64_t retire_before_next, const uint64_t sequence, const uint8_t cid_length, const uint8_t* cnxid_bytes, const uint8_t* secret_bytes, picoquic_remote_cnxid_t** pstashed);

uint64_t picoquic_stash_remote_cnxid(picoquic_cnx_t * cnx, uint64_t retire_before_next,
    const uint64_t unique_path_id, const uint64_t sequence, const uint8_t cid_length, const uint8_t * cnxid_bytes,
    const uint8_t * secret_bytes, picoquic_remote_cnxid_t ** pstashed);

picoquic_remote_cnxid_t* picoquic_remove_cnxid_from_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* remote_cnxid_stash, picoquic_remote_cnxid_t* removed, picoquic_remote_cnxid_t* previous);

picoquic_remote_cnxid_t* picoquic_remove_stashed_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_remote_cnxid_t* removed, 
    picoquic_remote_cnxid_t* previous);

picoquic_remote_cnxid_t* picoquic_get_cnxid_from_stash(picoquic_remote_cnxid_stash_t* stash);
picoquic_remote_cnxid_t* picoquic_obtain_stashed_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id);
void picoquic_dereference_stashed_cnxid(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int is_deleting_cnx);
uint64_t picoquic_remove_not_before_from_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash, uint64_t not_before, uint64_t current_time);
void picoquic_delete_remote_cnxid_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash);

uint64_t picoquic_remove_not_before_cid(picoquic_cnx_t* cnx, uint64_t unique_path_id, uint64_t not_before, uint64_t current_time);
int picoquic_renew_path_connection_id(picoquic_cnx_t* cnx, picoquic_path_t* path_x);

/* handling of retransmission queue */
void picoquic_queue_for_retransmit(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    size_t length, uint64_t current_time);
picoquic_packet_t* picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* p, int should_free,
    int add_to_data_repeat_queue);
void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx, picoquic_packet_t* p);

/* Reset the connection context, e.g. after retry */
int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time);

/* Reset packet context */
void picoquic_reset_packet_context(picoquic_cnx_t* cnx, picoquic_packet_context_t * pkt_ctx);

/* Notify error on connection */
int picoquic_connection_error(picoquic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type); 
int picoquic_connection_error_ex(picoquic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type, char const* local_reason);


void picoquic_connection_disconnect(picoquic_cnx_t* cnx);

/* Connection context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id, struct st_picoquic_local_cnxid_t ** l_cid_sequence);
picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, const struct sockaddr* addr);
picoquic_cnx_t* picoquic_cnx_by_icid(picoquic_quic_t* quic, picoquic_connection_id_t* icid,
    const struct sockaddr* addr);
picoquic_cnx_t* picoquic_cnx_by_secret(picoquic_quic_t* quic, const uint8_t* reset_secret, const struct sockaddr* addr);

/* Pacing implementation */
void picoquic_pacing_init(picoquic_pacing_t* pacing, uint64_t current_time);
int picoquic_is_pacing_blocked(picoquic_pacing_t* pacing);
int picoquic_is_authorized_by_pacing(picoquic_pacing_t* pacing, uint64_t current_time, uint64_t* next_time, unsigned int packet_train_mode, picoquic_quic_t * quic);
void picoquic_update_pacing_parameters(picoquic_pacing_t* pacing, double pacing_rate, uint64_t quantum, size_t send_mtu, uint64_t smoothed_rtt,
    picoquic_path_t* signalled_path);
void picoquic_update_pacing_window(picoquic_pacing_t* pacing, int slow_start, uint64_t cwin, size_t send_mtu, uint64_t smoothed_rtt, picoquic_path_t * signalled_path);
void picoquic_update_pacing_data_after_send(picoquic_pacing_t * pacing, size_t length, size_t send_mtu, uint64_t current_time);

/* Reset the pacing data after CWIN is updated */
void picoquic_update_pacing_data(picoquic_cnx_t* cnx, picoquic_path_t * path_x, int slow_start);
void picoquic_update_pacing_after_send(picoquic_path_t* path_x, size_t length, uint64_t current_time);
int picoquic_is_sending_authorized_by_pacing(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_time);
/* Reset pacing data if congestion algorithm computes it directly */
void picoquic_update_pacing_rate(picoquic_cnx_t* cnx, picoquic_path_t* path_x, double pacing_rate, uint64_t quantum);
/* Manage path quality updates */
void picoquic_refresh_path_quality_thresholds(picoquic_path_t* path_x);
int picoquic_issue_path_quality_update(picoquic_cnx_t* cnx, picoquic_path_t* path_x);

/* Next time is used to order the list of available connections,
        * so ready connections are polled first */
void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time);

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0]) << 8) | (uint16_t)((b)[1]))
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b)) << 8) | (uint32_t)((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | (uint32_t)PICOPARSE_16((b) + 2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b)) << 32) | (uint64_t)PICOPARSE_32((b) + 4))

/* Integer formatting functions */
void picoformat_16(uint8_t* bytes, uint16_t n16);
void picoformat_24(uint8_t* bytes, uint32_t n24);
void picoformat_32(uint8_t* bytes, uint32_t n32);
void picoformat_64(uint8_t* bytes, uint64_t n64);

size_t picoquic_varint_encode(uint8_t* bytes, size_t max_bytes, uint64_t n64);
void picoquic_varint_encode_16(uint8_t* bytes, uint16_t n16);
size_t picoquic_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64);
const uint8_t* picoquic_frames_varint_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
const uint8_t* picoquic_frames_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max);
size_t picoquic_varint_skip(const uint8_t* bytes);

size_t picoquic_encode_varint_length(uint64_t n64);
size_t picoquic_decode_varint_length(uint8_t byte);

/* Packet parsing */

picoquic_packet_type_enum picoquic_parse_long_packet_type(uint8_t flags, int version_index);

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    const uint8_t* bytes,
    size_t length,
    const struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving);

size_t picoquic_create_long_header(picoquic_packet_type_enum packet_type, 
    picoquic_connection_id_t* dest_cnx_id, picoquic_connection_id_t* srce_cnx_id,
    int do_grease_quic_bit, uint32_t version, int version_index, uint64_t sequence_number,
    size_t retry_token_length, uint8_t* retry_token,
    uint8_t* bytes, size_t* pn_offset, size_t* pn_length);

size_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_path_t* path_x,
    size_t header_length,
    uint8_t* bytes,
    size_t* pn_offset,
    size_t* pn_length);

size_t picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_packet_context_t* pkt_ctx);

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length);

size_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, picoquic_epoch_enum is_cleartext_mode);

void picoquic_protect_packet_header(uint8_t* send_buffer, size_t pn_offset, uint8_t first_mask, void* pn_enc);

size_t picoquic_protect_packet(picoquic_cnx_t* cnx, picoquic_packet_type_enum ptype, uint8_t* bytes, uint64_t sequence_number, size_t length, size_t header_length, uint8_t* send_buffer, size_t send_buffer_max, void* aead_context, void* pn_enc, picoquic_path_t* path_x, uint64_t current_time);

uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);

void picoquic_log_pn_dec_trial(picoquic_cnx_t* cnx); /* For debugging potential PN_ENC corruption */

int picoquic_remove_header_protection_inner(uint8_t* bytes, size_t length, uint8_t* decrypted_bytes, picoquic_packet_header* ph, void* pn_enc, unsigned int is_loss_bit_enabled_incoming, uint64_t sack_list_last);

size_t picoquic_pad_to_target_length(uint8_t* bytes, size_t length, size_t target);

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret,
    size_t length, size_t header_length, size_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, size_t send_buffer_max,
    picoquic_path_t * path_x, uint64_t current_time);

void picoquic_implicit_handshake_ack(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t current_time);
void picoquic_false_start_transition(picoquic_cnx_t* cnx, uint64_t current_time);
void picoquic_client_almost_ready_transition(picoquic_cnx_t* cnx);
void picoquic_ready_state_transition(picoquic_cnx_t* cnx, uint64_t current_time);

int picoquic_parse_header_and_decrypt(
    picoquic_quic_t* quic,
    const uint8_t* bytes,
    size_t length,
    size_t packet_length,
    const struct sockaddr* addr_from,
    uint64_t current_time,
    picoquic_stream_data_node_t* decrypted_data,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    size_t * consumed,
    int * new_context_created);

/* Shortcuts to packet numbers, last ack, last ack time.
 */
uint64_t picoquic_get_sequence_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc);

uint64_t picoquic_get_ack_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc);

picoquic_packet_t * picoquic_get_last_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc);

/* handling of ACK logic */
void picoquic_init_ack_ctx(picoquic_cnx_t* cnx, picoquic_ack_context_t* ack_ctx);

int picoquic_is_ack_needed(picoquic_cnx_t* cnx,  uint64_t current_time, uint64_t * next_wake_time, 
    picoquic_packet_context_enum pc, int is_opportunistic);

int picoquic_is_pn_already_received(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_local_cnxid_t * l_cid, uint64_t pn64);
int picoquic_record_pn_received(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_local_cnxid_t* l_cid, uint64_t pn64, uint64_t current_microsec);

void picoquic_sack_select_ack_ranges(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* first_sack,
    int max_ranges, int is_opportunistic, int* nb_sent_max, int* nb_sent_max_skip);

int picoquic_update_sack_list(picoquic_sack_list_t* sack,
    uint64_t pn64_min, uint64_t pn64_max, uint64_t current_time);
/* Check whether the data fills a hole. returns 0 if it does, -1 otherwise. */
int picoquic_check_sack_list(picoquic_sack_list_t* sack,
    uint64_t pn64_min, uint64_t pn64_max);

picoquic_sack_item_t* picoquic_process_ack_of_ack_range(picoquic_sack_list_t* first_sack, picoquic_sack_item_t* previous, uint64_t start_of_range, uint64_t end_of_range);
void picoquic_update_ack_horizon(picoquic_sack_list_t* sack_list, uint64_t current_time);

/* Return the first ACK item in the list */
picoquic_sack_item_t* picoquic_sack_first_item(picoquic_sack_list_t* sack_list);
picoquic_sack_item_t* picoquic_sack_last_item(picoquic_sack_list_t* sack_list);
picoquic_sack_item_t* picoquic_sack_next_item(picoquic_sack_item_t * sack);
picoquic_sack_item_t* picoquic_sack_previous_item(picoquic_sack_item_t* sack);
int picoquic_sack_insert_item(picoquic_sack_list_t* sack_list, uint64_t range_min, 
    uint64_t range_max, uint64_t current_time);

int picoquic_sack_list_is_empty(picoquic_sack_list_t* sack_list);

picoquic_ack_context_t* picoquic_ack_ctx_from_cnx_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, picoquic_local_cnxid_t* l_cid);

picoquic_sack_list_t* picoquic_sack_list_from_cnx_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, picoquic_local_cnxid_t* l_cid);

uint64_t picoquic_sack_list_first(picoquic_sack_list_t* first_sack);

uint64_t picoquic_sack_list_last(picoquic_sack_list_t* first_sack);

picoquic_sack_item_t* picoquic_sack_list_first_range(picoquic_sack_list_t* first_sack);

void picoquic_sack_list_init(picoquic_sack_list_t* first_sack);

int picoquic_sack_list_reset(picoquic_sack_list_t* first_sack, 
    uint64_t range_min, uint64_t range_max, uint64_t current_time);

void picoquic_sack_list_free(picoquic_sack_list_t* first_sack);

uint64_t picoquic_sack_item_range_start(picoquic_sack_item_t* sack_item);

uint64_t picoquic_sack_item_range_end(picoquic_sack_item_t* sack_item);

int picoquic_sack_item_nb_times_sent(picoquic_sack_item_t* sack_item, int is_opportunistic);

void picoquic_sack_item_record_sent(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* sack_item, int is_opportunistic);
void picoquic_sack_item_record_reset(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* sack_item);

size_t picoquic_sack_list_size(picoquic_sack_list_t* first_sack);

void picoquic_record_ack_packet_data(picoquic_packet_data_t* packet_data, picoquic_packet_t* acked_packet);

void picoquic_init_packet_ctx(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx, picoquic_packet_context_enum pc);

/*
 * Process ack of ack
 */
int picoquic_process_ack_of_ack_frame(
    picoquic_sack_list_t* first_sack, uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn);

/* Computation of ack delay max and ack gap, based on RTT and Data Rate.
 * If ACK Frequency extension is used, this function will compute the values
 * that will be sent to the peer. Otherwise, they computes the values used locally.
 */
void picoquic_compute_ack_gap_and_delay(picoquic_cnx_t* cnx, uint64_t rtt, uint64_t remote_min_ack_delay, uint64_t data_rate, uint64_t* ack_gap, uint64_t* ack_delay_max);

/* seed the rtt and bandwidth discovery */
void picoquic_seed_bandwidth(picoquic_cnx_t* cnx, uint64_t rtt_min, uint64_t cwin,
    const uint8_t* ip_addr, uint8_t ip_addr_length);

/* Management of timers, rtt, etc. */
uint64_t picoquic_current_retransmit_timer(picoquic_cnx_t* cnx, picoquic_path_t* path_x);

/* Update the path RTT upon receiving an explict or implicit acknowledgement */
void picoquic_update_path_rtt(picoquic_cnx_t* cnx, picoquic_path_t * old_path, picoquic_path_t* path_x, int epoch,
    uint64_t send_time, uint64_t current_time, uint64_t ack_delay, uint64_t time_stamp);

/* stream management */
picoquic_stream_head_t* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id);
picoquic_stream_head_t* picoquic_create_missing_streams(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote);
int picoquic_is_stream_closed(picoquic_stream_head_t* stream, int client_mode);
int picoquic_delete_stream_if_closed(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream);

void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx);

picoquic_stream_head_t * picoquic_stream_from_node(picosplay_node_t * node);
void picoquic_insert_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t * stream);
void picoquic_remove_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t * stream);
void picoquic_reorder_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream);
picoquic_stream_head_t * picoquic_first_stream(picoquic_cnx_t * cnx);
picoquic_stream_head_t * picoquic_last_stream(picoquic_cnx_t * cnx);
picoquic_stream_head_t * picoquic_next_stream(picoquic_stream_head_t * stream);
picoquic_stream_head_t* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id);
void picoquic_add_output_streams(picoquic_cnx_t * cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir);
picoquic_stream_head_t* picoquic_find_ready_stream_path(picoquic_cnx_t* cnx, picoquic_path_t* path_x);
picoquic_stream_head_t* picoquic_find_ready_stream(picoquic_cnx_t* cnx);
int picoquic_is_tls_stream_ready(picoquic_cnx_t* cnx);
const uint8_t* picoquic_decode_stream_frame(picoquic_cnx_t* cnx, const uint8_t* bytes,
    const uint8_t* bytes_max, picoquic_stream_data_node_t* received_data, uint64_t current_time);

uint8_t* picoquic_format_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream, 
    uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, int* is_still_active, int* ret);

void picoquic_update_max_stream_ID_local(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream);

/* Handling of retransmission of frames.
 * When a packet is deemed lost, the code looks at the frames that it contained and
 * calls "picoquic_check_frame_needs_repeat" to see whether a given frame needs to 
 * be retransmitted. This is different from checking whether a frame needs to be acked.
 * For example, a "MAX DATA" frame needs to be acked, but it will only be retransmitted
 * if it was not superceded by a similar frame carrying a larger max value.
 *
 * May have to split a retransmitted stream frame if it does not fit in the new packet size */
int picoquic_check_frame_needs_repeat(picoquic_cnx_t* cnx, const uint8_t* bytes,
    size_t bytes_max, picoquic_packet_type_enum p_type,
    int* no_need_to_repeat, int* do_not_detect_spurious, int *is_preemptive_needed);
uint8_t* picoquic_format_available_stream_frames(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    uint8_t* bytes_next, uint8_t* bytes_max, uint64_t current_priority,
    int* more_data, int* is_pure_ack, int* stream_tried_and_failed, int* ret);

/* Handling of stream_data_frames that need repeating.
 */
void picoquic_queue_data_repeat_init(picoquic_cnx_t* cnx);
void picoquic_queue_data_repeat_packet(
    picoquic_cnx_t* cnx, picoquic_packet_t* packet);
void picoquic_dequeue_data_repeat_packet(
    picoquic_cnx_t* cnx, picoquic_packet_t* packet);
picoquic_packet_t* picoquic_first_data_repeat_packet(picoquic_cnx_t* cnx);
uint8_t* picoquic_copy_stream_frame_for_retransmit(
    picoquic_cnx_t* cnx, picoquic_packet_t* packet,
    uint8_t* bytes_next, uint8_t* bytes_max);
uint8_t* picoquic_copy_stream_frames_for_retransmit(picoquic_cnx_t* cnx,
    uint8_t* bytes_next, uint8_t* bytes_max, uint64_t current_priority, int* more_data, int* is_pure_ack);
/* Processing of packets considered lost: queueing frames
 * that need to be repeated as "misc" frames, setting the
 * flag `add_to_data_repeat_queue` if the packet contains stream
 * frames that need to be queued.
 */
int picoquic_copy_before_retransmit(picoquic_packet_t * old_p,
    picoquic_cnx_t * cnx,
    uint8_t * new_bytes,
    size_t send_buffer_max_minus_checksum,
    int * packet_is_pure_ack,
    int * do_not_detect_spurious,
    int force_queue,
    size_t * length,
    int * add_to_data_repeat_queue);

int picoquic_retransmit_needed(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time, picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length);

void picoquic_set_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, int is_immediate_ack_required);

/* If the packet contained an ACK frame, perform the ACK of ACK pruning logic.
 * Record stream data as acknowledged, signal datagram frames as acknowledged.
 */
void picoquic_process_ack_of_frames(picoquic_cnx_t* cnx, picoquic_packet_t* p, picoquic_packet_data_t* packet_data,
    int is_spurious, uint64_t current_time);

/* Coding and decoding of frames */
typedef struct st_picoquic_stream_data_buffer_argument_t {
    uint8_t* bytes; /* Points to the beginning of the encoding of the stream frame */
    size_t byte_index; /* Current index position after encoding type, stream-id and offset */
    size_t byte_space; /* Number of bytes available in the packet after the current index */
    size_t allowed_space; /* Maximum number of bytes that the application is authorized to write */
    size_t length; /* number of bytes that the application commits to write */
    int is_fin; /* Whether this is the end of the stream */
    int is_still_active; /* whether the stream is still considered active after this call */
    uint8_t* app_buffer; /* buffer provided to the application. */
} picoquic_stream_data_buffer_argument_t;

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes);

uint8_t* picoquic_format_stream_frame_header(uint8_t* bytes, uint8_t* bytes_max, uint64_t stream_id, uint64_t offset);

int picoquic_parse_stream_header(
    const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed);

int picoquic_parse_ack_header(
    uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* path_id, uint64_t* largest,
    uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent);
const uint8_t* picoquic_decode_crypto_hs_frame(picoquic_cnx_t* cnx, const uint8_t* bytes,
    const uint8_t* bytes_max, picoquic_stream_data_node_t* received_data, int epoch);
uint8_t* picoquic_format_crypto_hs_frame(picoquic_stream_head_t* stream, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_ack_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, uint64_t current_time, picoquic_packet_context_enum pc, int is_opportunistic);
uint8_t* picoquic_format_connection_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_application_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_required_max_stream_data_frames(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_max_data_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, uint64_t maxdata_increase);
uint8_t* picoquic_format_max_stream_data_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, uint64_t new_max_data);
uint64_t picoquic_cc_increased_window(picoquic_cnx_t* cnx, uint64_t previous_window); /* Trigger sending more data if window increases */
uint8_t* picoquic_format_max_streams_frame_if_needed(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
void picoquic_stream_data_node_recycle(picoquic_stream_data_node_t* stream_data);
picoquic_stream_data_node_t* picoquic_stream_data_node_alloc(picoquic_quic_t* quic);
void picoquic_clear_stream(picoquic_stream_head_t* stream);
void picoquic_delete_stream(picoquic_cnx_t * cnx, picoquic_stream_head_t * stream);
picoquic_local_cnxid_list_t* picoquic_find_or_create_local_cnxid_list(picoquic_cnx_t* cnx, uint64_t unique_path_id, int do_create);
picoquic_local_cnxid_t* picoquic_create_local_cnxid(picoquic_cnx_t* cnx,
    uint64_t unique_path_id, picoquic_connection_id_t* suggested_value, uint64_t current_time);
int picoquic_demote_local_cnxid_list(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint64_t reason, uint64_t current_time);
void picoquic_delete_local_cnxid(picoquic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid);
void picoquic_delete_local_cnxid_list(picoquic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list);
void picoquic_delete_local_cnxid_lists(picoquic_cnx_t* cnx);
void picoquic_retire_local_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id, uint64_t sequence);
void picoquic_check_local_cnxid_ttl(picoquic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list, uint64_t current_time, uint64_t* next_wake_time);
picoquic_local_cnxid_t* picoquic_find_local_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_connection_id_t* cnxid);
uint8_t* picoquic_format_path_challenge_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, uint64_t challenge);
uint8_t* picoquic_format_path_response_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, uint64_t challenge);
int picoquic_should_repeat_path_response_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t bytes_max);
uint8_t* picoquic_format_new_connection_id_frame(picoquic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_local_cnxid_t* l_cid);
uint8_t* picoquic_format_max_path_id_frame(uint8_t* bytes, const uint8_t* bytes_max, uint64_t max_path_id, int * more_data);
uint8_t* picoquic_format_blocked_frames(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
int picoquic_queue_retire_connection_id_frame(picoquic_cnx_t * cnx, uint64_t unique_path_id, uint64_t sequence);
int picoquic_queue_new_token_frame(picoquic_cnx_t * cnx, uint8_t * token, size_t token_length);
uint8_t* picoquic_format_one_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream);
uint8_t* picoquic_format_first_misc_or_dg_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
    picoquic_misc_frame_header_t* misc_frame, picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last);
picoquic_misc_frame_header_t* picoquic_find_first_misc_frame(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc);
uint8_t* picoquic_format_misc_frames_in_context(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max,
    int* more_data, int* is_pure_ack, picoquic_packet_context_enum pc);
int picoquic_queue_misc_or_dg_frame(picoquic_cnx_t* cnx, picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last, const uint8_t* bytes, size_t length, int is_pure_ack, picoquic_packet_context_enum pc);
void picoquic_purge_misc_frames_after_ready(picoquic_cnx_t* cnx);
void picoquic_delete_misc_or_dg(picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last, picoquic_misc_frame_header_t* frame);
void picoquic_clear_ack_ctx(picoquic_ack_context_t* ack_ctx);
void picoquic_reset_ack_context(picoquic_ack_context_t* ack_ctx);
int picoquic_queue_handshake_done_frame(picoquic_cnx_t* cnx);
uint8_t* picoquic_format_first_datagram_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_ready_datagram_frame(picoquic_cnx_t* cnx, picoquic_path_t * path_x, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, int* ret);
uint8_t* picoquic_decode_datagram_frame_header(uint8_t* bytes, const uint8_t* bytes_max,
    uint8_t* frame_id, uint64_t* length);
const uint8_t* picoquic_parse_ack_frequency_frame(const uint8_t* bytes, const uint8_t* bytes_max, 
    uint64_t* seq, uint64_t* packets, uint64_t* microsec, uint8_t * ignore_order, uint64_t *reordering_threshold);
uint8_t* picoquic_format_ack_frequency_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data);
uint8_t* picoquic_format_immediate_ack_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data);
uint8_t* picoquic_format_time_stamp_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, uint64_t current_time);
size_t picoquic_encode_time_stamp_length(picoquic_cnx_t* cnx, uint64_t current_time);
uint8_t* picoquic_format_bdp_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, picoquic_path_t* path_x, int* more_data, int * is_pure_ack);
uint8_t* picoquic_format_path_abandon_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data,
    uint64_t path_id, uint64_t reason);
int picoquic_queue_path_abandon_frame(picoquic_cnx_t* cnx,
    uint64_t unique_path_id, uint64_t reason);
int picoquic_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t * path_x, const uint8_t* bytes, size_t bytes_max,
    picoquic_stream_data_node_t* received_data,
    int epoch, struct sockaddr* addr_from, struct sockaddr* addr_to, uint64_t pn64, int path_is_not_allocated, uint64_t current_time);
const uint8_t* picoquic_parse_observed_address_frame(const uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t ftype, uint64_t* sequence, const uint8_t** addr, uint16_t* port);
uint8_t* picoquic_format_observed_address_frame(
    uint8_t* bytes, const uint8_t* bytes_max, uint64_t ftype,
    uint64_t sequence_number, uint8_t* addr, uint16_t port, int * more_data);
uint8_t* picoquic_prepare_observed_address_frame(uint8_t* bytes, const uint8_t* bytes_max,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    int* more_data, int* is_pure_ack);
void picoquic_update_peer_addr(picoquic_path_t* path_x, const struct sockaddr* peer_addr);

int picoquic_skip_frame(const uint8_t* bytes, size_t bytes_max, size_t* consumed, int* pure_ack);
const uint8_t* picoquic_skip_path_abandon_frame(const uint8_t* bytes, const uint8_t* bytes_max);
const uint8_t* picoquic_skip_path_available_or_standby_frame(const uint8_t* bytes, const uint8_t* bytes_max);
int picoquic_queue_path_available_or_standby_frame(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_path_status_enum status);

int picoquic_decode_closing_frames(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, int* closing_received);

void picoquic_process_sooner_packets(picoquic_cnx_t* cnx, uint64_t current_time);
void picoquic_delete_sooner_packets(picoquic_cnx_t* cnx);

/* handling of transport extensions.
 */

const uint8_t* picoquic_process_tp_version_negotiation(const uint8_t* bytes, const uint8_t* bytes_max,
    int extension_mode, uint32_t envelop_vn, uint32_t* negotiated_vn, int* negotiated_index,
    uint64_t* vn_error);

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length, int is_pure_ack,
    picoquic_packet_context_enum pc);

/* Supported version upgrade.
 * Upgrades are only supported between compatible versions.
 *
 * When upgrading, there may be a need to update more than the version field. For example,
 * there may be a need to update encryption contexts if they were computed differently,
 * or to revisit some default options.
 *
 * The function takes three arguments: connection context, old version index and new version index.
 * The return code is zero if the upgrade was done, -1 if it could not be.
 * If the function is called with a null connection context, it returns 0 if the
 * upgrade is possible, -1 if it is not.
 */
int picoquic_process_version_upgrade(picoquic_cnx_t* cnx, int old_version_index, int new_version_index);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
