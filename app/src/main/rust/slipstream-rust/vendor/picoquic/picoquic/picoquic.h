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

#ifndef PICOQUIC_H
#define PICOQUIC_H

#include <stdint.h>
#include <stdarg.h>
#ifdef _WINDOWS
#include <WS2tcpip.h>
#include <Ws2def.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_VERSION "1.1.28.4"
#define PICOQUIC_ERROR_CLASS 0x400
#define PICOQUIC_ERROR_DUPLICATE (PICOQUIC_ERROR_CLASS + 1)
#define PICOQUIC_ERROR_AEAD_CHECK (PICOQUIC_ERROR_CLASS + 3)
#define PICOQUIC_ERROR_UNEXPECTED_PACKET (PICOQUIC_ERROR_CLASS + 4)
#define PICOQUIC_ERROR_MEMORY (PICOQUIC_ERROR_CLASS + 5)
#if 0
#define PICOQUIC_ERROR_SPURIOUS_REPEAT (PICOQUIC_ERROR_CLASS + 6)
#endif
#define PICOQUIC_ERROR_CNXID_CHECK (PICOQUIC_ERROR_CLASS + 7)
#define PICOQUIC_ERROR_INITIAL_TOO_SHORT (PICOQUIC_ERROR_CLASS + 8)
#define PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED (PICOQUIC_ERROR_CLASS + 9)
#define PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION (PICOQUIC_ERROR_CLASS + 10)
#define PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 11)
#define PICOQUIC_ERROR_ILLEGAL_TRANSPORT_EXTENSION (PICOQUIC_ERROR_CLASS + 12)
#define PICOQUIC_ERROR_CANNOT_RESET_STREAM_ZERO (PICOQUIC_ERROR_CLASS + 13)
#define PICOQUIC_ERROR_INVALID_STREAM_ID (PICOQUIC_ERROR_CLASS + 14)
#define PICOQUIC_ERROR_STREAM_ALREADY_CLOSED (PICOQUIC_ERROR_CLASS + 15)
#define PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 16)
#define PICOQUIC_ERROR_INVALID_FRAME (PICOQUIC_ERROR_CLASS + 17)
#define PICOQUIC_ERROR_CANNOT_CONTROL_STREAM_ZERO (PICOQUIC_ERROR_CLASS + 18)
#define PICOQUIC_ERROR_RETRY (PICOQUIC_ERROR_CLASS + 19)
#define PICOQUIC_ERROR_DISCONNECTED (PICOQUIC_ERROR_CLASS + 20)
#define PICOQUIC_ERROR_DETECTED (PICOQUIC_ERROR_CLASS + 21)
#define PICOQUIC_ERROR_INVALID_TICKET (PICOQUIC_ERROR_CLASS + 23)
#define PICOQUIC_ERROR_INVALID_FILE (PICOQUIC_ERROR_CLASS + 24)
#define PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 25)
#define PICOQUIC_ERROR_UNEXPECTED_STATE (PICOQUIC_ERROR_CLASS + 26)
#define PICOQUIC_ERROR_UNEXPECTED_ERROR (PICOQUIC_ERROR_CLASS + 27)
#define PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT (PICOQUIC_ERROR_CLASS + 28)
#define PICOQUIC_ERROR_NO_SUCH_FILE (PICOQUIC_ERROR_CLASS + 29)
#define PICOQUIC_ERROR_STATELESS_RESET (PICOQUIC_ERROR_CLASS + 30)
#define PICOQUIC_ERROR_CONNECTION_DELETED (PICOQUIC_ERROR_CLASS + 31)
#define PICOQUIC_ERROR_CNXID_SEGMENT (PICOQUIC_ERROR_CLASS + 32)
#define PICOQUIC_ERROR_CNXID_NOT_AVAILABLE (PICOQUIC_ERROR_CLASS + 33)
#define PICOQUIC_ERROR_MIGRATION_DISABLED (PICOQUIC_ERROR_CLASS + 34)
#define PICOQUIC_ERROR_CANNOT_COMPUTE_KEY (PICOQUIC_ERROR_CLASS + 35)
#define PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM (PICOQUIC_ERROR_CLASS + 36)
#define PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT (PICOQUIC_ERROR_CLASS + 37)
#define PICOQUIC_ERROR_INVALID_TOKEN (PICOQUIC_ERROR_CLASS + 38)
#define PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT (PICOQUIC_ERROR_CLASS + 39)
#define PICOQUIC_ERROR_KEY_ROTATION_NOT_READY (PICOQUIC_ERROR_CLASS + 40)
#define PICOQUIC_ERROR_AEAD_NOT_READY (PICOQUIC_ERROR_CLASS + 41)
#define PICOQUIC_ERROR_NO_ALPN_PROVIDED (PICOQUIC_ERROR_CLASS + 42)
#define PICOQUIC_ERROR_NO_CALLBACK_PROVIDED (PICOQUIC_ERROR_CLASS + 43)
#define PICOQUIC_STREAM_RECEIVE_COMPLETE (PICOQUIC_ERROR_CLASS + 44)
#define PICOQUIC_ERROR_PACKET_HEADER_PARSING (PICOQUIC_ERROR_CLASS + 45)
#define PICOQUIC_ERROR_QUIC_BIT_MISSING (PICOQUIC_ERROR_CLASS + 46)
#define PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP (PICOQUIC_ERROR_CLASS + 47)
#define PICOQUIC_NO_ERROR_SIMULATE_NAT (PICOQUIC_ERROR_CLASS + 48)
#define PICOQUIC_NO_ERROR_SIMULATE_MIGRATION (PICOQUIC_ERROR_CLASS + 49)
#define PICOQUIC_ERROR_VERSION_NOT_SUPPORTED (PICOQUIC_ERROR_CLASS + 50)
#define PICOQUIC_ERROR_IDLE_TIMEOUT (PICOQUIC_ERROR_CLASS + 51)
#define PICOQUIC_ERROR_REPEAT_TIMEOUT (PICOQUIC_ERROR_CLASS + 52)
#define PICOQUIC_ERROR_HANDSHAKE_TIMEOUT (PICOQUIC_ERROR_CLASS + 53)
#define PICOQUIC_ERROR_SOCKET_ERROR (PICOQUIC_ERROR_CLASS + 54)
#define PICOQUIC_ERROR_VERSION_NEGOTIATION (PICOQUIC_ERROR_CLASS + 55)
#define PICOQUIC_ERROR_PACKET_TOO_LONG (PICOQUIC_ERROR_CLASS + 56)
#define PICOQUIC_ERROR_PACKET_WRONG_VERSION (PICOQUIC_ERROR_CLASS + 57)
#define PICOQUIC_ERROR_PORT_BLOCKED (PICOQUIC_ERROR_CLASS + 58)
#define PICOQUIC_ERROR_DATAGRAM_TOO_LONG (PICOQUIC_ERROR_CLASS + 59)
#define PICOQUIC_ERROR_PATH_ID_INVALID (PICOQUIC_ERROR_CLASS + 60)
#define PICOQUIC_ERROR_RETRY_NEEDED (PICOQUIC_ERROR_CLASS + 61)
#define PICOQUIC_ERROR_SERVER_BUSY (PICOQUIC_ERROR_CLASS + 62)

/*
 * Protocol errors defined in the QUIC spec
 */
#define PICOQUIC_TRANSPORT_INTERNAL_ERROR (0x1)
#define PICOQUIC_TRANSPORT_SERVER_BUSY (0x2)
#define PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR (0x3)
#define PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR (0x4)
#define PICOQUIC_TRANSPORT_STREAM_STATE_ERROR (0x5)
#define PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR (0x6)
#define PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR (0x7)
#define PICOQUIC_TRANSPORT_PARAMETER_ERROR (0x8)
#define PICOQUIC_TRANSPORT_CONNECTION_ID_LIMIT_ERROR (0x9)
#define PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION (0xA)
#define PICOQUIC_TRANSPORT_INVALID_TOKEN (0xB)
#define PICOQUIC_TRANSPORT_APPLICATION_ERROR (0xC)
#define PICOQUIC_TRANSPORT_CRYPTO_BUFFER_EXCEEDED (0xD)
#define PICOQUIC_TRANSPORT_KEY_UPDATE_ERROR (0xE)
#define PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED (0xF) 

#define PICOQUIC_TRANSPORT_CRYPTO_ERROR(Alert) (((uint16_t)0x100) | ((uint16_t)((Alert)&0xFF)))
#define PICOQUIC_TLS_ALERT_WRONG_ALPN (0x178)
#define PICOQUIC_TLS_HANDSHAKE_FAILED (0x201)
#define PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR (0x11)

#define PICOQUIC_TRANSPORT_APPLICATION_ABANDON (0x4150504C4142414E)
#define PICOQUIC_TRANSPORT_RESOURCE_LIMIT_REACHED (0x5245534C494D4954)

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_RESET_SECRET_SIZE 16
#define PICOQUIC_RESET_PACKET_PAD_SIZE 23
#define PICOQUIC_RESET_PACKET_MIN_SIZE (PICOQUIC_RESET_PACKET_PAD_SIZE + PICOQUIC_RESET_SECRET_SIZE)
#define PICOQUIC_MAX_CRYPTO_BUFFER_GAP 16384

#define PICOQUIC_LOG_PACKET_MAX_SEQUENCE 100

#define FOURCC(a, b, c, d) ((((uint32_t)(d)<<24) | ((c)<<16) | ((b)<<8) | (a)))

#define PICOQUIC_AES_128_GCM_SHA256 0x1301
#define PICOQUIC_AES_256_GCM_SHA384 0x1302
#define PICOQUIC_CHACHA20_POLY1305_SHA256 0x1303

#define PICOQUIC_GROUP_SECP256R1 23

/*
* Connection states, useful to expose the state to the application.
*/
typedef enum {
    picoquic_state_client_init,
    picoquic_state_client_init_sent,
    picoquic_state_client_renegotiate,
    picoquic_state_client_retry_received,
    picoquic_state_client_init_resent,
    picoquic_state_server_init,
    picoquic_state_server_handshake,
    picoquic_state_client_handshake_start,
    picoquic_state_handshake_failure,
    picoquic_state_handshake_failure_resend,
    picoquic_state_client_almost_ready,
    picoquic_state_server_false_start,
    picoquic_state_server_almost_ready,
    picoquic_state_client_ready_start,
    picoquic_state_ready,
    picoquic_state_disconnecting,
    picoquic_state_closing_received,
    picoquic_state_closing,
    picoquic_state_draining,
    picoquic_state_disconnected
} picoquic_state_enum;

/* Packet contexts */
typedef enum {
    picoquic_packet_context_application = 0,
    picoquic_packet_context_handshake = 1,
    picoquic_packet_context_initial = 2,
    picoquic_nb_packet_context = 3
} picoquic_packet_context_enum;


/* PMTUD 
 */

typedef enum {
    picoquic_pmtud_basic = 0, /* default pmtud behavior, opportunistic */
    picoquic_pmtud_required = 1, /* force pmtud asap */
    picoquic_pmtud_delayed = 2, /* only do pmtud if lots of data has to be sent */
    picoquic_pmtud_blocked = 3 /* never do pmtud */
} picoquic_pmtud_policy_enum;
/*
* Quic spin bit variants
*/

typedef enum {
    picoquic_spinbit_basic = 0, /* default spin bit behavior, as specified in spin bit draft */
    picoquic_spinbit_random = 1, /* alternative spin bit behavior, randomized for each packet */
    picoquic_spinbit_null = 2, /* null behavior, randomized per path */
    picoquic_spinbit_on = 3 /* Option used in test to avoid randomizing spin bit on/off */
} picoquic_spinbit_version_enum;

/*
* Quic loss bit variants
*/

typedef enum {
    picoquic_lossbit_none = 0, /* No support for the loss bits */
    picoquic_lossbit_send_only = 1, /* Able to send the loss bit, but not receive it */
    picoquic_lossbit_send_receive = 2, /* Able to send or receive the loss bits */
} picoquic_lossbit_version_enum;

/*
* Path statuses
*/

typedef enum {
    picoquic_path_status_available = 0, /* Path available for sending */
    picoquic_path_status_standby = 1 /* Do not use if other path available */
} picoquic_path_status_enum;

/*
 * Provisional definition of the connection ID.
 */
#define PICOQUIC_CONNECTION_ID_MIN_SIZE 0
#define PICOQUIC_CONNECTION_ID_MAX_SIZE 20

typedef struct st_picoquic_connection_id_t {
    uint8_t id[PICOQUIC_CONNECTION_ID_MAX_SIZE];
    uint8_t id_len;
} picoquic_connection_id_t;


/* forward definition to avoid full dependency on picotls.h */
typedef struct st_ptls_iovec_t ptls_iovec_t; 

/* Detect whether error occured in TLS
 */
int picoquic_is_handshake_error(uint64_t error_code);


typedef struct st_picoquic_quic_t picoquic_quic_t;
typedef struct st_picoquic_cnx_t picoquic_cnx_t;
typedef struct st_picoquic_path_t picoquic_path_t;

typedef enum {
    picoquic_callback_stream_data = 0, /* Data received from peer on stream N */
    picoquic_callback_stream_fin, /* Fin received from peer on stream N; data is optional */
    picoquic_callback_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    picoquic_callback_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    picoquic_callback_stateless_reset, /* Stateless reset received from peer. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_close, /* Connection close. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_application_close, /* Application closed by peer. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_stream_gap,  /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
    picoquic_callback_prepare_to_send, /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    picoquic_callback_almost_ready, /* Data can be sent, but the connection is not fully established */
    picoquic_callback_ready, /* Data can be sent and received, connection migration can be initiated */
    picoquic_callback_datagram, /* Datagram frame has been received */
    picoquic_callback_version_negotiation, /* version negotiation requested */
    picoquic_callback_request_alpn_list, /* Provide the list of supported ALPN */
    picoquic_callback_set_alpn, /* Set ALPN to negotiated value */
    picoquic_callback_pacing_changed, /* Pacing rate for the connection changed */
    picoquic_callback_prepare_datagram, /* Prepare the next datagram */
    picoquic_callback_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
    picoquic_callback_datagram_lost, /* Packet carrying datagram-frame probably lost */
    picoquic_callback_datagram_spurious, /* Packet carrying datagram-frame was not really lost */
    picoquic_callback_path_available, /* A new path is available, or a suspended path is available again */
    picoquic_callback_path_suspended, /* An available path is suspended */
    picoquic_callback_path_deleted, /* An existing path has been deleted */
    picoquic_callback_path_quality_changed, /* Some path quality parameters have changed */
    picoquic_callback_path_address_observed, /* The peer has reported an address for the path */
    picoquic_callback_app_wakeup /* wakeup timer set by application has expired */
} picoquic_call_back_event_t;

typedef struct st_picoquic_tp_prefered_address_t {
    int is_defined;
    uint8_t ipv4Address[4];
    uint16_t ipv4Port;
    uint8_t ipv6Address[16];
    uint16_t ipv6Port;
    picoquic_connection_id_t connection_id;
    uint8_t statelessResetToken[16];
} picoquic_tp_prefered_address_t;

typedef struct st_picoquic_tp_version_negotiation_t {
    uint32_t current; /* Version found in TP, should match envelope */
    uint32_t previous; /* Version that triggered a VN before */
    size_t nb_received; /* Only present on client */
    uint32_t* received;
    size_t nb_supported; /* On client, list of compatible versions */
    uint32_t* supported;
} picoquic_tp_version_negotiation_t;

typedef struct st_picoquic_tp_t {
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_id_bidir;
    uint64_t initial_max_stream_id_unidir;
    uint64_t max_idle_timeout;
    uint32_t max_packet_size;
    uint32_t max_ack_delay; /* stored in in microseconds for convenience */
    uint32_t active_connection_id_limit;
    uint8_t ack_delay_exponent;
    unsigned int migration_disabled;
    picoquic_tp_prefered_address_t prefered_address;
    uint32_t max_datagram_frame_size;
    int enable_loss_bit;
    int enable_time_stamp; /* (x&1) want, (x&2) can */
    uint64_t min_ack_delay;
    int do_grease_quic_bit;
    picoquic_tp_version_negotiation_t version_negotiation;
    int enable_bdp_frame;
    int is_multipath_enabled;
    uint64_t initial_max_path_id;
    int address_discovery_mode; /* 0=none, 1=provide only, 2=receive only, 3=both */
} picoquic_tp_t;

/*
 * Stream types
 */
#define PICOQUIC_STREAM_ID_TYPE_MASK 3
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED 0
#define PICOQUIC_STREAM_ID_SERVER_INITIATED 1
#define PICOQUIC_STREAM_ID_BIDIR 0
#define PICOQUIC_STREAM_ID_UNIDIR 2
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED|PICOQUIC_STREAM_ID_BIDIR)
#define PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED|PICOQUIC_STREAM_ID_BIDIR)
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED|PICOQUIC_STREAM_ID_UNIDIR)
#define PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED|PICOQUIC_STREAM_ID_UNIDIR)
#define PICOQUIC_IS_CLIENT_STREAM_ID(id) (unsigned int)(((id) & 1) == 0)
#define PICOQUIC_IS_BIDIR_STREAM_ID(id)  (unsigned int)(((id) & 2) == 0)

#define PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_BIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_BIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_UNIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_UNIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR + ((65535-1)*4))

/* 
* Time management. Internally, picoquic works in "virtual time", updated via the "current time" parameter
* passed through picoquic_create(), picoquic_create_cnx(), picoquic_incoming_packet(), and picoquic_prepare_packet().
*
* There are two supported modes of operation, "wall time" synchronized with the system's current time function,
* and "simulated time". Production services are expected to use wall time, tests and simulation use the
* simulated time. The simulated time is held in a 64 bit counter, the address of which is passed as 
* the "p_simulated_time" parameter to picoquic_create().
*
* The time management needs to be consistent with the functions used internally by the TLS package "picotls".
* If the argument "p_simulated_time" is NULL, picotls will use "wall time", accessed through system API.
* If the argument is set, the default time function of picotls will be overridden by a function that
* reads the value of *p_simulated_time.
*
* The function "picoquic_current_time()" reads the wall time in microseconds, using the same system calls
* as picotls. The default socket code in "picosock.[ch]" uses that time function, and returns the time
* at which messages arrived. 
*
* The function "picoquic_get_quic_time()" returns the "virtual time" used by the specified quic
* context, which can be either the current wall time or the simulated time, depending on how the
* quic context was initialized.
*/

uint64_t picoquic_current_time(); /* wall time */
uint64_t picoquic_get_quic_time(picoquic_quic_t* quic); /* connection time, compatible with simulations */

/* Callback function for providing stream data to the application,
 * and generally for notifying events from stack to application.
 * The type of event is specified in an enum picoquic_call_back_event_t.
 * For stream related calls, stream ID provides the stream number, and the
 * parameter stream_ctx provides the application supplied stream context.
 */
typedef int (*picoquic_stream_data_cb_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void * stream_ctx);

/* Callback from the TLS stack upon receiving a list of proposed ALPN in the Client Hello
 * The stack passes a <list> of io <count> vectors (base, len) each containing a proposed
 * ALPN. The implementation returns the index of the selected ALPN, or a value >= count
 * if none of the proposed ALPN is supported.
 *
 * The callback is only called if no default ALPN is specified in the Quic context.
 */
typedef size_t (*picoquic_alpn_select_fn)(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count);

/* Function used during callback to provision an ALPN context. The stack 
 * issues a callback of type 
 */
int picoquic_add_proposed_alpn(void* tls_context, const char* alpn);

/* Callback function for producing a connection ID compatible
 * with the server environment.
 */

typedef void (*picoquic_connection_id_cb_fn)(picoquic_quic_t * quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t * cnx_id_returned);

/* The fuzzer function is used to inject error in packets randomly.
 * It is called just prior to sending a packet, and can randomly
 * change the content or length of the packet.
 */
typedef uint32_t(*picoquic_fuzz_fn)(void * fuzz_ctx, picoquic_cnx_t* cnx, uint8_t * bytes, 
    size_t bytes_max, size_t length, size_t header_length);
void picoquic_set_fuzz(picoquic_quic_t* quic, picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx);

/* Log application messages or other messages to the text log and binary log.
 */
void picoquic_log_app_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs);
void picoquic_log_app_message(picoquic_cnx_t* cnx, const char* fmt, ...);

/* Set the log level:
 * 1: log all packets
 * 0: only log the first 100 packets for each connection. */
void picoquic_set_log_level(picoquic_quic_t* quic, int log_level);

/* By default, the binary log and qlog files are named from the Initial CID
 * chosen by the client. For example, if the initial CID is set
 * to { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05 } the
 * qlog files will be named:
 *  - deadbeef0102030405.client.qlog (on the client)
 *  - deadbeef0102030405.server.qlog (on the server)
 * This works well if clients follow the guidance in RFC9000 and set the
 * files to a random value, with only a very small chance of collisions.
 * But if the client use non standard names, the risk of collision
 * increases.
 * 
 * Setting the "use unique log names" option causes the insertion
 * of a random 16 bit string in the name, as in:
 *  - deadbeef0102030405.a1ea.server.qlog (on the server)
 * Setting the option to 0 restores the default behavior.
 */
void picoquic_use_unique_log_names(picoquic_quic_t* quic, int use_unique_log_names);

/* The SSLKEYLOG function defines a way to publish the encryption keys
* used by QUIC. If that feature is enabled, the code read the environment
* variable SSLKEYLOG to find the path of the file where to log the encryption
* file. If the environment variable is not present, no file is set.
* 
* This is a very dangerous feature, that can be abused to break encryption.
* Using an environment variable may be a fine way to specify on which file
* copies of keys have to be written, but it is a terrible way to specify
* whether these keys should be. Environment variables can be installed by
* scripts, etc., and there are many ways of doing that without user awareness.
* 
* This feature is enabled by setting the "SSLKEYLOG" option (option -8 if
* using the "config" module in the application), or by calling
* the "picoquic_enable_sslkeylog" API. This setting is "off" by default.
* The SSLKEYLOG feature will be disabled, whatever the
* setting, on builds of picoquic that are compiled with the macro
* "PICOQUIC_WITHOUT_SSLKEYLOG" defined (e.g., set CFLAGS=-DPICOQUIC_WITHOUT_SSLKEYLOG).
*/
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
void picoquic_enable_sslkeylog(picoquic_quic_t* quic, int enable_sslkeylog);
int picoquic_is_sslkeylog_enabled(picoquic_quic_t* quic);
#endif
/* 
 * picoquic_set_random_initial:
 * randomization of initial PN numbers, i.e.. the number assigned to
 * the first packet in a given number space. The option has three possible values:
 * 
 *  0: do not randomize.
 *  1: only randomize the number of the first "Initial" packet
 *  2: randomize the value of the first packet in all packet spaces.
 * 
 * By default, the variable is set to 1, because randomizing the initial
 * packet numbers in the Initial space prevents some possible DOS amplification
 * attacks. Use the `picoquic_set_random_initial` API to set the value:
 * 
 *  - To 0 for test cases for which any randomization makes regression
 *    difficult to detect
 *  - To 2 to test whether the implementation or its peers correctly
 *    handles non-zero initial packet numbers.
 */
void picoquic_set_random_initial(picoquic_quic_t* quic, int random_initial);

/* Set the "packet train" mode for pacing */
void picoquic_set_packet_train_mode(picoquic_quic_t* quic, int train_mode);

/* set the padding policy.
 * The padding policy is parameterized by two variables:
 * - packets shorter than padding_min_size will be padded to that size.
 * - if packets are longer than the min_size, they will be padded to the min size plus
 *   the nearest multiple of the "padding multiple", or to the path MTU.
 *
 * Padding is done before encryption, and before adding the AEAD checksum.
 *
 * The default value of the min size is set to 39 to enable the reset process.
 * By default, the multiple is set to zero.
 * 
 * When using "packet trains", it is a good idea to also set the padding multiple, because that
 * ensures that most packets will be padded to full path MTU length.
 */
void picoquic_set_padding_policy(picoquic_quic_t* quic, uint32_t padding_min_size, uint32_t padding_multiple);

/* Require Picoquic to log the session keys in the specified files.
 * Instead of calling this API directly, consider calling the 
 * function picoquic_set_key_log_file_from_env() defined in 
 * picosocks.h */
void picoquic_set_key_log_file(picoquic_quic_t* quic, char const* keylog_filename);

/* Adjust maximum connections allowed to the specified value.
 * The maximum number cannot be set to a value higher than the limit set when the context was
 * created. Trying higher values has no effect.
 */
int picoquic_adjust_max_connections(picoquic_quic_t * quic, uint32_t max_nb_connections);

/* Get number of open connections */
uint32_t picoquic_current_number_connections(picoquic_quic_t * quic);

/* Set get the retry threshold -- if passed, new connection will trigger retry */
void picoquic_set_max_half_open_retry_threshold(picoquic_quic_t* quic, uint32_t max_half_open_before_retry);
uint32_t picoquic_get_max_half_open_retry_threshold(picoquic_quic_t* quic);

/* Obtain the reasons why a connection was closed */
void picoquic_get_close_reasons(picoquic_cnx_t* cnx, uint64_t* local_reason,
    uint64_t* remote_reason, uint64_t* local_application_reason,
    uint64_t* remote_application_reason);

/* Will be called to verify that the given data corresponds to the given signature.
 * This callback and the `verify_ctx` will be set by the `verify_certificate_cb_fn`.
 * If `data` and `sign` are empty buffers, an error occurred and `verify_ctx` should be freed.
 * Expect `0` as return value, when the data matches the signature.
 */
typedef struct st_ptls_verify_certificate_t ptls_verify_certificate_t;
typedef int (*picoquic_verify_sign_cb_fn)(void* verify_ctx, ptls_iovec_t data, ptls_iovec_t sign);
/* Will be called to verify a certificate of a connection.
 * The arguments `verify_sign` and `verify_sign_ctx` are expected to be set, when the function returns `0`.
 * See `verify_sign_cb_fn` for more information about these arguments.
 */
typedef int (*picoquic_verify_certificate_cb_fn)(void* ctx, picoquic_cnx_t* cnx, ptls_iovec_t* certs, size_t num_certs,
                                                 picoquic_verify_sign_cb_fn* verify_sign, void** verify_sign_ctx);

/* Is called to free the verify certificate ctx */
typedef void (*picoquic_free_verify_certificate_ctx)(ptls_verify_certificate_t* ctx);

/* Management of the blocked port list */
int picoquic_check_port_blocked(uint16_t port);
int picoquic_check_addr_blocked(const struct sockaddr* addr_from);
void picoquic_disable_port_blocking(picoquic_quic_t* quic, int is_port_blocking_disabled);

/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t max_nb_connections,
    char const* cert_file_name, char const* key_file_name, char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_data,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length);

void picoquic_free(picoquic_quic_t* quic);

/* Preference for low memory options.
 * setting this flag instructs picoquic to chose implementations of algorithms 
 * that use less memory while maintaining reasonable performance. For example,
 * choose the openssl implementation of AES instead of the fusion implementation,
 * which is a bit faster but requires an additional 7KB of data per connection */
int picoquic_set_low_memory_mode(picoquic_quic_t* quic, int low_memory_mode);

/* management of retry policy.
 * The cookie mode can be used to force the following behavior:
 * - if cookie_mode&1, check the token and force a retry for each incoming connection.
 * - if cookie&2, provide a token to the client after completing the handshake.
 * When the "force retry" is not set, the code will count the number of "half-open" 
 * connections. This can happen for example if the server is subject to a DDOS attack.
 * If the threshold is exceeded, the code will request a token before accepting new
 * connections, forcing DDOS attackers to reveal their IP address.
 * By default, the threshold is set to 128 connections.
 */
void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode);

/* Set cipher suite, for tests. 
 * use cipher_suite_id = 0 for default values, or one 
 * of the values defined by IANA for cipher suites, 
 * including: 
 *     PICOQUIC_AES_128_GCM_SHA256
 *     PICOQUIC_AES_256_GCM_SHA384
 *     PICOQUIC_CHACHA20_POLY1305_SHA256
 * returns 0 if OK, -1 if the specified ciphersuite is not supported.
 */
int picoquic_set_cipher_suite(picoquic_quic_t* quic, int cipher_suite_id);

/* Set key exchange algorithms, for tests.
 * use key_exchange_id = 0 for default values,
 * or PICOQUIC_GROUP_SECP256R1 for supporting only secp256r1
 * returns 0 if OK, -1 if the specified cipher suite is not supported.
 */
int picoquic_set_key_exchange(picoquic_quic_t* quic, int key_exchange_id);

/* Init of transport parameters per quic context */
int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t* tp);
/* Read default parameters per quic context */
picoquic_tp_t const* picoquic_get_default_tp(picoquic_quic_t* quic);
/* Set the transport parameters per connection */
void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t const * tp);
/* Get the transport parameters per connection */
picoquic_tp_t const* picoquic_get_transport_parameters(picoquic_cnx_t* cnx, int get_local);

/* Set the TLS certificate chain(DER format) for the QUIC context. The context will take ownership over the certs pointer. */
void picoquic_set_tls_certificate_chain(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count);

/* Set the TLS root certificates (DER format) for the QUIC context. The context will take ownership over the certs pointer.
 * The root certificates will be used to verify the certificate chain of the server and client (with client authentication activated).
 * Returns `0` on success, `-1` on error while loading X509 certificate or `-2` on error while adding a cert to the certificate store.
 */
int picoquic_set_tls_root_certificates(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count);

/* Tell the TLS stack to not attempt verifying certificates */
void picoquic_set_null_verifier(picoquic_quic_t* quic);

/* Set the TLS private key(DER format) for the QUIC context. The caller is responsible for cleaning up the pointer. */
int picoquic_set_tls_key(picoquic_quic_t* quic, const uint8_t* data, size_t len);

/* Set the verify certificate callback and context. */
void picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, 
    ptls_verify_certificate_t * cb, picoquic_free_verify_certificate_ctx free_fn);

/* Set client authentication in TLS (if enabled, client is required to send certificates). */
void picoquic_set_client_authentication(picoquic_quic_t* quic, int client_authentication);

/* By default, a quic context authorizes incoming connections if the certificate and
 * private key are provided, but if client authentication is required the client context
 * will also have certificaye and key. In that case, the function "enforce_client_only"
 * can be used to specify a pure client (do_enforce=1). For peer-to-peer application
 * that expect both incoming connections, there is no need to call that API, but it
 * could be used with "do_enforce = 0". */
void picoquic_enforce_client_only(picoquic_quic_t* quic, int do_enforce);

/* Set default padding policy for the context */
void picoquic_set_default_padding(picoquic_quic_t* quic, uint32_t padding_multiple, uint32_t padding_minsize);

/* Set default spin bit policy for the context
* return 0 if OK, -1 if the policy was invalid.
* Note that "picoquic_spinbit_on" is only allowed as a default policy,
* translating to unconditional setup when connections are created for
* the context. As a per conection setup, it is invalid.
 */
int picoquic_set_default_spinbit_policy(picoquic_quic_t * quic, picoquic_spinbit_version_enum default_spinbit_policy);
int picoquic_set_spinbit_policy(picoquic_cnx_t* cnx, picoquic_spinbit_version_enum spinbit_policy);

/* Set default loss bit policy for the context */
void picoquic_set_default_lossbit_policy(picoquic_quic_t* quic, picoquic_lossbit_version_enum default_lossbit_policy);

/* Set the multipath option for the context */
void picoquic_set_default_multipath_option(picoquic_quic_t* quic, int multipath_option);

/* Set the Address Discovery mode for the context */
void picoquic_set_default_address_discovery_mode(picoquic_quic_t* quic, int mode);

/** picoquic_set_cwin_max:
 * Set a maximum value for the congestion window (default: UINT64_MAX)
 * This option can be used to limit the amount of memory that the sender
 * will use to manage packet transmission. The main part of that memory
 * is the queue of packets not yet acknowledged, which size is mostly
 * similar to "cwin_max". Other components include the queue of packets
 * that have already been declared lost, and temporary copies of
 * data waiting to be resent. The copies of packets are kept for some time
 * in case the loss was "spurious"; the size of that queue is a fraction
 * of "cwin_max". The temporary copies of data are kept until data can
 * be sent, which is nor mally a very short delay but can become
 * longer if the congestion window shrunk after losses were detected.
 * 
 * This control is imperfect, because the maximum packet size is always
 * reserved for each packet.
 * 
 * The CWIN value is normally limited by the congestion control algorithm.
 * The "cwin_max" limit only licks in if the congestion control
 * algorithm would have authorized a larger value.
 */
void picoquic_set_cwin_max(picoquic_quic_t* quic, uint64_t cwin_max);

/* picoquic_set_max_data_limit: 
* set a maximum value for the "max data" option, thus limiting the
* amount of data that the peer will be able to send before data is
* acknowledged.
* This option can be used to control the amount of memory that the
* receiver will use to reorder received data frames. This control is
* indirect: the receiver always allocate a full packet size for incoming
* packets, even if they are small. In tests, we see the allocated memory
* per connection vary between 2 and 3 times the max data value.
* Setting the value to 0 (default) means that the "max data" limit
* will rapidly increase to let transmission proceed quickly.
*/
void picoquic_set_max_data_control(picoquic_quic_t* quic, uint64_t max_data);

/*
* Idle timeout and handshake timeout
* 
* The max idle timeout determines how long to wait for sign of activity from
* the peer before giving up on a connection. It is set by default to 
* PICOQUIC_MICROSEC_HANDSHAKE_MAX, coverted in milliseconds (30 seconds).
* It can be set per quic context using `picoquic_set_default_idle_timeout`,
* before creating new connections in that context. The value is expressed
* in milliseconds, with zero meaning "infinity". The value used for the
* connection is the lowest of the value proposed by the client and the server,
* as specified in RFC 9000.
* 
* The handshake timeout determines how long to wait for the completion
* of a connection. It can be specified per QUIC context using
* `picoquic_set_default_handshake_timeout`. The value is expressed
* in microseconds, with `0` meaning unspecified.
* 
* If the handshake timeout is not specified, the wait time is determined by the
* value of the default idle timeout specified for the QUIC context. If that
* value is zero, the system uses the value of PICOQUIC_MICROSEC_HANDSHAKE_MAX,
* i.e., 30 seconds.
*/

/* Set the idle timeout parameter for the context. Value is in milliseconds. */
void picoquic_set_default_idle_timeout(picoquic_quic_t* quic, uint64_t idle_timeout_ms);
/* Set the default handshake timeout parameter for the context.*/
void picoquic_set_default_handshake_timeout(picoquic_quic_t* quic, uint64_t handshake_timeout_us);

/* Set the length of a crypto epoch -- force rotation after that many packets sent */
void picoquic_set_default_crypto_epoch_length(picoquic_quic_t* quic, uint64_t crypto_epoch_length_max);

uint64_t picoquic_get_default_crypto_epoch_length(picoquic_quic_t* quic);

/* Get the local CID length */
uint8_t picoquic_get_local_cid_length(picoquic_quic_t* quic);

/* Check whether a CID is locally defined */
int picoquic_is_local_cid(picoquic_quic_t* quic, picoquic_connection_id_t* cid);

/* Manage session tickets and retry tokens.
 * There is no explicit call to load tickets, this must be done by passing
 * the ticket store name as an argument to picoquic_create().
 */
int picoquic_load_retry_tokens(picoquic_quic_t* quic, char const* token_store_filename);
int picoquic_save_session_tickets(picoquic_quic_t* quic, char const* ticket_store_filename);
int picoquic_save_retry_tokens(picoquic_quic_t* quic, char const* token_store_filename);

/* Manage bdps */
void picoquic_set_default_bdp_frame_option(picoquic_quic_t* quic, int enable_bdp_frame);

/* Set default connection ID length for the context.
 * All valid values are supported on the client.
 * Using a null value on the server is not tested, may not work.
 * Cannot be changed if there are active connections in the context.
 * Value must be compatible with what the cnx_id_callback() expects on a server */
int picoquic_set_default_connection_id_length(picoquic_quic_t* quic, uint8_t cid_length);

void picoquic_set_default_connection_id_ttl(picoquic_quic_t* quic, uint64_t ttl_usec);

uint64_t picoquic_get_default_connection_id_ttl(picoquic_quic_t* quic);

/* Setting the max mtu that can be found or tried using path MTU discovery.
 * The API uses the traditional definition of the path MTU. The size of 
 * packet sent is the sum of the lengths of IPv4 or IPv6 header (20 or 40 bytes),
 * UDP header (8 bytes) and UDP payload. The QUIC stack can only control the
 * size of the udp payload, which is negotiated through transport parameters
 * during the handshake. The negotiated value will be set by subtracting
 * from the "mtu_max" parameter the estimated IP and UDP over, which depends
 * on the IP address used for the connection and is computed using the
 * macro "PICOQUIC_MTU_OVERHEAD".
 */
#define PICOQUIC_MTU_OVERHEAD(p_s_addr) (((p_s_addr)->sa_family==AF_INET6)?48:28)
void picoquic_set_mtu_max(picoquic_quic_t* quic, uint32_t mtu_max);

void picoquic_set_initial_send_mtu(picoquic_quic_t* quic, uint32_t intitial_mtu_ipv4, uint32_t intitial_mtu_ipv6);

/* Set the ALPN function used to verify incoming ALPN */
void picoquic_set_alpn_select_fn(picoquic_quic_t* quic, picoquic_alpn_select_fn alpn_select_fn);

/* Set the default callback function for new connections.
 * This must be defined for every server implementation.
 */
void picoquic_set_default_callback(picoquic_quic_t * quic, picoquic_stream_data_cb_fn callback_fn, void * callback_ctx);

/* Set the minimum interval between consecutive stateless reset packets.
 * This limits the potential blowback of stateless reset packets when nder DoS attacks.
 * A value of zero will set no interval.
 * Default to PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT
 */
void picoquic_set_default_stateless_reset_min_interval(picoquic_quic_t* quic, uint64_t min_interval_usec);

/* Set and get the maximum number of simultaneously logged connections.
* If that number is too high, the maximum number of open files will be hit 
* at random places in the code. A small value means that some connections may
* not be logged. Default is set to 32. */
void picoquic_set_max_simultaneous_logs(picoquic_quic_t* quic, uint32_t max_simultaneous_logs);
uint32_t picoquic_get_max_simultaneous_logs(picoquic_quic_t* quic);

/* Connection context creation and registration */
picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id,
    const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode);

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

int picoquic_start_client_cnx(picoquic_cnx_t* cnx);

/* Closing the quic connection can be done in one of three ways.
 *
 * The function "picoquic_close" performs an ordered close. The "reason code"
 * is sent to the peer, and should be visible by the peer's application,
 * unless of course the peer discards the connection before receiving
 * the closing message. The action is delayed until the next
 * packet can be sent.
 * 
 * The function "picoquic_close_immediate" performs an abrupt close. The
 * connection will immediately move to a "draining" state, no more
 * packets will be sent, no information will be provided to the peer.
 * The connection context will be kept for a very
 * limited time, until it can be safely deleted.
 * This should be safe to use inclduing inside a picoquic callback,
 * but it is a bit experimental. Please file an issue if you see a problem.
 * 
 * The function "picoquic_delete_cnx" deletes all the resource associated
 * with the connection, including the connection context. Any reference
 * to the context after making this call will cause an error, which
 * makes it unsafe to use inside a callback.
 */
int picoquic_close(picoquic_cnx_t* cnx, uint64_t application_reason_code);

void picoquic_close_immediate(picoquic_cnx_t* cnx);

void picoquic_delete_cnx(picoquic_cnx_t* cnx);

/* set the app wake up time (or cancel it by setting it to zero) */
void picoquic_set_app_wake_time(picoquic_cnx_t* cnx, uint64_t app_wake_time);

/* Support for version negotiation:
 * Setting the "desired version" parameter will trigger compatible version
 * negotiation from the current version to that desired version, if the
 * server supports the desired version.
 * If starting the connection with a new version after receiving a VN packet,
 * setting the "rejected version" parameter will provide protection against
 * downgrade attacks.
 * These parameters must be set before starting the connection.
 */

void picoquic_set_desired_version(picoquic_cnx_t* cnx, uint32_t desired_version);
void picoquic_set_rejected_version(picoquic_cnx_t* cnx, uint32_t rejected_version);

/* Path management events and API
 * 
 * The "probe new path" API attempts to validate a new path. If multipath is enabled,
 * the new path will come in addition to the set of existing paths; if not,
 * the new path when validated will replace the default path.
 * The "abandon path" should only be used if multipath is enabled, and if more than
 * one path is available -- otherwise, just close the connection. If the command
 * is accepted, the peer will be informed of the need to close the path, and the
 * path will be demoted after a short delay.
 * 
 * Path event callbacks can be enabled by calling "picoquic_enable_path_callbacks".
 * This can be set as the default for new connections by calling
 * "picoquic_enable_path_callbacks_default". If enabled, the folling events
 * will be signalled by callbacks:
 * 
 *  - picoquic_callback_path_available: 
 *        A new path is available. On the client, this happens as soon as the 
 *        continuity has been verified. On the server, this happens when the
 *        continuity is verified and the client has started using the path
 *        (see section 8.2 of RFC 9000, path validation.)
 *        The same callback is used if a path was suspended, but becomes
 *        available again. 
 *  - picoquic_callback_path_suspended:
 *        A path that was available has been suspended. This happens for
 *        example if repeated transmission errors cause the scheduler to
 *        stop using that path for sending packets. 
 *  - picoquic_callback_path_deleted:
 *        An existing path has been deleted. The application should delete
 *        all references to that path.
 *  - picoquic_callback_path_quality_changed:
 *        Path parameters like RTT, data rate or packet loss rate have
 *        changed.
 * 
 * The "path" callback events use the same calling signature as the other 
 * callback events, but the definition of some fields changes:
 *  - the "stream_id" field is used to carry a "unique_path id"
 *  - the "bytes" and "length" fields are not used
 *  - the "stream_ctx" field carries the application specified "app_path_ctx"
 * The same "unique_path_id" is used to identify the path in the API calls.
 * 
 * The logical flow is that the application learns the path ID in a callback,
 * typically "picoquic_callback_path_available". If the application wants to
 * maintain path data in an app specific context, it will use a call to
 * "picoquic_set_app_path_ctx" to document it. The path created during
 * the connection setup has the unique_path_id 0.
 
 * 
 * If an error occurs, such as reference to an obsolete unique path id,
 * all the functions return -1.
 * 
 * The call to "refresh the connection ID" will trigger a renewal of the connection
 * ID used for sending packets on that path. This API is mostly used in test
 * programs. By default, picoquic will attempt to renew a path connection ID 
 * if that path resumes after a long silence: using
 * a new connection ID in these conditions makes correlation of old and new
 * connection data harder in case of NAT traversal.
 */

int picoquic_probe_new_path(picoquic_cnx_t* cnx, const struct sockaddr* addr_peer,
    const struct sockaddr* addr_local, uint64_t current_time);
int picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_peer,
    const struct sockaddr* addr_local, int if_index, uint64_t current_time, int to_preferred_address, int* path_id_p);
void picoquic_enable_path_callbacks(picoquic_cnx_t* cnx, int are_enabled);
void picoquic_enable_path_callbacks_default(picoquic_quic_t* quic, int are_enabled);
int picoquic_set_app_path_ctx(picoquic_cnx_t* cnx, uint64_t unique_path_id, void * app_path_ctx);
int picoquic_abandon_path(picoquic_cnx_t* cnx, uint64_t unique_path_id, 
    uint64_t reason, char const* phrase, uint64_t current_time);
int picoquic_refresh_path_connection_id(picoquic_cnx_t* cnx, uint64_t unique_path_id);
int picoquic_set_stream_path_affinity(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t unique_path_id);
int picoquic_set_path_status(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_path_status_enum status);
/* The get path addr API provides the IP addresses used by a specific path.
* The "local" argument determines whether the APi returns the local address
* (local == 1), the address of the peer (local == 2) or the address observed by the peer (local == 3).
*/
int picoquic_get_path_addr(picoquic_cnx_t* cnx, uint64_t unique_path_id, int local, struct sockaddr_storage* addr);

/*
* The calls to picoquic_get_path_quality takes as argument a structure
* of type `picoquic_path_quality_t`.
* 
* The call to picoquic_get_default_path_quality uses the same
* structure, but only reports the parameters for the "default" path.
* This is suitable for applications that do not use multipath.
* 
* The application can call `picoquic_get_path_quality` or 
* `picoquic_get_default_path_quality` at any time. The application can
* also subscribe to the `quality change` callback, and only call
* the path quality API after the callback signalled a path
* qualiy change.
* 
* The application subscribes to the path quality update
* using "picoquic_subscribe_to_quality_update" API
* for the connection, or "picoquic_subscribe_to_quality_update_per_path" API
* for a specific path, setting the "change" thresholds
* for the datarate and the rtt. 
* The function call "picoquic_default_quality_update"
* can be used to set the default values of these parameters in
* the quic context.
*/

typedef struct st_picoquic_path_quality_t {
    uint64_t receive_rate_estimate; /* In bytes per second */
    uint64_t pacing_rate; /* bytes per second */
    uint64_t cwin; /* number of bytes in congestion window */
    uint64_t rtt; /* smoothed estimate of roundtrip time in micros seconds */
    uint64_t rtt_sample; /* most recent RTT sample */
    uint64_t rtt_variant; /* estimate of RTT variability */
    uint64_t rtt_min; /* minimum value of RTT, computed since path creation */
    uint64_t rtt_max; /* maximum value of RTT, computed since path creation */
    uint64_t sent; /* number of packets sent on the path */
    uint64_t lost; /* number of packets considered lost among those sent */
    uint64_t timer_losses; /* packet losses detected due to timer expiring */
    uint64_t spurious_losses; /* number of packet lost that were later acked. */
    uint64_t max_spurious_rtt; /* maximum RTT for spurious losses */
    uint64_t max_reorder_delay; /* maximum time gap for out of order packets */
    uint64_t max_reorder_gap; /* maximum number gap for out of order packets */
    uint64_t bytes_in_transit; /* number of bytes currently in transit */

} picoquic_path_quality_t;

int picoquic_get_path_quality(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_path_quality_t * quality);
void picoquic_get_default_path_quality(picoquic_cnx_t* cnx, picoquic_path_quality_t* quality);
int picoquic_subscribe_to_quality_update_per_path(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint64_t pacing_rate_delta, uint64_t rtt_delta);
void picoquic_subscribe_to_quality_update(picoquic_cnx_t* cnx, uint64_t pacing_rate_delta, uint64_t rtt_delta);
void picoquic_default_quality_update(picoquic_quic_t* quic, uint64_t pacing_rate_delta, uint64_t rtt_delta);

/* Connection management API.
 * TODO: many of these API should be deprecated. They were created when we
 * envisaged that applications would directly manipulate which connection
 * should be awaken when. The code in picoquicdemo only uses
 * "picoquic_get_next_wake_delay" and then let the quic context poll the 
 * right connection by calling picoquic_prepare_next_packet_ex.
 */
int picoquic_start_key_rotation(picoquic_cnx_t * cnx);
picoquic_quic_t* picoquic_get_quic_ctx(picoquic_cnx_t* cnx);
picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic);
picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx);
int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time,
    int64_t delay_max);
int64_t picoquic_get_wake_delay(picoquic_cnx_t* cnx,
    uint64_t current_time,
    int64_t delay_max);
picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time);

uint64_t picoquic_get_next_wake_time(picoquic_quic_t* quic, uint64_t current_time);

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx);

void picoquic_cnx_set_padding_policy(picoquic_cnx_t * cnx, uint32_t padding_multiple, uint32_t padding_minsize);
void picoquic_cnx_get_padding_policy(picoquic_cnx_t * cnx, uint32_t * padding_multiple, uint32_t * padding_minsize);
/* Set spin bit policy for the connection */
void picoquic_cnx_set_spinbit_policy(picoquic_cnx_t * cnx, picoquic_spinbit_version_enum spinbit_policy);

/* Set max packet interval between key rotations */
void picoquic_set_crypto_epoch_length(picoquic_cnx_t* cnx, uint64_t crypto_epoch_length_max);
uint64_t picoquic_get_crypto_epoch_length(picoquic_cnx_t* cnx);

/* Set the PMTU discovery policy
 * The API picoquic_cnx_set_pmtud_required is obsolete, should use instead:
 * for is_pmtud_required = 0: picoquic_cnx_set_pmtud_policy(cnx, picoquic_pmtud_basic)
 * for is_pmtud_required = 1: picoquic_cnx_set_pmtud_policy(cnx, picoquic_pmtud_required)
 */
void picoquic_set_default_pmtud_policy(picoquic_quic_t* quic, picoquic_pmtud_policy_enum pmtud_policy);
void picoquic_cnx_set_pmtud_policy(picoquic_cnx_t* cnx, picoquic_pmtud_policy_enum pmtud_policy);
void picoquic_cnx_set_pmtud_required(picoquic_cnx_t* cnx, int is_pmtud_required);

/* Check whether the handshake is of type PSK*/
int picoquic_tls_is_psk_handshake(picoquic_cnx_t* cnx);

/* Manage addresses */
void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr);
void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr);
unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx);
int picoquic_set_local_addr(picoquic_cnx_t* cnx, struct sockaddr* addr);

/* Manage connection IDs*/
picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_remote_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_client_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_logging_cnxid(picoquic_cnx_t* cnx);

/* Manage connections */
uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx);
int picoquic_is_0rtt_available(picoquic_cnx_t* cnx);

int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx);

void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

picoquic_stream_data_cb_fn picoquic_get_default_callback_function(picoquic_quic_t * quic);

void * picoquic_get_default_callback_context(picoquic_quic_t * quic);

picoquic_stream_data_cb_fn picoquic_get_callback_function(picoquic_cnx_t * cnx);

void * picoquic_get_callback_context(picoquic_cnx_t* cnx);

/* Send extra frames */
int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length,
    int is_pure_ack, picoquic_packet_context_enum pc);

/* Queue a datagram frame for sending later.
 * The datagram length must be no more than PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH,
 * i.e., must fit in the minimum packet length supported by Quic. Trying to
 * queue a larger datagram will result in an error PICOQUIC_ERROR_DATAGRAM_TOO_LONG.
 */
#define PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH 1200
int picoquic_queue_datagram_frame(picoquic_cnx_t* cnx, size_t length, const uint8_t* bytes);

/* The incoming packet API is used to pass incoming packets to a 
 * Quic context. The API handles the decryption of the packets
 * and their processing in the context of connections.
 */

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time);

int picoquic_incoming_packet_ex(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    picoquic_cnx_t** first_cnx,
    int* first_path_id,
    uint64_t current_time);


int picoquic_select_next_path(picoquic_cnx_t * cnx, uint64_t current_time, uint64_t * next_wake_time, struct sockaddr_storage * p_addr_to, struct sockaddr_storage * p_addr_from, int* if_index);

/* Applications must regularly poll the "next packet" API to obtain the
 * next packet that will be set over the network. The API for that is
 * picoquic_prepare_next_packet", which operates on a "quic context".
 * The API "picoquic_prepare_packet" does the same but for just one
 * connection at a time. 
 */

int picoquic_prepare_next_packet_ex(picoquic_quic_t* quic, 
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, 
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_connection_id_t* log_cid, picoquic_cnx_t** p_last_cnx, size_t* send_msg_size);

int picoquic_prepare_next_packet(picoquic_quic_t* quic,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_connection_id_t* p_logcid, picoquic_cnx_t** p_last_cnx);

int picoquic_prepare_packet_ex(picoquic_cnx_t* cnx, int path_id_request,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    size_t* send_msg_size);

int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index);

/* Socket error signalling.
 * The application code is in charge of sending the packets prepared by the stack
 * to the designated network address. If the stack tries to send a packet to an unreachable
 * destination, the application may get an error indication from the socket "sendmsg"
 * API, or its equivalent. Passing the error back to the stack allows for better
 * handling, for example closing a connection immediately if the peer's address is
 * unreachable, or cancelling a migration attempt if the new path is not available.
 *
 * The signalling is per connection, using the connection context signalled for example
 * in the p_last_cnx parameter to the picoquic_prepare_next_packet API. The p_addr_to
 * parameter indicates the peer's address, the destination of the failed transmission.
 * The p_addr_from parameter indicates the source address provided by the 
 * picoquic_prepare_next_packet API, the if_index parameter indicates the interface ID
 * suggested by the stack. The socket_err parameter may be used by the stack for logging
 * purposes.
 */
void picoquic_notify_destination_unreachable(picoquic_cnx_t* cnx,
     uint64_t current_time, struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err);
void picoquic_notify_destination_unreachable_by_cnxid(picoquic_quic_t* quic, picoquic_connection_id_t * cnxid,
    uint64_t current_time, struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err);

/* Handling of out of sequence stream data delivery.
 *
 * For applications like video communication, it is important to process stream data
 * as soon as it arrives, even if it arrives out of order. For example, it might be
 * better to play the next video frame than to wait for the complete transmission
 * of the previous one. Picoquic enables that with the "direct receive" marking. If
 * a stream is marked as "direct receive", picoquic will hand data receive on
 * that stream to the application immediately, even if it is out of sequence.
 * 
 * The data will be delivered to a direct receive callback function, which will
 * pass the pointer to the data, the stream offset and length of the data, and
 * also indicates if a fin mark was received. When the fin mark is present, the
 * fin offset of the stream is located at the sum of offset and length, and
 * the length may be null.
 *
 * The function picoquic_mark_direct_receive_stream is used to mark a stream
 * as `direct receive` and provide the callback function and context for that
 * stream. Calling that function with a NULL callback function pointer results
 * in an error.
 *
 * If stream data was queued at the time the picoquic_mark_direct_receive_stream
 * function is called, the callback will be activated immediately.
 *
 * The callback function shall return:
 * - 0 if the data was processed normally.
 * - PICOQUIC_STREAM_RECEIVE_COMPLETE if the fin bit was received once and all
 *   expected bytes on the stream have been received.
 * - An appropriate error code if an error was encountered.
 *
 * Returning an error code will cause picoquic to close the connection with the
 * corresponding transport error, or PICOQUIC_TRANSPORT_INTERNAL_ERROR if the
 * error code in the range of the PICOQUIC_ERROR_CLASS.
 */

typedef int (*picoquic_stream_direct_receive_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, int fin, const uint8_t* bytes, uint64_t offset, size_t length,
    void* direct_receive_ctx);

void picoquic_set_default_direct_receive_callback(picoquic_quic_t* quic,
    picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx);

/* If set, ordered stream callbacks do not auto-consume data. */
void picoquic_set_stream_data_consumption_mode(picoquic_quic_t* quic,
    int defer_stream_data_consumption);

int picoquic_mark_direct_receive_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx);

int picoquic_stream_data_consumed(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t new_offset);

/* Associate stream with app context */
int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx);
/* Remove association between stream and context */
void picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);

/* Mark stream as active, or not.
 * If a stream is active, it will be polled for data when the transport
 * is ready to send. The polling will only start after all currently
 * queued data has been sent.
 */
int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void* v_stream_ctx);

/* Handling of stream priority. 
 * 
 * Picoquic handles priority as an 8 bit unsigned integer.
 * When ready to send stream frames, picoquic will pick the lowest priority
 * stream for which data can be send, i.e., it is available and flow control
 * allows it.
 *
 * When several streams are available at the same priority level, the
 * handling depends on the least significant bit of the priority code.
 * If that bit is zero, picoquic implements round robin scheduling and
 * select the stream on which data was least recently sent. If it is
 * one, picoquic implements FIFO scheduling and selects the stream with
 * the lowest stream id.
 * 
 * There is no formal association between priority level and stream
 * content. Application developers can pick whatever convention they
 * see fit. One possible example could be:
 * 
 * - 0: system priority, e.g., the "settings" stream in HTTP3 (round robin)
 * - 1: high priority data (FIFO)
 * - 2: high priority data (Round Robin)
 * - 4: real time audio (round robin)
 * - 6: real time video (round robin)
 * - 9: urgent data, such as CSS or JSON files (FIFO)
 * - 10: progressive data such as JPG files (round robin) 
 * - 11: web data (FIFO)
 * - 255: background data (FIFO)
 * 
 * When streams are created, the priority is set to a default value for
 * the QUIC context. By default, the default is 9 (FIFO), which mimics the
 * behavior of previous versions of picoquic before the formal priority
 * handling was introduced. The default stream priority can be changed
 * with the `picoquic_set_default_priority` API. Changing the default
 * priority only affects stream created after that change.
 * 
 * Individual stream priority can be set using `picoquic_set_stream_priority`.
 * 
 * The API `picoquic_mark_high_priority_stream` is a legacy of the previous
 * versions. It is equivalent to setting the priority of the specified
 * stream to zero if "is_high_priority" is true, or to the default
 * stream priority if it is not.
 */

/* Set the default priority for newly created streams */
#define PICOQUIC_DEFAULT_STREAM_PRIORITY 9
void picoquic_set_default_priority(picoquic_quic_t* quic, uint8_t default_stream_priority);

/* Set the priority level of a stream. */
int picoquic_set_stream_priority(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t stream_priority);

int picoquic_mark_high_priority_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_high_priority);

/* 
* Handling of datagram priorities
* 
* All datagrams sent on a connection have the same priority.
* The datagram priority value determines the relative priority of
* streams and datagrams.
* 
* Streams with a higher priority than the datagram priority will be
* scheduled before any datagram. Streams with a lower priority
* will only be scheduled if no datagram needs to be sent. 
* Streams with the same priority as the datagram priority will
* be scheduled in a  "round robin" manner: datagram on one round,
* then a stream on the next round, then back to datagrams, the general
* idea being about equal share for the datagrams and all streams of
* the same priority.
* 
* By default, the datagram priority is set to the value
* PICOQUIC_DEFAULT_STREAM_PRIORITY, same as streams, so the default behavior
* is a 50/50 share.
*/

void picoquic_set_default_datagram_priority(picoquic_quic_t* quic, uint8_t default_datagram_priority);

void picoquic_set_datagram_priority(picoquic_cnx_t * cnx, uint8_t datagram_priority);

/* If a stream is marked active, the application will receive a callback with
 * event type "picoquic_callback_prepare_to_send" when the transport is ready to
 * send data on a stream. The "length" argument in the call back indicates the
 * largest amount of data that can be sent, and the "bytes" argument points
 * to an opaque context structure. In order to prepare data, the application
 * needs to call "picoquic_provide_stream_data_buffer" with that context
 * pointer, with the number of bytes that it wants to write, with an indication
 * of whether or not the fin of the stream was reached, and also an indication
 * of whether or not the stream is still active. The function
 * returns the pointer to a memory address where to write the byte -- or
 * a NULL pointer in case of error. The application then copies the specified 
 * number of bytes at the provided address, and provide a return code 0 from
 * the callback in case of success, or non zero in case of error.
 */

uint8_t* picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);

/* Queue data on a stream, so the transport can send it immediately
 * when ready. The data is copied in an intermediate buffer managed by
 * the transport. Calling this API automatically erases the "active
 * mark" that might have been set by using "picoquic_mark_active_stream".
 * It also erases the "app_stream_ctx" value set in previous calls to
 * picoquic_add_to_stream_with_ctx or picoquic_mark_active_stream
 */
int picoquic_add_to_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, const uint8_t* data, size_t length, int set_fin);

void picoquic_reset_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);

/* Same as "picoquic_add_to_stream", but also sets the application stream context.
 * The context is used in call backs, so the application can directly process responses.
 */
int picoquic_add_to_stream_with_ctx(picoquic_cnx_t * cnx, uint64_t stream_id, const uint8_t * data, size_t length, int set_fin, void * app_stream_ctx);

/* Reset a stream, indicating that no more data will be sent on 
 * that stream and that any data currently queued can be abandoned. */
int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error);

/* Open the flow control for receiving the expected data on a stream */
int picoquic_open_flow_control(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t expected_data_size);

/* Obtain the next available stream ID in the local category */
uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir);

/* Ask the peer to stop sending on a stream. The peer is expected
 * to reset that stream when receiving the "stop sending" signal. */
int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error);

/* Discard stream. This is equivalent to sending a stream reset
 * and a stop sending request, and also setting the app context
 * of the stream to NULL */
int picoquic_discard_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint16_t local_stream_error);

/* The function picoquic_set_datagram_ready indicates to the stack
 * whether the application is ready to send datagrams. 
 * 
 * When running in a multipath environment, some applications may want to
 * send datagram on a specific path. For example, if an application is sending
 * voice over IP frames in datagrams, it may want to send all these datagrams
 * on the same path, to avoid the delay jitters due to random path selection.
 * The path variant specifies a unique path identifier,
 * indicating that datagrams are ready on that path. The callback
 * "picoquic_callback_prepare_datagram" will be issued if either
 * the current path or the whole connection is marked ready for datagrams.
 */
int picoquic_mark_datagram_ready(picoquic_cnx_t* cnx, int is_ready);
int picoquic_mark_datagram_ready_path(picoquic_cnx_t* cnx, uint64_t unique_path_id, int is_path_ready);

/* If a datagram is marked active, the application will receive a callback with
 * event type "picoquic_callback_prepare_datagram" when the transport is ready to
 * send data on a path. The "length" argument in the call back indicates the
 * largest amount of data that can be sent, and the "bytes" argument points
 * to an opaque context structure. If the application has indicated support
 * for path callbacks by using "", the "stream_id" argument is repurposed to
 * indicate the unique path identifier of the current path. In order to prepare data, 
 * the application needs to call "picoquic_provide_datagram_buffer" with the context
 * pointer, and with the number of bytes that it wants to write. The function
 * returns the pointer to a memory address where to write the bytes -- or
 * a NULL pointer in case of error. The application then copies the specified
 * number of bytes at the provided address, and provide a return code 0 from
 * the callback in case of success, or non zero in case of error.
 * 
 * There are two variants of "picoquic_callback_prepare_datagram", the old one
 * and the new one, "picoquic_callback_prepare_datagram_ex", which adds
 * an "is_active" parameter. This parameter helps handling some cases:
 * 
 * - if the application marked the context ready by mistake, it 
 *   should set the "length" argument to 0, and the "is_active" argument
 *   to picoquic_datagram_not_active. This is a way of saying "oops". The
 *   stack will stop polling for datagrams, until there is a new call to
 *   "picoquic_mark_datagram_ready"
 * 
 * - if the application does have data to send but the available
 *   length indicated in the callback is too small, it should set the "length"
 *   argument to 0, and the "is_active" argument to picoquic_datagram_active_any_path.
 *   The stack will try to immediately reissue the callback in the next packet, hopefully with
 *   more space available.
 * 
 * - if the application can send data, it should set the "length"
 *   argument to the desired value, and the "is_active" argument to
 *   either 0 if there is no datagram data immediately ready to send
 *   after that, or 1 if there is some. The stack will send the requested
 *   datagram, and then do the equivalent of a call to "picoquic_mark_datagram_ready"
 *   with the value of is_active parameter.
 * 
 * The old API will not treat those scenarios as reliably. If the application
 * is polled and has nothing to send, it MUST call
 * " picoquic_mark_datagram_ready(cnx, 0);" to tell the stack to not call
 * it again, otherwise there will be a hot loop consuming a lot of CPU. If you
 * see that, you should really switch to using the new "extended" API and set
 * the "is_active" parameter.
 * 
 * In multipath environments, the application can use the API 
 * `picoquic_mark_datagram_ready_path` to signal that is is ready to send
 * datagrams on a specific path. The picoquic_provide_datagram_path_ex
 * API allows the application to mark 4 different level of activity:
 * 
 * - picoquic_datagram_not_active: not active on this path or any other.
 * - picoquic_datagram_active_any_path: active, but not specifically on this path.
 * - picoquic_datagram_active_this_path_only: ready to send datagrams on this
 *   path, but not on other paths unless they were specifically marked.
 * - picoquic_datagram_active_this_path_and_others: has traffic ready to
 *   send on this path, and some different traffic ready for any other path.
 */

typedef enum {
    picoquic_datagram_not_active = 0,
    picoquic_datagram_active_any_path = 1,
    picoquic_datagram_active_this_path_only = 2,
    picoquic_datagram_active_this_path_and_others = 3
} picoquic_datagram_active_enum;

uint8_t* picoquic_provide_datagram_buffer(void* context, size_t length);
uint8_t* picoquic_provide_datagram_buffer_ex(void* context, size_t length, picoquic_datagram_active_enum is_active);

/* 
 * Set the optimistic ack policy. This is a security feature that prevents
 * peer from "faking" acknowledgements of packets that they have not
 * received by inserting "holes" in the sequence of packet numbers.
 * Acknowledging a hole is a protocol error, resulting in connection
 * closure.
 * 
 * The holes are inserted at random, based on
 * a period that doubles after each hole insertion in a given number space.
 * By default, the initial period is 256. Setting it to 0 suppresses further
 * hole insertion.
 */
void picoquic_set_optimistic_ack_policy(picoquic_quic_t* quic, uint32_t sequence_hole_pseudo_period);

/* Enable or disable the preemptive repeat function
 */
void picoquic_set_preemptive_repeat_policy(picoquic_quic_t* quic, int do_repeat);
void picoquic_set_preemptive_repeat_per_cnx(picoquic_cnx_t* cnx, int do_repeat);

/* Enables keep alive for a connection.
 * Keep alive interval is expressed in microseconds.
 * If `interval` is `0`, it is set to `idle_timeout / 2`.
 */
void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval);
/* Disables keep alive for a connection. */
void picoquic_disable_keep_alive(picoquic_cnx_t* cnx);

/* Returns if the given connection is the client. */
int picoquic_is_client(picoquic_cnx_t* cnx);

/* Returns the local error of the given connection context. */
uint64_t picoquic_get_local_error(picoquic_cnx_t* cnx);

/* Returns the remote error of the given connection context. */
uint64_t picoquic_get_remote_error(picoquic_cnx_t* cnx);

/* Returns the application error after application close */
uint64_t picoquic_get_application_error(picoquic_cnx_t* cnx);

/* Returns the remote error for the given stream. */
uint64_t picoquic_get_remote_stream_error(picoquic_cnx_t* cnx, uint64_t stream_id);


uint64_t picoquic_get_data_sent(picoquic_cnx_t * cnx);

uint64_t picoquic_get_data_received(picoquic_cnx_t * cnx);

int picoquic_cnx_is_still_logging(picoquic_cnx_t* cnx);

/* Congestion algorithm definition */

typedef enum {
    picoquic_congestion_notification_acknowledgement,
    picoquic_congestion_notification_repeat,
    picoquic_congestion_notification_timeout,
    picoquic_congestion_notification_spurious_repeat,
    picoquic_congestion_notification_rtt_measurement,
    picoquic_congestion_notification_ecn_ec,
    picoquic_congestion_notification_cwin_blocked,
    picoquic_congestion_notification_seed_cwin,
    picoquic_congestion_notification_reset,
    picoquic_congestion_notification_lost_feedback /* notification of lost feedback */
} picoquic_congestion_notification_t;

typedef struct st_picoquic_per_ack_state_t {
    uint64_t rtt_measurement; /* RTT as measured when receiving the ACK */
    uint64_t one_way_delay; /* One way delay when receiving the ACK, 0 if unknown */
    uint64_t nb_bytes_acknowledged; /* Number of bytes acknowledged by this ACK */
    uint64_t nb_bytes_newly_lost; /* Number of bytes in packets found lost because of this ACK */
    uint64_t nb_bytes_lost_since_packet_sent; /* Number of bytes lost between the time the packet was sent and now */
    uint64_t nb_bytes_delivered_since_packet_sent; /* Number of bytes acked between the time the packet was sent and now */
    uint64_t inflight_prior;
    uint64_t lost_packet_number;
    uint64_t lost_packet_sent_time;
    unsigned int is_app_limited : 1; /* App marked limited at time of ACK? */
    unsigned int is_cwnd_limited: 1; /* path marked CWIN limited after packet was sent. */
} picoquic_per_ack_state_t;

typedef void (*picoquic_congestion_algorithm_init)(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time);
typedef void (*picoquic_congestion_algorithm_notify)(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time);
typedef void (*picoquic_congestion_algorithm_delete)(picoquic_path_t* cnx);
typedef void (*picoquic_congestion_algorithm_observe)(
    picoquic_path_t* path_x, uint64_t * cc_state, uint64_t * cc_param);

typedef struct st_picoquic_congestion_algorithm_t {
    char const * congestion_algorithm_id;
    uint8_t congestion_algorithm_number;
    picoquic_congestion_algorithm_init alg_init;
    picoquic_congestion_algorithm_notify alg_notify;
    picoquic_congestion_algorithm_delete alg_delete;
    picoquic_congestion_algorithm_observe alg_observe;
} picoquic_congestion_algorithm_t;

extern picoquic_congestion_algorithm_t* picoquic_newreno_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_cubic_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_dcubic_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_fastcc_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_bbr_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_prague_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_bbr1_algorithm;

#define PICOQUIC_DEFAULT_CONGESTION_ALGORITHM picoquic_newreno_algorithm;

picoquic_congestion_algorithm_t const* picoquic_get_congestion_algorithm(char const* alg_name);

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* algo);

void picoquic_set_default_congestion_algorithm_by_name(picoquic_quic_t* quic, char const* alg_name);

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* algo);

/* Special code for Wi-Fi network. These networks are subject to occasional
 * "suspension", for power saving reasons. If the suspension is too long,
 * it causes transmission to stop after cngestion control credits are
 * exhausted. We expect that the effects of suspension are not so bad if
 * the congestion control parameters allow for transmission through the
 * suspension. The "wifi shadow RTT" parameter tells the congestion control
 * algorithm BBR to set the CWIN large enough to sustain transmission through
 * that duration. The value is in microseconds.
 * 
 * This parameter should be set before the first connections are started.
 * Changing the settings will not affect existing connections.
 */
void picoquic_set_default_wifi_shadow_rtt(picoquic_quic_t* quic, uint64_t wifi_shadow_rtt);

/* The experimental API `picoquic_set_default_bbr_quantum_ratio`
* allows application to change the "quantum ratio" parameter of the BBR
* algorithm. The default value is 0.001 (1/1000th of the pacing rate
* in bytes per second). Larger values like 0.01 would increase the
* size of the "leaky bucket" used by the pacing algorithms. Whether
* that's a good idea or not is debatable, probably depends on the
* application.
*/
void picoquic_set_default_bbr_quantum_ratio(picoquic_quic_t* quic, double quantum_ratio);

/* Temporary code, do define a set of BBR flags that
* turn on and off individual extensions. We want to use that
* to do "before/after" measurements.
 */
#define BBRExperiment on
#ifdef BBRExperiment
/* Control flags for BBR improvements */
typedef struct st_bbr_exp {
    unsigned int do_early_exit : 1;
    unsigned int do_rapid_start : 1;
    unsigned int do_handle_suspension : 1;
    unsigned int do_control_lost : 1;
    unsigned int do_exit_probeBW_up_on_delay : 1;
    unsigned int do_enter_probeBW_after_limited : 1;
} bbr_exp;

void picoquic_set_bbr_exp(picoquic_quic_t * quic, bbr_exp* exp);
#endif
/* The experimental API 'picoquic_set_priority_limit_for_bypass' 
* instruct the stack to send the high priority streams or datagrams
* immediately, even if congestion control would normally prevent it.
* 
* The "priority_limit" parameter indicates the lowest priority that will
* not be bypassed. For example, if the priority limit is set to 3, streams
* or datagrams with priority 0, 1 or 2 will be sent without waiting for
* congestion control credits, but streams will priority 3 or more will
* not. By default, the limit is set to 0, meaning no stream or datagram
* will bypass congestion control.
* 
* This experimental feature will not be activated in a multipath
* environment, i.e., if more that 1 path is activated.
* 
* To protect against potential abuse, the code includes a rate limiter,
* ensuring that if congestion control is blocking transmission, 
* the "bypass" will not result in more than 1 Mbps of
* traffic.
 */
void picoquic_set_priority_limit_for_bypass(picoquic_cnx_t* cnx, uint8_t priority_limit);

/* The experimental API `picoquic_set_feedback_loss_notification` allow applications
* to turn on the "feedback lost" event notification. These events are
* passed to the congestion control algorithm, allowing it to react
* quickly to a temporary loss of connectivity, instead of waiting
* for retransmission timers. Delay sensitive applications use this
* feature to stop queuing more data when connectivity is lost,
* and thus avoid the queues of less urgent data to delay
* arrival of urgent real time frames when connectivity is restored.
* On the other hand, this feature may lower the performance of
* applications sending lots of data, and thus should only be
* used when applications require it.
* 
* The lost control events fires if there is more that 2 "ack delay max" between
* the last ACK received and the next one. In practice, that means 1 RTT + 2 ack delays
* after the first non acked packet was sent. In contrast, the RTO fires
* 1 RTT + 4 STDEV + 1 ack delay after the last packet was sent. Given congestion
* control and CWIN, this "last packet" is typically sent 1 RTT after the "first
* packet not acknowledged". Thus, the "lost control" event will typically
* happen 1 RTT before the RTO event.
* 
* The `should_notify` should be set 1 to enable the feature, or to 0
* to stop notifications. It is set by default to zero when a connection
* is created.
*/
void picoquic_set_feedback_loss_notification(picoquic_cnx_t* cnx, unsigned int should_notify);

/* The experimental API `picoquic_request_forced_probe_up` direct the 
 * stack to send filler traffic when the congestion control algorithm is 
 * "probing for bandwidth". This is intended for "real time" applications
 * that often send less traffic that congestion control will allow, and
 * may suffer from an insufficient estimate of the path capacity.
 * Forcing more traffic will remedy that. 
 * 
 * When more traffic is requested, there is a risk of filling buffers and
 * creating packet losses. The stack will try to alleviate that risk
 * by building traffic with redundant copies of unacknowledged packets.
 */
void picoquic_request_forced_probe_up(picoquic_cnx_t* cnx, unsigned int request_forced_probe_up);
/* Bandwidth update and congestion control parameters value.
 * Congestion control in picoquic is characterized by three values:
 * - pacing rate, expressed in bytes per second (for example, 10Mbps would be noted as 1250000)
 * - congestion window, expressed in bytes
 * - RTT, expressed in microseconds
 * 
 * If an application subscribes to pacing rate updates, it will start receiving callback events
 * of type "picoquic_callback_pacing_changed". The subscription to the updates specifies
 * two levels:
 * - decrease threshold, in bytes per second
 * - increase threshold, in bytes per second
 * An event will be generated each time the bandwidth increases or decreases by a value
 * larger than the specified threshold. The "stream_id" parameter of the callback will 
 * indicate the new pacing rate, in bytes per second.
 *
 * By default, the threshold values are set to UINT64_MAX, and no event is generated.
 * 
 * Applications may also use a set of accessor functions to obtain the current values
 * of the key congestion control parameters, for the currently selected transmission
 * path.
 */

void picoquic_subscribe_pacing_rate_updates(picoquic_cnx_t* cnx, uint64_t decrease_threshold, uint64_t increase_threshold);
uint64_t picoquic_get_pacing_rate(picoquic_cnx_t* cnx);
uint64_t picoquic_get_cwin(picoquic_cnx_t* cnx);
uint64_t picoquic_get_rtt(picoquic_cnx_t* cnx);

/* Connection context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id_(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id);

/* List of ALPN types used in session negotiation */

typedef enum {
    picoquic_alpn_undef = 0,
    picoquic_alpn_http_0_9,
    picoquic_alpn_http_3,
    picoquic_alpn_quicperf
} picoquic_alpn_enum;

typedef struct st_picoquic_alpn_list_t {
    picoquic_alpn_enum alpn_code;
    char const* alpn_val;
    size_t len;
} picoquic_alpn_list_t;

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_H */
