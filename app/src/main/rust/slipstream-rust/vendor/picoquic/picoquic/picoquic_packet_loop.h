/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#ifndef PICOQUIC_PACKET_LOOP_H
#define PICOQUIC_PACKET_LOOP_H

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_PACKET_LOOP_SOCKETS_MAX 4
#define PICOQUIC_PACKET_LOOP_RECV_MAX 10
#define PICOQUIC_PACKET_LOOP_SEND_MAX 10
#define PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX 2500

typedef struct st_picoquic_socket_ctx_t {
    SOCKET_TYPE fd;
    int af;
    uint16_t port;

    /* Flags */
    unsigned int is_started : 1;
    unsigned int supports_udp_send_coalesced : 1;
    unsigned int supports_udp_recv_coalesced : 1;
    /* Receive data buffer and fields */
    size_t recv_buffer_size;
    uint8_t* recv_buffer;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    socklen_t from_length;
    socklen_t dest_length;
    int dest_if;
    unsigned char received_ecn;
    int bytes_recv;
    /* Management of sendmsg */
    char cmsg_buffer[1024];
    size_t udp_coalesced_size;
#ifdef _WINDOWS
    /* Windows specific */
    WSAOVERLAPPED overlap;
    LPFN_WSARECVMSG WSARecvMsg;
    LPFN_WSASENDMSG WSASendMsg;
    WSABUF dataBuf;
    WSAMSG msg;
    int nb_immediate_receive;
    int so_sndbuf;
    int so_rcvbuf;
#endif
} picoquic_socket_ctx_t;

/* The packet loop will call the application back after specific events.
 */
typedef enum {
    picoquic_packet_loop_ready = 0, /* Argument type: packet loop options */
    picoquic_packet_loop_before_select, /* Argument type size_t*: nb packets received */
    picoquic_packet_loop_after_receive, /* Argument type size_t*: nb packets received */
    picoquic_packet_loop_after_send, /* Argument type size_t*: nb packets sent */
    picoquic_packet_loop_port_update, /* argument type struct_sockaddr*: new address for wakeup */
    picoquic_packet_loop_time_check, /* argument type packet_loop_time_check_arg_t*. Optional. */
    picoquic_packet_loop_system_call_duration, /* argument type packet_loop_system_call_duration_t*. Optional. */
    picoquic_packet_loop_wake_up, /* no argument (void* NULL). Used when loop wakeup is supported */
    picoquic_packet_loop_alt_port /* Provide alt port for testing multipath or migration */
} picoquic_packet_loop_cb_enum;

/* System call statistics.
* The socket loop uses 'zero delay' calls to check whether
* more packets are ready to be received. In theory, these calls
* return immediately. But these are system calls, and the OS
* might decide to pause the process before returning from the
* call. If the application selects the "system call duration"
* option, it will receive callbacks when the call time varies
* significantly.
 */
typedef struct st_packet_loop_system_call_duration_t {
    uint64_t scd_last;
    uint64_t scd_max;
    uint64_t scd_smoothed;
    uint64_t scd_dev;
} packet_loop_system_call_duration_t;

/* The time check option passes as argument a pointer to a structure specifying
* the current time and the proposed delta. The application uses the specified
* current time to compute an updated delta.
*/
typedef struct st_packet_loop_time_check_arg_t {
    uint64_t current_time;
    int64_t delta_t;
} packet_loop_time_check_arg_t;

typedef int (*picoquic_packet_loop_cb_fn)(picoquic_quic_t * quic, picoquic_packet_loop_cb_enum cb_mode, void * callback_ctx, void * callback_argv);

/* Packet loop option list shows support by application of optional features.
 * It is set to null initially, and then passed to the socket as argument to
 * the "ready" callback. Application should set the flags corresponding to
 * the features that it supports */
typedef struct st_picoquic_packet_loop_options_t {
    unsigned int do_time_check : 1; /* App should be polled for next time before sock select */
    unsigned int do_system_call_duration : 1; /* App should be notified if the system call duration varies */
    unsigned int provide_alt_port : 1; /* Used for simulating multipath or migrations. */
} picoquic_packet_loop_options_t;

/* Version 2 of packet loop, works in progress.
* Parameters are set in a struct, for future
* extensibility.
 */
typedef struct st_picoquic_packet_loop_param_t {
    uint16_t local_port;
    int local_af;
    int dest_if;
    int socket_buffer_size;
    int do_not_use_gso;
    int extra_socket_required;
    int simulate_eio;
    size_t send_length_max;
    int is_client;
    ssize_t (*decode)(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage *peer_addr, struct sockaddr_storage *local_addr);
    ssize_t (*encode)(void* slot_p, void* callback_ctx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len, struct sockaddr_storage *peer_addr, struct sockaddr_storage *local_addr);
    int64_t delay_max;
} picoquic_packet_loop_param_t;

int picoquic_packet_loop_v2(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t * param,
    picoquic_packet_loop_cb_fn loop_callback,
    void * loop_callback_ctx);

void* picoquic_packet_loop_v3(void* v_ctx);
/* Threaded version of packet loop, when running picoquic in a background thread.
* 
* Thread is started by calling picoquic_start_network_thread, which
* returns an argument of type picoquic_network_thread_ctx_t. Returns a NULL
* pointer if the thread could not be created.
* 
* If the application needs to post new data or otherwise interact with
* the quic connections, it should call picoquic_wake_up_network_thread,
* passing the thread context as an argument. This with trigger a
* callback of type `picoquic_packet_loop_wake_up`, which executes
* in the context of the network thread. Picoquic APIs can be called
* in this context without worrying about concurrency issues.
* 
* If the application wants to close the network thread, it calls
* picoquic_close_network_thread, passing the thread context as an argument.
* The network thread context will be freed during that call.
*/
typedef int (*picoquic_custom_thread_create_fn)(void** thread_id, picoquic_thread_fn thread_fn, void* arg);
typedef void (*picoquic_custom_thread_setname_fn)(char const* thread_name);
typedef void (*picoquic_custom_thread_delete_fn)(void** thread_id);

typedef struct st_picoquic_network_thread_ctx_t {
    picoquic_quic_t* quic;
    picoquic_packet_loop_param_t* param;
    picoquic_packet_loop_cb_fn loop_callback;
    picoquic_custom_thread_delete_fn thread_delete_fn;
    picoquic_custom_thread_setname_fn thread_setname_fn;
    char const* thread_name;
    void* pthread; /* Can be cast to picoquic_thread_t, or custom type if using non native threads */
    void* loop_callback_ctx;
#ifdef _WINDOWS
    HANDLE wake_up_event;
#else
    int wake_up_pipe_fd[2];
#endif
    int is_threaded;
    int wake_up_defined;
    volatile int thread_is_ready;
    volatile int thread_should_close;
    volatile int thread_is_closed;
    int return_code;
} picoquic_network_thread_ctx_t;


int picoquic_packet_loop_select(picoquic_socket_ctx_t* s_ctx,
                                int nb_sockets,
                                struct sockaddr_storage* addr_from,
                                struct sockaddr_storage* addr_dest,
                                int* dest_if,
                                unsigned char* received_ecn,
                                uint8_t* buffer, int buffer_max,
                                int64_t delta_t,
                                int* is_wake_up_event,
                                picoquic_network_thread_ctx_t* thread_ctx,
                                int* socket_rank);


picoquic_network_thread_ctx_t* picoquic_start_network_thread(
    picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx,
    int * ret);

int picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx);
void picoquic_delete_network_thread(picoquic_network_thread_ctx_t* thread_ctx);

/* The function picoquic_start_network_thread creates a background thread using
* the "native" threading APIs, CreateThread in Windows or pthread_create in
* Unix/Posix systems. This will not work in some environments, if for example
* the threads should be created using a game engine API. In such cases,
* developers may use the function picoquic_start_custom_network_thread,
* passing the desired thread creation function, thread deletion function
* and thread naming function as a function pointer. The thread naming
* function will be called from inside the network thread after it is
* created, as this is required in some OSes. The thread deletion
* function will be called when the thread is delete, from inside
* the thread context destruction function.
* 
* The custom thread creation function must match the prototype 
* picoquic_custom_thread_create_fn, with the following arguments:
* 
* - void** pthread: a pointer to the thread (thread HANDLE in Windows,
*   pthread_t if using pthread),
* - picoquic_thread_fn thread_fn: the function that will be instantiated when creating the thread.
* - void* arg: the argument to thread_fn.
* 
* The return code is an integer, either 0 if success or an error code if failure.
* 
* The custom thread deletion function must match the prototype 
* picoquic_custom_thread_delete_fn, with the following arguments:
* 
* - void** pthread: a pointer to the thread, carrying the value returned
*   in pthread by the custom creation function.
* 
* The custom thread naming function must match the prototype 
* picoquic_custom_thread_delete_fn, with the following arguments:
* 
* - char const * thread_name: the desired thread name. Should be less
*   than 16 characters, including the final null terminator.
* 
* The function picoquic_start_custom_network_thread takes the following
* arguments:
* 
* - picoquic_quic_t* quic: the quic context, configured by the application
*   before starting the network thread.
* - picoquic_packet_loop_param_t* param: the loop creation parameters,
* - picoquic_custom_thread_create_fn thread_create_fn: the thread creation
*   function. If the value is NULL, the OS defaults will be used.
* - picoquic_custom_thread_create_fn thread_delete_fn: the thread
*   deletion function. If the value is NULL, the OS defaults will be used.
* - char const* thread_name: the desired thread name, or NULL if the
*   default value is sufficient.
* - picoquic_packet_loop_cb_fn loop_callback: the function that will
*   be called upon packet loop events.
* - void* loop_callback_ctx: the arguments to loop callback.
* - int * ret: error code, if any.
* 
* The function will return a pointer to the thread context, or NULL
* if an error happened.
* 
* Note that these functions set the name of the thread but do attempt to set
* the priority of the thread. Setting the name during the creation makes sense,
* as the name will typically not change during the process. It is also
* reasonably easy to set the name in a system independent way. In contrast,
* the handling of priority is system dependent, with Windows and Unix using
* different concepts, and there may be good reasons to change a thread priority
* after creation. Developers can use the system or framework APIs after the
* thread is created, using the thread handle in thread_ctx->pthread.
*/

picoquic_network_thread_ctx_t* picoquic_start_custom_network_thread(
    picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_custom_thread_create_fn thread_create_fn,
    picoquic_custom_thread_delete_fn thread_delete_fn,
    picoquic_custom_thread_setname_fn thread_setname_fn, 
    char const* thread_name,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx,
    int * ret);

void picoquic_open_network_wake_up(picoquic_network_thread_ctx_t* thread_ctx, int *ret);

/* Implementations of picoquic_custom_thread_create_fn and 
* picoquic_custom_thread_delete_fn for the native thread types.
* These functions are used in calls to picoquic_start_custom_network_thread
* when the create and delete function pointers are NULL.
* They are also used in the test library to test the use of
* function pointers in the thread creation function.
 */
int picoquic_internal_thread_create(void** pthread,
    picoquic_thread_fn thread_fn, void* thread_arg);
void picoquic_internal_thread_delete(void** pthread);
void picoquic_internal_thread_setname(char const * thread_name);

/* Legacy versions the packet loop, one portable and one specialized
 * for winsock. Keeping these API for compatibility, but the implementation
 * redirects to picoquic_packet_loop_v2.
 */
int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    int do_not_use_gso,
    picoquic_packet_loop_cb_fn loop_callback,
    void * loop_callback_ctx);

#ifdef _WINDOWS
int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx);
#endif

/* Following declarations are used for unit tests. */
void picoquic_packet_loop_close_socket(picoquic_socket_ctx_t* s_ctx);
int picoquic_packet_loop_open_sockets(uint16_t local_port, int local_af, int socket_buffer_size, int extra_socket_required,
    int do_not_use_gso, picoquic_socket_ctx_t* s_ctx);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_PACKET_LOOP_H */

