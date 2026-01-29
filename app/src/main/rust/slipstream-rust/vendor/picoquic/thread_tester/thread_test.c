#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2def.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif
#else
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
/* #include "picoquic_packet_loop.h" */
/* #include "picoquic_unified_log.h" */

/* Thread context, passed as parameter when starting network thread */
#define NB_THREAD_TEST_MSG 100
#define NB_THREAD_TEST_EVENT 100
#define ERROR_THREAD_TEST_MESSAGE 1
#define ERROR_THREAD_TEST_DUPLICATE 2
typedef struct st_thread_test_context_t {
#ifdef _WINDOWS
    HANDLE network_thread;
    HANDLE network_event;
    HANDLE events[2];
    picoquic_recvmsg_async_ctx_t* recv_ctx;
#else
    int network_pipe_fd[2];
    SOCKET_TYPE n_socket;
    uint8_t buffer[2048];
    size_t buffer_max;
#endif
    int is_ready;
    volatile int should_stop;
    uint16_t server_port;
    struct sockaddr_storage network_thread_addr;
    int network_thread_addr_len;
    int msg_recv_count;
    uint64_t msg_sent_at[NB_THREAD_TEST_MSG];
    uint64_t msg_recv_at[NB_THREAD_TEST_MSG];
    uint64_t event_sent_at[NB_THREAD_TEST_EVENT];
    uint64_t event_recv_at[NB_THREAD_TEST_EVENT];
    int timeout_count;
    int event_wake_count;
    volatile int event_sent_count;
    int event_seen_count;
    int message_error;
    uint64_t message_number_error;
    uint64_t network_exit_time;
    volatile int message_loop_sent;
    int message_loop_error;
    uint64_t message_loop_error_index;
    uint64_t message_loop_exit_time;


} thread_test_context_t;

/* Wakeup function */
int network_wake_up(thread_test_context_t* ctx)
{
    int ret = 0;
#ifdef _WINDOWS
    if (SetEvent(ctx->network_event) == 0) {
        DWORD err = WSAGetLastError();
        DBG_PRINTF("Set network event fails, error 0x%x", err);
        ret = (int)err;
    }
#else
    /* TODO: write to network pipe */
    ssize_t written = 0;
    if ((written = write(ctx->network_pipe_fd[1], &ret, 1)) != 1) {
        if (written == 0) {
            ret = EPIPE;
        }
        else {
            ret = errno;
        }
    }
#endif
    return ret;
}

#ifdef _WINDOWS
int windows_events_init(thread_test_context_t* ctx)
{
    DWORD ret = 0;
    int server_af = ctx->network_thread_addr.ss_family;
    /* Create an asynchronous socket */
    ctx->recv_ctx = picoquic_create_async_socket(server_af, 0, 0);
    if (ctx->recv_ctx == NULL) {
        ret = GetLastError();
        DBG_PRINTF("Cannot create async socket in AF = %d, err = 0x%x", server_af, ret);
    }
    if (ret == 0) {
        /* Bind to specified port */
        ret = picoquic_bind_to_port(ctx->recv_ctx->fd, server_af, ctx->server_port);
        if (ret != 0) {
            DBG_PRINTF("Cannot bind socket to port %d, err = %d (0x%x)", ctx->server_port, ret, ret);
        }
    }
    if (ret == 0) {
        /* Create an event */
        ctx->network_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (ctx->network_event == NULL) {
            ret = GetLastError();
            DBG_PRINTF("Cannot create event, err = %d (0x%x)", ret, ret);
        }
        else {
            /* Set the event list */
            ctx->events[0] = ctx->network_event;
            ctx->events[1] = ctx->recv_ctx->overlap.hEvent;
        }
    }
    if (ret == 0) {
        /* Start receiving */
        ret = picoquic_recvmsg_async_start(ctx->recv_ctx);
        if (ret != 0) {
            DBG_PRINTF("Cannot start recv on socket, err = %d (0x%x)", ret, ret);
        }
    }
    return ret;
}

int windows_wait_multiple(thread_test_context_t* ctx, int * receive_ready)
{
    int ret = 0;
    int event_rank = -1;
    DWORD ret_event = WSAWaitForMultipleEvents(2, ctx->events, FALSE, 1000, TRUE);
    if (ret_event == WSA_WAIT_FAILED) {
        ret = WSAGetLastError();
        DBG_PRINTF("WSAWaitForMultipleEvents fails, error 0x%x", ret);
    }
    else if (ret_event == WSA_WAIT_TIMEOUT) {
        ctx->timeout_count++;
        *receive_ready = 1;
    }
    else if (ret_event >= WSA_WAIT_EVENT_0) {
        event_rank = ret_event - WSA_WAIT_EVENT_0;
        if (event_rank > 0) {
            ctx->msg_recv_count++;
            *receive_ready = 1;
        }
        else {
            /* Event number 0 is the wake signal */
            ctx->event_wake_count++;
            if (ResetEvent(ctx->network_event) == 0) {
                ret = GetLastError();
                DBG_PRINTF("Cannot reset network event, error 0x%x", ret);
            }
        }
    }
    return ret;
}

int windows_receive_async(thread_test_context_t* ctx, int* received_length, uint8_t** p_recv_buf)
{
    /* On windows, receive async */
    int ret = picoquic_recvmsg_async_finish(ctx->recv_ctx);
    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot finish async recv");
    }
    else if (ResetEvent(ctx->recv_ctx->overlap.hEvent) == 0) {
        ret = GetLastError();
        DBG_PRINTF("Cannot reset socket event, error 0x%x", ret);
    }
    else {
        *received_length = (int)ctx->recv_ctx->bytes_recv;
        *p_recv_buf = ctx->recv_ctx->recv_buffer;
    }
    return ret;
}

void windows_close_socket(thread_test_context_t* ctx)
{
    /* Close the socket */
    if (ctx->recv_ctx != NULL) {
        picoquic_delete_async_socket(ctx->recv_ctx);
        ctx->recv_ctx = NULL;
    }
    /* Close the event handle */
    if (ctx->network_event != NULL) {
        CloseHandle(ctx->network_event);
        ctx->network_event = NULL;
    }
}
#else
int unix_sockets_init(thread_test_context_t* ctx)
{
    int ret = 0;
    int server_af = ctx->network_thread_addr.ss_family;
    ctx->buffer_max = sizeof(ctx->buffer);
    ctx->n_socket = picoquic_open_client_socket(server_af);

    /* Bind to specified port */
    if (ret == 0) {
        /* Bind to specified port */
        ret = picoquic_bind_to_port(ctx->n_socket, server_af, ctx->server_port);
        if (ret != 0) {
            DBG_PRINTF("Cannot bind socket to port %d, err = %d (0x%x)", ctx->server_port, ret, ret);
        }
    }
    if (ret == 0) {
        /* Create the pipe for network wake up */
        ret = pipe(ctx->network_pipe_fd);
    }
    return ret;
}

int unix_select_multiple(thread_test_context_t* ctx, int * receive_ready)
{
    fd_set readfds;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;
    int ret = 0;

    FD_ZERO(&readfds);

    FD_SET(ctx->n_socket, &readfds);
    sockmax = ctx->n_socket;
    FD_SET(ctx->network_pipe_fd[0], &readfds);
    if (sockmax < ctx->network_pipe_fd[0]) {
        sockmax = ctx->network_pipe_fd[0];
    }
    ret_select = select(sockmax + 1, &readfds, NULL, NULL, NULL);

    if (ret_select < 0) {
        bytes_recv = -1;
        ret = -1;
        DBG_PRINTF("Error: select returns %d\n", ret_select);
    }
    else {
        if (FD_ISSET(ctx->n_socket, &readfds)) {
            *receive_ready = 1;
        }
        if (FD_ISSET(ctx->network_pipe_fd[0], &readfds)) {
            /* Something was written on the "wakeup" pipe. Read it. */
            uint8_t eventbuf[8];
            if ((bytes_recv = read(ctx->network_pipe_fd[0], eventbuf, sizeof(eventbuf))) <= 0) {
                if (bytes_recv == 0) {
                    ret = EPIPE;
                }
                else {
                    ret = errno;
                }
            }
            else {
                ctx->event_wake_count++;
            }
        }
    }
    return ret;
}

int picoquic_recvmsg(SOCKET_TYPE fd,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max);

int unix_receive_from_socket(thread_test_context_t* ctx, int* received_length, uint8_t** p_recv_buf)
{
    int ret = 0;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    int dest_if;
    unsigned char received_ecn;
    int bytes_recv;

    bytes_recv = picoquic_recvmsg(ctx->n_socket, &addr_from,
        &addr_dest, &dest_if, &received_ecn,
        ctx->buffer, ctx->buffer_max);

    if (bytes_recv <= 0) {
        ret = errno;
        DBG_PRINTF("Could not receive packet on UDP socket[%d]= 0%x!\n",
            (int)ctx->n_socket, ret);
    }
    else {
        *received_length = bytes_recv;
        *p_recv_buf = ctx->buffer;
    }
    return ret;
}

void unix_close_socket(thread_test_context_t* ctx)
{
    /* Close the socket */
    if (ctx->n_socket != INVALID_SOCKET) {
        (void)close(ctx->n_socket);
        ctx->n_socket = INVALID_SOCKET;
    }
    /* Close the pipe */
    for (int i = 0; i < 2; i++) {
        (void)close(ctx->network_pipe_fd[i]);
    }
}
#endif


/* Network thread */
#ifdef _WINDOWS
DWORD WINAPI network_thread(LPVOID lpParam)
#else
void* network_thread(void * lpParam)
#endif
{
    uint64_t current_time = 0;
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;
#ifdef _WINDOWS
    int ret = windows_events_init(ctx);
#else
    int ret = unix_sockets_init(ctx);
#endif
    if (ret == 0) {
        printf("Starting network thread, state=%x.\n", ret);
        ctx->is_ready = 1;
    }
    /* Loop on wait for socket or event */
    while (!ctx->should_stop && ret == 0) {
        int receive_ready = 0;
        uint64_t message_number = 0;
        uint8_t* recv_buf = NULL;
        /* wait for socket or event */
#ifdef _WINDOWS
        ret = windows_wait_multiple(ctx, &receive_ready);
#else
        ret = unix_select_multiple(ctx, &receive_ready);
#endif
        /* get time */
        current_time = picoquic_current_time();
        /* if event received */
        while (ctx->event_seen_count < ctx->event_sent_count) {
            ctx->event_recv_at[ctx->event_seen_count] = current_time;
            ctx->event_seen_count++;
        }
        /* if receive ready */
        if (receive_ready) {
            int received_length = 0;
#ifdef _WINDOWS
            /* On windows, receive async */
            ret = windows_receive_async(ctx, &received_length, &recv_buf);
#else
            /* receive message on unix */
            ret = unix_receive_from_socket(ctx, &received_length, &recv_buf);
#endif
            if (ret == 0) {
                if (received_length >= 8) {
                    /* Get the message number */
                    message_number = PICOPARSE_64(recv_buf);
                    if (message_number > NB_THREAD_TEST_MSG) {
                        DBG_PRINTF("Unexpected message number: %" PRIx64, message_number);
                        ctx->message_error = ERROR_THREAD_TEST_MESSAGE;
                        ctx->message_number_error = message_number;
                        break;
                    }
                    else if (ctx->msg_recv_at[message_number] != 0) {
                        DBG_PRINTF("Unexpected message number: %" PRIx64 ", first: %" PRIu64 ", then: %" PRIu64,
                            message_number, ctx->msg_recv_at[message_number], current_time);
                        ctx->message_error = ERROR_THREAD_TEST_DUPLICATE;
                        ctx->message_number_error = message_number;
                        break;
                    }
                    else {
                        ctx->msg_recv_at[message_number] = current_time;
                    }
                }
                else {
                    DBG_PRINTF("Message too sort, nb_bytes = %d", received_length);
                }
            }
#ifdef _WINDOWS
            if (ret == 0) {
                /* Start receiving */
                ret = picoquic_recvmsg_async_start(ctx->recv_ctx);
                if (ret != 0) {
                    DBG_PRINTF("Cannot start recv on socket, err = %d (0x%x)", ret, ret);
                }
            }
#endif
        }
    }
    ctx->network_exit_time = current_time;
    printf("Network thread exits.\n");
#ifdef _WINDOWS
    windows_close_socket(ctx);
    return (DWORD)ret;
#else
    unix_close_socket(ctx);
    pthread_exit((void*)&ret);
#endif
}

/* Network load thread -- socket only */
#ifdef _WINDOWS
#define SLEEP(x) Sleep(x)
DWORD WINAPI network_load_thread(LPVOID lpParam)
#else
#define SLEEP(x) usleep((x)*1000)
void* network_load_thread(void* lpParam)
#endif
{
    int ret = 0;
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;
    SOCKET_TYPE l_socket;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t current_time;
    int nb_sent = 0;

    printf("Starting load thread.\n");

    memset(buffer, 0, sizeof(buffer));
    /* Create a socket */
    if ((l_socket = socket(ctx->network_thread_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET)
    {
        DBG_PRINTF("Cannot set socket (af=%d)\n", ctx->network_thread_addr.ss_family);
    }
    /* Loop on send to socket */
    for (uint64_t i = 0; i < NB_THREAD_TEST_MSG && !ctx->should_stop && ret == 0; i++)
    {
        size_t bytes_sent = 0;
        /* Wait some amount of time */
        SLEEP(1 + ((int)(i%7))*3);
        current_time = picoquic_current_time();
        nb_sent++;
        /* send the message */
        picoformat_64(buffer, i);
        bytes_sent = (int)sendto(l_socket, buffer, 256,
            0, (struct sockaddr*)&ctx->network_thread_addr, ctx->network_thread_addr_len);
        if (bytes_sent != 256) {
            /* Error. Document and exit */
            int err_ret = 0;
#ifdef _WINDOWS
            err_ret = (int)WSAGetLastError();
#else
            err_ret = (int)errno;
#endif
            DBG_PRINTF("Network load loop returns %d (0x%x), %d (0x%x)", ret, ret, err_ret, err_ret);
            ctx->message_loop_error = ret;
            ctx->message_loop_error_index = i;
            break;
        }
        else {
            ctx->msg_sent_at[i] = current_time;
            ctx->message_loop_sent++;
        }
    }

    printf("load thread ends after %d loops (%d, 0x%x).\n", nb_sent,
        ctx->should_stop, ret);

    ctx->message_loop_exit_time = picoquic_current_time();
    /* Close the socket */
    if (l_socket != INVALID_SOCKET) {
        SOCKET_CLOSE(l_socket);
        l_socket = INVALID_SOCKET;
    }
    /* exit the thread */
#ifdef _WINDOWS
    return (DWORD)ret;
#else
    pthread_exit((void*)&ret);
#endif
}

#ifdef _WINDOWS
/* Event loop thread -- event only */
DWORD WINAPI event_loop_thread(LPVOID lpParam)
#else
void* event_loop_thread(void* lpParam)
#endif
{
    int ret = 0;
    thread_test_context_t* ctx = (thread_test_context_t*)lpParam;

    printf("Starting event thread.\n");

    for (int i = 0; i < NB_THREAD_TEST_EVENT && !ctx->should_stop && ret == 0; i++)
    {
        SLEEP(5);
        ctx->event_sent_at[i] = picoquic_current_time();
        ctx->event_sent_count++;
        if ((ret = network_wake_up(ctx)) != 0) {
            DBG_PRINTF("Network wake up returns 0x%x", ret);
            break;
        }
    }

    printf("End event thread after %d events.\n", ctx->event_sent_count);
#ifdef _WINDOWS
    return (DWORD)ret;
#else
    pthread_exit((void*)&ret);
#endif
}

int main(int argc, char** argv)
{
    int ret = 0;
    thread_test_context_t ctx;
    int is_name = 0;
    picoquic_thread_t t_net = (picoquic_thread_t)0;
    picoquic_thread_t t_load = (picoquic_thread_t)0;
    picoquic_thread_t t_wake = (picoquic_thread_t)0;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    printf("testing the thread execution\n");

    debug_set_stream(stdout);

    memset(&ctx, 0, sizeof(thread_test_context_t));
    ctx.server_port = 12345;
    ret = picoquic_get_server_address("::1", ctx.server_port,
        &ctx.network_thread_addr, &is_name);
    ctx.network_thread_addr_len = sizeof(struct sockaddr_in6);
    if (ret != 0) {
        DBG_PRINTF("Cannot get server address, ret = %d (0x%x)", ret, ret);
    }

    if (ret == 0) {
        printf("thread1: backgroud thread, listens to a socket and to interrupts.\n");
        ret = picoquic_create_thread(&t_net, network_thread, &ctx);
        if (ret != 0) {
            DBG_PRINTF("Cannot create network thread, ret= 0x%x", ret);
        }
        else {
            for (int i = 0; i < 2000 && !ctx.is_ready; i++) {
                SLEEP(1);
            }
            if (ctx.is_ready) {
                printf("Network thread is ready.\n");
            }
            else {
                printf("Network thread not started in time.\n");
            }
        }
    }

    if (ret == 0) {
        printf("thread2: backgroud thread, Wakes up the main thread at random intervals.\n");
        ret = picoquic_create_thread(&t_wake, event_loop_thread, &ctx);
        if (ret != 0) {
            DBG_PRINTF("Cannot create event loop thread, ret= 0x%x", ret);
        }
    }
    if (ret == 0) {
        printf("thread3: network thread, sends at random intervals.\n");
        ret = picoquic_create_thread(&t_load, network_load_thread, &ctx);
        if (ret != 0) {
            DBG_PRINTF("Cannot create network load thread, ret= 0x%x", ret);
        }
    }
    /* Wait first on the message load thread. */
    if (ret == 0) {
        printf("Waiting for network load thread.\n");
        ret = picoquic_wait_thread(t_load);
        if (ret != 0) {
            DBG_PRINTF("Cannot close load thread, ret= 0x%x", ret);
        }
        else {
            t_load = (picoquic_thread_t)0;
        }
    }
    /* Wait next on the message event thread. */
    if (ret == 0) {
        printf("Waiting for wake thread.\n");
        ret = picoquic_wait_thread(t_wake);
        if (ret != 0) {
            DBG_PRINTF("Cannot close wake thread, ret= 0x%x", ret);
        }
        else {
            t_wake = (picoquic_thread_t)0;
        }
    }
    printf("Load and wake thread are closed.\n");
    /* Wait explicitly for some time, to give the program a chance to receive data */
    SLEEP(100);
    /* Set the termination flag */
    ctx.should_stop = 1;
    /* Wait for the network thread */
    if (ret == 0) {
        printf("Waiting for net thread.\n");
        (void)network_wake_up(&ctx);
        ret = picoquic_wait_thread(t_net);
        if (ret != 0) {
            DBG_PRINTF("Cannot close wake thread, ret= 0x%x", ret);
        }
        else {
            t_net = (picoquic_thread_t)0;
        }
    }
    /* To do: statistics */
    if (ret == 0) {
        uint64_t event_delay_min = UINT64_MAX;
        uint64_t event_delay_max = 0;
        printf("Timeouts: %d\n", ctx.timeout_count);
        printf("Events sent: %d\n", ctx.event_sent_count);
        printf("Events wake: %d\n", ctx.event_wake_count);
        printf("Events received: %d\n", ctx.event_seen_count);
        if (ctx.event_seen_count == ctx.event_sent_count && ctx.event_seen_count > 0) {
            for (int i = 0; i < ctx.event_sent_count; i++) {
                uint64_t delay = ctx.event_recv_at[i] - ctx.event_sent_at[i];
                if (delay < event_delay_min) {
                    event_delay_min = delay;
                }
                if (delay > event_delay_max) {
                    event_delay_max = delay;
                }
            }
            printf("Events delay min: %" PRIu64 "us.\n", event_delay_min);
            printf("Events delay max: %" PRIu64 "us.\n", event_delay_max);
        }
    }

    if (ret == 0) {
        int msg_sent = 0;
        int msg_recv = 0;
        uint64_t msg_delay_min = UINT64_MAX;
        uint64_t msg_delay_max = 0;

        for (int i = 0; i < NB_THREAD_TEST_MSG; i++) {
            uint64_t delay;
            if (ctx.msg_sent_at[i] == 0) {
                continue;
            }
            msg_sent++;
            if (ctx.msg_recv_at[i] == 0) {
                continue;
            }
            msg_recv++;
            delay = ctx.msg_recv_at[i] - ctx.msg_sent_at[i];
            if (delay < msg_delay_min) {
                msg_delay_min = delay;
            }
            if (delay > msg_delay_max) {
                msg_delay_max = delay;
            }
        }

        printf("Messages sent: %d\n", msg_sent);
        printf("Messages received: %d\n", msg_recv);
        printf("Losses: %d\n", msg_sent - msg_recv);
        if (msg_recv > 0){
            printf("Message delay min: %" PRIu64 "us.\n", msg_delay_min);
            printf("Message delay max: %" PRIu64 "us.\n", msg_delay_max);
        }
    }

    /* To do: clean up */
    
    exit(ret);
}
