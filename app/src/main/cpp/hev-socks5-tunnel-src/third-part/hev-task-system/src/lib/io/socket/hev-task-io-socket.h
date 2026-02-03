/*
 ============================================================================
 Name        : hev-task-io-socket.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Task socket I/O operations
 ============================================================================
 */

#ifndef __HEV_TASK_IO_SOCKET_H__
#define __HEV_TASK_IO_SOCKET_H__

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MSG_WAITFORONE
struct mmsghdr
{
    struct msghdr msg_hdr;
    unsigned int msg_len;
};
#endif

/**
 * hev_task_io_socket_socket:
 * @domain: the communications domain
 * @type: the type of socket
 * @protocol: a particular protocol to be used with the socket
 *
 * The socket function shall create an unbound socket in a communications
 * domain, and return a file descriptor that can be used in later function calls
 * that operate on sockets.
 *
 * Returns: the socket file descriptor.
 *
 * Since: 3.3.5
 */
int hev_task_io_socket_socket (int domain, int type, int protocol);

/**
 * hev_task_io_socket_socketpair:
 * @domain: the communications domain
 * @type: the type of socket
 * @protocol: a particular protocol to be used with the socket
 * @socket_vector: the file descriptors of the created socket pair
 *
 * The socketpair function shall create an unbound pair of connected sockets in
 * a specified @domain, of a specified @type, under the protocol optionally
 * specified by the @protocol augument.
 *
 * Returns: the status of create.
 *
 * Since: 3.3.5
 */
int hev_task_io_socket_socketpair (int domain, int type, int protocol,
                                   int socket_vector[2]);

/**
 * hev_task_io_socket_connect:
 * @fd: a file descriptor
 * @addr: socket address
 * @addr_len: socket address length
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The connect function shall attempt to make a connection on a connection-mode
 * socket or to set or reset the peer address of a connectionless-mode socket.
 *
 * Returns: the status of connect
 *
 * Since: 3.2
 */
int hev_task_io_socket_connect (int fd, const struct sockaddr *addr,
                                socklen_t addr_len, HevTaskIOYielder yielder,
                                void *yielder_data);

/**
 * hev_task_io_socket_accept:
 * @fd: a file descriptor
 * @addr: socket address
 * @addr_len: socket address length
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The accept function shall extract the first connection on the queue of
 * pending connections, create a new socket with the same socket type protocol
 * and address family as the specified socket, and allocate a new file
 * descriptor for that socket.
 *
 * Returns: the file descriptor of accepted socket
 *
 * Since: 3.2
 */
int hev_task_io_socket_accept (int fd, struct sockaddr *addr,
                               socklen_t *addr_len, HevTaskIOYielder yielder,
                               void *yielder_data);

/**
 * hev_task_io_socket_recv:
 * @fd: a file descriptor
 * @buf: buffer
 * @len: buffer length
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The recv function shall receive a message from a connection-mode or
 * connectionless-mode socket. It is normally used with connected sockets
 * because it does not permit the application to retrieve the source address of
 * received data.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_recv (int fd, void *buf, size_t len, int flags,
                                 HevTaskIOYielder yielder, void *yielder_data);

/**
 * hev_task_io_socket_send:
 * @fd: a file descriptor
 * @buf: buffer
 * @len: buffer length
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The send function shall initiate transmission of a message from the specified
 * socket to its peer. The send function shall send a message only when the
 * socket is connected. If the socket is a connectionless-mode socket, the
 * message shall be sent to the pre-specified peer address.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_send (int fd, const void *buf, size_t len, int flags,
                                 HevTaskIOYielder yielder, void *yielder_data);

/**
 * hev_task_io_socket_recvfrom:
 * @fd: a file descriptor
 * @buf: buffer
 * @len: buffer length
 * @flags: flags
 * @addr: socket address
 * @addr_len: socket address length
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The recvfrom function shall receive a message from a connection-mode or
 * connectionless-mode socket. It is normally used with connected sockets
 * because it does not permit the application to retrieve the source address of
 * received data.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_recvfrom (int fd, void *buf, size_t len, int flags,
                                     struct sockaddr *addr, socklen_t *addr_len,
                                     HevTaskIOYielder yielder,
                                     void *yielder_data);

/**
 * hev_task_io_socket_sendto:
 * @fd: a file descriptor
 * @buf: buffer
 * @len: buffer length
 * @flags: flags
 * @addr: socket address
 * @addr_len: socket address length
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The sendto function shall initiate transmission of a message from the
 * specified socket to its peer. The send function shall send a message only
 * when the socket is connected. If the socket is a connectionless-mode socket,
 * the message shall be sent to the pre-specified peer address.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_sendto (int fd, const void *buf, size_t len,
                                   int flags, const struct sockaddr *addr,
                                   socklen_t addr_len, HevTaskIOYielder yielder,
                                   void *yielder_data);

/**
 * hev_task_io_socket_recvmsg:
 * @fd: a file descriptor
 * @msg: message
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The recvmsg function shall receive a message from a connection-mode or
 * connectionless-mode socket. It is normally used with connected sockets
 * because it does not permit the application to retrieve the source address of
 * received data.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_recvmsg (int fd, struct msghdr *msg, int flags,
                                    HevTaskIOYielder yielder,
                                    void *yielder_data);

/**
 * hev_task_io_socket_sendmsg:
 * @fd: a file descriptor
 * @msg: message
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The sendmsg function shall initiate transmission of a message from the
 * specified socket to its peer. The send function shall send a message only
 * when the socket is connected. If the socket is a connectionless-mode socket,
 * the message shall be sent to the pre-specified peer address.
 *
 * Returns: the length of the message in bytes
 *
 * Since: 3.2
 */
ssize_t hev_task_io_socket_sendmsg (int fd, const struct msghdr *msg, int flags,
                                    HevTaskIOYielder yielder,
                                    void *yielder_data);

/**
 * hev_task_io_socket_recvmmsg:
 * @fd: a file descriptor
 * @msgv: an array of mmsghdr structures
 * @n: size of mmsghdr array
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The recvmmsg function that allows the caller to receive multiple messages
 * from a socket using a single system call.
 *
 * The recvmmsg is not supported for stream sockets.
 *
 * Returns: the number of messages received in msgv
 *
 * Since: 5.10
 */
int hev_task_io_socket_recvmmsg (int fd, void *msgv, unsigned int n, int flags,
                                 HevTaskIOYielder yielder, void *yielder_data);

/**
 * hev_task_io_socket_sendmmsg:
 * @fd: a file descriptor
 * @msgv: an array of mmsghdr structures
 * @n: size of mmsghdr array
 * @flags: flags
 * @yielder: a #HevTaskIOYielder
 * @yielder_data: user data
 *
 * The sendmmsg  that allows the caller to transmit multiple messages on a
 * socket using a single system call.
 *
 * The sendmmsg is not supported for stream sockets.
 *
 * Returns: the number of messages sent from msgv
 *
 * Since: 5.10
 */
int hev_task_io_socket_sendmmsg (int fd, void *msgv, unsigned int n, int flags,
                                 HevTaskIOYielder yielder, void *yielder_data);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_TASK_IO_SOCKET_H__ */
