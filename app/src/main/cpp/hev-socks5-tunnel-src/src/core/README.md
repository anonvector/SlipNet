# HevSocks5Core

HevSocks5Core is a simple, lightweight socks5 library.

**Features**
* IPv4/IPv6. (dual stack)
* Standard `CONNECT` command.
* Standard `UDP ASSOCIATE` command.
* Extended `FWD UDP` command. (UDP in TCP)
* Multiple username/password authentication.

**Dependencies**
* HevTaskSystem - https://github.com/heiher/hev-task-system

## Examples

### Server

```c
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-dns.h>
#include <hev-task-system.h>

#include <hev-socks5-server.h>

static void
server_entry (void *data)
{
    HevSocks5Server *server = data;
    hev_socks5_server_run (server);
    hev_object_unref (HEV_OBJECT (server));
}

static void
listener_entry (void *data)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result;
    int fd;

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    hev_task_dns_getaddrinfo (NULL, "1080", &hints, &result);
    fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, 0);
    bind (fd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo (result);
    listen (fd, 5);

    hev_task_add_fd (hev_task_self (), fd, POLLIN);

    for (;;) {
        HevSocks5Server *server;
        HevTask *task;
        int nfd;

        nfd = hev_task_io_socket_accept (fd, NULL, NULL, NULL, NULL);

        task = hev_task_new (-1);
        server = hev_socks5_server_new (nfd);
        hev_task_run (task, server_entry, server);
    }

    close (fd);
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    hev_task_system_init ();

    task = hev_task_new (-1);
    hev_task_run (task, listener_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
```

### Client

```c
#include <stddef.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-socks5-client-tcp.h>
#include <hev-socks5-client-udp.h>

static void
tcp_client_entry (void *data)
{
    HevSocks5ClientTCP *tcp;

    tcp = hev_socks5_client_tcp_new_name ("www.google.com", 443);
    hev_socks5_client_connect (HEV_SOCKS5_CLIENT (tcp), "127.0.0.1", 1080);
    hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (tcp));

    /*
     * splice data to/from a socket fd:
     *     hev_socks5_tcp_splice (HEV_SOCKS5_TCP (tcp), fd);
     */

    hev_object_unref (HEV_OBJECT (tcp));
}

static void
udp_client_entry (void *data)
{
    HevSocks5ClientUDP *udp;

    udp = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    hev_socks5_client_connect (HEV_SOCKS5_CLIENT (udp), "127.0.0.1", 1080);
    hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (udp));

    /*
     * HevSocks5UDPMsg msgv[num];
     *
     * send udp packets:
     *     hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (udp), msgv, num);
     *
     * recv udp packets:
     *     hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (udp), msgv, num, 0);
     */

    hev_object_unref (HEV_OBJECT (udp));
}

int
main (int argc, char *argv[])
{
    HevTask *task;

    hev_task_system_init ();

    task = hev_task_new (-1);
    hev_task_run (task, tcp_client_entry, NULL);

    task = hev_task_new (-1);
    hev_task_run (task, udp_client_entry, NULL);

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
```

## UDP in TCP

UDP-in-TCP mode is a proprietary extension based on RFC 1928, designed to
forward UDP packets within the primary SOCKS5 TCP stream. The protocol is
defined as follows:

### SOCKS5 Requests

```
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
```

* CMD
    * UDP IN TCP: X'05'

### UDP Relays

```
    +--------+--------+------+----------+----------+----------+
    | MSGLEN | HDRLEN | ATYP | DST.ADDR | DST.PORT |   DATA   |
    +--------+--------+------+----------+----------+----------+
    |   2    |   1    |  1   | Variable |    2     | Variable |
    +--------+--------+------+----------+----------+----------+
```

- MSGLEN: The total length of the UDP relay message. `[MSGLEN, DATA]`
- HDRLEN: The header length of the UDP relay message. `[MSGLEN, DST.PORT]`
- ATYPE/DST.ADDR/DST.PORT: Fields follow the definitions specified in RFC 1928.

## Users

* **HevSocks5Server** - https://github.com/heiher/hev-socks5-server
* **HevSocks5TProxy** - https://github.com/heiher/hev-socks5-tproxy
* **HevSocks5Tunnel** - https://github.com/heiher/hev-socks5-tunnel

## Contributors
* **hev** - https://hev.cc
* **spider84** - https://github.com/spider84

## License
MIT
