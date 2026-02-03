# LwIP

[![status](https://github.com/heiher/lwip/actions/workflows/build.yaml/badge.svg?branch=main&event=push)](https://github.com/heiher/lwip)

This is a branch of liblwip with a simple build system.

## Features

* UDP: Allow receiving packets are not destined to localhost.
* TCP: Allow accepting connections are not destined to localhost.

## Examples

### TCP

```c
static void
gateway_init(void)
{
    // Init netif
    netif_set_up (&netif);
    netif_set_link_up (&netif);
    netif_set_default (&netif);

    // Allow to pretend TCP on this netif
    netif_set_flags (&netif, NETIF_FLAG_PRETEND_TCP);

    tcp = tcp_new_ip_type (IPADDR_TYPE_ANY);

    // Bind TCP to netif first
    tcp_bind_netif (tcp, &netif);

    // Bind to accept incoming connections to other hosts
    tcp_bind (tcp, NULL, 0);

    tcp_listen (tcp);
    tcp_accept (tcp, tcp_accept_handler);
}

static err_t
tcp_accept_handler (void *arg, struct tcp_pcb *pcb, err_t err)
{
    // Accept new TCP connection
    // @pcb->local_ip: The real destination address
    // @pcb->local_port: The real destination port
    // @pcb->remote_ip: The real source address
    // @pcb->remote_port: The real source port
}
```

### UDP

```c
static void
gateway_init(void)
{
    // Init netif
    netif_set_up (&netif);
    netif_set_link_up (&netif);
    netif_set_default (&netif);

    // Allow to pretend UDP on this netif
    netif_set_flags (&netif, NETIF_FLAG_PRETEND_UDP);

    udp = udp_new_ip_type (IPADDR_TYPE_ANY);

    // Bind TCP to netif first
    udp_bind_netif (udp, &netif);

    // Bind to receive packets to other hosts
    udp_bind (udp, NULL, 0);

    udp_recv (udp, udp_accept_handler, NULL);
}

static void
udp_accept_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    // Similar to TCP accept, receive packets on new UDP PCB.
    // @pcb: An new UDP PCB for sending and receiving.
    // @p: Unused
    // @addr: Unused
    // @port: Unused
    udp_recv (pcb, udp_recv_handler, NULL);
}

static void
udp_recv_handler (void *arg, struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *addr, u16_t port)
{
    // Receive UDP packets

    // @pcb->local_ip: The real destination address
    // @pcb->local_port: The real destination port
    // @pcb->remote_ip: The real source address
    // @pcb->remote_port: The real source port
    // @addr: Unused
    // @port: Unused

    // Send with source address
    udp_sendfrom (pcb, p, real_src_ip, real_src_port);
    pbuf_free (p);
}
```

## How to Build

**Unix**:
```bash
git clone https://gitlab.com/hev/lwip
cd lwip
make
```

**Android**:
```bash
mkdir lwip
cd lwip
git clone https://gitlab.com/hev/lwip jni
ndk-build
```

**Windows**:
```bash
git clone https://gitlab.com/hev/lwip
cd lwip
make CROSS_PREFIX=x86_64-w64-mingw32-
```

## Upstream
https://savannah.nongnu.org/projects/lwip

[PROJECT_URL]: https://gitlab.com/hev/lwip/commits/main
[PIPELINE_STATUS]: https://gitlab.com/hev/lwip/badges/main/pipeline.svg
