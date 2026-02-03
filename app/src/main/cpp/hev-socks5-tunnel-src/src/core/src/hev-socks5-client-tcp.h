/*
 ============================================================================
 Name        : hev-socks5-client-tcp.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Client TCP
 ============================================================================
 */

#ifndef __HEV_SOCKS5_CLIENT_TCP_H__
#define __HEV_SOCKS5_CLIENT_TCP_H__

#include "hev-socks5-tcp.h"
#include "hev-socks5-proto.h"

#include "hev-socks5-client.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_SOCKS5_CLIENT_TCP(p) ((HevSocks5ClientTCP *)p)
#define HEV_SOCKS5_CLIENT_TCP_CLASS(p) ((HevSocks5ClientTCPClass *)p)
#define HEV_SOCKS5_CLIENT_TCP_TYPE (hev_socks5_client_tcp_class ())

typedef struct _HevSocks5ClientTCP HevSocks5ClientTCP;
typedef struct _HevSocks5ClientTCPClass HevSocks5ClientTCPClass;

struct _HevSocks5ClientTCP
{
    HevSocks5Client base;

    HevSocks5Addr *addr;
};

struct _HevSocks5ClientTCPClass
{
    HevSocks5ClientClass base;

    HevSocks5TCPIface tcp;
};

HevObjectClass *hev_socks5_client_tcp_class (void);

int hev_socks5_client_tcp_construct (HevSocks5ClientTCP *self,
                                     const HevSocks5Addr *addr);

HevSocks5ClientTCP *hev_socks5_client_tcp_new_name (const char *name, int port);
HevSocks5ClientTCP *hev_socks5_client_tcp_new_ipv4 (const void *ipv4, int port);
HevSocks5ClientTCP *hev_socks5_client_tcp_new_ipv6 (const void *ipv6, int port);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_CLIENT_TCP_H__ */
