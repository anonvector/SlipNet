/*
 ============================================================================
 Name        : hev-socks5-udp.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 UDP
 ============================================================================
 */

#ifndef __HEV_SOCKS5_UDP_H__
#define __HEV_SOCKS5_UDP_H__

#include "hev-socks5-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_SOCKS5_UDP(p) ((HevSocks5UDP *)p)
#define HEV_SOCKS5_UDP_IFACE(p) ((HevSocks5UDPIface *)p)
#define HEV_SOCKS5_UDP_TYPE (hev_socks5_udp_iface ())

typedef void HevSocks5UDP;
typedef struct _HevSocks5UDPMsg HevSocks5UDPMsg;
typedef struct _HevSocks5UDPIface HevSocks5UDPIface;

struct _HevSocks5UDPMsg
{
    HevSocks5Addr *addr;
    void *buf;
    size_t len;
};

struct _HevSocks5UDPIface
{
    int (*get_fd) (HevSocks5UDP *self);
    int (*splicer) (HevSocks5UDP *self, int fd);
};

void *hev_socks5_udp_iface (void);

int hev_socks5_udp_get_fd (HevSocks5UDP *self);

int hev_socks5_udp_sendmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num);
int hev_socks5_udp_recvmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num, int nonblock);

int hev_socks5_udp_splice (HevSocks5UDP *self, int fd);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_UDP_H__ */
