/*
 ============================================================================
 Name        : hev-socks5.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2023 hev
 Description : Socks5
 ============================================================================
 */

#ifndef __HEV_SOCKS5_H__
#define __HEV_SOCKS5_H__

#include <netinet/in.h>
#include <sys/socket.h>

#include <hev-object.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_SOCKS5(p) ((HevSocks5 *)p)
#define HEV_SOCKS5_CLASS(p) ((HevSocks5Class *)p)
#define HEV_SOCKS5_TYPE (hev_socks5_class ())

typedef struct _HevSocks5 HevSocks5;
typedef struct _HevSocks5Class HevSocks5Class;
typedef enum _HevSocks5Type HevSocks5Type;
typedef enum _HevSocks5AddrFamily HevSocks5AddrFamily;

enum _HevSocks5Type
{
    HEV_SOCKS5_TYPE_NONE,
    HEV_SOCKS5_TYPE_TCP,
    HEV_SOCKS5_TYPE_UDP_IN_TCP,
    HEV_SOCKS5_TYPE_UDP_IN_UDP,
};

enum _HevSocks5AddrFamily
{
    HEV_SOCKS5_ADDR_FAMILY_IPV4 = AF_INET,
    HEV_SOCKS5_ADDR_FAMILY_IPV6 = AF_INET6,
    HEV_SOCKS5_ADDR_FAMILY_UNSPEC = AF_UNSPEC,
};

struct _HevSocks5
{
    HevObject base;

    int fd;
    int timeout;
    int udp_associated;
    HevSocks5Type type;
    HevSocks5AddrFamily addr_family;
};

struct _HevSocks5Class
{
    HevObjectClass base;

    int (*binder) (HevSocks5 *self, int sock, const struct sockaddr *dest);
};

HevObjectClass *hev_socks5_class (void);

int hev_socks5_construct (HevSocks5 *self, HevSocks5Type type);

int hev_socks5_get_timeout (HevSocks5 *self);
void hev_socks5_set_timeout (HevSocks5 *self, int timeout);

HevSocks5AddrFamily hev_socks5_get_addr_family (HevSocks5 *self);
void hev_socks5_set_addr_family (HevSocks5 *self, HevSocks5AddrFamily family);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_H__ */
