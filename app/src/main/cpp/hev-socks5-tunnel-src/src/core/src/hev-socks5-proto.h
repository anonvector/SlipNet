/*
 ============================================================================
 Name        : hev-socks5-proto.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2023 hev
 Description : Socks5 Proto
 ============================================================================
 */

#ifndef __HEV_SOCKS5_PROTO_H__
#define __HEV_SOCKS5_PROTO_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _HevSocks5Version HevSocks5Version;
typedef enum _HevSocks5AuthMethod HevSocks5AuthMethod;
typedef enum _HevSocks5AuthVersion HevSocks5AuthVersion;
typedef enum _HevSocks5ReqCmd HevSocks5ReqCmd;
typedef enum _HevSocks5ResRep HevSocks5ResRep;
typedef enum _HevSocks5AddrType HevSocks5AddrType;

typedef struct _HevSocks5Auth HevSocks5Auth;
typedef struct _HevSocks5Addr HevSocks5Addr;
typedef struct _HevSocks5ReqRes HevSocks5ReqRes;
typedef struct _HevSocks5UDPHdr HevSocks5UDPHdr;

enum _HevSocks5Version
{
    HEV_SOCKS5_VERSION_5 = 5,
};

enum _HevSocks5AuthMethod
{
    HEV_SOCKS5_AUTH_METHOD_NONE = 0,
    HEV_SOCKS5_AUTH_METHOD_USER = 2,
    HEV_SOCKS5_AUTH_METHOD_DENY = 255,
};

enum _HevSocks5AuthVersion
{
    HEV_SOCKS5_AUTH_VERSION_1 = 1,
};

enum _HevSocks5ReqCmd
{
    HEV_SOCKS5_REQ_CMD_CONNECT = 1,
    HEV_SOCKS5_REQ_CMD_UDP_ASC = 3,
    HEV_SOCKS5_REQ_CMD_FWD_UDP = 5,
};

enum _HevSocks5ResRep
{
    HEV_SOCKS5_RES_REP_SUCC = 0,
    HEV_SOCKS5_RES_REP_FAIL = 1,
    HEV_SOCKS5_RES_REP_HOST = 4,
    HEV_SOCKS5_RES_REP_IMPL = 7,
    HEV_SOCKS5_RES_REP_ADDR = 8,
};

enum _HevSocks5AddrType
{
    HEV_SOCKS5_ADDR_TYPE_IPV4 = 1,
    HEV_SOCKS5_ADDR_TYPE_IPV6 = 4,
    HEV_SOCKS5_ADDR_TYPE_NAME = 3,
};

struct _HevSocks5Auth
{
    uint8_t ver;
    union
    {
        uint8_t method;
        uint8_t method_len;
    };
    uint8_t methods[256];
} __attribute__ ((packed));

struct _HevSocks5Addr
{
    uint8_t atype;
    union
    {
        struct
        {
            uint8_t addr[4];
            uint16_t port;
        } ipv4 __attribute__ ((packed));
        struct
        {
            uint8_t addr[16];
            uint16_t port;
        } ipv6 __attribute__ ((packed));
        struct
        {
            uint8_t len;
            uint8_t addr[256 + 2];
        } domain;
    };
} __attribute__ ((packed));

struct _HevSocks5ReqRes
{
    uint8_t ver;
    union
    {
        uint8_t cmd;
        uint8_t rep;
    };
    uint8_t rsv;
    HevSocks5Addr addr;
} __attribute__ ((packed));

struct _HevSocks5UDPHdr
{
    union
    {
        uint8_t rsv[3];
        struct
        {
            uint16_t datlen;
            uint8_t hdrlen;
        } __attribute__ ((packed));
    };
    HevSocks5Addr addr;
} __attribute__ ((packed));

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_PROTO_H__ */
