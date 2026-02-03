/*
 ============================================================================
 Name        : hev-socks5-misc-priv.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 Misc Private
 ============================================================================
 */

#ifndef __HEV_SOCKS5_MISC_PRIV_H__
#define __HEV_SOCKS5_MISC_PRIV_H__

#include <netinet/in.h>

#include <hev-task.h>
#include <hev-task-io.h>

#include "hev-socks5-misc.h"
#include "hev-socks5-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

int hev_socks5_socket (int type);

const char *hev_socks5_addr_into_str (const HevSocks5Addr *addr, char *buf,
                                      int len);

int hev_socks5_get_connect_timeout (void);
int hev_socks5_get_tcp_timeout (void);
int hev_socks5_get_udp_timeout (void);

int hev_socks5_get_task_stack_size (void);
int hev_socks5_get_udp_copy_buffer_nums (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_MISC_PRIV_H__ */
