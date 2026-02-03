/*
 ============================================================================
 Name        : hev-socks5-logger.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 hev
 Description : Socks5 Logger
 ============================================================================
 */

#ifndef __HEV_SOCKS5_LOGGER_H__
#define __HEV_SOCKS5_LOGGER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _HevSocks5LoggerLevel HevSocks5LoggerLevel;

enum _HevSocks5LoggerLevel
{
    HEV_SOCKS5_LOGGER_DEBUG,
    HEV_SOCKS5_LOGGER_INFO,
    HEV_SOCKS5_LOGGER_WARN,
    HEV_SOCKS5_LOGGER_ERROR,
    HEV_SOCKS5_LOGGER_UNSET,
};

int hev_socks5_logger_init (HevSocks5LoggerLevel level, const char *path);
void hev_socks5_logger_fini (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_LOGGER_H__ */
