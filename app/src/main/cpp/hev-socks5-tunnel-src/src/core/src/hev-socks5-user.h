/*
 ============================================================================
 Name        : hev-socks5-user.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2023 hev
 Description : Socks5 User
 ============================================================================
 */

#ifndef __HEV_SOCKS5_USER_H__
#define __HEV_SOCKS5_USER_H__

#include <hev-object-atomic.h>

#include "hev-rbtree.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_SOCKS5_USER(p) ((HevSocks5User *)p)
#define HEV_SOCKS5_USER_CLASS(p) ((HevSocks5UserClass *)p)
#define HEV_SOCKS5_USER_TYPE (hev_socks5_user_class ())

typedef struct _HevSocks5User HevSocks5User;
typedef struct _HevSocks5UserClass HevSocks5UserClass;

struct _HevSocks5User
{
    HevObjectAtomic base;

    HevRBTreeNode node;

    char *name;
    char *pass;
    unsigned int name_len;
    unsigned int pass_len;
};

struct _HevSocks5UserClass
{
    HevObjectAtomicClass base;

    int (*checker) (HevSocks5User *self, const char *pass,
                    unsigned int pass_len);
};

HevObjectClass *hev_socks5_user_class (void);

int hev_socks5_user_construct (HevSocks5User *self, const char *name,
                               unsigned int name_len, const char *pass,
                               unsigned int pass_len);

HevSocks5User *hev_socks5_user_new (const char *name, unsigned int name_len,
                                    const char *pass, unsigned int pass_len);

int hev_socks5_user_check (HevSocks5User *self, const char *pass,
                           unsigned int pass_len);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_SOCKS5_USER_H__ */
