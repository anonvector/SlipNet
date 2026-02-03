/*
 ============================================================================
 Name        : hev-socks5-user.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2023 hev
 Description : Socks5 User
 ============================================================================
 */

#include <string.h>
#include <stdlib.h>

#include "hev-socks5-logger-priv.h"

#include "hev-socks5-user.h"

HevSocks5User *
hev_socks5_user_new (const char *name, unsigned int name_len, const char *pass,
                     unsigned int pass_len)
{
    HevSocks5User *self;
    int res;

    self = calloc (1, sizeof (HevSocks5User));
    if (!self)
        return NULL;

    res = hev_socks5_user_construct (self, name, name_len, pass, pass_len);
    if (res < 0) {
        free (self);
        return NULL;
    }

    LOG_D ("%p socks5 user new", self);

    return self;
}

int
hev_socks5_user_check (HevSocks5User *self, const char *pass,
                       unsigned int pass_len)
{
    HevSocks5UserClass *klass = HEV_OBJECT_GET_CLASS (self);

    return klass->checker (self, pass, pass_len);
}

static int
hev_socks5_user_checker (HevSocks5User *self, const char *pass,
                         unsigned int pass_len)
{
    LOG_D ("%p socks5 user checker", self);

    if (self->pass_len != pass_len)
        return -1;

    if (memcmp (self->pass, pass, pass_len) != 0)
        return -1;

    return 0;
}

int
hev_socks5_user_construct (HevSocks5User *self, const char *name,
                           unsigned int name_len, const char *pass,
                           unsigned int pass_len)
{
    int res;

    res = hev_object_atomic_construct (&self->base);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 user construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_USER_TYPE;

    self->name = malloc (name_len);
    self->name_len = name_len;
    memcpy (self->name, name, name_len);

    self->pass = malloc (pass_len);
    self->pass_len = pass_len;
    memcpy (self->pass, pass, pass_len);

    return 0;
}

static void
hev_socks5_user_destruct (HevObject *base)
{
    HevSocks5User *self = HEV_SOCKS5_USER (base);

    LOG_D ("%p socks5 user destruct", self);

    free (self->name);
    free (self->pass);

    HEV_OBJECT_ATOMIC_TYPE->destruct (base);
    free (base);
}

HevObjectClass *
hev_socks5_user_class (void)
{
    static HevSocks5UserClass klass;
    HevSocks5UserClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_OBJECT_ATOMIC_TYPE, sizeof (HevObjectAtomicClass));

        okptr->name = "HevSocks5User";
        okptr->destruct = hev_socks5_user_destruct;

        kptr->checker = hev_socks5_user_checker;
    }

    return okptr;
}
