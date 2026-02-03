/*
 ============================================================================
 Name        : hev-socks5-authenticator.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2023 hev
 Description : Socks5 Authenticator
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "hev-compiler.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-authenticator.h"

HevSocks5Authenticator *
hev_socks5_authenticator_new (void)
{
    HevSocks5Authenticator *self;
    int res;

    self = calloc (1, sizeof (HevSocks5Authenticator));
    if (!self)
        return NULL;

    res = hev_socks5_authenticator_construct (self);
    if (res < 0) {
        free (self);
        return NULL;
    }

    LOG_D ("%p socks5 authenticator new", self);

    return self;
}

int
hev_socks5_authenticator_add (HevSocks5Authenticator *self, HevSocks5User *user)
{
    HevRBTreeNode **new = &self->tree.root, *parent = NULL;

    while (*new) {
        HevSocks5User *this;
        int res;

        this = container_of (*new, HevSocks5User, node);

        if (this->name_len < user->name_len)
            res = -1;
        else if (this->name_len > user->name_len)
            res = 1;
        else
            res = memcmp (this->name, user->name, this->name_len);

        parent = *new;
        if (res < 0)
            new = &((*new)->left);
        else if (res > 0)
            new = &((*new)->right);
        else
            return -1;
    }

    hev_rbtree_node_link (&user->node, parent, new);
    hev_rbtree_insert_color (&self->tree, &user->node);

    return 0;
}

int
hev_socks5_authenticator_del (HevSocks5Authenticator *self, const char *name,
                              unsigned int name_len)
{
    HevRBTreeNode *node = self->tree.root;

    while (node) {
        HevSocks5User *this;
        int res;

        this = container_of (node, HevSocks5User, node);
        if (this->name_len < name_len)
            res = -1;
        else if (this->name_len > name_len)
            res = 1;
        else
            res = memcmp (this->name, name, name_len);

        if (res < 0) {
            node = node->left;
        } else if (res > 0) {
            node = node->right;
        } else {
            hev_rbtree_erase (&self->tree, node);
            hev_object_unref (HEV_OBJECT (this));
            return 0;
        }
    }

    return -1;
}

HevSocks5User *
hev_socks5_authenticator_get (HevSocks5Authenticator *self, const char *name,
                              unsigned int name_len)
{
    HevRBTreeNode *node = self->tree.root;

    while (node) {
        HevSocks5User *this;
        int res;

        this = container_of (node, HevSocks5User, node);
        if (this->name_len < name_len)
            res = -1;
        else if (this->name_len > name_len)
            res = 1;
        else
            res = memcmp (this->name, name, name_len);

        if (res < 0)
            node = node->left;
        else if (res > 0)
            node = node->right;
        else
            return this;
    }

    return NULL;
}

void
hev_socks5_authenticator_clear (HevSocks5Authenticator *self)
{
    HevRBTreeNode *n;

    while ((n = hev_rbtree_first (&self->tree))) {
        HevSocks5User *t;

        t = container_of (n, HevSocks5User, node);
        hev_rbtree_erase (&self->tree, n);
        hev_object_unref (HEV_OBJECT (t));
    }
}

int
hev_socks5_authenticator_construct (HevSocks5Authenticator *self)
{
    int res;

    res = hev_object_atomic_construct (&self->base);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 authenticator construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_AUTHENTICATOR_TYPE;

    return 0;
}

static void
hev_socks5_authenticator_destruct (HevObject *base)
{
    HevSocks5Authenticator *self = HEV_SOCKS5_AUTHENTICATOR (base);

    LOG_D ("%p socks5 authenticator destruct", self);

    hev_socks5_authenticator_clear (self);

    HEV_OBJECT_ATOMIC_TYPE->destruct (base);
    free (base);
}

HevObjectClass *
hev_socks5_authenticator_class (void)
{
    static HevSocks5AuthenticatorClass klass;
    HevSocks5AuthenticatorClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_OBJECT_ATOMIC_TYPE, sizeof (HevObjectAtomicClass));

        okptr->name = "HevSocks5Authenticator";
        okptr->destruct = hev_socks5_authenticator_destruct;
    }

    return okptr;
}
