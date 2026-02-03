/*
 ============================================================================
 Name        : hev-rbtree-cached.c
 Authors     : Andrea Arcangeli <andrea@suse.de>
               David Woodhouse <dwmw2@infradead.org>
               Michel Lespinasse <walken@google.com>
               Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : RedBlack Tree Cached
 ============================================================================
 */

#include "hev-rbtree-cached.h"

void
hev_rbtree_cached_insert_color (HevRBTreeCached *self, HevRBTreeNode *node,
                                int leftmost)
{
    if (leftmost)
        self->leftmost = node;

    hev_rbtree_insert_color (&self->base, node);
}

void
hev_rbtree_cached_replace (HevRBTreeCached *self, HevRBTreeNode *victim,
                           HevRBTreeNode *new)
{
    hev_rbtree_replace (&self->base, victim, new);

    if (self->leftmost == victim)
        self->leftmost = new;
}

void
hev_rbtree_cached_erase (HevRBTreeCached *self, HevRBTreeNode *node)
{
    if (node == self->leftmost)
        self->leftmost = hev_rbtree_node_next (node);

    hev_rbtree_erase (&self->base, node);
}
