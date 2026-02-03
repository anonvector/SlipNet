/*
 ============================================================================
 Name        : hev-rbtree-cached.h
 Authors     : Andrea Arcangeli <andrea@suse.de>
               David Woodhouse <dwmw2@infradead.org>
               Michel Lespinasse <walken@google.com>
               Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : RedBlack Tree Cached
 ============================================================================
 */

#ifndef __HEV_RBTREE_CACHED_H__
#define __HEV_RBTREE_CACHED_H__

#include "hev-rbtree.h"

typedef struct _HevRBTreeCached HevRBTreeCached;

/*
 * Leftmost-cached rbtrees.
 *
 * We do not cache the rightmost node based on footprint
 * size vs number of potential users that could benefit
 * from O(1) rb_last(). Just not worth it, users that want
 * this feature can always implement the logic explicitly.
 * Furthermore, users that want to cache both pointers may
 * find it a bit asymmetric, but that's ok.
 */
struct _HevRBTreeCached
{
    HevRBTree base;
    HevRBTreeNode *leftmost;
};

static inline HevRBTreeNode *
hev_rbtree_cached_first (HevRBTreeCached *self)
{
    return self->leftmost;
}

void hev_rbtree_cached_insert_color (HevRBTreeCached *self, HevRBTreeNode *node,
                                     int leftmost);

void hev_rbtree_cached_replace (HevRBTreeCached *self, HevRBTreeNode *victim,
                                HevRBTreeNode *new);

void hev_rbtree_cached_erase (HevRBTreeCached *self, HevRBTreeNode *node);

#endif /* __HEV_RBTREE_CACHED_H__ */
