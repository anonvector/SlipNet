/*
 ============================================================================
 Name        : hev-rbtree.h
 Authors     : Andrea Arcangeli <andrea@suse.de>
               David Woodhouse <dwmw2@infradead.org>
               Michel Lespinasse <walken@google.com>
               Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : RedBlack Tree
 ============================================================================
 */

#ifndef __HEV_RBTREE_H__
#define __HEV_RBTREE_H__

#include <stddef.h>

typedef struct _HevRBTree HevRBTree;
typedef struct _HevRBTreeNode HevRBTreeNode;

struct _HevRBTree
{
    HevRBTreeNode *root;
};

struct _HevRBTreeNode
{
    unsigned long __parent_color;
    HevRBTreeNode *right;
    HevRBTreeNode *left;
} __attribute__ ((aligned (sizeof (long))));

static inline int
hev_rbtree_node_empty (HevRBTreeNode *node)
{
    return node->__parent_color == (unsigned long)node;
}

static inline HevRBTreeNode *
hev_rbtree_node_parent (HevRBTreeNode *node)
{
    return (HevRBTreeNode *)(node->__parent_color & ~3);
}

static inline void
hev_rbtree_node_link (HevRBTreeNode *node, HevRBTreeNode *parent,
                      HevRBTreeNode **link)
{
    node->__parent_color = (unsigned long)parent;
    node->left = node->right = NULL;

    *link = node;
}

HevRBTreeNode *hev_rbtree_node_prev (HevRBTreeNode *node);
HevRBTreeNode *hev_rbtree_node_next (HevRBTreeNode *node);

HevRBTreeNode *hev_rbtree_first (HevRBTree *self);
HevRBTreeNode *hev_rbtree_last (HevRBTree *self);

void hev_rbtree_insert_color (HevRBTree *self, HevRBTreeNode *node);

void hev_rbtree_replace (HevRBTree *self, HevRBTreeNode *victim,
                         HevRBTreeNode *new);

void hev_rbtree_erase (HevRBTree *self, HevRBTreeNode *node);

#endif /* __HEV_RBTREE_H__ */
