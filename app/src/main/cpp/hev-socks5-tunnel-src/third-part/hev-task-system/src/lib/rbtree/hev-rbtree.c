/*
 ============================================================================
 Name        : hev-rbtree.c
 Authors     : Andrea Arcangeli <andrea@suse.de>
               David Woodhouse <dwmw2@infradead.org>
               Michel Lespinasse <walken@google.com>
               Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : RedBlack Tree
 ============================================================================
 */

#include "hev-rbtree.h"

typedef enum _HevRBTreeColor HevRBTreeColor;

enum _HevRBTreeColor
{
    HEV_RBTREE_RED = 0,
    HEV_RBTREE_BLACK,
};

static inline int
hev_rbtree_node_color (HevRBTreeNode *node)
{
    return node->__parent_color & 1;
}

static inline int
hev_rbtree_node_is_red (HevRBTreeNode *node)
{
    return !(hev_rbtree_node_color (node) & HEV_RBTREE_BLACK);
}

static inline int
hev_rbtree_node_is_black (HevRBTreeNode *node)
{
    return hev_rbtree_node_color (node) & HEV_RBTREE_BLACK;
}

static inline int
_hev_rbtree_node_is_black (unsigned long pc)
{
    return pc & HEV_RBTREE_BLACK;
}

static inline HevRBTreeNode *
_hev_rbtree_node_parent (unsigned long pc)
{
    return ((HevRBTreeNode *)(pc & ~3));
}

static inline HevRBTreeNode *
hev_rbtree_node_red_parent (HevRBTreeNode *node)
{
    return (HevRBTreeNode *)node->__parent_color;
}

static inline void
hev_rbtree_node_set_black (HevRBTreeNode *node)
{
    node->__parent_color |= HEV_RBTREE_BLACK;
}

static inline void
hev_rbtree_node_set_parent (HevRBTreeNode *node, HevRBTreeNode *parent)
{
    node->__parent_color = hev_rbtree_node_color (node) | (unsigned long)parent;
}

static inline void
hev_rbtree_node_set_parent_color (HevRBTreeNode *node, HevRBTreeNode *parent,
                                  int color)
{
    node->__parent_color = (unsigned long)parent | color;
}

static inline void
hev_rbtree_change_child (HevRBTree *self, HevRBTreeNode *old,
                         HevRBTreeNode *new, HevRBTreeNode *parent)
{
    if (parent) {
        if (parent->left == old)
            parent->left = new;
        else
            parent->right = new;
    } else {
        self->root = new;
    }
}

/*
 * Helper function for rotations:
 * - old's parent and color get assigned to new
 * - old gets assigned new as a parent and 'color' as a color.
 */
static inline void
hev_rbtree_rotate_set_parents (HevRBTree *self, HevRBTreeNode *old,
                               HevRBTreeNode *new, int color)
{
    HevRBTreeNode *parent = hev_rbtree_node_parent (old);
    new->__parent_color = old->__parent_color;
    hev_rbtree_node_set_parent_color (old, new, color);
    hev_rbtree_change_child (self, old, new, parent);
}

HevRBTreeNode *
hev_rbtree_node_prev (HevRBTreeNode *node)
{
    HevRBTreeNode *parent;

    if (hev_rbtree_node_empty (node))
        return NULL;

    /*
     * If we have a left-hand child, go down and then right as far
     * as we can.
     */
    if (node->left) {
        node = node->left;
        while (node->right)
            node = node->right;
        return (HevRBTreeNode *)node;
    }

    /*
     * No left-hand children. Go up till we find an ancestor which
     * is a right-hand child of its parent.
     */
    while ((parent = hev_rbtree_node_parent (node)) && node == parent->left)
        node = parent;

    return parent;
}

HevRBTreeNode *
hev_rbtree_node_next (HevRBTreeNode *node)
{
    HevRBTreeNode *parent;

    if (hev_rbtree_node_empty (node))
        return NULL;

    /*
     * If we have a right-hand child, go down and then left as far
     * as we can.
     */
    if (node->right) {
        node = node->right;
        while (node->left)
            node = node->left;
        return (HevRBTreeNode *)node;
    }

    /*
     * No right-hand children. Everything down and left is smaller than us,
     * so any 'next' node must be in the general direction of our parent.
     * Go up the tree; any time the ancestor is a right-hand child of its
     * parent, keep going up. First time it's a left-hand child of its
     * parent, said parent is our 'next' node.
     */
    while ((parent = hev_rbtree_node_parent (node)) && node == parent->right)
        node = parent;

    return parent;
}

HevRBTreeNode *
hev_rbtree_first (HevRBTree *self)
{
    HevRBTreeNode *n;

    n = self->root;
    if (!n)
        return NULL;
    while (n->left)
        n = n->left;
    return n;
}

HevRBTreeNode *
hev_rbtree_last (HevRBTree *self)
{
    HevRBTreeNode *n;

    n = self->root;
    if (!n)
        return NULL;
    while (n->right)
        n = n->right;
    return n;
}

void
hev_rbtree_insert_color (HevRBTree *self, HevRBTreeNode *node)
{
    HevRBTreeNode *parent = hev_rbtree_node_red_parent (node), *gparent, *tmp;

    while (1) {
        /*
         * Loop invariant: node is red.
         */
        if (!parent) {
            /*
             * The inserted node is root. Either this is the
             * first node, or we recursed at Case 1 below and
             * are no longer violating 4).
             */
            hev_rbtree_node_set_parent_color (node, NULL, HEV_RBTREE_BLACK);
            break;
        }

        /*
         * If there is a black parent, we are done.
         * Otherwise, take some corrective action as,
         * per 4), we don't want a red root or two
         * consecutive red nodes.
         */
        if (hev_rbtree_node_is_black (parent))
            break;

        gparent = hev_rbtree_node_red_parent (parent);

        tmp = gparent->right;
        if (parent != tmp) { /* parent == gparent->left */
            if (tmp && hev_rbtree_node_is_red (tmp)) {
                /*
                 * Case 1 - node's uncle is red (color flips).
                 *
                 *       G            g
                 *      / \          / \
                 *     p   u  -->   P   U
                 *    /            /
                 *   n            n
                 *
                 * However, since g's parent might be red, and
                 * 4) does not allow this, we need to recurse
                 * at g.
                 */
                hev_rbtree_node_set_parent_color (tmp, gparent,
                                                  HEV_RBTREE_BLACK);
                hev_rbtree_node_set_parent_color (parent, gparent,
                                                  HEV_RBTREE_BLACK);
                node = gparent;
                parent = hev_rbtree_node_parent (node);
                hev_rbtree_node_set_parent_color (node, parent, HEV_RBTREE_RED);
                continue;
            }

            tmp = parent->right;
            if (node == tmp) {
                /*
                 * Case 2 - node's uncle is black and node is
                 * the parent's right child (left rotate at parent).
                 *
                 *      G             G
                 *     / \           / \
                 *    p   U  -->    n   U
                 *     \           /
                 *      n         p
                 *
                 * This still leaves us in violation of 4), the
                 * continuation into Case 3 will fix that.
                 */
                tmp = node->left;
                parent->right = tmp;
                node->left = parent;
                if (tmp)
                    hev_rbtree_node_set_parent_color (tmp, parent,
                                                      HEV_RBTREE_BLACK);
                hev_rbtree_node_set_parent_color (parent, node, HEV_RBTREE_RED);
                parent = node;
                tmp = node->right;
            }

            /*
             * Case 3 - node's uncle is black and node is
             * the parent's left child (right rotate at gparent).
             *
             *        G           P
             *       / \         / \
             *      p   U  -->  n   g
             *     /                 \
             *    n                   U
             */
            gparent->left = tmp; /* == parent->right */
            parent->right = gparent;
            if (tmp)
                hev_rbtree_node_set_parent_color (tmp, gparent,
                                                  HEV_RBTREE_BLACK);
            hev_rbtree_rotate_set_parents (self, gparent, parent,
                                           HEV_RBTREE_RED);
            break;
        } else {
            tmp = gparent->left;
            if (tmp && hev_rbtree_node_is_red (tmp)) {
                /* Case 1 - color flips */
                hev_rbtree_node_set_parent_color (tmp, gparent,
                                                  HEV_RBTREE_BLACK);
                hev_rbtree_node_set_parent_color (parent, gparent,
                                                  HEV_RBTREE_BLACK);
                node = gparent;
                parent = hev_rbtree_node_parent (node);
                hev_rbtree_node_set_parent_color (node, parent, HEV_RBTREE_RED);
                continue;
            }

            tmp = parent->left;
            if (node == tmp) {
                /* Case 2 - right rotate at parent */
                tmp = node->right;
                parent->left = tmp;
                node->right = parent;
                if (tmp)
                    hev_rbtree_node_set_parent_color (tmp, parent,
                                                      HEV_RBTREE_BLACK);
                hev_rbtree_node_set_parent_color (parent, node, HEV_RBTREE_RED);
                parent = node;
                tmp = node->left;
            }

            /* Case 3 - left rotate at gparent */
            gparent->right = tmp; /* == parent->left */
            parent->left = gparent;
            if (tmp)
                hev_rbtree_node_set_parent_color (tmp, gparent,
                                                  HEV_RBTREE_BLACK);
            hev_rbtree_rotate_set_parents (self, gparent, parent,
                                           HEV_RBTREE_RED);
            break;
        }
    }
}

void
hev_rbtree_replace (HevRBTree *self, HevRBTreeNode *victim, HevRBTreeNode *new)
{
    HevRBTreeNode *parent = hev_rbtree_node_parent (victim);

    /* Copy the pointers/colour from the victim to the replacement */
    *new = *victim;

    /* Set the surrounding nodes to point to the replacement */
    if (victim->left)
        hev_rbtree_node_set_parent (victim->left, new);
    if (victim->right)
        hev_rbtree_node_set_parent (victim->right, new);
    hev_rbtree_change_child (self, victim, new, parent);
}

static inline HevRBTreeNode *
_hev_rbtree_erase (HevRBTree *self, HevRBTreeNode *node)
{
    HevRBTreeNode *child = node->right;
    HevRBTreeNode *tmp = node->left;
    HevRBTreeNode *parent, *rebalance;
    unsigned long pc;

    if (!tmp) {
        /*
         * Case 1: node to erase has no more than 1 child (easy!)
         *
         * Note that if there is one child it must be red due to 5)
         * and node must be black due to 4). We adjust colors locally
         * so as to bypass _hev_rbtree_erase_color() later on.
         */
        pc = node->__parent_color;
        parent = _hev_rbtree_node_parent (pc);
        hev_rbtree_change_child (self, node, child, parent);
        if (child) {
            child->__parent_color = pc;
            rebalance = NULL;
        } else
            rebalance = _hev_rbtree_node_is_black (pc) ? parent : NULL;
        tmp = parent;
    } else if (!child) {
        /* Still case 1, but this time the child is node->left */
        tmp->__parent_color = pc = node->__parent_color;
        parent = _hev_rbtree_node_parent (pc);
        hev_rbtree_change_child (self, node, tmp, parent);
        rebalance = NULL;
        tmp = parent;
    } else {
        HevRBTreeNode *successor = child, *child2;

        tmp = child->left;
        if (!tmp) {
            /*
             * Case 2: node's successor is its right child
             *
             *    (n)          (s)
             *    / \          / \
             *  (x) (s)  ->  (x) (c)
             *        \
             *        (c)
             */
            parent = successor;
            child2 = successor->right;
        } else {
            /*
             * Case 3: node's successor is leftmost under
             * node's right child subtree
             *
             *    (n)          (s)
             *    / \          / \
             *  (x) (y)  ->  (x) (y)
             *      /            /
             *    (p)          (p)
             *    /            /
             *  (s)          (c)
             *    \
             *    (c)
             */
            do {
                parent = successor;
                successor = tmp;
                tmp = tmp->left;
            } while (tmp);
            child2 = successor->right;
            parent->left = child2;
            successor->right = child;
            hev_rbtree_node_set_parent (child, successor);
        }

        tmp = node->left;
        successor->left = tmp;
        hev_rbtree_node_set_parent (tmp, successor);

        pc = node->__parent_color;
        tmp = _hev_rbtree_node_parent (pc);
        hev_rbtree_change_child (self, node, successor, tmp);

        if (child2) {
            hev_rbtree_node_set_parent_color (child2, parent, HEV_RBTREE_BLACK);
            rebalance = NULL;
        } else {
            rebalance = hev_rbtree_node_is_black (successor) ? parent : NULL;
        }
        successor->__parent_color = pc;
        tmp = successor;
    }

    return rebalance;
}

/*
 * Inline version for hev_rbtree_erase() use - we want to be able to inline
 * and eliminate the dummy_rotate callback there
 */
static inline void
_hev_rbtree_erase_color (HevRBTree *self, HevRBTreeNode *parent)
{
    HevRBTreeNode *node = NULL, *sibling, *tmp1, *tmp2;

    while (1) {
        /*
         * Loop invariants:
         * - node is black (or NULL on first iteration)
         * - node is not the root (parent is not NULL)
         * - All leaf paths going through parent and node have a
         *   black node count that is 1 lower than other leaf paths.
         */
        sibling = parent->right;
        if (node != sibling) { /* node == parent->left */
            if (hev_rbtree_node_is_red (sibling)) {
                /*
                 * Case 1 - left rotate at parent
                 *
                 *     P               S
                 *    / \             / \
                 *   N   s    -->    p   Sr
                 *      / \         / \
                 *     Sl  Sr      N   Sl
                 */
                tmp1 = sibling->left;
                parent->right = tmp1;
                sibling->left = parent;
                hev_rbtree_node_set_parent_color (tmp1, parent,
                                                  HEV_RBTREE_BLACK);
                hev_rbtree_rotate_set_parents (self, parent, sibling,
                                               HEV_RBTREE_RED);
                sibling = tmp1;
            }
            tmp1 = sibling->right;
            if (!tmp1 || hev_rbtree_node_is_black (tmp1)) {
                tmp2 = sibling->left;
                if (!tmp2 || hev_rbtree_node_is_black (tmp2)) {
                    /*
                     * Case 2 - sibling color flip
                     * (p could be either color here)
                     *
                     *    (p)           (p)
                     *    / \           / \
                     *   N   S    -->  N   s
                     *      / \           / \
                     *     Sl  Sr        Sl  Sr
                     *
                     * This leaves us violating 5) which
                     * can be fixed by flipping p to black
                     * if it was red, or by recursing at p.
                     * p is red when coming from Case 1.
                     */
                    hev_rbtree_node_set_parent_color (sibling, parent,
                                                      HEV_RBTREE_RED);
                    if (hev_rbtree_node_is_red (parent))
                        hev_rbtree_node_set_black (parent);
                    else {
                        node = parent;
                        parent = hev_rbtree_node_parent (node);
                        if (parent)
                            continue;
                    }
                    break;
                }
                /*
                 * Case 3 - right rotate at sibling
                 * (p could be either color here)
                 *
                 *   (p)           (p)
                 *   / \           / \
                 *  N   S    -->  N   sl
                 *     / \             \
                 *    sl  Sr            S
                 *                       \
                 *                        Sr
                 *
                 * Note: p might be red, and then both
                 * p and sl are red after rotation(which
                 * breaks property 4). This is fixed in
                 * Case 4 (in hev_rbtree_rotate_set_parents()
                 *         which set sl the color of p
                 *         and set p HEV_RBTREE_BLACK)
                 *
                 *   (p)            (sl)
                 *   / \            /  \
                 *  N   sl   -->   P    S
                 *       \        /      \
                 *        S      N        Sr
                 *         \
                 *          Sr
                 */
                tmp1 = tmp2->right;
                sibling->left = tmp1;
                tmp2->right = sibling;
                parent->right = tmp2;
                if (tmp1)
                    hev_rbtree_node_set_parent_color (tmp1, sibling,
                                                      HEV_RBTREE_BLACK);
                tmp1 = sibling;
                sibling = tmp2;
            }
            /*
             * Case 4 - left rotate at parent + color flips
             * (p and sl could be either color here.
             *  After rotation, p becomes black, s acquires
             *  p's color, and sl keeps its color)
             *
             *      (p)             (s)
             *      / \             / \
             *     N   S     -->   P   Sr
             *        / \         / \
             *      (sl) sr      N  (sl)
             */
            tmp2 = sibling->left;
            parent->right = tmp2;
            sibling->left = parent;
            hev_rbtree_node_set_parent_color (tmp1, sibling, HEV_RBTREE_BLACK);
            if (tmp2)
                hev_rbtree_node_set_parent (tmp2, parent);
            hev_rbtree_rotate_set_parents (self, parent, sibling,
                                           HEV_RBTREE_BLACK);
            break;
        } else {
            sibling = parent->left;
            if (hev_rbtree_node_is_red (sibling)) {
                /* Case 1 - right rotate at parent */
                tmp1 = sibling->right;
                parent->left = tmp1;
                sibling->right = parent;
                hev_rbtree_node_set_parent_color (tmp1, parent,
                                                  HEV_RBTREE_BLACK);
                hev_rbtree_rotate_set_parents (self, parent, sibling,
                                               HEV_RBTREE_RED);
                sibling = tmp1;
            }
            tmp1 = sibling->left;
            if (!tmp1 || hev_rbtree_node_is_black (tmp1)) {
                tmp2 = sibling->right;
                if (!tmp2 || hev_rbtree_node_is_black (tmp2)) {
                    /* Case 2 - sibling color flip */
                    hev_rbtree_node_set_parent_color (sibling, parent,
                                                      HEV_RBTREE_RED);
                    if (hev_rbtree_node_is_red (parent))
                        hev_rbtree_node_set_black (parent);
                    else {
                        node = parent;
                        parent = hev_rbtree_node_parent (node);
                        if (parent)
                            continue;
                    }
                    break;
                }
                /* Case 3 - left rotate at sibling */
                tmp1 = tmp2->left;
                sibling->right = tmp1;
                tmp2->left = sibling;
                parent->left = tmp2;
                if (tmp1)
                    hev_rbtree_node_set_parent_color (tmp1, sibling,
                                                      HEV_RBTREE_BLACK);
                tmp1 = sibling;
                sibling = tmp2;
            }
            /* Case 4 - right rotate at parent + color flips */
            tmp2 = sibling->right;
            parent->left = tmp2;
            sibling->right = parent;
            hev_rbtree_node_set_parent_color (tmp1, sibling, HEV_RBTREE_BLACK);
            if (tmp2)
                hev_rbtree_node_set_parent (tmp2, parent);
            hev_rbtree_rotate_set_parents (self, parent, sibling,
                                           HEV_RBTREE_BLACK);
            break;
        }
    }
}

void
hev_rbtree_erase (HevRBTree *self, HevRBTreeNode *node)
{
    HevRBTreeNode *rebalance;
    rebalance = _hev_rbtree_erase (self, node);
    if (rebalance)
        _hev_rbtree_erase_color (self, rebalance);
}
