/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* This code is copied and adapted from https://github.com/lrem/splay,
* copyright (c) Remigiusz Modrzejewski 2014, filed on Github with MIT license.
*/

#include <stdlib.h>
#include <assert.h>
#include "picosplay.h"

/* The single most important utility function. */
static void rotate(picosplay_node_t *child);
/* And a few more. */
static picosplay_node_t* leftmost(picosplay_node_t *node);
static picosplay_node_t* rightmost(picosplay_node_t *node);


/* The meat: splay the node x. */
static void zig(picosplay_node_t *x);
static void zigzig(picosplay_node_t *x, picosplay_node_t *p);
static void zigzag(picosplay_node_t *x);
static void splay(picosplay_tree_t *tree, picosplay_node_t *x) {
    while(1) {
        picosplay_node_t *p = x->parent;
        if(p == NULL) {
            tree->root = x;
            return;
        }
        picosplay_node_t *g = p->parent;
        if(p->parent == NULL)
            zig(x);
        else
            if((x == p->left && p == g->left) ||
                    (x == p->right && p == g->right))
                zigzig(x, p);
            else
                zigzag(x);
    }
}

/* When p is root, rotate on the edge between x and p.*/
static void zig(picosplay_node_t *x) {
    rotate(x);
}

/* When both x and p are left (or both right) children,
 * rotate on edge between p and g, then on edge between x and p.
 */
static void zigzig(picosplay_node_t *x, picosplay_node_t *p) {
    rotate(p);
    rotate(x);
}

/* When one of x and p is a left child and the other a right child,
 * rotate on the edge between x and p, then on the new edge between x and g.
 */
static void zigzag(picosplay_node_t *x) {
    rotate(x);
    rotate(x);
}

/* Initialize an empty tree, storing the picosplay_comparator. */
void picosplay_init_tree(picosplay_tree_t* tree, picosplay_comparator comp, picosplay_create create, picosplay_delete_node delete_node, picosplay_node_value node_value) {
    tree->comp = comp;
    tree->create = create;
    tree->delete_node = delete_node;
    tree->node_value = node_value;
    tree->root = NULL;
    tree->size = 0;
}

/* Return an empty tree, storing the picosplay_comparator. */
picosplay_tree_t* picosplay_new_tree(picosplay_comparator comp, picosplay_create create, picosplay_delete_node delete_node, picosplay_node_value node_value) {
    picosplay_tree_t *new = malloc(sizeof(picosplay_tree_t));
    if (new != NULL) {
        picosplay_init_tree(new, comp, create, delete_node, node_value);
    }
    return new;
}

/* picosplay_insert and return a new node with the given value, splaying the tree. 
 * The insertion is essentially a generic BST insertion.
 */
picosplay_node_t* picosplay_insert(picosplay_tree_t *tree, void *value) {
    picosplay_node_t *new = tree->create(value);

    if (new != NULL) {
        new->left = NULL;
        new->right = NULL;
        if (tree->root == NULL) {
            tree->root = new;
            new->parent = NULL;
        }
        else {
            picosplay_node_t *curr = tree->root;
            picosplay_node_t *parent = NULL;
            int left = 0;
            while (curr != NULL) {
                parent = curr;
                if (tree->comp(tree->node_value(new), tree->node_value(curr)) < 0) {
                    left = 1;
                    curr = curr->left;
                }
                else {
                    left = 0;
                    curr = curr->right;
                }
            }
            new->parent = parent;
            if (left)
                parent->left = new;
            else
                parent->right = new;
        }
        splay(tree, new);
        tree->size++;
    }

    return new;
}

/* Find a node with the given value, splaying the tree. */
picosplay_node_t* picosplay_find(picosplay_tree_t *tree, void *value)
{
    picosplay_node_t *curr = tree->root;
    int found = 0;
    while(curr != NULL && !found) {
        int64_t relation = tree->comp(value, tree->node_value(curr));
        if(relation == 0) {
            found = 1;
        } else if(relation < 0) {
            curr = curr->left;
        } else {
            curr = curr->right;
        }
    }

    /* TODO: there may or may not be a need to perform a splay on a find operation.
     * The Wikipedia example omits it, but this code keeps it. We should
     * perform measurements with and without it and keep the best alternative. */
    if(curr != NULL)
        splay(tree, curr);
    return curr;
}

/* Find a node with the given value, splaying the tree. */
picosplay_node_t* picosplay_find_previous(picosplay_tree_t* tree, void* value)
{
    picosplay_node_t* curr = tree->root;
    picosplay_node_t* previous = NULL;
    int found = 0;
    while (curr != NULL && !found) {
        int64_t relation = tree->comp(value, tree->node_value(curr));
        if (relation == 0) {
            found = 1;
            previous = curr;
        }
        else if (relation < 0) {
            curr = curr->left;
        }
        else {
            previous = curr;
            curr = curr->right;
        }
    }

    return previous;
}

/* Remove a node with the given value, splaying the tree. */
void picosplay_delete(picosplay_tree_t *tree, void *value) {
    picosplay_node_t *node = picosplay_find(tree, value);
    picosplay_delete_hint(tree, node);
}

/* Remove the node given by the pointer, splaying the tree. */
void picosplay_delete_hint(picosplay_tree_t *tree, picosplay_node_t *node) {
    if(node == NULL)
        return;
    splay(tree, node); /* Now node is tree's root. */
    if(node->left == NULL) {
        tree->root = node->right;
        if(tree->root != NULL)
            tree->root->parent = NULL;
    } else if(node->right == NULL) {
        tree->root = node->left;
        tree->root->parent = NULL;
    } else {
        picosplay_node_t *x = leftmost(node->right);
        if(x->parent != node) {
            x->parent->left = x->right;
            if(x->right != NULL)
                x->right->parent = x->parent;
            x->right = node->right;
            x->right->parent = x;
        }
        tree->root = x;
        x->parent = NULL;
        x->left = node->left;
        x->left->parent = x;
    }
    tree->delete_node(tree, node);
    tree->size--;
}

void picosplay_empty_tree(picosplay_tree_t * tree)
{
    if (tree != NULL) {
        while (tree->root != NULL) {
            picosplay_delete_hint(tree, tree->root);
        }
    }
}

picosplay_node_t* picosplay_first(picosplay_tree_t *tree) {
    return leftmost(tree->root);
}

picosplay_node_t* picosplay_previous(picosplay_node_t* node) {
    if (node->left != NULL)
        return rightmost(node->left);
    while (node->parent != NULL && node == node->parent->left)
        node = node->parent;
    return node->parent;
}

/* Return the minimal node that is bigger than the given.
 * This is either:
 *  - leftmost child in the right subtree
 *  - closest ascendant for which given node is in left subtree
 */
picosplay_node_t* picosplay_next(picosplay_node_t *node) {
    if(node->right != NULL)
        return leftmost(node->right);
    while(node->parent != NULL && node == node->parent->right)
        node = node->parent;
    return node->parent;
}

picosplay_node_t* picosplay_last(picosplay_tree_t *tree) {
    return rightmost(tree->root);
}

#if 0
/* analyzer flags a memory leak in this code. We do not use it yet. */
/* TODO: fix memory leak before restoring this. */
/* An in-order traversal of the tree. */
static void store(picosplay_node_t *node, void ***out);
void* picosplay_contents(picosplay_tree_t *tree) {
    if(tree->size == 0)
        return NULL;
    void **out = malloc(tree->size * sizeof(void*));
    void ***tmp = &out;
    store(tree->root, tmp);
    return out - tree->size;
}

static void store(picosplay_node_t *node, void ***out) {
    if(node->left != NULL)
        store(node->left, out);
    **out = node->value;
    (*out)++;
    if(node->right != NULL)
        store(node->right, out);
}
#endif
/* This mutates the parental relationships, copy pointer to old parent. */
static void mark_gp(picosplay_node_t *child);

/* Rotate to make the given child take its parent's place in the tree. */
static void rotate(picosplay_node_t *child) {
    picosplay_node_t *parent = child->parent;
    assert(parent != NULL);
    if(parent->left == child) { /* A left child given. */
        mark_gp(child);
        parent->left = child->right;
        if(child->right != NULL)
            child->right->parent = parent;
        child->right = parent;
    } else { /* A right child given. */ 
        mark_gp(child);
        parent->right = child->left;
        if(child->left != NULL)
            child->left->parent = parent;
        child->left = parent;
    }
}

static void mark_gp(picosplay_node_t *child) {
    picosplay_node_t *parent = child->parent;
    picosplay_node_t *grand = parent->parent;
    child->parent = grand;
    parent->parent = child;
    if(grand == NULL)
        return;
    if(grand->left == parent)
        grand->left = child;
    else
        grand->right = child;
}

static picosplay_node_t* leftmost(picosplay_node_t *node) {
    picosplay_node_t *parent = NULL;
    while(node != NULL) {
        parent = node;
        node = node->left;
    }
    return parent;
}

static picosplay_node_t* rightmost(picosplay_node_t *node) {
    picosplay_node_t *parent = NULL;
    while(node != NULL) {
        parent = node;
        node = node->right;
    }
    return parent;
}

