/*
 ============================================================================
 Name        : hev-task-timer.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 - 2025 everyone.
 Description : Timer
 ============================================================================
 */

#include <stdlib.h>

#include "hev-task-timer.h"
#include "kern/core/hev-task-system-private.h"
#include "mem/api/hev-memory-allocator-api.h"
#include "lib/misc/hev-compiler.h"

typedef struct _HevTaskTimerNode HevTaskTimerNode;

struct _HevTaskTimer
{
    HevRBTreeCached sort_tree;
    HevTaskSystemContext *ctx;
};

struct _HevTaskTimerNode
{
    HevRBTreeNode base;

    struct timespec expire;
    HevTask *task;
};

static inline int
hev_task_timer_cmp (const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_sec > b->tv_sec)
        return 1;

    if (a->tv_nsec < b->tv_nsec)
        return -1;
    if (a->tv_nsec > b->tv_nsec)
        return 1;

    return 0;
}

static inline int
hev_task_timer_node_cmp (HevTaskTimerNode *a, HevTaskTimerNode *b)
{
    int res;

    res = hev_task_timer_cmp (&a->expire, &b->expire);
    if (res)
        return res;

    if (a < b)
        return -1;
    if (a > b)
        return 1;

    return 0;
}

static inline void
hev_task_timer_get_curr (struct timespec *curr)
{
    if (clock_gettime (CLOCK_MONOTONIC, curr) < 0)
        abort ();
}

static inline void
hev_task_timer_get_expire (struct timespec *expire, unsigned int milliseconds)
{
    expire->tv_sec += milliseconds / 1000;
    expire->tv_nsec += (milliseconds % 1000) * 1000000;
    if (expire->tv_nsec > 1000000000L) {
        expire->tv_sec++;
        expire->tv_nsec -= 1000000000L;
    }
}

static inline unsigned int
hev_task_timer_get_time (const struct timespec *curr,
                         const struct timespec *expire)
{
    time_t sec;
    long nsec;

    sec = expire->tv_sec - curr->tv_sec;
    nsec = expire->tv_nsec - curr->tv_nsec;
    if (nsec < 0) {
        sec--;
        nsec += 1000000000L;
    }

    if (sec < 0)
        return 0;

    return (sec * 1000) + ((nsec + 999999) / 1000000);
}

HevTaskTimer *
hev_task_timer_new (void *ctx)
{
    HevTaskTimer *self;

    self = hev_malloc0 (sizeof (HevTaskTimer));
    if (!self)
        return NULL;

    self->ctx = ctx;

    return self;
}

void
hev_task_timer_destroy (HevTaskTimer *self)
{
    hev_free (self);
}

int
hev_task_timer_get_timeout (HevTaskTimer *self)
{
    HevTaskTimerNode *this;
    HevRBTreeNode *node;
    struct timespec curr;

    node = hev_rbtree_cached_first (&self->sort_tree);
    if (!node)
        return -1;

    hev_task_timer_get_curr (&curr);
    this = container_of (node, HevTaskTimerNode, base);
    return hev_task_timer_get_time (&curr, &this->expire);
}

static void
hev_task_timer_wakeup (HevTaskTimer *self, const struct timespec *curr)
{
    HevTaskTimerNode *this;
    HevRBTreeNode *node;

    node = hev_rbtree_cached_first (&self->sort_tree);
    if (!node)
        return;

    this = container_of (node, HevTaskTimerNode, base);
    if (hev_task_timer_cmp (curr, &this->expire) < 0)
        return;

    hev_task_system_wakeup_task_with_context (self->ctx, this->task);
}

void
hev_task_timer_wake (HevTaskTimer *self)
{
    HevRBTreeNode *node;
    struct timespec curr;

    node = hev_rbtree_cached_first (&self->sort_tree);
    if (!node)
        return;

    hev_task_timer_get_curr (&curr);
    hev_task_timer_wakeup (self, &curr);
}

unsigned int
hev_task_timer_wait (HevTaskTimer *self, unsigned int milliseconds,
                     HevTask *task)
{
    HevTaskTimerNode curr_node, *node = &curr_node;
    HevRBTreeNode **new = &self->sort_tree.base.root, *parent = NULL;
    struct timespec curr;
    int leftmost = 1;

    /* get expire time */
    hev_task_timer_get_curr (&node->expire);
    hev_task_timer_get_expire (&node->expire, milliseconds);
    node->task = task;

    /* insert to sort tree */
    while (*new) {
        HevTaskTimerNode *this = container_of (*new, HevTaskTimerNode, base);
        int result = hev_task_timer_node_cmp (node, this);

        parent = *new;
        if (result < 0) {
            new = &((*new)->left);
        } else {
            new = &((*new)->right);
            leftmost = 0;
        }
    }
    hev_rbtree_node_link (&node->base, parent, new);
    hev_rbtree_cached_insert_color (&self->sort_tree, &node->base, leftmost);

    hev_task_yield (HEV_TASK_WAITIO);

    /* check current is first */
    if (&node->base == hev_rbtree_cached_first (&self->sort_tree))
        leftmost = 1;

    /* remove from sort tree */
    hev_rbtree_cached_erase (&self->sort_tree, &node->base);

    hev_task_timer_get_curr (&curr);
    if (leftmost)
        hev_task_timer_wakeup (self, &curr);

    /* get remaining milliseconds */
    return hev_task_timer_get_time (&curr, &curr_node.expire);
}
