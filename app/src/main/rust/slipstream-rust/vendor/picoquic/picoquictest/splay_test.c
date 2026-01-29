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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "picoquic_utils.h"
#include "picosplay.h"

typedef struct st_int_node_t {
    int v;
    picosplay_node_t node;
} int_node_t;

static int_node_t * new_int_node(int x) {
    int_node_t * i_n = (int_node_t *)malloc(sizeof(int_node_t));
    if (i_n != NULL) {
        i_n->v = x;
    }
    return i_n;
}

static int64_t compare_int(void* l, void* r) {

    return (int64_t)((int_node_t*)l)->v - ((int_node_t*)r)->v;
}

static picosplay_node_t * create_int_node(void * value)
{
    return &((int_node_t *)value)->node;
}


static void * int_node_value(picosplay_node_t * node)
{
    return (void*)((char*)node - offsetof(struct st_int_node_t, node));
}

static void delete_int_node(void * tree, picosplay_node_t * node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    free(int_node_value(node));
}

static int check_node_sanity(picosplay_node_t *x, void *floor, void *ceil, picosplay_comparator comp) {
    int count = 0;

    if (x != NULL) {
        count = 1;
        if (x->left != NULL) {
            if (x->left->parent == x) {
                void *new_floor;
                if (floor == NULL || comp(int_node_value(x), floor) < 0)
                    new_floor = int_node_value(x);
                else
                    new_floor = floor;
                count += check_node_sanity(x->left, new_floor, ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
        if (x->right != NULL && count > 0) {
            if (x->right->parent == x) {
                void *new_ceil;
                if (ceil == NULL || comp(int_node_value(x), ceil) > 0)
                    new_ceil = int_node_value(x);
                else
                    new_ceil = ceil;
                count += check_node_sanity(x->right, floor, new_ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
    }

    return count;
}

int splay_test() {
    int ret = 0;
    int count = 0;
    picosplay_tree_t *tree = picosplay_new_tree(&compare_int, create_int_node, delete_int_node, int_node_value);
    int values[] = {5, 7, 1, 3, 13, 9, 11};
    int values_first[] = { 5, 5, 1, 1, 1, 1, 1 };
    int values_last[] = { 5, 7, 7, 7, 13, 13, 13 };
    int previous_test[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
    int previous_value[] = { -1, 1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13 };
    int value2_first[] = { 1, 1, 3, 9, 9, 11, 0 };
    int value2_last[] = { 13, 13, 13, 13, 11, 11, 0 };

    if (tree == NULL) {
        DBG_PRINTF("%s", "Cannot create tree.\n");
        ret = -1;
    }
    else {
        for (int i = 0; ret == 0 && i < 7; i++) {
            picosplay_insert(tree, new_int_node(values[i]));
            /* Verify sanity and count after each insertion */
            count = check_node_sanity(tree->root, NULL, NULL, &compare_int);
            if (count != i + 1) {
                DBG_PRINTF("Insert v[%d] = %d, expected %d nodes, got %d instead\n",
                    i, values[i], i + 1, count);
                ret = -1;
            }
            else if (tree->size != count) {
                DBG_PRINTF("Insert v[%d] = %d, expected tree size %d, got %d instead\n",
                    i, values[i], count, tree->size);
                ret = -1;
            }
            else if (((int_node_t*)int_node_value(picosplay_first(tree)))->v != values_first[i]) {
                DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                    i, values[i],
                    values_first[i], ((int_node_t*)int_node_value(picosplay_first(tree)))->v);
                ret = -1;
            }
            else if (((int_node_t*)int_node_value(picosplay_last(tree)))->v != values_last[i]) {
                DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                    i, values[i],
                    values_last[i], ((int_node_t*)int_node_value(picosplay_last(tree)))->v);
                ret = -1;
            }
        }

        for (int i = 0; ret == 0 && i < 15; i++) {
            int_node_t x;
            picosplay_node_t* y;
            
            x.v = previous_test[i];
            y = picosplay_find(tree, (void*)&x);

            if (previous_value[i] == previous_test[i]) {
                if (y == NULL) {
                    DBG_PRINTF("Find v[%d] = %d, expected = %d, got NULL instead\n",
                        i, previous_test[i], previous_value[i]);
                    ret = -1;
                }
                else {
                    int v = ((int_node_t*)int_node_value(y))->v;
                    if (v != previous_value[i]) {
                        DBG_PRINTF("Find v[%d] = %d, expected = %d, got %d instead\n",
                            i, previous_test[i], previous_value[i], v);
                        ret = -1;
                    }
                }
            }
            else {
                if (y != NULL) {
                    DBG_PRINTF("Find v[%d], expected NULL, got %d instead\n",
                        i, ((int_node_t*)int_node_value(y))->v);
                    ret = -1;
                }
            }
        }

        for (int i = 0; ret == 0 && i < 15; i++) {
            int_node_t x;
            picosplay_node_t* y;

            x.v = previous_test[i];
            y = picosplay_find_previous(tree, (void*)&x);

            if (previous_value[i] >= 0) {
                if (y == NULL) {
                    DBG_PRINTF("Next v[%d] = %d, expected = %d, got NULL instead\n",
                        i, previous_test[i], previous_value[i]);
                    ret = -1;
                }
                else {
                    int v = ((int_node_t*)int_node_value(y))->v;
                    if (v != previous_value[i]) {
                        DBG_PRINTF("next v[%d] = %d, expected = %d, got %d instead\n",
                            i, previous_test[i], previous_value[i], v);
                        ret = -1;
                    }
                }
            }
            else {
                if (y != NULL) {
                    DBG_PRINTF("Next v[%d], expected NULL, got %d instead\n",
                        i, ((int_node_t*)int_node_value(y))->v);
                    ret = -1;
                }
            }
        }

        for (int i = 0; ret == 0 && i < 7; i++) {
            int_node_t to_delete = { 0 };
            to_delete.v = values[i];
            picosplay_delete(tree, &to_delete);
            /* Verify sanity and count after each deletion */
            count = check_node_sanity(tree->root, NULL, NULL, &compare_int);
            if (count != 6 - i) {
                DBG_PRINTF("Delete v[%d] = %d, expected %d nodes, got %d instead\n",
                    i, values[i], 6 - i, count);
                ret = -1;
            }
            else if (tree->size != count) {
                DBG_PRINTF("Insert v[%d] = %d, expected tree size %d, got %d instead\n",
                    i, values[i], count, tree->size);
                ret = -1;
            }
            else if (i < 6) {
                if (((int_node_t*)int_node_value(picosplay_first(tree)))->v != value2_first[i]) {
                    DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i], value2_first[i], ((int_node_t*)int_node_value(picosplay_first(tree)))->v);
                    ret = -1;
                }
                else if (((int_node_t*)int_node_value(picosplay_last(tree)))->v != value2_last[i]) {
                    DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i], value2_last[i], ((int_node_t*)int_node_value(picosplay_last(tree)))->v);
                    ret = -1;
                }
            }
        }

        if (ret == 0 && tree->root != NULL) {
            DBG_PRINTF("%s", "Final tree root should be NULL, is not.\n");
            ret = -1;
        }
        picosplay_empty_tree(tree);
        free(tree);
        tree = NULL;
    }

    return ret;
}
