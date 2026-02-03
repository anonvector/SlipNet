/*
 ============================================================================
 Name        : memory.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2018 everyone.
 Description : Memory Test
 ============================================================================
 */

#include <stddef.h>
#include <assert.h>
#include <string.h>

#include <hev-task-system.h>
#include <hev-memory-allocator.h>

int
main (int argc, char *argv[])
{
    void *ptr;
    static char zero[128];

    assert (hev_task_system_init () == 0);

    ptr = hev_malloc (16);
    assert (ptr != NULL);
    hev_free (ptr);

    ptr = hev_malloc0 (64);
    assert (ptr != NULL);
    assert (memcmp (ptr, zero, 64) == 0);
    hev_free (ptr);

    ptr = hev_calloc (2, 64);
    assert (ptr != NULL);
    assert (memcmp (ptr, zero, 2 * 64) == 0);
    hev_free (ptr);

    ptr = hev_malloc (128);
    assert (ptr != NULL);
    memset (ptr, 0, 128);
    ptr = hev_realloc (ptr, 256);
    assert (memcmp (ptr, zero, 128) == 0);
    ptr = hev_realloc (ptr, 32);
    assert (memcmp (ptr, zero, 32) == 0);
    hev_realloc (ptr, 0);

    hev_task_system_fini ();

    return 0;
}
