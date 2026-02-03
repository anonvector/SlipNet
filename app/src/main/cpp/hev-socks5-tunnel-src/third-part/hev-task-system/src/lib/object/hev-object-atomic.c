/*
 ============================================================================
 Name        : hev-object-atomic.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Object with atomic ref-count
 ============================================================================
 */

#include <string.h>
#include <stdatomic.h>

#include "lib/misc/hev-compiler.h"

#include "hev-object-atomic.h"

EXPORT_SYMBOL int
hev_object_atomic_construct (HevObjectAtomic *self)
{
    int res;

    res = hev_object_construct (&self->base);
    if (res < 0)
        return res;

    HEV_OBJECT (self)->klass = HEV_OBJECT_ATOMIC_TYPE;

    return 0;
}

static void
_hev_object_atomic_destruct (HevObject *base)
{
    HEV_OBJECT_TYPE->destruct (base);
}

static void
_hev_object_atomic_ref (HevObject *base, int ref)
{
    HevObjectAtomic *self = HEV_OBJECT_ATOMIC (base);
    HevObjectClass *kptr = HEV_OBJECT_GET_CLASS (self);
    atomic_uint *rcp = (atomic_uint *)&base->ref_count;
    unsigned int rc;

    if (ref) {
        atomic_fetch_add_explicit (rcp, 1, memory_order_relaxed);
        return;
    }

    rc = atomic_fetch_sub_explicit (rcp, 1, memory_order_relaxed);
    if (rc > 1)
        return;

    kptr->destruct (base);
}

EXPORT_SYMBOL HevObjectClass *
hev_object_atomic_class (void)
{
    static HevObjectAtomicClass klass;
    HevObjectAtomicClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_OBJECT_TYPE, sizeof (HevObjectClass));

        okptr->name = "HevObjectAtomic";
        okptr->destruct = _hev_object_atomic_destruct;
        okptr->ref = _hev_object_atomic_ref;
    }

    return okptr;
}
