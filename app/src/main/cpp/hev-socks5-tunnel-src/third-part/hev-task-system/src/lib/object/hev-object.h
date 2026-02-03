/*
 ============================================================================
 Name        : hev-object.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2024 hev
 Description : Object
 ============================================================================
 */

#ifndef __HEV_OBJECT_H__
#define __HEV_OBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define HEV_OBJECT(p) ((HevObject *)p)
#define HEV_OBJECT_CLASS(p) ((HevObjectClass *)p)
#define HEV_OBJECT_GET_CLASS(p) ((void *)((HevObject *)p)->klass)
#define HEV_OBJECT_GET_IFACE(p, i) (((HevObject *)p)->klass->iface (p, i))
#define HEV_OBJECT_TYPE (hev_object_class ())

typedef struct _HevObject HevObject;
typedef struct _HevObjectClass HevObjectClass;

struct _HevObject
{
    HevObjectClass *klass;

    unsigned int ref_count;
};

struct _HevObjectClass
{
    const char *name;

    void (*ref) (HevObject *, int);
    void (*destruct) (HevObject *);
    void *(*iface) (HevObject *, void *);
};

/**
 * hev_object_class:
 *
 * Get the class of #HevObject.
 *
 * Returns: a #HevObjectClass
 *
 * Since: 5.3
 */
HevObjectClass *hev_object_class (void);

/**
 * hev_object_construct:
 * @self: a #HevObject
 *
 * Construct a new object.
 *
 * Returns: When successful, returns zero. otherwise, returns -1.
 *
 * Since: 5.3
 */
int hev_object_construct (HevObject *self);

/**
 * hev_object_ref:
 * @self: a #HevObject
 *
 * Increases the reference count of the @self by one.
 *
 * Since: 5.3
 */
static inline void
hev_object_ref (HevObject *self)
{
    HevObjectClass *kptr = HEV_OBJECT_GET_CLASS (self);
    kptr->ref (self, 1);
}

/**
 * hev_object_unref:
 * @self: a #HevObject
 *
 * Decreases the reference count of @self. When its reference count
 * drops to 0, the object is finalized (i.e. its memory is freed).
 *
 * Since: 5.3
 */
static inline void
hev_object_unref (HevObject *self)
{
    HevObjectClass *kptr = HEV_OBJECT_GET_CLASS (self);
    kptr->ref (self, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* __HEV_OBJECT_H__ */
