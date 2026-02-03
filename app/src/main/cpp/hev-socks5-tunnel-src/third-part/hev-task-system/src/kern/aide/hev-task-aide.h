/*
 ============================================================================
 Name        : hev-task-aide.h
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2022 everyone.
 Description : Aide
 ============================================================================
 */

#ifndef __HEV_TASK_AIDE_H__
#define __HEV_TASK_AIDE_H__

typedef struct _HevTaskAideWork HevTaskAideWork;
typedef void (*HevTaskAideWorkHandler) (unsigned int revents, void *data);

struct _HevTaskAideWork
{
    int fd;
    unsigned int events;
    HevTaskAideWorkHandler handler;
    void *data;
};

int hev_task_aide_init (void);

int hev_task_aide_add (HevTaskAideWork *work);
int hev_task_aide_del (HevTaskAideWork *work);

#endif /* __HEV_TASK_AIDE_H__ */
