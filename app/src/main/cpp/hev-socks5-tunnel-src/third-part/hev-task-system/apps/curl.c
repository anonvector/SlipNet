/*
 ============================================================================
 Name        : curl.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 everyone.
 Description :
 ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <poll.h>
#include <dlfcn.h>

#include <hev-task.h>
#include <hev-task-system.h>

#include <curl/curl.h>

typedef int (*posix_poll_func) (struct pollfd[], nfds_t, int);

static posix_poll_func posix_poll;

int
poll (struct pollfd fds[], nfds_t nfds, int timeout)
{
    HevTask *task = hev_task_self ();
    int res;

    if (!task)
        return posix_poll (fds, nfds, timeout);

    if (timeout == 0) {
        res = posix_poll (fds, nfds, 0);
    } else {
        unsigned int i;

        for (i = 0; i < nfds; i++) {
            if (hev_task_mod_fd (task, fds[i].fd, fds[i].events) < 0)
                hev_task_add_fd (task, fds[i].fd, fds[i].events);
        }

        if (timeout > 0) {
            do {
                timeout = hev_task_sleep (timeout);
                res = posix_poll (fds, nfds, 0);
            } while (timeout > 0 && res == 0);
        } else {
            do {
                hev_task_yield (HEV_TASK_WAITIO);
                res = posix_poll (fds, nfds, 0);
            } while (res == 0);
        }
    }

    return res;
}

static void
task_socket_entry (void *data)
{
    const char *url = data;
    CURL *curl;
    FILE *fp;
    static int index = 0;
    char path[32];

    curl = curl_easy_init ();
    if (!curl)
        return;

    snprintf (path, 32, "%d.dat", index++);
    fp = fopen (path, "w");
    if (!fp)
        return;

    curl_easy_setopt (curl, CURLOPT_URL, url);
    curl_easy_setopt (curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt (curl, CURLOPT_WRITEDATA, fp);
    curl_easy_perform (curl);

    fclose (fp);
    curl_easy_cleanup (curl);

    printf ("%s DONE\n", url);
}

int
main (int argc, char **argv)
{
    int i;

    posix_poll = dlsym (RTLD_NEXT, "poll");
    if (!posix_poll || posix_poll == poll)
        return -1;

    hev_task_system_init ();

    for (i = 1; i < argc; i++) {
        HevTask *task;

        task = hev_task_new (-1);
        hev_task_run (task, task_socket_entry, argv[i]);
    }

    hev_task_system_run ();

    hev_task_system_fini ();

    return 0;
}
