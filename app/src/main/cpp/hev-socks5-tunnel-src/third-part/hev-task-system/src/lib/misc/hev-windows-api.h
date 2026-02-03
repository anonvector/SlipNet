/*
 ============================================================================
 Name        : hev-windows-api.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2025 everyone.
 Description : Windows API
 ============================================================================
 */

#ifndef __HEV_WINDOWS_API_H__
#define __HEV_WINDOWS_API_H__

#include <winerror.h>
#include <handleapi.h>
#include <minwinbase.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INFINITE
#define INFINITE 0xffffffff
#endif

#ifndef FD_READ
#define FD_READ (1 << 0)
#endif

#ifndef FD_WRITE
#define FD_WRITE (1 << 1)
#endif

#ifndef FD_ACCEPT
#define FD_ACCEPT (1 << 3)
#endif

#ifndef FD_CONNECT
#define FD_CONNECT (1 << 4)
#endif

#ifndef FD_CLOSE
#define FD_CLOSE (1 << 5)
#endif

typedef struct _WSANETWORKEVENTS
{
    int lNetworkEvents;
    int iErrorCode[10];
} WSANETWORKEVENTS, *LPWSANETWORKEVENTS;

DWORD GetLastError ();

HANDLE WINAPI CreateIoCompletionPort (HANDLE, HANDLE, ULONG_PTR, DWORD);

BOOL GetQueuedCompletionStatus (HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED *,
                                DWORD);

BOOL PostQueuedCompletionStatus (HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);

HANDLE CreateEventA (LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);

BOOL WINAPI WSACloseEvent (HANDLE hEvent);

int WINAPI WSAEventSelect (UINT_PTR, HANDLE, long);

int WINAPI WSAEnumNetworkEvents (UINT_PTR, HANDLE, LPWSANETWORKEVENTS);

BOOL RegisterWaitForSingleObject (PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID,
                                  ULONG, ULONG);

BOOL UnregisterWaitEx (HANDLE, HANDLE);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_WINDOWS_API_H__ */
