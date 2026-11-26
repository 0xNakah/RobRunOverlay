/*
 * Wire contract for the WmPort transport (EAC-hardened build).
 *
 * IOCTL codes changed from the previous build so old EAC signatures do not match.
 * Request numbers use ((type << 16) | (function << 2)) with METHOD_BUFFERED
 * and FILE_ANY_ACCESS.
 *
 * Keep this file, the driver and the client transport in step.
 */

#ifndef WM_H
#define WM_H

#include <ntddk.h>

#define WM_TYPE        0x37UL   /* changed from 0x29 */
#define WM_CTL(fn)     ((ULONG)((WM_TYPE << 16) | (((ULONG)(fn)) << 2)))

#define WM_IO_READ     WM_CTL(0x9B1)
#define WM_IO_BASE     WM_CTL(0x9B2)
#define WM_IO_UNLOAD   WM_CTL(0x9B3)
#define WM_IO_WRITE    WM_CTL(0x9B4)
#define WM_IO_PEB      WM_CTL(0x9B5)
#define WM_IO_REGION   WM_CTL(0x9B6)
#define WM_IO_BATCH    WM_CTL(0x9B7)
#define WM_IO_VEIL     WM_CTL(0x9B8)
#define WM_IO_ALLOC    WM_CTL(0x9B9)
#define WM_IO_CONTEXT  WM_CTL(0x9BD)
#define WM_IO_SYSCALL  WM_CTL(0x9BE)   /* direct syscall channel */

#define WM_BATCH_MAX      64
#define WM_MAX_TRANSFER   0x10000
#define WM_VEIL_MAX       16

#pragma pack(push, 1)

typedef struct _WM_PACKET {
    ULONG     key;
    ULONG     size;
    ULONG     pid;
    ULONG     pad;
    ULONGLONG address;
} WM_PACKET, *PWM_PACKET;

typedef struct _WM_ITEM {
    ULONG     offset;
    ULONG     size;
    ULONGLONG address;
} WM_ITEM, *PWM_ITEM;

typedef struct _WM_BATCH {
    ULONG   key;
    ULONG   count;
    ULONG   total;
    ULONG   pid;
    WM_ITEM items[WM_BATCH_MAX];
} WM_BATCH, *PWM_BATCH;

typedef struct _WM_REGION {
    ULONG     state;
    ULONG     protect;
    ULONG     type;
    ULONG     pad;
    ULONGLONG base;
    ULONGLONG size;
} WM_REGION, *PWM_REGION;

typedef struct _WM_CTX_REQ {
    ULONG key;
    ULONG tid;
} WM_CTX_REQ, *PWM_CTX_REQ;

typedef struct _WM_REGS {
    ULONG     tid;
    ULONG     ok;
    ULONGLONG rflags;
    ULONGLONG rbp;
    ULONGLONG rsp;
    ULONGLONG rip;
} WM_REGS, *PWM_REGS;

typedef struct _WM_VEIL_REQ {
    ULONG key;
    ULONG pid;
    ULONG action;
    ULONG pad;
} WM_VEIL_REQ, *PWM_VEIL_REQ;

typedef struct _WM_ALLOC_REQ {
    ULONG     key;
    ULONG     pid;
    ULONG     protect;
    ULONG     pad;
    ULONGLONG size;
} WM_ALLOC_REQ, *PWM_ALLOC_REQ;

typedef struct _WM_SYSCALL_REQ {
    ULONG     key;
    ULONG     number;
    ULONGLONG arg1;
    ULONGLONG arg2;
    ULONGLONG arg3;
    ULONGLONG arg4;
    ULONGLONG arg5;
    ULONGLONG arg6;
} WM_SYSCALL_REQ, *PWM_SYSCALL_REQ;

#pragma pack(pop)

#endif /* WM_H */