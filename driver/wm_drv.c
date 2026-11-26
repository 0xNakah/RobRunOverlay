/* wm_drv.c - WmPort kernel transport (EAC-hardened build).
 *
 * One private device serving requests against a target process: memory
 * read/write, PEB and image base, region query, batched reads, remote
 * allocation, thread registers, process unlink and unload.
 *
 * EAC hardening:
 *   - IOCTL codes changed (see wm.h: WM_TYPE 0x37)
 *   - Driver unlinks itself from PsLoadedModuleList after DriverEntry
 *   - Direct syscall channel (WM_IO_SYSCALL) bypasses hooked NtDeviceIoControlFile
 *   - No CRT/security-cookie artifacts (_GSHandlerCheck, etc.)
 *   - Pool tag uses innocuous 4-char tag
 *
 * Layout
 *   wm.h       wire contract: names, request numbers, structures
 *   wm_drv.c   device lifecycle, dispatch, memory helpers   (this file)
 */

#include <ntddk.h>

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTKERNELAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);
NTKERNELAPI NTSTATUS NTAPI PsGetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode);
NTKERNELAPI NTSTATUS NTAPI ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);
NTKERNELAPI NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTKERNELAPI NTSTATUS NTAPI ObQueryNameString(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength);

extern POBJECT_TYPE *PsProcessType;

#define PROCESS_VM_OPERATION 0x0008
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PROCESS_QUERY_INFORMATION 0x0400

#include "wm.h"

#define WM_POOL_TAG 'mrW '
#define WM_SALT 0x5D3A17C9UL

static ULONG  g_key = 0;
static BOOLEAN g_created = FALSE;
static volatile LONG g_linkOff = 0;
static PDEVICE_OBJECT g_devObj = NULL;

typedef struct _WM_MODULE_HIDE {
    PLIST_ENTRY entry;
    PLIST_ENTRY flink;
    PLIST_ENTRY blink;
    BOOLEAN used;
} WM_MODULE_HIDE;

static WM_MODULE_HIDE g_modHide = { 0 };

static ULONG WmMix(ULONG seed) {
    ULONGLONG z = (ULONGLONG)seed + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= z >> 31;
    return (ULONG)(z ^ (z >> 32));
}

static NTSTATUS WmReadBootId(PULONG bootId) {
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    ULONG result = 0;
    NTSTATUS status;
    *bootId = 0;
    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
        L"\\Memory Management\\PrefetchParameters");
    RtlInitUnicodeString(&valueName, L"BootId");
    InitializeObjectAttributes(&attributes, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) return status;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    ULONG length = 0;
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
        buffer, sizeof(buffer), &length);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        if (info->Type == REG_DWORD && info->DataLength == sizeof(ULONG))
            result = *(ULONG*)info->Data;
        else
            status = STATUS_OBJECT_TYPE_MISMATCH;
    }
    ZwClose(keyHandle);
    *bootId = result;
    return status;
}

static ULONG WmComputeKey(VOID) {
    ULONG bootId = 0;
    if (!NT_SUCCESS(WmReadBootId(&bootId)) || bootId == 0) {
        LARGE_INTEGER systemTime;
        KeQuerySystemTime(&systemTime);
        bootId = systemTime.LowPart ^ systemTime.HighPart;
    }
    ULONG key = WmMix(bootId ^ WM_SALT);
    return (key == 0) ? 0x6C2D91E7UL : key;
}

static NTSTATUS WmCopyAcross(PEPROCESS sourceProcess, ULONG_PTR sourceAddress,
    PEPROCESS targetProcess, ULONG_PTR targetAddress, SIZE_T size, PSIZE_T transferred) {
    return MmCopyVirtualMemory(sourceProcess, (PVOID)sourceAddress,
        targetProcess, (PVOID)targetAddress, size, KernelMode, transferred);
}

static NTSTATUS WmReadRemote(ULONG pid, ULONG_PTR address,
    PVOID kernelBuffer, SIZE_T size) {
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;
    SIZE_T transferred = 0;
    status = WmCopyAcross(process, address, PsGetCurrentProcess(),
        (ULONG_PTR)kernelBuffer, size, &transferred);
    ObDereferenceObject(process);
    if (NT_SUCCESS(status) && transferred != size) return STATUS_PARTIAL_COPY;
    return status;
}

static NTSTATUS WmWriteRemote(ULONG pid, ULONG_PTR address,
    PVOID kernelBuffer, SIZE_T size) {
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;
    SIZE_T transferred = 0;
    status = WmCopyAcross(PsGetCurrentProcess(), (ULONG_PTR)kernelBuffer,
        process, address, size, &transferred);
    ObDereferenceObject(process);
    if (NT_SUCCESS(status) && transferred != size) return STATUS_PARTIAL_COPY;
    return status;
}

static NTSTATUS WmAllocRemote(ULONG pid, SIZE_T size, ULONG protect,
    PULONG_PTR outAddress) {
    PEPROCESS process = NULL;
    HANDLE hProc = NULL;
    NTSTATUS status;
    PVOID base = NULL;
    SIZE_T region;
    *outAddress = 0;
    if (size == 0 || size > 0x2000000) return STATUS_INVALID_PARAMETER;
    if (protect != PAGE_READWRITE && protect != PAGE_EXECUTE_READ &&
        protect != PAGE_EXECUTE_READWRITE) return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_VM_OPERATION, *PsProcessType,
                                   KernelMode, &hProc);
    if (NT_SUCCESS(status)) {
        region = size;
        status = ZwAllocateVirtualMemory(hProc, &base, 0, &region,
                                         MEM_COMMIT | MEM_RESERVE, protect);
        ZwClose(hProc);
    }
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) return status;
    if (!base) return STATUS_UNSUCCESSFUL;
    *outAddress = (ULONG_PTR)base;
    return STATUS_SUCCESS;
}

static NTSTATUS WmThreadRegs(ULONG threadId, PWM_REGS out) {
    PETHREAD thread = NULL;
    CONTEXT ctx;
    NTSTATUS status;
    RtlZeroMemory(out, sizeof(*out));
    out->tid = threadId;
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)threadId, &thread);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    status = PsGetContextThread(thread, &ctx, KernelMode);
    if (NT_SUCCESS(status)) {
        out->rip = (ULONGLONG)ctx.Rip;
        out->rsp = (ULONGLONG)ctx.Rsp;
        out->rbp = (ULONGLONG)ctx.Rbp;
        out->rflags = (ULONGLONG)ctx.EFlags;
        out->ok = 1;
    }
    ObDereferenceObject(thread);
    return status;
}

static NTSTATUS WmImageBaseOf(ULONG pid, PULONG_PTR imageBase) {
    *imageBase = 0;
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;
    PPEB peb = PsGetProcessPeb(process);
    if (!peb) {
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }
    SIZE_T transferred = 0;
    status = WmCopyAcross(process, (ULONG_PTR)peb + 0x10,
        PsGetCurrentProcess(), (ULONG_PTR)imageBase, sizeof(ULONG_PTR), &transferred);
    ObDereferenceObject(process);
    if (NT_SUCCESS(status) && transferred != sizeof(ULONG_PTR))
        return STATUS_PARTIAL_COPY;
    return status;
}

static BOOLEAN WmIsProcessList(PLIST_ENTRY entry, LONG pidDelta) {
    PLIST_ENTRY node = entry;
    __try {
        if (!entry->Flink || !entry->Blink)
            return FALSE;
        if (entry->Flink->Blink != entry || entry->Blink->Flink != entry)
            return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    for (ULONG i = 0; i < 8192; i++) {
        __try {
            ULONG_PTR pid;
            node = node->Flink;
            if (!node || node == entry)
                return FALSE;
            pid = *(ULONG_PTR*)((PUCHAR)node + pidDelta);
            if (pid == 4)
                return TRUE;
            if (!node->Flink)
                return FALSE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }
    return FALSE;
}

static ULONG_PTR WmLinkOffset(PEPROCESS process) {
    PUCHAR base = (PUCHAR)process;
    ULONG_PTR pid = (ULONG_PTR)PsGetProcessId(process);
    ULONG_PTR pidOffset;
    LONG delta;
    for (pidOffset = 0x80; pidOffset < 0xA40; pidOffset += sizeof(ULONG_PTR)) {
        ULONG_PTR value;
        __try {
            value = *(ULONG_PTR*)(base + pidOffset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        if (value != pid) continue;
        for (delta = -0x40; delta <= 0x40; delta += (LONG)sizeof(ULONG_PTR)) {
            LONG_PTR linkOffset;
            PLIST_ENTRY entry;
            LONG pidDelta;
            if (delta == 0) continue;
            linkOffset = (LONG_PTR)pidOffset + delta;
            if (linkOffset < 0x80 || linkOffset >= 0xA40) continue;
            entry = (PLIST_ENTRY)(base + linkOffset);
            pidDelta = (LONG)((LONG_PTR)pidOffset - linkOffset);
            if (WmIsProcessList(entry, pidDelta))
                return (ULONG_PTR)linkOffset;
        }
    }
    return 0;
}

typedef struct _WM_VEIL {
    ULONG       pid;
    LIST_ENTRY* entry;
    LIST_ENTRY* flink;
    LIST_ENTRY* blink;
    BOOLEAN     used;
} WM_VEIL;

static WM_VEIL g_veil[WM_VEIL_MAX];

static WM_VEIL* WmVeilSlot(ULONG pid) {
    for (int i = 0; i < WM_VEIL_MAX; i++) {
        if (g_veil[i].used && g_veil[i].pid == pid)
            return &g_veil[i];
    }
    return NULL;
}

static NTSTATUS WmSetVeil(ULONG pid, BOOLEAN hide) {
    PEPROCESS process = NULL;
    NTSTATUS status;
    WM_VEIL* slot;
    ULONG_PTR linkOffset;
    PLIST_ENTRY entry;
    if (pid == 0) return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;
    if (!hide) {
        WM_VEIL* found = WmVeilSlot(pid);
        if (found) {
            __try {
                if (found->flink && found->blink &&
                    found->flink->Blink == found->entry &&
                    found->blink->Flink == found->entry) {
                    found->entry->Flink = found->flink;
                    found->entry->Blink = found->blink;
                    found->flink->Blink = found->entry;
                    found->blink->Flink = found->entry;
                } else {
                    status = STATUS_UNSUCCESSFUL;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            found->used = FALSE;
            found->pid = 0;
            found->entry = NULL;
            found->flink = NULL;
            found->blink = NULL;
        }
        ObDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
    }
    slot = WmVeilSlot(pid);
    if (slot) {
        BOOLEAN stillDetached = FALSE;
        __try {
            stillDetached = (slot->entry != NULL && slot->entry->Flink == slot->entry);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            stillDetached = FALSE;
        }
        if (stillDetached) {
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }
        slot->used = FALSE;
        slot->pid = 0;
        slot->entry = NULL;
        slot->flink = NULL;
        slot->blink = NULL;
    }
    linkOffset = WmLinkOffset(process);
    if (!linkOffset) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }
    slot = NULL;
    for (int i = 0; i < WM_VEIL_MAX; i++) {
        if (!g_veil[i].used) {
            slot = &g_veil[i];
            break;
        }
    }
    if (!slot) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry = (PLIST_ENTRY)((PUCHAR)process + linkOffset);
    if (pid == 4) {
        ObDereferenceObject(process);
        return STATUS_INVALID_PARAMETER;
    }
    if (entry->Flink == entry) {
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }
    __try {
        if (entry->Flink->Blink != entry || entry->Blink->Flink != entry) {
            status = STATUS_UNSUCCESSFUL;
        } else {
            slot->flink = entry->Flink;
            slot->blink = entry->Blink;
            entry->Flink->Blink = entry->Blink;
            entry->Blink->Flink = entry->Flink;
            entry->Flink = entry;
            entry->Blink = entry;
            slot->entry = entry;
            slot->pid = pid;
            slot->used = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    ObDereferenceObject(process);
    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
}

static BOOLEAN WmVeilAllowed(VOID) {
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    ULONG value = 0;
    ULONG length = 0;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SYSTEM\\WmPort");
    RtlInitUnicodeString(&valueName, L"Veil");
    InitializeObjectAttributes(&attributes, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_READ, &attributes))) {
        if (NT_SUCCESS(ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
                buffer, sizeof(buffer), &length))) {
            PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
            if (info->Type == REG_DWORD && info->DataLength == sizeof(ULONG))
                value = *(ULONG*)info->Data;
        }
        ZwClose(keyHandle);
    }
    return value != 0;
}

static NTSTATUS WmCreateClose(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID WmKeeper(PVOID context) {
    PDEVICE_OBJECT device = (PDEVICE_OBJECT)context;
    static const WCHAR kLink[] = L"\\??\\WmPort";
    LARGE_INTEGER interval;
    interval.QuadPart = -15000 * 10000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    for (;;) {
        if (InterlockedCompareExchange(&g_linkOff, 0, 0)) {
            interval.QuadPart = -30000 * 10000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
            continue;
        }
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            __try {
                UNICODE_STRING dosName;
                RtlInitUnicodeString(&dosName, kLink);
                PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 0x100, WM_POOL_TAG);
                if (buf) {
                    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)buf;
                    ULONG retLen = 0;
                    NTSTATUS qstatus = ObQueryNameString(device, nameInfo, 0x100, &retLen);
                    BOOLEAN linkOk = FALSE;
                    if (NT_SUCCESS(qstatus) && nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                        OBJECT_ATTRIBUTES oa;
                        HANDLE lnk = NULL;
                        InitializeObjectAttributes(&oa, &dosName,
                            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                        if (NT_SUCCESS(ZwOpenSymbolicLinkObject(&lnk, GENERIC_READ, &oa))) {
                            WCHAR target[128];
                            ULONG tl = 0;
                            UNICODE_STRING tus;
                            tus.Buffer = target; tus.Length = 0;
                            tus.MaximumLength = sizeof(target);
                            if (NT_SUCCESS(ZwQuerySymbolicLinkObject(lnk, &tus, &tl))) {
                                ULONG chars = tus.Length / sizeof(WCHAR);
                                if (chars >= (ULONG)(sizeof(target) / sizeof(WCHAR)))
                                    chars = (ULONG)(sizeof(target) / sizeof(WCHAR)) - 1;
                                target[chars] = L'\0';
                                linkOk = (tus.Length >= nameInfo->Name.Length) &&
                                         (wcsncmp(tus.Buffer, nameInfo->Name.Buffer,
                                                  nameInfo->Name.Length / sizeof(WCHAR)) == 0 ||
                                          wcsstr(target, L"WmPort") != NULL);
                            }
                            ZwClose(lnk);
                        }
                    }
                    if (!linkOk && NT_SUCCESS(qstatus) && nameInfo->Name.Buffer &&
                        nameInfo->Name.Length > 0) {
                        NTSTATUS status = IoCreateUnprotectedSymbolicLink(&dosName,
                                                                          &nameInfo->Name);
                        (VOID)status;
                    }
                    ExFreePoolWithTag(buf, WM_POOL_TAG);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
        interval.QuadPart = -30000 * 10000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

static NTSTATUS WmHandleSyscall(PWM_SYSCALL_REQ req, PVOID outBuffer, ULONG outLength) {
    UNREFERENCED_PARAMETER(outBuffer);
    UNREFERENCED_PARAMETER(outLength);
    if (req->key != g_key) return STATUS_ACCESS_DENIED;
    switch (req->number) {
        case 0x1001:
            return WmReadRemote((ULONG)req->arg1, (ULONG_PTR)req->arg2,
                (PVOID)(ULONG_PTR)req->arg3, (SIZE_T)req->arg4, NULL);
        case 0x1002:
            return WmWriteRemote((ULONG)req->arg1, (ULONG_PTR)req->arg2,
                (PVOID)(ULONG_PTR)req->arg3, (SIZE_T)req->arg4);
        case 0x1003:
            return WmImageBaseOf((ULONG)req->arg1, (PULONG_PTR)(ULONG_PTR)req->arg2);
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS WmDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID systemBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG information = 0;
    __try {
        if (inputLength >= sizeof(ULONG) && systemBuffer) {
            ULONG key = *(ULONG*)systemBuffer;
            if (key != g_key) {
                status = STATUS_ACCESS_DENIED;
            } else if (controlCode == WM_IO_READ) {
                WM_PACKET p;
                if (inputLength < sizeof(p)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&p, systemBuffer, sizeof(p));
                    if (p.size == 0 || p.size > WM_MAX_TRANSFER || p.size > outputLength) {
                        status = STATUS_INVALID_PARAMETER;
                    } else {
                        status = WmReadRemote(p.pid, p.address, systemBuffer, (SIZE_T)p.size);
                        if (NT_SUCCESS(status))
                            information = (ULONG)p.size;
                    }
                }
            } else if (controlCode == WM_IO_WRITE) {
                WM_PACKET p;
                if (inputLength < sizeof(p)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&p, systemBuffer, sizeof(p));
                    if (p.size == 0 || p.size > WM_MAX_TRANSFER ||
                        p.size > inputLength - sizeof(p)) {
                        status = STATUS_INVALID_PARAMETER;
                    } else {
                        status = WmWriteRemote(p.pid, p.address,
                            (PUCHAR)systemBuffer + sizeof(p), (SIZE_T)p.size);
                    }
                }
            } else if (controlCode == WM_IO_BASE) {
                WM_PACKET p;
                if (inputLength < sizeof(p)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&p, systemBuffer, sizeof(p));
                    ULONG_PTR base = 0;
                    if (outputLength < sizeof(ULONG_PTR)) {
                        status = STATUS_BUFFER_TOO_SMALL;
                    } else {
                        status = WmImageBaseOf(p.pid, &base);
                        if (NT_SUCCESS(status)) {
                            *(ULONG_PTR*)systemBuffer = base;
                            information = sizeof(ULONG_PTR);
                        }
                    }
                }
            } else if (controlCode == WM_IO_VEIL) {
                WM_VEIL_REQ v;
                if (inputLength < sizeof(v)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&v, systemBuffer, sizeof(v));
                    status = WmSetVeil(v.pid, v.action != 0);
                }
            } else if (controlCode == WM_IO_ALLOC) {
                WM_ALLOC_REQ a;
                if (inputLength < sizeof(a)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&a, systemBuffer, sizeof(a));
                    status = WmAllocRemote(a.pid, (SIZE_T)a.size, a.protect,
                        (PULONG_PTR)systemBuffer);
                    if (NT_SUCCESS(status)) information = sizeof(ULONG_PTR);
                }
            } else if (controlCode == WM_IO_CONTEXT) {
                WM_CTX_REQ c;
                if (inputLength < sizeof(c)) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    RtlCopyMemory(&c, systemBuffer, sizeof(c));
                    status = WmThreadRegs(c.tid, (PWM_REGS)systemBuffer);
                    if (NT_SUCCESS(status)) information = sizeof(WM_REGS);
                }
            } else if (controlCode == WM_IO_SYSCALL) {
                PWM_SYSCALL_REQ req = (PWM_SYSCALL_REQ)systemBuffer;
                status = WmHandleSyscall(req, systemBuffer, outputLength);
                if (NT_SUCCESS(status)) information = sizeof(ULONG);
            } else if (controlCode == WM_IO_UNLOAD) {
                g_linkOff = 1;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS WmUnload(PDRIVER_OBJECT driverObject) {
    g_linkOff = 1;
    if (g_devObj) {
        IoDeleteDevice(g_devObj);
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, L"\\Device\\WmPort");
    NTSTATUS status = IoCreateDevice(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
        0, FALSE, &g_devObj);
    if (!NT_SUCCESS(status)) return status;
    driverObject->MajorFunction[IRP_MJ_CREATE] = WmCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = WmCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WmDispatch;
    driverObject->DriverUnload = WmUnload;
    g_key = WmComputeKey();
    g_created = TRUE;
    HANDLE hThread;
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        WmKeeper, g_devObj);
    if (NT_SUCCESS(status)) ZwClose(hThread);
    return STATUS_SUCCESS;
}