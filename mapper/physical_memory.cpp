// mapper/physical_memory.cpp
// Kernel memory read/write via \\.\PhysicalMemory.
// Requires SeDebugPrivilege (administrator). No vulnerable signed driver.

#include "primitive.h"

#include <aclapi.h>
#include <sddl.h>
#include <iostream>

namespace primitive {

static bool enable_debug_privilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

bool kernel_rw_init(KernelRW& rw) {
    if (!enable_debug_privilege()) {
        std::cerr << "[-] Failed to enable SeDebugPrivilege. Run as administrator.\n";
        return false;
    }

    rw.hMem = CreateFileW(
        L"\\\\.\\PhysicalMemory",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (rw.hMem == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open \\\\.\\PhysicalMemory (error " << GetLastError() << ")\n";
        return false;
    }

    rw.initialized = true;
    return true;
}

bool kernel_rw_read(KernelRW& rw, uintptr_t physAddr, void* buffer, size_t size) {
    if (!rw.initialized || rw.hMem == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)physAddr;

    if (!SetFilePointerEx(rw.hMem, offset, NULL, FILE_BEGIN))
        return false;

    DWORD read = 0;
    return ReadFile(rw.hMem, buffer, (DWORD)size, &read, NULL) && read == (DWORD)size;
}

bool kernel_rw_write(KernelRW& rw, uintptr_t physAddr, const void* buffer, size_t size) {
    if (!rw.initialized || rw.hMem == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)physAddr;

    if (!SetFilePointerEx(rw.hMem, offset, NULL, FILE_BEGIN))
        return false;

    DWORD written = 0;
    return WriteFile(rw.hMem, buffer, (DWORD)size, &written, NULL) && written == (DWORD)size;
}

void kernel_rw_close(KernelRW& rw) {
    if (rw.hMem != INVALID_HANDLE_VALUE) {
        CloseHandle(rw.hMem);
        rw.hMem = INVALID_HANDLE_VALUE;
    }
    rw.initialized = false;
}

} // namespace primitive