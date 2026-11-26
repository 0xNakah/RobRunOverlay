#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>

namespace primitive {

// Kernel memory read/write primitives.
// Uses \\.\PhysicalMemory which requires SeDebugPrivilege.
// No vulnerable signed driver is used - avoids EAC detection of BYOVD patterns.

struct KernelRW {
    HANDLE hMem = INVALID_HANDLE_VALUE;
    bool initialized = false;
};

// Open the physical memory device. Requires administrator + SeDebugPrivilege.
bool kernel_rw_init(KernelRW& rw);

// Read kernel memory at physical address.
bool kernel_rw_read(KernelRW& rw, uintptr_t physAddr, void* buffer, size_t size);

// Write kernel memory at physical address.
bool kernel_rw_write(KernelRW& rw, uintptr_t physAddr, const void* buffer, size_t size);

// Close the handle.
void kernel_rw_close(KernelRW& rw);

} // namespace primitive