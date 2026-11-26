// mapper/main.cpp - Custom EAC-hardened kernel driver mapper with PhysicalMemory primitive.
//
// Replaces the KdMapper-style BYOVD (intel_driver) with a direct
// kernel-pool mapping approach using \\.\PhysicalMemory.
// No vulnerable signed driver is used.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

#include "primitive.h"

#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; uint32_t e_lfanew; } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER { uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { uint32_t VirtualAddress; uint32_t Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER64 { uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_NT_HEADERS64 { uint32_t Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef struct _IMAGE_SECTION_HEADER { uint8_t Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress; uint32_t SizeOfRawData; uint32_t PointerToRawData; uint32_t PointerToRelocations; uint32_t PointerToLinenumbers; uint16_t NumberOfRelocations; uint16_t NumberOfLinenumbers; uint32_t Characteristics; } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
typedef struct _IMAGE_IMPORT_DESCRIPTOR { uint32_t OriginalFirstThunk; uint32_t TimeDateStamp; uint32_t ForwarderChain; uint32_t Name; uint32_t FirstThunk; } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;
typedef struct _IMAGE_THUNK_DATA64 { uint64_t u1; } IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
typedef struct _IMAGE_IMPORT_BY_NAME { uint16_t Hint; char Name[1]; } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
typedef struct _IMAGE_BASE_RELOCATION { uint32_t VirtualAddress; uint32_t SizeOfBlock; } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
#pragma pack(pop)

static BOOL read_file(const wchar_t* path, std::vector<uint8_t>& out) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD size = GetFileSize(h, NULL);
    out.resize(size);
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), size, &read, NULL);
    CloseHandle(h);
    return ok && read == size;
}

// Resolve a kernel export by name from ntoskrnl.exe or hal.dll.
// We read the export directory from the kernel module's mapped image.
static uintptr_t resolve_kernel_export(primitive::KernelRW& rw, uintptr_t moduleBase, const char* name) {
    // Read DOS header
    IMAGE_DOS_HEADER dos;
    if (!primitive::kernel_rw_read(rw, moduleBase, &dos, sizeof(dos)))
        return 0;
    if (dos.e_magic != 0x5A4D)
        return 0;

    // Read NT headers
    IMAGE_NT_HEADERS64 nt;
    if (!primitive::kernel_rw_read(rw, moduleBase + dos.e_lfanew, &nt, sizeof(nt)))
        return 0;
    if (nt.Signature != 0x00004550)
        return 0;

    // Export directory is DataDirectory[0]
    if (nt.OptionalHeader.DataDirectory[0].Size == 0)
        return 0;

    uintptr_t exportDir = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    uint32_t exportSize = nt.OptionalHeader.DataDirectory[0].Size;

    std::vector<uint8_t> exportData(exportSize);
    if (!primitive::kernel_rw_read(rw, moduleBase + exportDir, exportData.data(), exportSize))
        return 0;

    // Parse export directory
    auto* pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(exportData.data());

    uint32_t numNames = pExportDir->NumberOfNames;
    uint32_t nameRvaBase = pExportDir->AddressOfNames;
    uint32_t funcRvaBase = pExportDir->AddressOfFunctions;
    uint32_t ordRvaBase = pExportDir->AddressOfNameOrdinals;

    std::vector<uint32_t> nameRvas(numNames);
    std::vector<uint16_t> ords(numNames);
    if (!primitive::kernel_rw_read(rw, moduleBase + nameRvaBase, nameRvas.data(), numNames * sizeof(uint32_t)))
        return 0;
    if (!primitive::kernel_rw_read(rw, moduleBase + ordRvaBase, ords.data(), numNames * sizeof(uint16_t)))
        return 0;

    for (uint32_t i = 0; i < numNames; i++) {
        // Read the name string
        char nameBuf[256] = { 0 };
        if (!primitive::kernel_rw_read(rw, moduleBase + nameRvas[i], nameBuf, sizeof(nameBuf) - 1))
            continue;
        if (strcmp(nameBuf, name) == 0) {
            uint16_t ord = ords[i];
            uint32_t funcRva;
            if (!primitive::kernel_rw_read(rw, moduleBase + funcRvaBase + ord * sizeof(uint32_t), &funcRva, sizeof(funcRva)))
                return 0;
            return moduleBase + funcRva;
        }
    }
    return 0;
}

// Get the base address of ntoskrnl.exe from the registry or by scanning.
// Simplified: we use a known approach - read from PsLoadedModuleList via the
// kernel, or use NtQuerySystemInformation. For now we use a hardcoded scan.
static uintptr_t get_ntoskrnl_base(primitive::KernelRW& rw) {
    // Try to find ntoskrnl base via the registry or system information.
    // Simplified approach: scan for the MZ signature in kernel range.
    // This is a placeholder; in practice use NtQuerySystemInformation
    // SystemModuleInformation to get the base.
    return 0; // Will be filled by caller
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <driver.sys> [ntoskrnl_base]\n", argv[0]);
        return 1;
    }

    primitive::KernelRW rw;
    if (!primitive::kernel_rw_init(rw)) {
        return 1;
    }

    std::vector<uint8_t> driverImage;
    if (!read_file(argv[1], driverImage)) {
        fwprintf(stderr, L"Failed to read driver image\n");
        primitive::kernel_rw_close(rw);
        return 1;
    }

    fwprintf(stderr, L"[+] Driver image loaded: %llu bytes\n", driverImage.size());

    // Parse PE headers from the local copy
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(driverImage.data());
    if (dos->e_magic != 0x5A4D) {
        fwprintf(stderr, L"[-] Invalid DOS header\n");
        primitive::kernel_rw_close(rw);
        return 1;
    }

    PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(driverImage.data() + dos->e_lfanew);
    if (nt->Signature != 0x00004550) {
        fwprintf(stderr, L"[-] Invalid NT headers\n");
        primitive::kernel_rw_close(rw);
        return 1;
    }

    uint64_t imageSize = nt->OptionalHeader.SizeOfImage;
    fwprintf(stderr, L"[+] Driver SizeOfImage: 0x%llX\n", imageSize);

    // Allocate executable non-paged kernel pool.
    // We need to find ExAllocatePoolWithTag in ntoskrnl and call it.
    // For now, we allocate via PhysicalMemory by writing to a known pool
    // location or by calling the kernel allocator.
    // Simplified: allocate a chunk in kernel memory.

    fwprintf(stderr, L"[!] Kernel pool allocation requires ntoskrnl base and ExAllocatePoolWithTag\n");
    fwprintf(stderr, L"[!] Pass ntoskrnl base as second argument to continue\n");

    if (argc >= 3) {
        uintptr_t ntoskrnlBase = std::stoull(argv[2], nullptr, 16);
        fwprintf(stderr, L"[+] Using ntoskrnl base: 0x%llX\n", ntoskrnlBase);

        // Resolve ExAllocatePoolWithTag
        uintptr_t exAllocPool = resolve_kernel_export(rw, ntoskrnlBase, "ExAllocatePoolWithTag");
        if (exAllocPool) {
            fwprintf(stderr, L"[+] ExAllocatePoolWithTag at 0x%llX\n", exAllocPool);
        } else {
            fwprintf(stderr, L"[-] Failed to resolve ExAllocatePoolWithTag\n");
        }

        // Resolve PsLoadedModuleList for DKOM unlinking
        uintptr_t psLoadedModuleList = resolve_kernel_export(rw, ntoskrnlBase, "PsLoadedModuleList");
        // Note: PsLoadedModuleList is not an export, it's a global symbol.
        // We'd need to scan for it or use a different approach.
        fwprintf(stderr, L"[!] PsLoadedModuleList is a global, not an export - need pattern scan\n");
    }

    primitive::kernel_rw_close(rw);
    fwprintf(stderr, L"[+] Mapper framework ready.\n");
    return 0;
}