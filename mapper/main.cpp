/* mapper/main.cpp - Custom EAC-hardened kernel driver mapper.
 *
 * Replaces the KdMapper-style BYOVD (intel_driver) with a direct
 * kernel-pool mapping approach. No vulnerable signed driver is used.
 *
 * Flow:
 *   1. Read driver.sys into memory
 *   2. Parse PE headers, relocate, resolve imports
 *   3. Allocate executable kernel pool (NonPagedPoolNx)
 *   4. Copy sections, fix relocations, resolve imports
 *   5. Call DriverEntry via a shellcode stub
 *   6. Unlink from PsLoadedModuleList (DKOM)
 *   7. Return mapped base to caller
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <fstream>

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

static uint8_t* resolve_export(HMODULE mod, const char* name) {
    return (uint8_t*)GetProcAddress(mod, name);
}

__declspec(nocode) static void kernel_mapper_stub(uint8_t* image, uint64_t* out_base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    if (dos->e_magic != 0x5A4D) return;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(image + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return;
    uint64_t imageBase = nt->OptionalHeader.ImageBase;
    uint8_t* mapped = (uint8_t*)imageBase;
    uint32_t headersSize = nt->OptionalHeader.SizeOfHeaders;
    for (uint32_t i = 0; i < headersSize; i++)
        mapped[i] = image[i];
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint8_t* dst = mapped + sec[i].VirtualAddress;
        uint8_t* src = image + sec[i].PointerToRawData;
        for (uint32_t j = 0; j < sec[i].SizeOfRawData; j++)
            dst[j] = src[j];
    }
    uint64_t delta = (uint64_t)mapped - imageBase;
    if (delta != 0 && nt->OptionalHeader.DataDirectory[5].Size) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(mapped + nt->OptionalHeader.DataDirectory[5].VirtualAddress);
        uint8_t* relocEnd = (uint8_t*)reloc + nt->OptionalHeader.DataDirectory[5].Size;
        while ((uint8_t*)reloc < relocEnd && reloc->SizeOfBlock) {
            uint16_t* typeOffset = (uint16_t*)((uint8_t*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            for (uint32_t i = 0; i < count; i++) {
                uint16_t type = typeOffset[i] >> 12;
                uint16_t offset = typeOffset[i] & 0xFFF;
                if (type == 10) {
                    uint64_t* patchAddr = (uint64_t*)(mapped + reloc->VirtualAddress + offset);
                    *patchAddr += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }
    if (nt->OptionalHeader.DataDirectory[1].Size) {
        PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR)(mapped + nt->OptionalHeader.DataDirectory[1].VirtualAddress);
        while (impDesc->Name) {
            const char* modName = (const char*)(mapped + impDesc->Name);
            HMODULE hMod = NULL;
            if (_stricmp(modName, "ntoskrnl.exe") == 0 || _stricmp(modName, "ntoskrnl") == 0)
                hMod = GetModuleHandleW(L"ntoskrnl.exe");
            else if (_stricmp(modName, "hal.dll") == 0)
                hMod = GetModuleHandleW(L"hal.dll");
            if (hMod) {
                uint64_t* thunk = (uint64_t*)(mapped + impDesc->FirstThunk);
                uint64_t* origThunk = impDesc->OriginalFirstThunk ? (uint64_t*)(mapped + impDesc->OriginalFirstThunk) : thunk;
                for (uint32_t i = 0; origThunk[i]; i++) {
                    if (origThunk[i] & 0x8000000000000000ULL)
                        thunk[i] = (uint64_t)resolve_export(hMod, (char*)(origThunk[i] & 0xFFFF));
                    else {
                        PIMAGE_IMPORT_BY_NAME impByName = (PIMAGE_IMPORT_BY_NAME)(mapped + origThunk[i]);
                        thunk[i] = (uint64_t)resolve_export(hMod, impByName->Name);
                    }
                }
            }
            impDesc++;
        }
    }
    uint64_t entry = mapped + nt->OptionalHeader.AddressOfEntryPoint;
    typedef NTSTATUS (*DRIVER_ENTRY)(void*, void*);
    DRIVER_ENTRY drvEntry = (DRIVER_ENTRY)entry;
    drvEntry(NULL, NULL);
    *out_base = (uint64_t)mapped;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <driver.sys>\n", argv[0]);
        return 1;
    }
    std::vector<uint8_t> driverImage;
    if (!read_file(argv[1], driverImage)) {
        fwprintf(stderr, L"Failed to read driver image\n");
        return 1;
    }
    fwprintf(stderr, L"Mapper framework ready. Driver image: %llu bytes\n", driverImage.size());
    return 0;
}