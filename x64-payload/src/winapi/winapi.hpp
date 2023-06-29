/*
*	winapi.hpp
* 
*	reimplementation of some winapi funcs (the ones that arent syscalls)
*/

#pragma once

#include <stdint.h>

// page state macros
constexpr uint32_t MEM_COMMIT = 0x00001000;
constexpr uint32_t MEM_RESERVE = 0x00002000;

// page protection macros
constexpr uint32_t PAGE_EXECUTE_READ = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;

// section characteristics macros
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

// NTSTATUS macros
constexpr uint32_t TRUE = 1;
constexpr uint32_t FALSE = 0;

// pointer types
typedef void* PVOID, * LPVOID;
typedef unsigned long* PULONG;
typedef unsigned long* PDWORD, * DWORD_PTR;
typedef __int64* PLARGE_INTEGER;
typedef unsigned __int64* PSIZE_T, *PULONG_PTR;

// integer types
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef __int64 ULONGLONG;
typedef __int64 LARGE_INTEGER;
typedef unsigned __int64 SIZE_T, ULONG_PTR;

// misc types
typedef int BOOL;
typedef long NTSTATUS;

// handle types
typedef void* HANDLE, * PHANDLE;
typedef void* HMODULE;

// misc types
typedef uint32_t ACCESS_MASK;

// type structs
typedef struct _UNICODE_STRING
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

// PE header type structs
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[8]; // IMAGE_SIZEOF_SHORT_NAME = 8
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// psuedo stuff
constexpr HANDLE GetCurrentProcess()
{
    return reinterpret_cast<HANDLE>(-1);
}

constexpr bool NT_SUCCESS( NTSTATUS Status )
{
    return (Status >= 0);
}

// string.cpp
extern "C" void __stdcall RtlInitUnicodeString( _Inout_ PUNICODE_STRING DestinationString,
                                                _In_ const wchar_t* SourceString );

// file.cpp
extern "C" NTSTATUS __stdcall NtCreateFile( _Out_ PHANDLE FileHandle,
                                            _In_ ACCESS_MASK DesiredAccess,
                                            _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                            _In_ PLARGE_INTEGER AllocationSize,
                                            _In_ ULONG FileAttributes,
                                            _In_ ULONG ShareAccess,
                                            _In_ ULONG CreateDisposition,
                                            _In_ ULONG CreateOptions,
                                            _In_ PVOID EaBuffer,
                                            _In_ ULONG EaLength );

// paging.cpp

// VirtualAlloc

extern "C" NTSTATUS __stdcall NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle,
                                                     _Inout_ PVOID BaseAddress,
                                                     _In_ ULONG_PTR ZeroBits,
                                                     _Inout_ PSIZE_T RegionSize,
                                                     _In_ ULONG AllocationType,
                                                     _In_ ULONG Protect );

inline LPVOID __stdcall VirtualAllocEx( _In_ HANDLE hProcess,
                                        _In_opt_ LPVOID lpAddress,
                                        _In_ SIZE_T dwSize,
                                        _In_ DWORD flAllocationType,
                                        _In_ DWORD flProtect )
{
    flProtect &= ~0x3Fu;

    ULONG_PTR RegionSize = dwSize;
    PVOID BaseAddress = lpAddress;

    if ( NT_SUCCESS( NtAllocateVirtualMemory( hProcess, &BaseAddress, 0u, &RegionSize, flAllocationType, flProtect ) ) )
        return BaseAddress;

    return NULL;
}

inline LPVOID VirtualAlloc( _In_opt_ LPVOID lpAddress,
                            _In_ SIZE_T dwSize,
                            _In_ DWORD flAllocationType,
                            _In_ DWORD flProtect )
{
    return VirtualAllocEx( GetCurrentProcess(), lpAddress, dwSize, flAllocationType, flProtect );
}

// VirtualProtect

extern "C" NTSTATUS __stdcall NtProtectVirtualMemory( _In_ HANDLE Processhandle,
                                                      _Inout_ PVOID BaseAddress,
                                                      _Inout_ PSIZE_T NumberOfBytesToProtect,
                                                      _In_ ULONG NewAccessProtection,
                                                      _Out_ PULONG OldAccessProtection );

inline BOOL __stdcall VirtualProtectEx( _In_ HANDLE hProcess,
                                        _In_ LPVOID lpAddress,
                                        _In_ SIZE_T dwSize,
                                        _In_ DWORD flNewProtect,
                                        _Out_ PDWORD lpflOldProtect )
{
    SIZE_T MemoryLength = dwSize;
    PVOID MemoryCache = lpAddress;

    if ( NT_SUCCESS( NtProtectVirtualMemory( hProcess, &MemoryCache, &MemoryLength, flNewProtect, lpflOldProtect ) ) )
        return TRUE;

    return FALSE;
}

inline BOOL __stdcall VirtualProtect( _In_ LPVOID lpAddress,
                                      _In_ SIZE_T dwSize,
                                      _In_ DWORD flNewProtect,
                                      _Out_ PDWORD lpflOldProtect )
{
    return VirtualProtectEx( GetCurrentProcess(), lpAddress, dwSize, flNewProtect, lpflOldProtect );
}

// NtUnmapViewOfSection


