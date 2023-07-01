/*
*	winapi.hpp
* 
*	reimplementation of some winapi stuff
*/

#pragma once

#include <stdint.h>

// page state macros
constexpr uint32_t MEM_COMMIT = 0x00001000;
constexpr uint32_t MEM_RESERVE = 0x00002000;

// page dealloc macros
constexpr uint32_t MEM_RELEASE = 0x00008000;

// page protection macros
constexpr uint32_t PAGE_EXECUTE_READ = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;

// section characteristics macros
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

constexpr uint32_t MEM_IMAGE = 0x1000000;
constexpr uint32_t MEM_MAPPED = 0x40000;
constexpr uint32_t MEM_PRIVATE = 0x20000;

// this makes sense
typedef long NTSTATUS;

// NTSTATUS error codes
constexpr NTSTATUS STATUS_INVALID_PARAMETER = 0xC000000DL;

// NTSTATUS macros
constexpr uint32_t TRUE = 1;
constexpr uint32_t FALSE = 0;

// pointer types
typedef void* PVOID, * LPVOID;
typedef const void* LPCVOID;
typedef unsigned long* PULONG;
typedef unsigned long* PDWORD;
typedef unsigned __int64 *PULONG_PTR;
typedef unsigned __int64* PSIZE_T;
typedef __int64* PLARGE_INTEGER;

// integer types
typedef unsigned char BYTE, UCHAR;
typedef unsigned short WORD, USHORT;
typedef long LONG;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned __int64 DWORD_PTR;
typedef unsigned __int64 ULONG_PTR;
typedef unsigned __int64 SIZE_T;
typedef __int64 ULONGLONG;
typedef __int64 LARGE_INTEGER;

// misc types
typedef unsigned char BOOLEAN;
typedef int BOOL;

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

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink; // its so tempting to just name these next and previous...
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct _MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    WORD PartitionId;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

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

// PEB structs
typedef struct _PEB_LDR_DATA // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm?tx=185
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/index.htm
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;

    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };

    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;

    // ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE CloseHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput; //
    HANDLE StandardOutput; //
    HANDLE StandardError; // all 3 used in kernel32.dll!GetStdHandle (https://cdn.discordapp.com/attachments/765576637265739789/1124373733184913508/image.png)
    UCHAR CurrentDirectory[24]; // wtf is `CURDIR` ? (probably UNICODE_STRING without MaximumLength field...)
    UNICODE_STRING DllPath; 
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FileAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    
    // ...
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;

    union
    {
        UCHAR BitField;
        struct
        {
            UCHAR ImageUsedLargePages : 1;
            UCHAR IsProtectedProcess : 1;
            UCHAR IsImageDynamicallyRelocated : 1;
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;
            UCHAR IsAppContainer : 1;
            UCHAR IsProtectedProcessLight : 1;
            UCHAR IsLongPathAwareProcess : 1;
        } BitFieldBits;
    };

#if defined(_WIN64)
    //UCHAR Padding0[4];
#endif
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    RTL_USER_PROCESS_PARAMETERS* ProcessParemeters;
    PVOID SubSystemData;
    PVOID ProcessHeap; // used in kernel32.dll!GetProcessHeap (https://cdn.discordapp.com/attachments/765576637265739789/1124360735405916170/image.png)

    // ...
} PEB, * PPEB;

// TIB structs
typedef struct _NT_TIB32
{
    UCHAR Padding0[4];
    uint32_t StackBase;
    uint32_t StackLimit;
} NT_TIB32, * PNT_TIB32;

typedef struct _TEB32 // https://cdn.discordapp.com/attachments/765576637265739789/1124754924878704670/image.png
{
    NT_TIB32 NtTib;
    // 4 + 4 + 4 = 12 = 0xC
    UCHAR Padding0[0xE00]; // 0x1478 - 0x18
    uint32_t DeallocationStack;
    // 0xE00 + 0x4 = 0xE04
    UCHAR Padding1[0x168];
    uint32_t GuaranteedStackBytes;

    // ...
} TEB32, * PTEB32;

// CONTAINING_RECORD macro
#define CONTAINING_RECORD(address, type, field) \
    reinterpret_cast<type*>((uint8_t*)(address) - reinterpret_cast<uintptr_t>(&(reinterpret_cast<type*>(0)->field)))

// psuedo stuff
constexpr HANDLE GetCurrentProcess()
{
    return reinterpret_cast<HANDLE>(-1);
}

constexpr bool NT_SUCCESS( _In_ NTSTATUS Status )
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

// VirtualFree

extern "C" NTSTATUS __stdcall NtFreeVirtualMemory( _In_ HANDLE ProcessHandle,
                                                   _Inout_ PVOID * BaseAddress,
                                                   _Inout_ PSIZE_T RegionSize,
                                                   _In_ ULONG FreeType );

inline BOOL __stdcall VirtualFreeEx( _In_ HANDLE hProcess,
                                     _In_ LPVOID lpAddress,
                                     _In_ SIZE_T dwSize,
                                     _In_ DWORD dwFreeType )
{
    ULONG_PTR RegionSize = dwSize;
    PVOID BaseAddress = lpAddress;

    if ( NT_SUCCESS( NtFreeVirtualMemory( hProcess, &BaseAddress, &RegionSize, dwFreeType ) ) )
        return TRUE;

    return FALSE;
}

inline BOOL __stdcall VirtualFree( _In_ LPVOID lpAddress,
                                   _In_ SIZE_T dwSize,
                                   _In_ DWORD dwFreeType )
{
    return VirtualFreeEx( GetCurrentProcess(), lpAddress, dwSize, dwFreeType );
}

// NtUnmapViewOfSection

extern "C" NTSTATUS __stdcall NtUnmapViewOfSection( _In_ HANDLE ProcessHandle,
                                                    _In_ PVOID BaseAddress );

// NtQueryVirtualMemory

extern "C" NTSTATUS __stdcall NtQueryVirtualMemory( _In_ HANDLE ProcessHandle,
                                                    _In_opt_ PVOID BaseAddress,
                                                    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                                    _Out_ PVOID MemoryInformation,
                                                    _In_ SIZE_T MemoryInformationLength,
                                                    _Out_opt_ PSIZE_T ReturnLength );

inline SIZE_T __stdcall VirtualQueryEx( _In_ HANDLE hProcess,
                                        _In_opt_ LPCVOID lpAddress,
                                        _Out_ PMEMORY_BASIC_INFORMATION lpBuffer,
                                        _In_ SIZE_T dwLength )
{
    ULONG_PTR ReturnLength = NULL;

    if ( NT_SUCCESS( NtQueryVirtualMemory( hProcess, const_cast<PVOID>(lpAddress), MEMORY_INFORMATION_CLASS::MemoryBasicInformation, lpBuffer, dwLength, &ReturnLength ) ) )
        return ReturnLength;

    return FALSE;
}

inline SIZE_T __stdcall VirtualQuery( _In_opt_ LPCVOID lpAddress,
                                      _Out_ PMEMORY_BASIC_INFORMATION lpBuffer,
                                      _In_ SIZE_T dwLength )
{
    return VirtualQueryEx( GetCurrentProcess(), lpAddress, lpBuffer, dwLength );
}
