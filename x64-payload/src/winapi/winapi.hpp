/*
*	winapi.hpp
* 
*	reimplementation of some winapi funcs (the ones that arent syscalls)
*/

#pragma once

#include <stdint.h>

// macros
constexpr uintptr_t MEM_COMMIT = 0x00001000;
constexpr uintptr_t MEM_RESERVE = 0x00002000;
constexpr uintptr_t PAGE_EXECUTE_READWRITE = 0x40;

// integer types
typedef void* PVOID, * LPVOID;
typedef unsigned long ULONG, * PULONG;
typedef unsigned __int64 SIZE_T, * PSIZE_T, ULONG_PTR, * PULONG_PTR;
typedef unsigned long DWORD, * DWORD_PTR;
typedef __int64 LARGE_INTEGER, * PLARGE_INTEGER;
typedef long NTSTATUS;

// handle types
typedef void* HANDLE, * PHANDLE;
typedef void* HMODULE;

// misc types
typedef uint32_t ACCESS_MASK;

// structs
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

// psuedo stuff
constexpr HANDLE GetCurrentProcess()
{
    return reinterpret_cast<HANDLE>(-1);
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

// // VirtualAllocEx calls VirtualAllocExNuma(..., 0xFFFFFFFF); (https://cdn.discordapp.com/attachments/765576637265739789/1123379513020121178/image.png)
// calls NtAllocateVirtualMemory(...); (https://cdn.discordapp.com/attachments/765576637265739789/1123380022305099916/image.png)

// VirtualAlloc
extern "C" NTSTATUS __stdcall NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle,
                                                     _Inout_ PVOID BaseAddress,
                                                     _In_ ULONG_PTR ZeroBits,
                                                     _In_ PSIZE_T RegionSize,
                                                     _In_ ULONG AllocationType,
                                                     _In_ ULONG Protect );

inline LPVOID __stdcall VirtualAllocEx(_In_ HANDLE hProcess,
                                           _In_opt_ LPVOID lpAddress,
                                           _In_ SIZE_T dwSize,
                                           _In_ DWORD flAllocationType,
                                           _In_ DWORD flProtect )
{
    flProtect &= ~0x3Fu;

    ULONG_PTR RegionSize = dwSize;
    PVOID BaseAddress = lpAddress;

    NTSTATUS Status = NtAllocateVirtualMemory( hProcess, &BaseAddress, 0u, &RegionSize, flAllocationType, flProtect );
    if ( Status >= 0 )
        return BaseAddress;

    return 0;
}

inline LPVOID VirtualAlloc( _In_opt_ LPVOID lpAddress,
                               _In_ SIZE_T dwSize,
                               _In_ DWORD flAllocationType,
                               _In_ DWORD flProtect )
{
    return VirtualAllocEx( GetCurrentProcess(), lpAddress, dwSize, flAllocationType, flProtect );
}

// VirtualFree
// ...
