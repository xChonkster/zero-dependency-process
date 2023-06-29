/*
*	winapi.hpp
* 
*	reimplementation of some winapi funcs (the ones that arent syscalls)
*/

#pragma once

#include <stdint.h>

// page state macros
constexpr uintptr_t MEM_COMMIT = 0x00001000;
constexpr uintptr_t MEM_RESERVE = 0x00002000;

// page protection macros
constexpr uintptr_t PAGE_EXECUTE_READ = 0x20;
constexpr uintptr_t PAGE_EXECUTE_READWRITE = 0x40;

// NTSTATUS macros
constexpr uint32_t TRUE = 1;
constexpr uint32_t FALSE = 0;

// integer types
typedef void* PVOID, * LPVOID;
typedef unsigned long ULONG, * PULONG;
typedef unsigned __int64 SIZE_T, * PSIZE_T, ULONG_PTR, * PULONG_PTR;
typedef unsigned long DWORD, * PDWORD, * DWORD_PTR;
typedef __int64 LARGE_INTEGER, * PLARGE_INTEGER;
typedef int BOOL;
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


