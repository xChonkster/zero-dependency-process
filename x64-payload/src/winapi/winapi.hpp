/*
*	winapi.hpp
* 
*	reimplementation of some winapi funcs (the ones that arent syscalls)
*/

#pragma once

#include <stdint.h>

// integer types
typedef void* PVOID, * LPVOID;
typedef unsigned long ULONG, * PULONG;
typedef unsigned long ULONG_PTR, * PULONG_PTR;
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

// string.cpp
extern void __stdcall RtlInitUnicodeString( _Inout_ PUNICODE_STRING DestinationString,
                                            _In_ const wchar_t* SourceString );

// file.cpp
extern NTSTATUS __stdcall NtCreateFile( _Out_ PHANDLE FileHandle,
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

