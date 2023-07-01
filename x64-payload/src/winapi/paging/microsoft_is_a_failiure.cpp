/*
*	paging.cpp
*
*	virtual memory management functions
*/

/*

#include "../winapi.hpp"

// VirtualAlloc

extern "C" NTSTATUS __stdcall NtAllocateVirtualMemory( _In_ HANDLE ProcessHandle,
                                                       _Inout_ PVOID BaseAddress,
                                                       _In_ ULONG_PTR ZeroBits,
                                                       _Inout_ PSIZE_T RegionSize,
                                                       _In_ ULONG AllocationType,
                                                       _In_ ULONG Protect )
{
    return syscall( 0x18 );
}

// VirtualProtect

extern "C" NTSTATUS __stdcall NtProtectVirtualMemory( _In_ HANDLE Processhandle,
                                                      _Inout_ PVOID BaseAddress,
                                                      _Inout_ PSIZE_T NumberOfBytesToProtect,
                                                      _In_ ULONG NewAccessProtection,
                                                      _Out_ PULONG OldAccessProtection )
{
    return syscall( 0x50 );
}

// ...

extern "C" NTSTATUS __stdcall NtUnmapViewOfSection( _In_ HANDLE ProcessHandle,
                                                    _In_ PVOID BaseAddress )
{
    return syscall( 0x2A );
}

*/

// if only i could use cdecl or something...
