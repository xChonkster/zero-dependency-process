/*
*   x64-payload.hpp
* 
*   the actual entry point
*/

#pragma once

#include "./winapi/winapi.hpp"

/*

// 32 bit peb structs (there has to be a better way to do this...)
typedef struct _LIST_ENTRY32
{
	uint32_t Flink;
	uint32_t Blink;
} LIST_ENTRY32, * PLIST_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	UCHAR Padding0[8];
	LIST_ENTRY32 InMemoryOrderLinks;
	UCHAR Padding1[8];
	uint32_t DllBase;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32
{
	UCHAR Padding0[20];
	LIST_ENTRY32 InMemoryOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _PEB32
{
	UCHAR Padding0[12];
	uint32_t pLdr; // 32 bit address to LDR
} PEB32, * PPEB32;

*/

// intrinsics
extern "C" void* __readfsdword( int offset );
extern "C" unsigned long __readgsdword( int offset );
extern "C" void* get_stack_pointer();
extern "C" void align_stack_pointer( int alignment ); // really shouldnt be int lol

void payload_entry_point( uintptr_t allocation_base )
{
	align_stack_pointer( 16 ); // this is sick af

	/*

	// unload from 32 bit peb
	PEB32* peb32 = reinterpret_cast<PEB32*>(__readfsdword( 0x30 )); // fs:30h

	LIST_ENTRY32* start32 = &reinterpret_cast<PEB_LDR_DATA32*>(peb32->pLdr)->InMemoryOrderModuleList;

	for ( LIST_ENTRY32* current_entry = reinterpret_cast<LIST_ENTRY32*>(start32->Flink); current_entry != start32; current_entry = reinterpret_cast<LIST_ENTRY32*>(current_entry->Flink) )
	{
		LDR_DATA_TABLE_ENTRY32* current_record = CONTAINING_RECORD( current_entry, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks );

		NtUnmapViewOfSection( GetCurrentProcess(), reinterpret_cast<PVOID>(current_record->DllBase) );
	}

	// unload modules from 64 bit PEB
	PEB* peb64 = reinterpret_cast<PEB*>(static_cast<__int64>(__readgsdword( 0x60 ))); // gs:60h (https://cdn.discordapp.com/attachments/765576637265739789/1124357062311297125/image.png)

	LIST_ENTRY* start64 = &peb64->Ldr->InMemoryOrderModuleList;

	for ( LIST_ENTRY* current_entry = start64->Flink; current_entry != start64; current_entry = current_entry->Flink )
	{
		LDR_DATA_TABLE_ENTRY* current_record = CONTAINING_RECORD( current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

		NtUnmapViewOfSection( GetCurrentProcess(), current_record->DllBase );
	}

	wrote this code for nothing...

	*/

	TEB32* teb32 = reinterpret_cast<TEB32*>(__readfsdword( 0x18 )); // https://cdn.discordapp.com/attachments/765576637265739789/1124746044257878108/image.png (reading 36 bit values because were still operating on 32 bit stack)

	char* real_stack_base = reinterpret_cast<char*>(static_cast<__int64>(teb32->DeallocationStack)); // https://en.wikipedia.org/wiki/Win32_Thread_Information_Block (absolute gold, praise wine dev team)
	char* real_stack_limit = reinterpret_cast<char*>(static_cast<__int64>(teb32->NtTib.StackLimit)); // + teb32->GuaranteedStackBytes; /* kernelbase.dll!SetThreadStackGuarantee */

	// query size of committed stack region
	__declspec(align(16)) MEMORY_BASIC_INFORMATION mbi{ 0 };

	VirtualQuery( real_stack_limit, &mbi, sizeof( MEMORY_BASIC_INFORMATION ) );

	// add it
	real_stack_limit += mbi.RegionSize;

	// start unmapping
	char* base_address = 0u;
	
	while ( VirtualQuery( base_address, &mbi, sizeof( MEMORY_BASIC_INFORMATION ) ) )
	{
		if ( mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED )
		{
			NtUnmapViewOfSection( GetCurrentProcess(), mbi.AllocationBase );
		}
		else if ( mbi.Type == MEM_PRIVATE
				  && reinterpret_cast<uintptr_t>(mbi.AllocationBase) != allocation_base // not our alloc
				  && !(get_stack_pointer() > real_stack_base && get_stack_pointer() <= real_stack_limit) ) // dont deallocate our stack space
		{
			VirtualFree( mbi.AllocationBase, NULL, MEM_RELEASE );
		}

		base_address += mbi.RegionSize;
	}
	
	// the plan: browse PEB, unmap each module -- DONE! (NVM)
	// VirtualQuery each alloc, free it -- DONE
	// empty addres space!

	// crash at the end of this function (obviously)
}

