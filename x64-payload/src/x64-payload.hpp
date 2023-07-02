/*
*   x64-payload.hpp
* 
*   the actual entry point
*/

#pragma once

#include "./winapi/winapi.hpp"

// intrinsics
extern "C" void* __readfsdword( int offset );
extern "C" unsigned long __readgsdword( int offset );
extern "C" void* get_stack_pointer();
extern "C" void align_stack_pointer( int alignment ); // really shouldnt be int lol

void payload_entry_point( uintptr_t allocation_base )
{
	align_stack_pointer( 16 ); // this is sick af

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
	
	// im so done with this project
	// maybe ill add a console to this later
	// crash at the end of this function (obviously)
}

