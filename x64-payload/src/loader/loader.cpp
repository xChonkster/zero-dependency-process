/*
*	loader.cpp
* 
*	this code is responsible for loading our payload at some 64 bit address
*/

#include "../x64-payload.hpp"

#include "../winapi/winapi.hpp"
#include "../crt/crt.hpp"

#pragma code_seg(push, ".code")

void create_and_run_64_bit_payload()
{
	// calculate required size
	const size_t payload_entry_point_size = reinterpret_cast<uintptr_t>(payload_entry_point_end) - reinterpret_cast<uintptr_t>(payload_entry_point);

	// allocate some memory
	void* memory = VirtualAlloc( reinterpret_cast<LPVOID>(0x10000000000), payload_entry_point_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy the function
	memcpy( memory, payload_entry_point, payload_entry_point_size );

	// call the copied function
	(reinterpret_cast<decltype(&payload_entry_point)>(memory))();
}

#pragma code_seg(pop)
