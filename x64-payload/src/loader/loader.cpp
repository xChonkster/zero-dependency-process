/*
*	loader.cpp
* 
*	this code is responsible for loading our payload at some 64 bit address
*/

#include "../x64-payload.hpp"

#include "../winapi/winapi.hpp"
#include "../crt/crt.hpp"

#include <windows.h>

// text bounds

__declspec(dllexport) extern "C" void create_and_run_64_bit_payload(void* base)
{
	

	/*
	// calculate required size
	const uintptr_t text_section_size = reinterpret_cast<intptr_t>(&text_section_end) - reinterpret_cast<intptr_t>(&text_section_start);

	// allocate memory
	void* memory = VirtualAlloc( reinterpret_cast<LPVOID>(0x10000000000), text_section_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy .text & .code
	memcpy( memory, &text_section_start, text_section_size );

	// call entry point at address
	(reinterpret_cast<decltype(&payload_entry_point)>(reinterpret_cast<uintptr_t>(memory) + (reinterpret_cast<uintptr_t>(payload_entry_point) - reinterpret_cast<uintptr_t>(&text_section_start))))();
	*/
} // theres deffo better solutions to this problem, if i were to remake this project i'd have done alot of things differently
