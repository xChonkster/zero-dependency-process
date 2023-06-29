/*
*   x64-payload.hpp
* 
*   the actual entry point
*/

#include "./winapi/winapi.hpp"

void payload_entry_point()
{
	void* memory = VirtualAlloc( NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	DWORD old_prot{ 0 };
	VirtualProtect( memory, 0x1000, PAGE_EXECUTE_READ, &old_prot );

	// crash at the end of this function (obviously)
}

void payload_entry_point_end()
{
}
