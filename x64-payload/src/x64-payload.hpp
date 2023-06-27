/*
*   x64-payload.hpp
* 
*   the actual entry point
*/

#include "./winapi/winapi.hpp"

void payload_entry_point()
{
	int a = 0;

	a |= 0xFFFFFFFFF;
}

void payload_entry_point_end()
{
}
