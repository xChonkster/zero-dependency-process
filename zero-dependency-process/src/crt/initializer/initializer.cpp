/*
*	initializer.cpp
* 
*	manages static object initialization (just for testing, we probably dont even need this)
*/

#include "../crt.hpp"

// typedef of static initializer function
typedef void( __cdecl* dynamic_initializer )();

// create variables at begin and end of CRT section
#pragma section(".CRT$A")
__declspec(allocate(".CRT$A")) dynamic_initializer dynamic_initializer_start[]{ 0 };

#pragma section(".CRT$Z")
__declspec(allocate(".CRT$Z")) dynamic_initializer dynamic_initializer_end[]{ 0 };

// merge CRT section
#pragma comment(linker, "/merge:.CRT=.rdata")

namespace crt
{

void call_dynamic_initializers()
{
	for ( dynamic_initializer* current_dynamic_initializer = dynamic_initializer_start; current_dynamic_initializer < dynamic_initializer_end; current_dynamic_initializer++ )
		if ( *current_dynamic_initializer )
			(**current_dynamic_initializer)();
}

} // namespace crt

