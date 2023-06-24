/*
*   zero-dependency-process.cpp
* 
*   ...
*/

#include "./crt/crt.hpp"
#include "./winapi/winapi.hpp"
#include "./x86_64/x86_64.hpp"

extern "C" void __cdecl WinMainCRTStartup()
{
	crt::call_dynamic_initializers();

	UNICODE_STRING uni_string{ 0 };

	if ( x64::is_cpuid_available() )
	{
		RtlInitUnicodeString( &uni_string, L"Hello, World!" );

		x64::load_global_descriptor_table();
		
		// code from this point onward wont run lol
	}
}

