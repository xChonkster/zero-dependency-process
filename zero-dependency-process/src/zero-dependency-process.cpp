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
	while ( true ) {}
	crt::call_dynamic_initializers();

	UNICODE_STRING uni_string{ 0 };

	if ( x64::is_cpuid_available() )
	{
		RtlInitUnicodeString( &uni_string, L"Hello, World!" );

		x64::mode_switch_to_64();
		x64::mode_switch_to_32();
		
		x64::is_cpuid_available();
		// code from this point onward wont run lol
	}
}

