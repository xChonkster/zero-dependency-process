/*
*   zero-dependency-process.cpp
* 
*   ...
*/

#include "./crt/crt.hpp"

struct sstruct
{
	int i = 0;

	sstruct(int _i)
		: i( _i )
	{
	}
};

sstruct s( 32 );

extern "C" void __cdecl WinMainCRTStartup()
{
	crt::call_dynamic_initializers();
}

