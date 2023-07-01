/*
*	string.cpp
* 
*	RTL string funcs
*/

#include "../winapi.hpp"

extern "C" void __stdcall RtlInitUnicodeString( _Inout_ PUNICODE_STRING DestinationString,
												_In_ const wchar_t* SourceString )
{
	DestinationString->Length = 0;
	DestinationString->MaximumLength = 0;
	DestinationString->Buffer = const_cast<wchar_t*>(SourceString);

	while ( *SourceString++ != NULL )
		DestinationString->Length++;

	DestinationString->MaximumLength = DestinationString->Length--; // ->Length does not include null terminator
}

