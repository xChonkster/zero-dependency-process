/*
*	loader.cpp
* 
*	this code is responsible for loading our payload at some 64 bit address
*/

#include "../x64-payload.hpp"

#include "../winapi/winapi.hpp"
#include "../crt/crt.hpp"

extern "C" __declspec(dllexport) void create_and_run_64_bit_payload(char* base)
{
	const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos_header->e_lfanew);

	IMAGE_FILE_HEADER* file_header = &(nt_headers->FileHeader);
	IMAGE_OPTIONAL_HEADER64* optional_header = &(nt_headers->OptionalHeader);

	// where were mapping
	char* memory = reinterpret_cast<char*>(VirtualAlloc( reinterpret_cast<LPVOID>(0x10000000000), optional_header->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

	// get first section
	auto current_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(optional_header) + file_header->SizeOfOptionalHeader);

	// map sections
	for ( int index = 0; index < file_header->NumberOfSections; current_section_header++, index++ )
	{
		// only map sections we can execute
		if ( current_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
			memcpy( memory + current_section_header->VirtualAddress, base + current_section_header->VirtualAddress, current_section_header->SizeOfRawData );
		}
	}

	// call mapped entry point
	(reinterpret_cast<decltype(&payload_entry_point)>(memory + (reinterpret_cast<uintptr_t>(payload_entry_point) - reinterpret_cast<uintptr_t>(base))))();
}
