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

	fhost.seekg( 0, std::ios::beg );
	fpayload.seekg( 0, std::ios::beg );

	char* host_memory = static_cast<char*>(operator new(host_file_size));
	char* payload_memory = static_cast<char*>(operator new(payload_file_size));

	fhost.read( host_memory, host_file_size );
	fpayload.read( payload_memory, payload_file_size );

	// get last pe section header of host (host is 32 bit so we need to be explicit about sizes)
	const auto host_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(host_memory);
	const auto host_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(host_memory + host_dos_header->e_lfanew);

	const IMAGE_FILE_HEADER* host_file_header = &(host_nt_headers->FileHeader); // shouldnt be const...
	const IMAGE_OPTIONAL_HEADER32* host_optional_header = &(host_nt_headers->OptionalHeader); // shouldnt be const...

	const auto host_last_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER32*>(host_optional_header)) + host_file_header->SizeOfOptionalHeader) + host_file_header->NumberOfSections - 1;

	// write sections of payload dll into last section (payload dll is 64 bit...)
	const auto payload_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(payload_memory);
	const auto payload_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(payload_memory + payload_dos_header->e_lfanew);

	const IMAGE_FILE_HEADER* payload_file_header = &(payload_nt_headers->FileHeader);
	const IMAGE_OPTIONAL_HEADER64* payload_optional_header = &(payload_nt_headers->OptionalHeader);
	
	// the payload dll has to be laid out virtually, so we need more memory
	const size_t payload_virtual_memory_size = payload_optional_header->SizeOfImage;

	char* payload_virtual_memory = static_cast<char*>(operator new(payload_virtual_memory_size));

	std::memset( payload_virtual_memory, NULL, payload_virtual_memory_size );

	// change host last section size
	const unsigned long file_alignment = host_optional_header->FileAlignment;
	const unsigned long section_alignment = host_optional_header->SectionAlignment;

	const_cast<IMAGE_OPTIONAL_HEADER32*>(host_optional_header)->SizeOfImage += (static_cast<DWORD>(payload_virtual_memory_size) + section_alignment - 1) & ~(section_alignment - 1); // image doesnt run without this

	host_last_section_header->Misc.VirtualSize += static_cast<DWORD>(payload_virtual_memory_size);
	host_last_section_header->SizeOfRawData += (static_cast<DWORD>(payload_virtual_memory_size) + file_alignment - 1) & ~(file_alignment - 1);

	// mark section as executable
	host_last_section_header->Characteristics |= IMAGE_SCN_MEM_EXECUTE; // very hacky, probably shouldnt do this

	// start writing sections
	auto payload_current_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER64*>(payload_optional_header)) + payload_file_header->SizeOfOptionalHeader);

	for ( int index = 0; index < payload_file_header->NumberOfSections; index++, payload_current_section_header++ )
	{
		// only write sections that we can execute
		if ( payload_current_section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE )
		{
			std::memcpy( payload_virtual_memory + payload_current_section_header->VirtualAddress, payload_memory + payload_current_section_header->PointerToRawData, payload_current_section_header->SizeOfRawData );
		}
	}

	// at this point, payload_current_section_header is at the last section, so we can get the size of the pe header and copy it
	const size_t size_of_pe_header = reinterpret_cast<char*>(payload_current_section_header) - payload_memory;

	std::memcpy( payload_virtual_memory, payload_memory, size_of_pe_header );

	// reset fhost cursor pos
	fhost.seekg( 0, std::ios::beg );

	// write host memory back to disk
	fhost.write( host_memory, host_file_size );

	// write payload memory back to disk
	fhost.write( payload_virtual_memory, payload_virtual_memory_size );

	// close file handles
	fhost.close();
	fpayload.close();

	// free memory (cba to use smart pointers...)
	operator delete(host_memory);
	operator delete(payload_memory);
	operator delete(payload_virtual_memory);
} // this code was written quickly, the code order makes no sense and the function is way too big, but for this project its *fine*

} // namespace merger