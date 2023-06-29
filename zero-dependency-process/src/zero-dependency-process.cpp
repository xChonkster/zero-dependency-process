/*
*   zero-dependency-process.cpp
* 
*   ...
*/

#include "./x86_64/x86_64.hpp"

#include <windows.h>
#include <winnt.h>

// PEB struct type
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    // this is all we need
} PEB, *PPEB;

extern "C" void __cdecl WinMainCRTStartup()
{
    // get image base of current process
	char* current_process_base = reinterpret_cast<char*>(reinterpret_cast<PEB*>(__readfsdword( 0x30 ))->Reserved3[1]); // https://cdn.discordapp.com/attachments/765576637265739789/1123304928073502750/image.png

    // get address of last section
    const auto host_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(current_process_base);
    const auto host_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS32*>(current_process_base + host_dos_header->e_lfanew);

    const IMAGE_FILE_HEADER* host_file_header = &(host_nt_headers->FileHeader);
    const IMAGE_OPTIONAL_HEADER32* host_optional_header = &(host_nt_headers->OptionalHeader);

    const auto host_last_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER32*>(host_optional_header)) + host_file_header->SizeOfOptionalHeader) + host_file_header->NumberOfSections - 1;
    char* parsed_pe_address = current_process_base + host_last_section_header->VirtualAddress + 0x200; // just assume 200 size...
    
    // parse (64 bit) merged pe at that section
    const auto payload_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(parsed_pe_address);
    const auto payload_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(parsed_pe_address + payload_dos_header->e_lfanew);

    const IMAGE_FILE_HEADER* payload_file_header = &(payload_nt_headers->FileHeader);
    const IMAGE_OPTIONAL_HEADER64* payload_optional_header = &(payload_nt_headers->OptionalHeader);

    auto payload_current_section = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(const_cast<IMAGE_OPTIONAL_HEADER64*>(payload_optional_header)) + payload_file_header->SizeOfOptionalHeader);

    // look for .code section (could just export loader function but meh)
    for ( int index = 0; index < payload_file_header->NumberOfSections; index++, payload_current_section++ )
    {
        const char* name = reinterpret_cast<char*>(payload_current_section->Name);

        if ( name[0] == '.' && name[1] == 'c' && name[2] == 'o' && name[3] == 'd' && name[4] == 'e' ) // name == ".code"
        {
            const uintptr_t address = reinterpret_cast<uintptr_t>(const_cast<char*>(parsed_pe_address)) + payload_current_section->VirtualAddress;

            __asm
            {
                // set up the call
                push address

                // JUMP!
                jmp x64::mode_switch_to_64
            }
        }
    }
}

