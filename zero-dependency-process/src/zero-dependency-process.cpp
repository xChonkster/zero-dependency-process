/*
*   zero-dependency-process.cpp
* 
*   ...
*/

#include "./x86_64/x86_64.hpp"

#include <windows.h>
#include <winnt.h>
#include <stdint.h>

// string compare func
bool are_strings_equal( const char* str1, const char* str2 )
{
    while ( *str1 == *str2 && (*str1 && *str2) )
            str1++, str2++;
            
    return !static_cast<bool>(*str1 - *str2);
} // couldnt use strcmp lol

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

    IMAGE_FILE_HEADER* host_file_header = &(host_nt_headers->FileHeader);
    IMAGE_OPTIONAL_HEADER32* host_optional_header = &(host_nt_headers->OptionalHeader);

    const auto host_last_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(host_optional_header) + host_file_header->SizeOfOptionalHeader) + host_file_header->NumberOfSections - 1;
    char* parsed_pe_address = current_process_base + host_last_section_header->VirtualAddress; // merger inserts its own section
    
    // parse (64 bit) merged pe at that section
    const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(parsed_pe_address);
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(parsed_pe_address + dos_header->e_lfanew);

    //const IMAGE_FILE_HEADER* file_header = &(nt_headers->FileHeader);
    const IMAGE_OPTIONAL_HEADER64* optional_header = &(nt_headers->OptionalHeader);

    // get export directory
    const IMAGE_DATA_DIRECTORY* export_data_entry = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    IMAGE_EXPORT_DIRECTORY* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(parsed_pe_address + export_data_entry->VirtualAddress);
    
    uint32_t* address_of_names = reinterpret_cast<uint32_t*>(parsed_pe_address + export_directory->AddressOfNames);
    const uint32_t* address_of_names_end = address_of_names + export_directory->NumberOfNames;

    uint32_t ordinal = 0u;

    // look for exported loader func
    for (uint32_t* current_name_rva = address_of_names; current_name_rva < address_of_names_end; current_name_rva++, ordinal++ )
    {
        const char* current_name = reinterpret_cast<char*>(parsed_pe_address + *current_name_rva);

        if ( are_strings_equal( current_name, "create_and_run_64_bit_payload" ) ) // almost didnt have a reloc table
            break;
    }

    // get the address of the export
    uint32_t* export_table_offset = reinterpret_cast<uint32_t*>(parsed_pe_address + export_directory->AddressOfFunctions) + ordinal;
    uintptr_t export_address = reinterpret_cast<uintptr_t>(parsed_pe_address + *export_table_offset);

    __asm
    {
        // set up the call
        push export_address

        // arg base address of mapped module
        mov ecx, parsed_pe_address

        // JUMP!
        jmp x64::mode_switch_to_64
    }
} // i would just like to say that this code worked first time

