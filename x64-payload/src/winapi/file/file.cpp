/*
*	file.cpp
* 
*	CreateFileW
*/

#include "../winapi.hpp"

/*

extern "C" NTSTATUS __stdcall NtCreateFile( _Out_ PHANDLE FileHandle,
                                            _In_ ACCESS_MASK DesiredAccess,
                                            _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                                            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                                            _In_ PLARGE_INTEGER AllocationSize,
                                            _In_ ULONG FileAttributes,
                                            _In_ ULONG ShareAccess,
                                            _In_ ULONG CreateDisposition,
                                            _In_ ULONG CreateOptions,
                                            _In_ PVOID EaBuffer,
                                            _In_ ULONG EaLength )
{
    // NtCreateFile = 0x77B32FD0
    // Wow64SystemServiceCall = 0x77B48AB0
    // Wow64Transition = 0x77BE9228
    // wow64cpu.dll!KiFastSystemCall = 0x77AB7000 (64 bit?)
    // far jump to 0x33:0x9 (!) 0x33 = 0b110 (index = 6) 0 (TI (Table Indicator) flag cleared) 11 (priv level 3)
    // jmp [r15:0x0000000077ab4660 + 0xF8] ; (r15 = export directory of wow64cpu.dll?) (first 64 bit instruction)
    // wow64cpu!CpupReturnFromSimulatedCode returns from x86 (simulated) code
    // https://cdn.discordapp.com/attachments/751511097462358106/1121813333209788487/image.png (pushfq is interesting)
    // mov ecx, eax ; (ecx = eax is syscall id)
    // shr ecx, 10h ; (???)
    // jmp qword ptr [r15+rcx*8] ; (where r15 is the same address and rcx is (higher half of rcx) + ecx
    // jump does nothing ???????????
    // wow64cpu!ServiceNoTurbo+0x5:
    // 00000000`77ab17bd ff15fd290000    call    qword ptr [wow64cpu!_imp_Wow64SystemServiceEx (00000000`77ab41c0)] ds:00000000`77ab41c0={wow64!Wow64SystemServiceEx (00007ff8`2c4a8f80)}
    // call to wow64.dll!Wow64SystemServiceEx

    // https://cdn.discordapp.com/attachments/751511097462358106/1121834540739067904/image.png
    // https://cdn.discordapp.com/attachments/751511097462358106/1121921410688897135/image.png
    // https://cdn.discordapp.com/attachments/751511097462358106/1121921460043251792/image.png

    return 0; // Wow64SystemServiceCall()...;
}

*/
