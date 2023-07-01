section .text
use64

global NtAllocateVirtualMemory
NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, 0x18 ; syscall id
	syscall
	ret

global NtProtectVirtualMemory
NtProtectVirtualMemory:
	mov r10, rcx
	mov eax, 0x50
	syscall
	ret

global NtUnmapViewOfSection
NtUnmapViewOfSection:
	mov r10, rcx
	mov eax, 0x2A
	syscall
	ret
	
global NtQueryVirtualMemory
NtQueryVirtualMemory:
	mov r10, rcx
	mov eax, 0x23
	syscall
	ret

global NtFreeVirtualMemory
NtFreeVirtualMemory:
	mov r10, rcx
	mov eax, 0x1E
	syscall
	ret
