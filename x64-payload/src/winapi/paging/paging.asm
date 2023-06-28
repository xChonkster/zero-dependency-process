section .text
use64

global NtAllocateVirtualMemory
NtAllocateVirtualMemory:
	mov r10, rcx
	mov eax, 0x18 ; syscall id
	syscall
	ret