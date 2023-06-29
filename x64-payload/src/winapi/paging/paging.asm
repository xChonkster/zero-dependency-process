section .code
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
	mov eax, 0x50 ; syscall id
	syscall
	ret

