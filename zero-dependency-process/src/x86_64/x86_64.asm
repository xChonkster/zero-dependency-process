section .text

; function for switching to 32 bit mode
; return address must be in 32 bit address space

global _mode_switch_to_32
_mode_switch_to_32:
use64
	pop rax ; load return address into rax

	sub esp, 8 ; reserve 8 bytes of stack space (operating size of retf is 4 bytes)

	mov dword [esp], eax ; write return address
	mov dword [esp + 4], 0x23 ; write return code segment

	retf ; far return to 0x23:eax (and pop EIP & CS from stack)

; function for switching to 64 bit mode
; can be called from anywhere

global _mode_switch_to_64
_mode_switch_to_64:
use32
	pop eax ; load return address into eax

	sub esp, 8 ; reserve 8 bytes of stack space

	mov dword [esp], eax ; return address
	mov dword [esp + 4], 0x33 ; 64 bit mode code segment

	retf ; far return to caller in 64 bit mode

	; ret - removed because it popped 8 bytes from stack instead of 8 and it didnt work
