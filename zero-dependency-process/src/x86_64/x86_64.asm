section .text

global _mode_switch_to_32
_mode_switch_to_32:
use64
	pop rax
	sub esp, 8
	mov dword [esp], eax
	mov dword [esp + 4], 0x23
	retf

global _mode_switch_to_64
_mode_switch_to_64:
use32
	jmp 0x33:.resume

.resume:
use64
	add rax, 8
	call _mode_switch_to_32
use32
	ret

