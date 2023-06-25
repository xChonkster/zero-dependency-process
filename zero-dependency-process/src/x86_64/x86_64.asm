section .text

global _mode_switch_to_32
_mode_switch_to_32:
use64
	push .resume
	iretq
	
use32
.resume
	ret

global _mode_switch_to_64
_mode_switch_to_64:
use32
	jmp 0x33:.resume

.resume
use64
	add rax, 8
	call _mode_switch_to_32
	ret

