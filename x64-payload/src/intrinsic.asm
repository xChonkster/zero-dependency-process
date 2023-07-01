section .text
use64

global __readfsdword
__readfsdword:
	mov eax, dword fs:[rcx]
	ret

global __readgsdword
__readgsdword:
	mov eax, dword gs:[rcx]
	ret

global get_stack_pointer
get_stack_pointer:
	mov rax, rsp
	ret
	
global align_stack_pointer
align_stack_pointer:
	pop rax ; old rip

	sub rcx, 1
	not rcx

	and rsp, rcx ; align the stack

	jmp rax ; jmp back
