/*
*	gate.hpp
* 
*	bunch of assembly for bridging the gap between 32 and 64 bit
*/

#pragma once

namespace x64
{

inline bool __declspec(naked) is_cpuid_available()
{
	__asm
	{
		// read EFLAGS into eax
		pushfd
		pop eax

		// flip the ID bit (bit 21 from LSB)
		xor eax, 1 << 21

		// write EFLAGS
		push eax
		popfd

		// read EFLAGS into ecx
		pushfd
		pop ecx

		// if eax and ecx are equal eax will be zero
		xor eax, ecx

		// invert for logic
		not eax

		// done
		ret
	}
} // this function is pretty much completely and utterly useless, cpuid is 100% available, i just wanted to write it lol

extern "C" void mode_switch_to_64();
extern "C" void mode_switch_to_32();

} // namespace x64