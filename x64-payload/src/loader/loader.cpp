/*
*	loader.cpp
* 
*	this code is responsible for loading our payload at some 64 bit address
*/

#include "../x64-payload.hpp"

#pragma code_seg(push, ".code")

void create_and_run_64_bit_payload()
{
	int lol = 700;
	lol += 2;
}

#pragma code_seg(pop)
