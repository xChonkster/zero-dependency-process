/*
*	x86_64.hpp
* 
*	bunch of assembly for bridging the gap between 32 and 64 bit
*/

#pragma once

namespace x64
{

extern "C" void mode_switch_to_64();
extern "C" void mode_switch_to_32();

} // namespace x64
