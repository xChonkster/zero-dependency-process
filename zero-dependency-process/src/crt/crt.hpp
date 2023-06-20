/*
*	crt.hpp
* 
*	reimplementation of CRT
*/

#pragma once

namespace crt
{

// initialize global scope objects
extern void call_dynamic_initializers();

} // namespace crt

