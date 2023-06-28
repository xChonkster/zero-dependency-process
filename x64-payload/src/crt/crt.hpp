/*
*	crt.hpp
* 
*	basic C helper functions
*/

#pragma once

#include <stdint.h>

constexpr void memcpy( void* destination, const void* source, size_t length )
{
	for ( size_t index = 0u; index < length; index++ )
	{
		*(reinterpret_cast<uint8_t*>(destination) + index) = *(reinterpret_cast<const uint8_t*>(source) + index);
	}
}

