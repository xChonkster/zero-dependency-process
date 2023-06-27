/*
*	ex.hpp
* 
*	assert function
*/

#pragma once

#include <stdexcept>
#include <string_view>

namespace ex
{

constexpr void assert( bool condition, const std::string_view& message )
{
	if ( !condition )
		throw std::runtime_error( message.data() );
}

} // namespace ex

