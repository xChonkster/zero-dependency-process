/*
*	pe-merger.cpp
* 
*	entrypoint
*/

#include "./merge/merge.hpp"

#include <windows.h>
#include <iostream>
#include <filesystem>

int main()
{
	std::string working_directory = std::filesystem::current_path().string();

	std::string host = working_directory + "\\zero-dependency-process.exe";
	std::string payload = working_directory + "\\x64-payload.dll";

	merger::merge( host, payload );
}

