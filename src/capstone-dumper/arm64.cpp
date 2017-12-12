/**
 * @file src/capstone-dumper/arm64.cpp
 * @brief ARM64 specific code.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

void dumpInstructionArchDependentArm64(csh handle, cs_arm64* i)
{
	// todo
}

} // namespace capstone_dumper
