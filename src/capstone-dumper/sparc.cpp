/**
 * @file src/capstone-dumper/sparc.cpp
 * @brief SPARC specific code.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

void dumpInstructionArchDependentSparc(csh handle, cs_sparc* i)
{
	// todo
}

} // namespace capstone_dumper
