/**
 * @file src/capstone-dumper/capstone_dumper.h
 * @brief Capstone usage demonstration application.
 *        Use all (as much as makes sense) capstone capabilities to decode and
 *        dump code snippets from various architectures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FRONTEND_CAPSTONE_DUMPER_CAPSTONE_DUMPER_H
#define FRONTEND_CAPSTONE_DUMPER_CAPSTONE_DUMPER_H

#include <sstream>
#include <string>
#include <vector>

#include <capstone/capstone.h>

namespace capstone_dumper {

std::string getHexStringRepre(uint8_t* data, size_t size);

std::string reg_2_string(csh handle, unsigned reg);
std::string cs_ac_type_2_string(uint8_t a);

void dumpInstructionArchDependentArm(csh handle, cs_arm* i);
void dumpInstructionArchDependentArm64(csh handle, cs_arm64* i);
void dumpInstructionArchDependentMips(csh handle, cs_mips* i);
void dumpInstructionArchDependentX86(csh handle, cs_x86* i);
void dumpInstructionArchDependentPpc(csh handle, cs_ppc* i);
void dumpInstructionArchDependentSparc(csh handle, cs_sparc* i);
void dumpInstructionArchDependentSysz(csh handle, cs_sysz* i);
void dumpInstructionArchDependentXcore(csh handle, cs_xcore* i);
void dumpInstructionArchDependentM68k(csh handle, cs_m68k* i);
void dumpInstructionArchDependentTms320c64x(csh handle, cs_tms320c64x* i);

} // namespace capstone_dumper

#endif
