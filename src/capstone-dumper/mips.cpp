/**
 * @file src/capstone-dumper/mips.cpp
 * @brief MIPS specific code.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

/**
 * @return String representation of the passed x86 operand @c op.
 */
string mips_op_type_2_string(mips_op_type op)
{
	switch (op)
	{
		case MIPS_OP_INVALID: return "MIPS_OP_INVALID";
		case MIPS_OP_REG: return "MIPS_OP_REG";
		case MIPS_OP_IMM: return "MIPS_OP_IMM";
		case MIPS_OP_MEM: return "MIPS_OP_MEM";
		default: return "UNKNOWN";
	}
}

void dumpInstructionArchDependentMips(csh handle, cs_mips* i)
{
	cout << "\t\t" << "op cnt :  " << dec << unsigned(i->op_count) << endl;
	for (unsigned j = 0; j < i->op_count; ++j)
	{
		cs_mips_op& op = i->operands[j];

		cout << endl;
		cout << "\t\t\t" << "type   :  " << mips_op_type_2_string(op.type)
				<< endl;
		switch (op.type)
		{
			case MIPS_OP_REG:
			{
				cout << "\t\t\t" << "reg    :  " << reg_2_string(handle, op.reg)
						<< endl;
				break;
			}
			case MIPS_OP_IMM:
			{
				cout << "\t\t\t" << "imm    :  " << hex << op.imm << endl;
				break;
			}
			case MIPS_OP_MEM:
			{
				cout << "\t\t\t" << "base r :  "
						<< reg_2_string(handle, op.mem.base) << endl;
				cout << "\t\t\t" << "disp   :  " << hex << op.mem.disp << endl;
				break;
			}
			case MIPS_OP_INVALID:
			{
				break;
			}
			default:
			{
				assert(false && "impossible value");
				break;
			}
		}
	}
}

} // namespace capstone_dumper
