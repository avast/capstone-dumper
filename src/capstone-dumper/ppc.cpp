/**
 * @file src/capstone-dumper/ppc.cpp
 * @brief PowerPC specific code.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

/**
 * @return String representation of the passed ppc branch code @c bc.
 */
string ppc_bc_2_string(ppc_bc bc)
{
	switch (bc)
	{
		case PPC_BC_INVALID: return "PPC_BC_INVALID";
		case PPC_BC_LT: return "PPC_BC_LT";
		case PPC_BC_LE: return "PPC_BC_LE";
		case PPC_BC_EQ: return "PPC_BC_EQ";
		case PPC_BC_GE: return "PPC_BC_GE";
		case PPC_BC_GT: return "PPC_BC_GT";
		case PPC_BC_NE: return "PPC_BC_NE";
		case PPC_BC_UN: return "PPC_BC_UN";
		case PPC_BC_NU: return "PPC_BC_NU";
		case PPC_BC_SO: return "PPC_BC_SO";
		case PPC_BC_NS: return "PPC_BC_NS";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed ppc branch hint @c bh.
 */
string ppc_bh_2_string(ppc_bh bh)
{
	switch (bh)
	{
		case PPC_BH_INVALID: return "PPC_BH_INVALID";
		case PPC_BH_PLUS: return "PPC_BH_PLUS";
		case PPC_BH_MINUS: return "PPC_BH_MINUS";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed ppc operand @c op.
 */
string ppc_op_type_2_string(ppc_op_type op)
{
	switch (op)
	{
		case PPC_OP_INVALID: return "PPC_OP_INVALID";
		case PPC_OP_REG: return "PPC_OP_REG";
		case PPC_OP_IMM: return "PPC_OP_IMM";
		case PPC_OP_MEM: return "PPC_OP_MEM";
		case PPC_OP_CRX: return "PPC_OP_CRX";
		default: return "UNKNOWN";
	}
}

void dump_cs_ppc_op(csh handle, cs_ppc_op& op)
{
	cout << "\t\t\t" << "type   :  " << ppc_op_type_2_string(op.type) << endl;

	switch (op.type)
	{
		case PPC_OP_INVALID:
		{
			break;
		}
		case PPC_OP_REG:
		{
			cout << "\t\t\t" << "reg    :  " << reg_2_string(handle, op.reg)
					<< endl;
			break;
		}
		case PPC_OP_IMM:
		{
			cout << "\t\t\t" << "imm    :  " << hex << op.imm << endl;
			break;
		}
		case PPC_OP_MEM:
		{
			cout << "\t\t\t" << "base r :  "
					<< reg_2_string(handle, op.mem.base) << endl;
			cout << "\t\t\t" << "disp   :  " << hex << op.mem.disp << endl;
			break;
		}
		case PPC_OP_CRX:
		{
			cout << "\t\t\t" << "scale  :  " << dec << op.crx.scale << endl;
			cout << "\t\t\t" << "reg    :  " << reg_2_string(handle, op.crx.reg)
					<< endl;
			cout << "\t\t\t" << "br cnd :  " << ppc_bc_2_string(op.crx.cond)
					<< endl;
			break;
		}
		default:
		{
			assert(false && "unhandled value");
			break;
		}
	}
}

void dumpInstructionArchDependentPpc(csh handle, cs_ppc* i)
{
	cout << "\t\t" << "branch code :  "
			<< ppc_bc_2_string(i->bc) << std::endl;

	cout << "\t\t" << "branch hint :  "
			<< ppc_bh_2_string(i->bh) << std::endl;

	cout << "\t\t" << "update cr0  :  "
			<< boolalpha << i->update_cr0 << std::endl;

	cout << "\t\t" << "op count    :  " << dec << unsigned(i->op_count)
			<< std::endl;

	for (unsigned j = 0; j < i->op_count; ++j)
	{
		cout << endl;
		dump_cs_ppc_op(handle, i->operands[j]);
	}
}

} // namespace capstone_dumper
