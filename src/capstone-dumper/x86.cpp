/**
 * @file src/capstone-dumper/x86.cpp
 * @brief x86 specific code.
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
string x86_op_type_2_string(x86_op_type op)
{
	switch (op)
	{
		case X86_OP_INVALID: return "X86_OP_INVALID";
		case X86_OP_REG: return "X86_OP_REG";
		case X86_OP_IMM: return "X86_OP_IMM";
		case X86_OP_MEM: return "X86_OP_MEM";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed x86 prefix @c p.
 */
string x86_prefix_2_string(uint8_t p)
{
	switch (p)
	{
		case X86_PREFIX_LOCK: return "X86_PREFIX_LOCK";
		case X86_PREFIX_REP: return "X86_PREFIX_REP(E)";
		case X86_PREFIX_REPNE: return "X86_PREFIX_REPNE";
		case X86_PREFIX_CS: return "X86_PREFIX_CS";
		case X86_PREFIX_SS: return "X86_PREFIX_SS";
		case X86_PREFIX_DS: return "X86_PREFIX_DS";
		case X86_PREFIX_ES: return "X86_PREFIX_ES";
		case X86_PREFIX_FS: return "X86_PREFIX_FS";
		case X86_PREFIX_GS: return "X86_PREFIX_GS";
		case X86_PREFIX_OPSIZE: return "X86_PREFIX_OPSIZE";
		case X86_PREFIX_ADDRSIZE: return "X86_PREFIX_ADDRSIZE";
		default: return "-";
	}
}

/**
 * @return String representation of the passed x86 SSE cc @c sse_cc.
 */
string x86_sse_cc_2_string(x86_sse_cc sse_cc)
{
	switch (sse_cc)
	{
		case X86_SSE_CC_INVALID: return "X86_SSE_CC_INVALID";
		case X86_SSE_CC_EQ: return "X86_SSE_CC_EQ";
		case X86_SSE_CC_LT: return "X86_SSE_CC_LT";
		case X86_SSE_CC_LE: return "X86_SSE_CC_LE";
		case X86_SSE_CC_UNORD: return "X86_SSE_CC_UNORD";
		case X86_SSE_CC_NEQ: return "X86_SSE_CC_NEQ";
		case X86_SSE_CC_NLT: return "X86_SSE_CC_NLT";
		case X86_SSE_CC_NLE: return "X86_SSE_CC_NLE";
		case X86_SSE_CC_ORD: return "X86_SSE_CC_ORD";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed x86 AVX cc @c avx_cc.
 */
string x86_avx_cc_2_string(x86_avx_cc avx_cc)
{
	switch (avx_cc)
	{
		case X86_AVX_CC_INVALID: return "X86_AVX_CC_INVALID";
		case X86_AVX_CC_EQ: return "X86_AVX_CC_EQ";
		case X86_AVX_CC_LT: return "X86_AVX_CC_LT";
		case X86_AVX_CC_LE: return "X86_AVX_CC_LE";
		case X86_AVX_CC_UNORD: return "X86_AVX_CC_UNORD";
		case X86_AVX_CC_NEQ: return "X86_AVX_CC_NEQ";
		case X86_AVX_CC_NLT: return "X86_AVX_CC_NLT";
		case X86_AVX_CC_NLE: return "X86_AVX_CC_NLE";
		case X86_AVX_CC_ORD: return "X86_AVX_CC_ORD";
		case X86_AVX_CC_EQ_UQ: return "X86_AVX_CC_EQ_UQ";
		case X86_AVX_CC_NGE: return "X86_AVX_CC_NGE";
		case X86_AVX_CC_NGT: return "X86_AVX_CC_NGT";
		case X86_AVX_CC_FALSE: return "X86_AVX_CC_FALSE";
		case X86_AVX_CC_NEQ_OQ: return "X86_AVX_CC_NEQ_OQ";
		case X86_AVX_CC_GE: return "X86_AVX_CC_GE";
		case X86_AVX_CC_GT: return "X86_AVX_CC_GT";
		case X86_AVX_CC_TRUE: return "X86_AVX_CC_TRUE";
		case X86_AVX_CC_EQ_OS: return "X86_AVX_CC_EQ_OS";
		case X86_AVX_CC_LT_OQ: return "X86_AVX_CC_LT_OQ";
		case X86_AVX_CC_LE_OQ: return "X86_AVX_CC_LE_OQ";
		case X86_AVX_CC_UNORD_S: return "X86_AVX_CC_UNORD_S";
		case X86_AVX_CC_NEQ_US: return "X86_AVX_CC_NEQ_US";
		case X86_AVX_CC_NLT_UQ: return "X86_AVX_CC_NLT_UQ";
		case X86_AVX_CC_NLE_UQ: return "X86_AVX_CC_NLE_UQ";
		case X86_AVX_CC_ORD_S: return "X86_AVX_CC_ORD_S";
		case X86_AVX_CC_EQ_US: return "X86_AVX_CC_EQ_US";
		case X86_AVX_CC_NGE_UQ: return "X86_AVX_CC_NGE_UQ";
		case X86_AVX_CC_NGT_UQ: return "X86_AVX_CC_NGT_UQ";
		case X86_AVX_CC_FALSE_OS: return "X86_AVX_CC_FALSE_OS";
		case X86_AVX_CC_NEQ_OS: return "X86_AVX_CC_NEQ_OS";
		case X86_AVX_CC_GE_OQ: return "X86_AVX_CC_GE_OQ";
		case X86_AVX_CC_GT_OQ: return "X86_AVX_CC_GT_OQ";
		case X86_AVX_CC_TRUE_US: return "X86_AVX_CC_TRUE_US";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed x86 AVX rm @c avx_rm.
 */
string x86_avx_rm_2_string(x86_avx_rm avx_rm)
{
	switch (avx_rm)
	{
		case X86_AVX_RM_INVALID: return "X86_AVX_RM_INVALID";
		case X86_AVX_RM_RN: return "X86_AVX_RM_RN";
		case X86_AVX_RM_RD: return "X86_AVX_RM_RD";
		case X86_AVX_RM_RU: return "X86_AVX_RM_RU";
		case X86_AVX_RM_RZ: return "X86_AVX_RM_RZ";
		default: return "UNKNOWN";
	}
}

/**
 * @return String representation of the passed x86 AVX bcast @c bcast.
 */
string x86_avx_bcast_2_string(x86_avx_bcast bcast)
{
	switch (bcast)
	{
		case X86_AVX_BCAST_INVALID: return "X86_AVX_BCAST_INVALID";
		case X86_AVX_BCAST_2: return "X86_AVX_BCAST_2";
		case X86_AVX_BCAST_4: return "X86_AVX_BCAST_4";
		case X86_AVX_BCAST_8: return "X86_AVX_BCAST_8";
		case X86_AVX_BCAST_16: return "X86_AVX_BCAST_16";
		default: return "UNKNOWN";
	}
}

void dump_cs_x86_op(csh handle, cs_x86_op& op)
{
	cout << "\t\t\t" << "type   :  " << x86_op_type_2_string(op.type) << endl;
	switch (op.type)
	{
		case X86_OP_REG:
		{
			cout << "\t\t\t" << "reg    :  " << reg_2_string(handle, op.reg)
					<< endl;
			break;
		}
		case X86_OP_IMM:
		{
			cout << "\t\t\t" << "imm    :  " << hex << op.imm << endl;
			break;
		}
		case X86_OP_MEM:
		{
			cout << "\t\t\t" << "seg r  :  "
					<< reg_2_string(handle, op.mem.segment) << endl;
			cout << "\t\t\t" << "base r :  "
					<< reg_2_string(handle, op.mem.base) << endl;
			cout << "\t\t\t" << "idx r  :  "
					<< reg_2_string(handle, op.mem.index) << endl;
			cout << "\t\t\t" << "scale  :  " << dec << op.mem.scale << endl;
			cout << "\t\t\t" << "disp   :  " << hex << op.mem.disp << endl;
			break;
		}
		case X86_OP_INVALID:
		{
			break;
		}
		default:
		{
			assert(false && "impossible value");
			break;
		}
	}
	cout << "\t\t\t" << "size   :  " << dec << unsigned(op.size) << endl;

	cout << "\t\t\t" << "access :  " << cs_ac_type_2_string(op.access)
			<< endl;

	cout << "\t\t\t" << "avx bct:  " << x86_avx_bcast_2_string(op.avx_bcast)
			<< endl;

	cout << "\t\t\t" << "avx 0 m:  " << boolalpha << op.avx_zero_opmask << endl;
}

/**
 * Dump arch dependent details about instruction from @c cs_x86.
 */
void dumpInstructionArchDependentX86(csh handle, cs_x86* i)
{
	cout << "\t\t" << "prefix :  "
			<< getHexStringRepre(i->prefix, 4)
			<< " (" << x86_prefix_2_string(i->prefix[0])
			<< ", " << x86_prefix_2_string(i->prefix[1])
			<< ", " << x86_prefix_2_string(i->prefix[2])
			<< ", " << x86_prefix_2_string(i->prefix[3])
			<< ")" << endl;
	cout << "\t\t" << "opcode :  "
				<< getHexStringRepre(i->opcode, 4) << endl;
	cout << "\t\t" << "rex    :  " << dec << unsigned(i->rex) << endl;
	cout << "\t\t" << "addr sz:  " << dec
			<< unsigned(i->addr_size) << endl;
	cout << "\t\t" << "modrm  :  " << dec << unsigned(i->modrm) << endl;
	cout << "\t\t" << "sib    :  " << dec << unsigned(i->sib) << endl;
	cout << "\t\t" << "disp   :  " << dec << i->disp << endl;
	cout << "\t\t" << "sib idx:  " << dec << reg_2_string(handle, i->sib_index)
			<< endl;
	cout << "\t\t" << "sib sc :  " << dec << unsigned(i->sib_scale) << endl;
	cout << "\t\t" << "sib bs :  " << dec << reg_2_string(handle, i->sib_base)
			<< endl;
	cout << "\t\t" << "sse cc :  " << x86_sse_cc_2_string(i->sse_cc) << endl;
	cout << "\t\t" << "avx cc :  " << x86_avx_cc_2_string(i->avx_cc) << endl;
	cout << "\t\t" << "avx sae:  " << boolalpha << i->avx_sae << endl;
	cout << "\t\t" << "avx rm :  " << x86_avx_rm_2_string(i->avx_rm) << endl;
	cout << "\t\t" << "op cnt :  " << dec << unsigned(i->op_count) << endl;

	for (unsigned j = 0; j < i->op_count; ++j)
	{
		cout << endl;
		dump_cs_x86_op(handle, i->operands[j]);
	}
}

} // namespace capstone_dumper
