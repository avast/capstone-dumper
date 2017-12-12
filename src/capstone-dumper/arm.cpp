/**
 * @file src/capstone-dumper/arm.cpp
 * @brief ARM specific code.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

std::string arm_vectordata_type_2_string(arm_vectordata_type vt)
{
	switch (vt)
	{
		case ARM_VECTORDATA_INVALID: return "ARM_VECTORDATA_INVALID";
		case ARM_VECTORDATA_I8: return "ARM_VECTORDATA_I8";
		case ARM_VECTORDATA_I16: return "ARM_VECTORDATA_I16";
		case ARM_VECTORDATA_I32: return "ARM_VECTORDATA_I32";
		case ARM_VECTORDATA_I64: return "ARM_VECTORDATA_I64";
		case ARM_VECTORDATA_S8: return "ARM_VECTORDATA_S8";
		case ARM_VECTORDATA_S16: return "ARM_VECTORDATA_S16";
		case ARM_VECTORDATA_S32: return "ARM_VECTORDATA_S32";
		case ARM_VECTORDATA_S64: return "ARM_VECTORDATA_S64";
		case ARM_VECTORDATA_U8: return "ARM_VECTORDATA_U8";
		case ARM_VECTORDATA_U16: return "ARM_VECTORDATA_U16";
		case ARM_VECTORDATA_U32: return "ARM_VECTORDATA_U32";
		case ARM_VECTORDATA_U64: return "ARM_VECTORDATA_U64";
		case ARM_VECTORDATA_P8: return "ARM_VECTORDATA_P8";
		case ARM_VECTORDATA_F32: return "ARM_VECTORDATA_F32";
		case ARM_VECTORDATA_F64: return "ARM_VECTORDATA_F64";
		case ARM_VECTORDATA_F16F64: return "ARM_VECTORDATA_F16F64";
		case ARM_VECTORDATA_F64F16: return "ARM_VECTORDATA_F64F16";
		case ARM_VECTORDATA_F32F16: return "ARM_VECTORDATA_F32F16";
		case ARM_VECTORDATA_F16F32: return "ARM_VECTORDATA_F16F32";
		case ARM_VECTORDATA_F64F32: return "ARM_VECTORDATA_F64F32";
		case ARM_VECTORDATA_F32F64: return "ARM_VECTORDATA_F32F64";
		case ARM_VECTORDATA_S32F32: return "ARM_VECTORDATA_S32F32";
		case ARM_VECTORDATA_U32F32: return "ARM_VECTORDATA_U32F32";
		case ARM_VECTORDATA_F32S32: return "ARM_VECTORDATA_F32S32";
		case ARM_VECTORDATA_F32U32: return "ARM_VECTORDATA_F32U32";
		case ARM_VECTORDATA_F64S16: return "ARM_VECTORDATA_F64S16";
		case ARM_VECTORDATA_F32S16: return "ARM_VECTORDATA_F32S16";
		case ARM_VECTORDATA_F64S32: return "ARM_VECTORDATA_F64S32";
		case ARM_VECTORDATA_S16F64: return "ARM_VECTORDATA_S16F64";
		case ARM_VECTORDATA_S16F32: return "ARM_VECTORDATA_S16F32";
		case ARM_VECTORDATA_S32F64: return "ARM_VECTORDATA_S32F64";
		case ARM_VECTORDATA_U16F64: return "ARM_VECTORDATA_U16F64";
		case ARM_VECTORDATA_U16F32: return "ARM_VECTORDATA_U16F32";
		case ARM_VECTORDATA_U32F64: return "ARM_VECTORDATA_U32F64";
		case ARM_VECTORDATA_F64U16: return "ARM_VECTORDATA_F64U16";
		case ARM_VECTORDATA_F32U16: return "ARM_VECTORDATA_F32U16";
		case ARM_VECTORDATA_F64U32: return "ARM_VECTORDATA_F64U32";
		default: return "UNKNOWN";
	}
}

std::string arm_cpsmode_type_2_string(arm_cpsmode_type ty)
{
	switch (ty)
	{
		case ARM_CPSMODE_INVALID: return "ARM_CPSMODE_INVALID";
		case ARM_CPSMODE_IE: return "ARM_CPSMODE_IE";
		case ARM_CPSMODE_ID: return "ARM_CPSMODE_ID";
		default: return "UNKNOWN";
	}
}

std::string arm_cpsflag_type_2_string(arm_cpsflag_type ty)
{
	switch (ty)
	{
		case ARM_CPSFLAG_INVALID: return "ARM_CPSFLAG_INVALID";
		case ARM_CPSFLAG_F: return "ARM_CPSFLAG_F";
		case ARM_CPSFLAG_I: return "ARM_CPSFLAG_I";
		case ARM_CPSFLAG_A: return "ARM_CPSFLAG_A";
		case ARM_CPSFLAG_NONE: return "ARM_CPSFLAG_NONE";
		default: return "UNKNOWN";
	}
}

std::string arm_cc_2_string(arm_cc cc)
{
	switch (cc)
	{
		case ARM_CC_INVALID: return "ARM_CC_INVALID";
		case ARM_CC_EQ: return "ARM_CC_EQ";
		case ARM_CC_NE: return "ARM_CC_NE";
		case ARM_CC_HS: return "ARM_CC_HS";
		case ARM_CC_LO: return "ARM_CC_LO";
		case ARM_CC_MI: return "ARM_CC_MI";
		case ARM_CC_PL: return "ARM_CC_PL";
		case ARM_CC_VS: return "ARM_CC_VS";
		case ARM_CC_VC: return "ARM_CC_VC";
		case ARM_CC_HI: return "ARM_CC_HI";
		case ARM_CC_LS: return "ARM_CC_LS";
		case ARM_CC_GE: return "ARM_CC_GE";
		case ARM_CC_LT: return "ARM_CC_LT";
		case ARM_CC_GT: return "ARM_CC_GT";
		case ARM_CC_LE: return "ARM_CC_LE";
		case ARM_CC_AL: return "ARM_CC_AL";
		default: return "UNKNOWN";
	}
}

std::string arm_mem_barrier_2_string(arm_mem_barrier mb)
{
	switch (mb)
	{
		case ARM_MB_INVALID: return "ARM_MB_INVALID";
		case ARM_MB_RESERVED_0: return "ARM_MB_RESERVED_0";
		case ARM_MB_OSHLD: return "ARM_MB_OSHLD";
		case ARM_MB_OSHST: return "ARM_MB_OSHST";
		case ARM_MB_OSH: return "ARM_MB_OSH";
		case ARM_MB_RESERVED_4: return "ARM_MB_RESERVED_4";
		case ARM_MB_NSHLD: return "ARM_MB_NSHLD";
		case ARM_MB_NSHST: return "ARM_MB_NSHST";
		case ARM_MB_NSH: return "ARM_MB_NSH";
		case ARM_MB_RESERVED_8: return "ARM_MB_RESERVED_8";
		case ARM_MB_ISHLD: return "ARM_MB_ISHLD";
		case ARM_MB_ISHST: return "ARM_MB_ISHST";
		case ARM_MB_ISH: return "ARM_MB_ISH";
		case ARM_MB_RESERVED_12: return "ARM_MB_RESERVED_12";
		case ARM_MB_LD: return "ARM_MB_LD";
		case ARM_MB_ST: return "ARM_MB_ST";
		case ARM_MB_SY: return "ARM_MB_SY";
		default: return "UNKNOWN";
	}
}

std::string arm_shifter_2_string(arm_shifter sft)
{
	switch (sft)
	{
		case ARM_SFT_INVALID: return "ARM_SFT_INVALID";
		case ARM_SFT_ASR: return "ARM_SFT_ASR";
		case ARM_SFT_LSL: return "ARM_SFT_LSL";
		case ARM_SFT_LSR: return "ARM_SFT_LSR";
		case ARM_SFT_ROR: return "ARM_SFT_ROR";
		case ARM_SFT_RRX: return "ARM_SFT_RRX";
		case ARM_SFT_ASR_REG: return "ARM_SFT_ASR_REG";
		case ARM_SFT_LSL_REG: return "ARM_SFT_LSL_REG";
		case ARM_SFT_LSR_REG: return "ARM_SFT_LSR_REG";
		case ARM_SFT_ROR_REG: return "ARM_SFT_ROR_REG";
		case ARM_SFT_RRX_REG: return "ARM_SFT_RRX_REG";
		default: return "UNKNOWN";
	}
}

std::string arm_op_type_2_string(arm_op_type opt)
{
	switch (opt)
	{
		case ARM_OP_INVALID: return "ARM_OP_INVALID";
		case ARM_OP_REG: return "ARM_OP_REG";
		case ARM_OP_IMM: return "ARM_OP_IMM";
		case ARM_OP_MEM: return "ARM_OP_MEM";
		case ARM_OP_FP: return "ARM_OP_FP";
		case ARM_OP_CIMM: return "ARM_OP_CIMM";
		case ARM_OP_PIMM: return "ARM_OP_PIMM";
		case ARM_OP_SETEND: return "ARM_OP_SETEND";
		case ARM_OP_SYSREG: return "ARM_OP_SYSREG";
		default: return "UNKNOWN";
	}
}

std::string arm_setend_type_2_string(arm_setend_type ty)
{
	switch (ty)
	{
		case ARM_SETEND_INVALID: return "ARM_SETEND_INVALID";
		case ARM_SETEND_BE: return "ARM_SETEND_BE";
		case ARM_SETEND_LE: return "ARM_SETEND_LE";
		default: return "UNKNOWN";
	}
}

void dump_cs_arm_op(csh handle, cs_arm_op& op)
{
	cout << "\t\t\t" << "op type    :  " << arm_op_type_2_string(op.type)
			<< endl;
	cout << "\t\t\t" << "vector idx :  " << dec << op.vector_index << endl;
	cout << "\t\t\t" << "shift type :  " << arm_shifter_2_string(op.shift.type)
			<< endl;
	cout << "\t\t\t" << "shift val  :  " << dec << op.shift.value << endl;

	switch (op.type)
	{
		case ARM_OP_INVALID:
		{
			break;
		}
		case ARM_OP_SYSREG:
		case ARM_OP_REG:
		{
			cout << "\t\t\t" << "reg        :  " << reg_2_string(handle, op.reg)
					<< endl;
			break;
		}
		case ARM_OP_IMM:
		case ARM_OP_PIMM:
		case ARM_OP_CIMM:
		{
			cout << "\t\t\t" << "imm        :  " << hex << op.imm << endl;
			break;
		}
		case ARM_OP_MEM:
		{
			cout << "\t\t\t" << "base reg   :  "
					<< reg_2_string(handle, op.mem.base) << endl;
			cout << "\t\t\t" << "idx reg    :  "
					<< reg_2_string(handle, op.mem.index) << endl;
			cout << "\t\t\t" << "scale      :  " << dec << op.mem.scale << endl;
			cout << "\t\t\t" << "disp       :  " << dec << op.mem.disp << endl;
			cout << "\t\t\t" << "lshift     :  " << dec << op.mem.lshift << endl;
			break;
		}
		case ARM_OP_FP:
		{
			cout << "\t\t\t" << "fp         :  " << hex << op.fp << endl;
			break;
		}
		case ARM_OP_SETEND:
		{
			cout << "\t\t\t" << "setend     :  "
					<< arm_setend_type_2_string(op.setend) << endl;
			break;
		}
		default:
		{
			assert(false && "unhandled value");
			break;
		}
	}

	cout << "\t\t\t" << "subtracted :  " << boolalpha << op.subtracted << endl;
	cout << "\t\t\t" << "access     :  " << cs_ac_type_2_string(op.access)
			<< endl;
	cout << "\t\t\t" << "neon lane  :  " << int(op.neon_lane) << endl;
}

void dumpInstructionArchDependentArm(csh handle, cs_arm* i)
{
	cout << "\t\t" << "usermode  :  " << boolalpha << i->usermode << endl;
	cout << "\t\t" << "vector sz :  " << dec << i->vector_size << endl;
	cout << "\t\t" << "vector ty :  "
			<< arm_vectordata_type_2_string(i->vector_data) << endl;
	cout << "\t\t" << "cspm ty   :  "
			<< arm_cpsmode_type_2_string(i->cps_mode) << endl;
	cout << "\t\t" << "csp flag  :  "
			<< arm_cpsflag_type_2_string(i->cps_flag) << endl;
	cout << "\t\t" << "cond code :  "
			<< arm_cc_2_string(i->cc) << endl;
	cout << "\t\t" << "update fs :  " << boolalpha << i->update_flags << endl;
	cout << "\t\t" << "writeback :  " << boolalpha << i->writeback << endl;
	cout << "\t\t" << "m barrier :  "
			<< arm_mem_barrier_2_string(i->mem_barrier) << endl;

	cout << "\t\t" << "op count    :  " << dec << unsigned(i->op_count)
			<< std::endl;

	for (unsigned j = 0; j < i->op_count; ++j)
	{
		cout << endl;
		dump_cs_arm_op(handle, i->operands[j]);
	}
}

} // namespace capstone_dumper
