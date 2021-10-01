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

std::string arm64_vas_2_string(arm64_vas vas)
{
	switch (vas)
	{
		case ARM64_VAS_INVALID: return "ARM64_VAS_INVALID";
		case ARM64_VAS_8B: return "ARM64_VAS_8B";
		case ARM64_VAS_16B: return "ARM64_VAS_16B";
		case ARM64_VAS_4H: return "ARM64_VAS_4H";
		case ARM64_VAS_8H: return "ARM64_VAS_8H";
		case ARM64_VAS_2S: return "ARM64_VAS_2S";
		case ARM64_VAS_4S: return "ARM64_VAS_4S";
		case ARM64_VAS_1D: return "ARM64_VAS_1D";
		case ARM64_VAS_2D: return "ARM64_VAS_2D";
		case ARM64_VAS_1Q: return "ARM64_VAS_1Q";
		default: return "UNKNOWN";
	}
}

std::string arm64_vess_2_string(arm64_vess vess)
{
	switch (vess)
	{
		case ARM64_VESS_INVALID: return "ARM64_VESS_INVALID";
		case ARM64_VESS_B: return "ARM64_VESS_B";
		case ARM64_VESS_H: return "ARM64_VESS_H";
		case ARM64_VESS_S: return "ARM64_VESS_S";
		case ARM64_VESS_D: return "ARM64_VESS_D";
		default: return "UNKNOWN";
	}
}

std::string arm64_ext_2_string(arm64_extender ext)
{
	switch (ext)
	{
		case ARM64_EXT_INVALID: return "ARM64_EXT_INVALID";
		case ARM64_EXT_UXTB: return "ARM64_EXT_UXTB";
		case ARM64_EXT_UXTH: return "ARM64_EXT_UXTH";
		case ARM64_EXT_UXTW: return "ARM64_EXT_UXTW";
		case ARM64_EXT_UXTX: return "ARM64_EXT_UXTX";
		case ARM64_EXT_SXTB: return "ARM64_EXT_SXTB";
		case ARM64_EXT_SXTH: return "ARM64_EXT_SXTH";
		case ARM64_EXT_SXTW: return "ARM64_EXT_SXTW";
		case ARM64_EXT_SXTX: return "ARM64_EXT_SXTX";
		default: return "UNKNOWN";
	}
}

std::string arm64_pstate_2_string(arm64_pstate ps)
{
	switch (ps)
	{
		case ARM64_PSTATE_INVALID: return "ARM64_PSTATE_INVALID";
		case ARM64_PSTATE_SPSEL: return "ARM64_PSTATE_SPSEL";
		case ARM64_PSTATE_DAIFSET: return "ARM64_PSTATE_DAIFSET";
		case ARM64_PSTATE_DAIFCLR: return "ARM64_PSTATE_DAIFCLR";
		default: return "UNKNOWN";
	}
}

std::string arm64_msr_reg_2_string(arm64_reg r)
{
	switch (r)
	{
		case ARM64_SYSREG_DBGDTRTX_EL0: return "ARM64_SYSREG_DBGDTRTX_EL0";
		case ARM64_SYSREG_OSLAR_EL1: return "ARM64_SYSREG_OSLAR_EL1";
		case ARM64_SYSREG_PMSWINC_EL0: return "ARM64_SYSREG_PMSWINC_EL0";
		case ARM64_SYSREG_TRCOSLAR: return "ARM64_SYSREG_TRCOSLAR";
		case ARM64_SYSREG_TRCLAR: return "ARM64_SYSREG_TRCLAR";
		case ARM64_SYSREG_ICC_EOIR1_EL1: return "ARM64_SYSREG_ICC_EOIR1_EL1";
		case ARM64_SYSREG_ICC_EOIR0_EL1: return "ARM64_SYSREG_ICC_EOIR0_EL1";
		case ARM64_SYSREG_ICC_DIR_EL1: return "ARM64_SYSREG_ICC_DIR_EL1";
		case ARM64_SYSREG_ICC_SGI1R_EL1: return "ARM64_SYSREG_ICC_SGI1R_EL1";
		case ARM64_SYSREG_ICC_ASGI1R_EL1: return "ARM64_SYSREG_ICC_ASGI1R_EL1";
		case ARM64_SYSREG_ICC_SGI0R_EL1: return "ARM64_SYSREG_ICC_SGI0R_EL1";
		default: return "UNKNOWN";
	}
}

std::string arm64_mrs_reg_2_string(arm64_reg r)
{
	switch (r)
	{
		default: return "UNKNOWN";
	}
}

std::string arm64_prefetch_2_string(arm64_prefetch_op pf)
{
	switch (pf)
	{
		case ARM64_PRFM_INVALID: return "ARM64_PRFM_INVALID";
		case ARM64_PRFM_PLDL1KEEP: return "ARM64_PRFM_PLDL1KEEP";
		case ARM64_PRFM_PLDL1STRM: return "ARM64_PRFM_PLDL1STRM";
		case ARM64_PRFM_PLDL2KEEP: return "ARM64_PRFM_PLDL2KEEP";
		case ARM64_PRFM_PLDL2STRM: return "ARM64_PRFM_PLDL2STRM";
		case ARM64_PRFM_PLDL3KEEP: return "ARM64_PRFM_PLDL3KEEP";
		case ARM64_PRFM_PLDL3STRM: return "ARM64_PRFM_PLDL3STRM";
		case ARM64_PRFM_PLIL1KEEP: return "ARM64_PRFM_PLIL1KEEP";
		case ARM64_PRFM_PLIL1STRM: return "ARM64_PRFM_PLIL1STRM";
		case ARM64_PRFM_PLIL2KEEP: return "ARM64_PRFM_PLIL2KEEP";
		case ARM64_PRFM_PLIL2STRM: return "ARM64_PRFM_PLIL2STRM";
		case ARM64_PRFM_PLIL3KEEP: return "ARM64_PRFM_PLIL3KEEP";
		case ARM64_PRFM_PLIL3STRM: return "ARM64_PRFM_PLIL3STRM";
		case ARM64_PRFM_PSTL1KEEP: return "ARM64_PRFM_PSTL1KEEP";
		case ARM64_PRFM_PSTL1STRM: return "ARM64_PRFM_PSTL1STRM";
		case ARM64_PRFM_PSTL2KEEP: return "ARM64_PRFM_PSTL2KEEP";
		case ARM64_PRFM_PSTL2STRM: return "ARM64_PRFM_PSTL2STRM";
		case ARM64_PRFM_PSTL3KEEP: return "ARM64_PRFM_PSTL3KEEP";
		case ARM64_PRFM_PSTL3STRM: return "ARM64_PRFM_PSTL3STRM";
		default: return "UNKNOWN";
	}
}

std::string arm64_barrier_2_string(arm64_barrier_op bo)
{
	switch (bo)
	{
		case ARM64_BARRIER_INVALID: return "ARM64_BARRIER_INVALID";
		case ARM64_BARRIER_OSHLD: return "ARM64_BARRIER_OSHLD";
		case ARM64_BARRIER_OSHST: return "ARM64_BARRIER_OSHST";
		case ARM64_BARRIER_OSH: return "ARM64_BARRIER_OSH";
		case ARM64_BARRIER_NSHLD: return "ARM64_BARRIER_NSHLD";
		case ARM64_BARRIER_NSHST: return "ARM64_BARRIER_NSHST";
		case ARM64_BARRIER_NSH: return "ARM64_BARRIER_NSH";
		case ARM64_BARRIER_ISHLD: return "ARM64_BARRIER_ISHLD";
		case ARM64_BARRIER_ISHST: return "ARM64_BARRIER_ISHST";
		case ARM64_BARRIER_ISH: return "ARM64_BARRIER_ISH";
		case ARM64_BARRIER_LD: return "ARM64_BARRIER_LD";
		case ARM64_BARRIER_ST: return "ARM64_BARRIER_ST";
		case ARM64_BARRIER_SY: return "ARM64_BARRIER_SY";
		default: return "UNKNOWN";
	}
}

std::string arm64_cc_2_string(arm64_cc cc)
{
	switch (cc)
	{
		case ARM64_CC_INVALID: return "ARM64_CC_INVALID";
		case ARM64_CC_EQ: return "ARM64_CC_EQ";
		case ARM64_CC_NE: return "ARM64_CC_NE";
		case ARM64_CC_HS: return "ARM64_CC_HS";
		case ARM64_CC_LO: return "ARM64_CC_LO";
		case ARM64_CC_MI: return "ARM64_CC_MI";
		case ARM64_CC_PL: return "ARM64_CC_PL";
		case ARM64_CC_VS: return "ARM64_CC_VS";
		case ARM64_CC_VC: return "ARM64_CC_VC";
		case ARM64_CC_HI: return "ARM64_CC_HI";
		case ARM64_CC_LS: return "ARM64_CC_LS";
		case ARM64_CC_GE: return "ARM64_CC_GE";
		case ARM64_CC_LT: return "ARM64_CC_LT";
		case ARM64_CC_GT: return "ARM64_CC_GT";
		case ARM64_CC_LE: return "ARM64_CC_LE";
		case ARM64_CC_AL: return "ARM64_CC_AL";
		case ARM64_CC_NV: return "ARM64_CC_NV";
		default: return "UNKNOWN";
	}
}

std::string arm64_barrier_op_2_string(arm64_barrier_op bp)
{
	switch (bp)
	{
		case ARM64_BARRIER_INVALID: return "ARM64_BARRIER_INVALID";
		case ARM64_BARRIER_OSHLD: return "ARM64_BARRIER_OSHLD";
		case ARM64_BARRIER_OSHST: return "ARM64_BARRIER_OSHST";
		case ARM64_BARRIER_OSH: return "ARM64_BARRIER_OSH";
		case ARM64_BARRIER_NSHLD: return "ARM64_BARRIER_NSHLD";
		case ARM64_BARRIER_NSHST: return "ARM64_BARRIER_NSHST";
		case ARM64_BARRIER_NSH: return "ARM64_BARRIER_NSH";
		case ARM64_BARRIER_ISHLD: return "ARM64_BARRIER_ISHLD";
		case ARM64_BARRIER_ISHST: return "ARM64_BARRIER_ISHST";
		case ARM64_BARRIER_ISH: return "ARM64_BARRIER_ISH";
		case ARM64_BARRIER_LD: return "ARM64_BARRIER_LD";
		case ARM64_BARRIER_ST: return "ARM64_BARRIER_ST";
		case ARM64_BARRIER_SY: return "ARM64_BARRIER_SY";
		default: return "UNKNOWN";
	}
}

std::string arm64_shifter_2_string(arm64_shifter sft)
{
	switch (sft)
	{
		case ARM64_SFT_INVALID: return "ARM64_SFT_INVALID";
		case ARM64_SFT_LSL: return "ARM64_SFT_LSL";
		case ARM64_SFT_MSL: return "ARM64_SFT_MSL";
		case ARM64_SFT_LSR: return "ARM64_SFT_LSR";
		case ARM64_SFT_ASR: return "ARM64_SFT_ASR";
		case ARM64_SFT_ROR: return "ARM64_SFT_ROR";
		default: return "UNKNOWN";
	}
}

std::string arm64_op_type_2_string(arm64_op_type opt)
{
	switch (opt)
	{
		case ARM64_OP_INVALID: return "ARM64_OP_INVALID";
		case ARM64_OP_REG: return "ARM64_OP_REG";
		case ARM64_OP_IMM: return "ARM64_OP_IMM";
		case ARM64_OP_MEM: return "ARM64_OP_MEM";
		case ARM64_OP_FP: return "ARM64_OP_FP";
		case ARM64_OP_CIMM: return "ARM64_OP_CIMM";
		case ARM64_OP_REG_MRS: return "ARM64_OP_REG_MRS";
		case ARM64_OP_REG_MSR: return "ARM64_OP_REG_MSR";
		case ARM64_OP_PSTATE: return "ARM64_OP_PSTATE";
		case ARM64_OP_SYS: return "ARM64_OP_SYS";
		case ARM64_OP_PREFETCH: return "ARM64_OP_PREFETCH";
		case ARM64_OP_BARRIER: return "ARM64_OP_BARRIER";
		default: return "UNKNOWN";
	}
}

std::string arm64_sysreg_2_string(arm64_reg sys) {
	switch (sys)
	{
		case ARM64_SYSREG_INVALID: return "ARM64_SYSREG_INVALID";
		case ARM64_SYSREG_MDCCSR_EL0: return "ARM64_SYSREG_MDCCSR_EL0";
		case ARM64_SYSREG_DBGDTRRX_EL0: return "ARM64_SYSREG_DBGDTRRX_EL0";
		case ARM64_SYSREG_MDRAR_EL1: return "ARM64_SYSREG_MDRAR_EL1";
		case ARM64_SYSREG_OSLSR_EL1: return "ARM64_SYSREG_OSLSR_EL1";
		case ARM64_SYSREG_DBGAUTHSTATUS_EL1: return "ARM64_SYSREG_DBGAUTHSTATUS_EL1";
		case ARM64_SYSREG_PMCEID0_EL0: return "ARM64_SYSREG_PMCEID0_EL0";
		case ARM64_SYSREG_PMCEID1_EL0: return "ARM64_SYSREG_PMCEID1_EL0";
		case ARM64_SYSREG_MIDR_EL1: return "ARM64_SYSREG_MIDR_EL1";
		case ARM64_SYSREG_CCSIDR_EL1: return "ARM64_SYSREG_CCSIDR_EL1";
		case ARM64_SYSREG_CLIDR_EL1: return "ARM64_SYSREG_CLIDR_EL1";
		case ARM64_SYSREG_CTR_EL0: return "ARM64_SYSREG_CTR_EL0";
		case ARM64_SYSREG_MPIDR_EL1: return "ARM64_SYSREG_MPIDR_EL1";
		case ARM64_SYSREG_REVIDR_EL1: return "ARM64_SYSREG_REVIDR_EL1";
		case ARM64_SYSREG_AIDR_EL1: return "ARM64_SYSREG_AIDR_EL1";
		case ARM64_SYSREG_DCZID_EL0: return "ARM64_SYSREG_DCZID_EL0";
		case ARM64_SYSREG_ID_PFR0_EL1: return "ARM64_SYSREG_ID_PFR0_EL1";
		case ARM64_SYSREG_ID_PFR1_EL1: return "ARM64_SYSREG_ID_PFR1_EL1";
		case ARM64_SYSREG_ID_DFR0_EL1: return "ARM64_SYSREG_ID_DFR0_EL1";
		case ARM64_SYSREG_ID_AFR0_EL1: return "ARM64_SYSREG_ID_AFR0_EL1";
		case ARM64_SYSREG_ID_MMFR0_EL1: return "ARM64_SYSREG_ID_MMFR0_EL1";
		case ARM64_SYSREG_ID_MMFR1_EL1: return "ARM64_SYSREG_ID_MMFR1_EL1";
		case ARM64_SYSREG_ID_MMFR2_EL1: return "ARM64_SYSREG_ID_MMFR2_EL1";
		case ARM64_SYSREG_ID_MMFR3_EL1: return "ARM64_SYSREG_ID_MMFR3_EL1";
		case ARM64_SYSREG_ID_ISAR0_EL1: return "ARM64_SYSREG_ID_ISAR0_EL1";
		case ARM64_SYSREG_ID_ISAR1_EL1: return "ARM64_SYSREG_ID_ISAR1_EL1";
		case ARM64_SYSREG_ID_ISAR2_EL1: return "ARM64_SYSREG_ID_ISAR2_EL1";
		case ARM64_SYSREG_ID_ISAR3_EL1: return "ARM64_SYSREG_ID_ISAR3_EL1";
		case ARM64_SYSREG_ID_ISAR4_EL1: return "ARM64_SYSREG_ID_ISAR4_EL1";
		case ARM64_SYSREG_ID_ISAR5_EL1: return "ARM64_SYSREG_ID_ISAR5_EL1";
		case ARM64_SYSREG_ID_A64PFR0_EL1: return "ARM64_SYSREG_ID_A64PFR0_EL1";
		case ARM64_SYSREG_ID_A64PFR1_EL1: return "ARM64_SYSREG_ID_A64PFR1_EL1";
		case ARM64_SYSREG_ID_A64DFR0_EL1: return "ARM64_SYSREG_ID_A64DFR0_EL1";
		case ARM64_SYSREG_ID_A64DFR1_EL1: return "ARM64_SYSREG_ID_A64DFR1_EL1";
		case ARM64_SYSREG_ID_A64AFR0_EL1: return "ARM64_SYSREG_ID_A64AFR0_EL1";
		case ARM64_SYSREG_ID_A64AFR1_EL1: return "ARM64_SYSREG_ID_A64AFR1_EL1";
		case ARM64_SYSREG_ID_A64ISAR0_EL1: return "ARM64_SYSREG_ID_A64ISAR0_EL1";
		case ARM64_SYSREG_ID_A64ISAR1_EL1: return "ARM64_SYSREG_ID_A64ISAR1_EL1";
		case ARM64_SYSREG_ID_A64MMFR0_EL1: return "ARM64_SYSREG_ID_A64MMFR0_EL1";
		case ARM64_SYSREG_ID_A64MMFR1_EL1: return "ARM64_SYSREG_ID_A64MMFR1_EL1";
		case ARM64_SYSREG_MVFR0_EL1: return "ARM64_SYSREG_MVFR0_EL1";
		case ARM64_SYSREG_MVFR1_EL1: return "ARM64_SYSREG_MVFR1_EL1";
		case ARM64_SYSREG_MVFR2_EL1: return "ARM64_SYSREG_MVFR2_EL1";
		case ARM64_SYSREG_RVBAR_EL1: return "ARM64_SYSREG_RVBAR_EL1";
		case ARM64_SYSREG_RVBAR_EL2: return "ARM64_SYSREG_RVBAR_EL2";
		case ARM64_SYSREG_RVBAR_EL3: return "ARM64_SYSREG_RVBAR_EL3";
		case ARM64_SYSREG_ISR_EL1: return "ARM64_SYSREG_ISR_EL1";
		case ARM64_SYSREG_CNTPCT_EL0: return "ARM64_SYSREG_CNTPCT_EL0";
		case ARM64_SYSREG_CNTVCT_EL0: return "ARM64_SYSREG_CNTVCT_EL0";
		case ARM64_SYSREG_TRCSTATR: return "ARM64_SYSREG_TRCSTATR";
		case ARM64_SYSREG_TRCIDR8: return "ARM64_SYSREG_TRCIDR8";
		case ARM64_SYSREG_TRCIDR9: return "ARM64_SYSREG_TRCIDR9";
		case ARM64_SYSREG_TRCIDR10: return "ARM64_SYSREG_TRCIDR10";
		case ARM64_SYSREG_TRCIDR11: return "ARM64_SYSREG_TRCIDR11";
		case ARM64_SYSREG_TRCIDR12: return "ARM64_SYSREG_TRCIDR12";
		case ARM64_SYSREG_TRCIDR13: return "ARM64_SYSREG_TRCIDR13";
		case ARM64_SYSREG_TRCIDR0: return "ARM64_SYSREG_TRCIDR0";
		case ARM64_SYSREG_TRCIDR1: return "ARM64_SYSREG_TRCIDR1";
		case ARM64_SYSREG_TRCIDR2: return "ARM64_SYSREG_TRCIDR2";
		case ARM64_SYSREG_TRCIDR3: return "ARM64_SYSREG_TRCIDR3";
		case ARM64_SYSREG_TRCIDR4: return "ARM64_SYSREG_TRCIDR4";
		case ARM64_SYSREG_TRCIDR5: return "ARM64_SYSREG_TRCIDR5";
		case ARM64_SYSREG_TRCIDR6: return "ARM64_SYSREG_TRCIDR6";
		case ARM64_SYSREG_TRCIDR7: return "ARM64_SYSREG_TRCIDR7";
		case ARM64_SYSREG_TRCOSLSR: return "ARM64_SYSREG_TRCOSLSR";
		case ARM64_SYSREG_TRCPDSR: return "ARM64_SYSREG_TRCPDSR";
		case ARM64_SYSREG_TRCDEVAFF0: return "ARM64_SYSREG_TRCDEVAFF0";
		case ARM64_SYSREG_TRCDEVAFF1: return "ARM64_SYSREG_TRCDEVAFF1";
		case ARM64_SYSREG_TRCLSR: return "ARM64_SYSREG_TRCLSR";
		case ARM64_SYSREG_TRCAUTHSTATUS: return "ARM64_SYSREG_TRCAUTHSTATUS";
		case ARM64_SYSREG_TRCDEVARCH: return "ARM64_SYSREG_TRCDEVARCH";
		case ARM64_SYSREG_TRCDEVID: return "ARM64_SYSREG_TRCDEVID";
		case ARM64_SYSREG_TRCDEVTYPE: return "ARM64_SYSREG_TRCDEVTYPE";
		case ARM64_SYSREG_TRCPIDR4: return "ARM64_SYSREG_TRCPIDR4";
		case ARM64_SYSREG_TRCPIDR5: return "ARM64_SYSREG_TRCPIDR5";
		case ARM64_SYSREG_TRCPIDR6: return "ARM64_SYSREG_TRCPIDR6";
		case ARM64_SYSREG_TRCPIDR7: return "ARM64_SYSREG_TRCPIDR7";
		case ARM64_SYSREG_TRCPIDR0: return "ARM64_SYSREG_TRCPIDR0";
		case ARM64_SYSREG_TRCPIDR1: return "ARM64_SYSREG_TRCPIDR1";
		case ARM64_SYSREG_TRCPIDR2: return "ARM64_SYSREG_TRCPIDR2";
		case ARM64_SYSREG_TRCPIDR3: return "ARM64_SYSREG_TRCPIDR3";
		case ARM64_SYSREG_TRCCIDR0: return "ARM64_SYSREG_TRCCIDR0";
		case ARM64_SYSREG_TRCCIDR1: return "ARM64_SYSREG_TRCCIDR1";
		case ARM64_SYSREG_TRCCIDR2: return "ARM64_SYSREG_TRCCIDR2";
		case ARM64_SYSREG_TRCCIDR3: return "ARM64_SYSREG_TRCCIDR3";
		case ARM64_SYSREG_ICC_IAR1_EL1: return "ARM64_SYSREG_ICC_IAR1_EL1";
		case ARM64_SYSREG_ICC_IAR0_EL1: return "ARM64_SYSREG_ICC_IAR0_EL1";
		case ARM64_SYSREG_ICC_HPPIR1_EL1: return "ARM64_SYSREG_ICC_HPPIR1_EL1";
		case ARM64_SYSREG_ICC_HPPIR0_EL1: return "ARM64_SYSREG_ICC_HPPIR0_EL1";
		case ARM64_SYSREG_ICC_RPR_EL1: return "ARM64_SYSREG_ICC_RPR_EL1";
		case ARM64_SYSREG_ICH_VTR_EL2: return "ARM64_SYSREG_ICH_VTR_EL2";
		case ARM64_SYSREG_ICH_EISR_EL2: return "ARM64_SYSREG_ICH_EISR_EL2";
		case ARM64_SYSREG_ICH_ELSR_EL2: return "ARM64_SYSREG_ICH_ELSR_EL2";
		default: return "UNKNOWN";
	}
}

void dump_cs_arm64_op(csh handle, cs_arm64_op& op)
{
	cout << "\t\t\t" << "op type    :  " << arm64_op_type_2_string(op.type)
			<< endl;
	cout << "\t\t\t" << "vector idx :  " << dec << op.vector_index << endl;
	cout << "\t\t\t" << "vas        :  " << arm64_vas_2_string(op.vas) << endl;
	cout << "\t\t\t" << "vess       :  " << arm64_vess_2_string(op.vess) << endl;

	// Struct shift.
	cout << "\t\t\t" << "shift type :  " << arm64_shifter_2_string(op.shift.type)
			<< endl;
	cout << "\t\t\t" << "shift val  :  " << dec << op.shift.value << endl;

	cout << "\t\t\t" << "ext type   :  " << arm64_ext_2_string(op.ext) << endl;

	switch (op.type)
	{
		case ARM64_OP_INVALID:
		{
			break;
		}
		case ARM64_OP_REG:
		{
			cout << "\t\t\t" << "reg        :  " << reg_2_string(handle, op.reg) << endl;
			break;
		}
		case ARM64_OP_IMM:
		case ARM64_OP_CIMM:
		{
			cout << "\t\t\t" << "imm        :  " << hex << op.imm << endl;
			break;
		}
		case ARM64_OP_MEM:
		{
			cout << "\t\t\t" << "base reg   :  " << reg_2_string(handle, op.mem.base) << endl;
			cout << "\t\t\t" << "idx reg    :  " << reg_2_string(handle, op.mem.index) << endl;
			cout << "\t\t\t" << "disp       :  " << dec << op.mem.disp << endl;
			break;
		}
		case ARM64_OP_FP:
		{
			cout << "\t\t\t" << "fp         :  " << hex << op.fp << endl;
			break;
		}
		case ARM64_OP_PSTATE:
		{
			cout << "\t\t\t" << "pstate     :  " << arm64_pstate_2_string(op.pstate) << endl;
			break;
		}
		case ARM64_OP_REG_MRS:
		{
			// This is prob no even used and OP_SYS is prefered
			cout << "\t\t\t" << "reg mrs    :  " << arm64_mrs_reg_2_string(op.reg) << endl;
			// TODO: mrs x8, teecr32_el1?
			break;
		}
		case ARM64_OP_REG_MSR:
		{
			// This is prob no even used and OP_SYS is prefered
			//cout << "\t\t\t" << "reg msr    :  " << arm64_msr_reg_2_string(op.reg) << endl;
			cout << "\t\t\t" << "reg msr    :  " << reg_2_string(handle, op.reg) << endl;
			break;
		}
		case ARM64_OP_SYS:
		{
			//cout << "\t\t\t" << "sys        :  " << hex << op.sys << endl;
			cout << "\t\t\t" << "sys        :  " << arm64_sysreg_2_string(op.reg) << endl;
			// To distinguish between operation type {IC, DC, AT, TLBI} the initial instruction
			// is needed e.g. ARM64_INS_IC, so we only print hex

			// From source
			//unsigned int sys;  ///< IC/DC/AT/TLBI operation (see arm64_ic_op, arm64_dc_op, arm64_at_op, arm64_tlbi_op)
			break;
		}
		case ARM64_OP_PREFETCH:
		{
			cout << "\t\t\t" << "prefetch   :  " << arm64_prefetch_2_string(op.prefetch) << endl;
			break;

		}
		case ARM64_OP_BARRIER:
		{
			cout << "\t\t\t" << "barrier    :  " << arm64_barrier_2_string(op.barrier) << endl;
			break;
		}
		default:
		{
			assert(false && "unhandled value");
			break;
		}
	}

	cout << "\t\t\t" << "access     :  " << cs_ac_type_2_string(op.access) << endl;
}

void dumpInstructionArchDependentArm64(csh handle, cs_arm64* i)
{
	cout << "\t\t" << "cond code :  " << arm64_cc_2_string(i->cc) << endl;
	cout << "\t\t" << "update fs :  " << boolalpha << i->update_flags << endl;
	cout << "\t\t" << "writeback :  " << boolalpha << i->writeback << endl;
	cout << "\t\t" << "op count  :  " << dec << unsigned(i->op_count)
			<< endl;

	for (unsigned j = 0; j < i->op_count; ++j)
	{
		cout << endl;
		dump_cs_arm64_op(handle, i->operands[j]);
	}
}

} // namespace capstone_dumper
