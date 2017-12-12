/**
 * @file src/capstone-dumper/capstone_dumper.cpp
 * @brief Capstone usage demonstration application.
 *        Use all (as much as makes sense) capstone capabilities to decode and
 *        dump code snippets from various architectures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <tuple>

#include <keystone/keystone.h>

#include <tl-cpputils/conversion.h>

#include "capstone-dumper/capstone_dumper.h"

using namespace std;

namespace capstone_dumper {

/**
 * Convert binary @a data of @a size into printable hexadecimal string.
 */
string getHexStringRepre(uint8_t* data, size_t size)
{
	stringstream ret;
	for (unsigned j = 0; j < size; ++j)
	{
		ret << setw(2) << setfill('0') << hex
				<< int(data[j]) << " ";
	}
	return ret.str();
}

/**
 * Print capstone version get by cs_version().
 */
void printVersion()
{
	int major = 0;
	int minor = 0;
	int version = cs_version(&major, &minor);

	cout << endl;
	cout << "Capstone version: " << version << " (major: " << major
			<< ", minor: " << minor << ")" << endl;
}

/**
 * @return String representation of the passed architecture @c arch.
 */
string cs_arch_2_string(cs_arch arch)
{
	switch (arch)
	{
		case CS_ARCH_ARM: return "CS_ARCH_ARM";
		case CS_ARCH_ARM64: return "CS_ARCH_ARM64";
		case CS_ARCH_MIPS: return "CS_ARCH_MIPS";
		case CS_ARCH_X86: return "CS_ARCH_X86";
		case CS_ARCH_PPC: return "CS_ARCH_PPC";
		case CS_ARCH_SPARC: return "CS_ARCH_SPARC";
		case CS_ARCH_SYSZ: return "CS_ARCH_SYSZ";
		case CS_ARCH_XCORE: return "CS_ARCH_XCORE";
		case CS_ARCH_M68K: return "CS_ARCH_M68K";
		case CS_ARCH_TMS320C64X: return "CS_ARCH_TMS320C64X";
		case CS_ARCH_MAX: return "CS_ARCH_MAX";
		case CS_ARCH_ALL: return "CS_ARCH_ALL";
		default: return "UNKNOWN";
	}
}

/**
 *
 */
string reg_2_string(csh handle, unsigned reg)
{
	stringstream ret;

	string regName = "-";
	if (reg != ARM_REG_INVALID
			&& reg != ARM64_REG_INVALID
			&& reg != ARM64_SYSREG_INVALID
			&& reg != M68K_REG_INVALID
			&& reg != MIPS_REG_INVALID
			&& reg != PPC_REG_INVALID
			&& reg != X86_REG_INVALID
			&& reg != SPARC_REG_INVALID
			&& reg != SYSZ_REG_INVALID
			&& reg != XCORE_REG_INVALID
			&& reg != TMS320C64X_REG_INVALID)
	{
		regName = cs_reg_name(handle, reg);
	}
	ret << dec << reg << " (" << regName << ")";

	return ret.str();
}

std::string cs_ac_type_2_string(uint8_t a)
{
	if (a == CS_AC_INVALID) return "CS_AC_INVALID";
	if (a == CS_AC_READ + CS_AC_WRITE) return "CS_AC_READ + CS_AC_WRITE";
	if (a == CS_AC_READ) return "CS_AC_READ";
	if (a == CS_AC_WRITE) return "CS_AC_WRITE";
	return "UNKNOWN";
}

class ProgramOptions
{
	public:
		ProgramOptions()
		{

		}
		ProgramOptions(int argc, char *argv[])
		{
			if (argc > 0)
			{
				_programName = argv[0];
			}

			for (int i = 1; i < argc; ++i)
			{
				std::string c = argv[i];

				if (c == "-a")
				{
					_arch = getParamOrDie(argc, argv, i);
					if (_arch == "arm")
					{
						arch = CS_ARCH_ARM;
						basicMode = CS_MODE_ARM;
					}
					else if (_arch == "arm64")
					{
						arch = CS_ARCH_ARM64;
						basicMode = CS_MODE_ARM;
					}
					else if (_arch == "mips") arch = CS_ARCH_MIPS;
					else if (_arch == "x86") arch = CS_ARCH_X86;
					else if (_arch == "ppc") arch = CS_ARCH_PPC;
					else if (_arch == "sparc") arch = CS_ARCH_SPARC;
					else if (_arch == "sysz") arch = CS_ARCH_SYSZ;
					else if (_arch == "xcore") arch = CS_ARCH_XCORE;
					else if (_arch == "m68k") arch = CS_ARCH_M68K;
					else if (_arch == "tms320c64x") arch = CS_ARCH_TMS320C64X;
					else printHelpAndDie();
				}
				else if (c == "-b")
				{
					_base = getParamOrDie(argc, argv, i);
					if (!tl_cpputils::strToNum(_base, base, hex))
					{
						printHelpAndDie();
					}
				}
				else if (c == "-c")
				{
					_code = getParamOrDie(argc, argv, i);
					code = tl_cpputils::hexStringToBytes(_code);
				}
				else if (c == "-t")
				{
					text = getParamOrDie(argc, argv, i);
				}
				else if (c == "-m")
				{
					_basicMode = getParamOrDie(argc, argv, i);
					if (_basicMode == "arm") basicMode = CS_MODE_ARM;
					else if (_basicMode == "thumb") basicMode = CS_MODE_THUMB;
					else if (_basicMode == "16") basicMode = CS_MODE_16;
					else if (_basicMode == "32") basicMode = CS_MODE_32;
					else if (_basicMode == "64") basicMode = CS_MODE_64;
					else if (_basicMode == "mips3") basicMode = CS_MODE_MIPS3;
					else if (_basicMode == "mips32r6") basicMode = CS_MODE_MIPS32R6;
					else if (_basicMode == "mips32") basicMode = CS_MODE_MIPS32;
					else if (_basicMode == "mips64") basicMode = CS_MODE_MIPS64;
					else printHelpAndDie();
				}
				else if (c == "-e")
				{
					_extraMode = getParamOrDie(argc, argv, i);
					if (_extraMode == "little") extraMode = CS_MODE_LITTLE_ENDIAN;
					else if (_extraMode == "mclass") extraMode = CS_MODE_MCLASS;
					else if (_extraMode == "v8") extraMode = CS_MODE_V8;
					else if (_extraMode == "micro") extraMode = CS_MODE_MICRO;
					else if (_extraMode == "v9") extraMode = CS_MODE_V9;
					else if (_extraMode == "big") extraMode = CS_MODE_BIG_ENDIAN;
					else printHelpAndDie();
				}
				else if (c == "-h")
				{
					printHelpAndDie();
				}
				else if (c == "-s")
				{
					printSupportAndDie();
				}
				else
				{
					printHelpAndDie();
				}
			}
		}

		std::string getParamOrDie(int argc, char *argv[], int& i)
		{
			if (argc > i+1)
			{
				return argv[++i];
			}
			else
			{
				printHelpAndDie();
				return std::string();
			}
		}

		void dump() const
		{
			cout << endl;
			cout << "Program Options:" << endl;
			cout << "\t" << "arch     : " << arch << " (" << _arch << ")" << endl;
			cout << "\t" << "base     : " << hex << base << " (" << _base << ")" << endl;
			cout << "\t" << "code     : " << tl_cpputils::bytesToHexString(code) << " (" << _code << ")" << endl;
			cout << "\t" << "b mode   : " << hex << basicMode << " (" << _basicMode << ")" << endl;
			cout << "\t" << "e mode   : " << hex << extraMode << " (" << _extraMode << ")" << endl;
			cout << "\t" << "asm text : " << text << endl;
			cout << endl;
		}

		void printHelpAndDie()
		{
			cout << _programName << ":\n"
				"\t-a name   Set architecture name.\n"
				"\t          Possible values: arm, arm64, mips, x86, ppc, sparc, sysz, xcore, m68k, tms320c64x\n"
				"\t          Default value: x86.\n"
				"\t-b base   Base address in hexadecimal format (e.g. 0x1000).\n"
				"\t          Default value 0x1000.\n"
				"\t-c code   Binary data to decode in hexadecimal format.\n"
				"\t          E.g. \"0b 84 d1 a0 80 60 40\" or \"0b84d1a0806040\".\n"
				"\t-t asm    Assembly text to assemble, disassemble and dump.\n"
				"\t          Most of the time, this is more convenient than -c option.\n"
				"\t-m mode   Capstone basic mode to use.\n"
				"\t          Possible values: arm, thumb, 16, 32, 64, mips3, mips32r6,\n"
				"\t          mips32, mips64\n"
				"\t          Default value: 32.\n"
				"\t-e mode   Capstone extra mode to use.\n"
				"\t          Possible values: little, big, micro, mclass, v8, v9.\n"
				"\t          Default value: little.\n"
				"\t-h        Print this help message and exit.\n"
				"\t-s        Print supported architectures and exit.\n";

			exit(0);
		}

		/**
		 * Print supported architectures and modes.
		 */
		void printSupportAndDie()
		{
			printVersion();

			cout << endl;
			cout << cs_arch_2_string(CS_ARCH_ARM) << " is "
					<< (cs_support(CS_ARCH_ARM) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_ARM64) << " is "
					<< (cs_support(CS_ARCH_ARM64) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_MIPS) << " is "
					<< (cs_support(CS_ARCH_MIPS) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_X86) << " is "
					<< (cs_support(CS_ARCH_X86) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_PPC) << " is "
					<< (cs_support(CS_ARCH_PPC) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_SPARC) << " is "
					<< (cs_support(CS_ARCH_SPARC) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_SYSZ) << " is "
					<< (cs_support(CS_ARCH_SYSZ) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_XCORE) << " is "
					<< (cs_support(CS_ARCH_XCORE) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_M68K) << " is "
					<< (cs_support(CS_ARCH_M68K) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_TMS320C64X) << " is "
					<< (cs_support(CS_ARCH_TMS320C64X) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_MAX) << " is "
					<< (cs_support(CS_ARCH_MAX) ? "supported" : "unsupported") << endl;
			cout << cs_arch_2_string(CS_ARCH_ALL) << " is "
					<< (cs_support(CS_ARCH_ALL) ? "supported" : "unsupported") << endl;
			cout << "CS_SUPPORT_DIET" << " is "
					<< (cs_support(CS_SUPPORT_DIET) ? "supported" : "unsupported") << endl;
			cout << "CS_SUPPORT_X86_REDUCE" << " is "
					<< (cs_support(CS_SUPPORT_X86_REDUCE) ? "supported" : "unsupported") << endl;

			exit(0);
		}

	public:
		cs_arch arch = CS_ARCH_X86;
		uint64_t base = 0x1000;
		vector<uint8_t> code;
		string text;
		cs_mode basicMode = CS_MODE_32;
		cs_mode extraMode = CS_MODE_LITTLE_ENDIAN;

	private:
		string _programName = "capstone-dumper";
		string _arch;
		string _base;
		string _code;
		string _basicMode;
		string _extraMode;
};

/**
 * Print last error for the passed @a handle and call @c exit(1).
 */
void printErrorAndDie(csh handle)
{
	cs_err err = cs_errno(handle);
	cerr << "Error: " << cs_strerror(err) << endl;
	exit(1);
}

/**
 * Print passed error message @a msg and call @c exit(1).
 */
void printErrorAndDie(const string& msg)
{
	cerr << "Error: " << msg << endl;
	exit(1);
}

/**
 * @return Opened and configured Capstone handle.
 */
csh initAndConfigHandle(const ProgramOptions& po)
{
	csh handle;

	cs_mode mode = static_cast<cs_mode>(po.basicMode | po.extraMode);
	if (cs_open(po.arch, mode, &handle) != CS_ERR_OK)
	{
		printErrorAndDie(handle);
	}

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	{
		printErrorAndDie(handle);
	}

	return handle;
}

/**
 * Free instructions @a insn and close @a handle.
 */
void freeAndDestroyHandle(csh handle, cs_insn* insn, size_t count)
{
	cs_free(insn, count);

	if (cs_close(&handle) != CS_ERR_OK)
	{
		printErrorAndDie(handle);
	}
}

/**
 * Disassemble global @c CODE array using passed @a handle.
 * @return Pair of disassembled instructions and number of these instructions.
 */
pair<cs_insn*, size_t> disassemble(const ProgramOptions& po, csh handle)
{
	cs_insn* insn = nullptr;
	size_t disAll = 0;
	size_t count = cs_disasm(
			handle,
			po.code.data(),
			po.code.size(),
			po.base,
			disAll,
			&insn);
	if (count == 0)
	{
		printErrorAndDie("Failed to disassemble given code!");
		freeAndDestroyHandle(handle, insn, count);
	}
	return {insn, count};
}

/**
 * Dump general info about instruction from @c cs_insn.
 */
void dumpInstructionGeneral(csh handle, cs_insn* i)
{
	cout << "\t" << "General info:" << endl;

	cout << "\t\t" << "id     :  " << dec << i->id
			<< " (" << cs_insn_name(handle, i->id) << ")" << endl;
	cout << "\t\t" << "addr   :  " << hex << i->address << endl;
	cout << "\t\t" << "size   :  " << dec << i->size << endl;
	cout << "\t\t" << "bytes  :  "
			<< getHexStringRepre(i->bytes, i->size) << endl;
	cout << "\t\t" << "mnem   :  " << i->mnemonic << endl;
	cout << "\t\t" << "op str :  " << i->op_str << endl;
}

/**
 * Dump arch independent details about instruction from @c cs_detail.
 */
void dumpInstructionDetail(csh handle, cs_insn* i)
{
	cs_detail* detail = i->detail;

	cout << "\t" << "Detail info:" << endl;

	cout << "\t\t" << "R regs :  " << dec
			<< unsigned(detail->regs_read_count) << endl;
	for (unsigned j = 0; j < detail->regs_read_count; ++j)
	{
		uint32_t reg = detail->regs_read[j];
		cout << "\t\t\t" << dec << reg_2_string(handle, reg) << endl;
	}

	cout << "\t\t" << "W regs :  " << dec
			<< unsigned(detail->regs_write_count) << endl;
	for (unsigned j = 0; j < detail->regs_write_count; ++j)
	{
		uint32_t reg = detail->regs_write[j];
		cout << "\t\t\t" << dec << reg_2_string(handle, reg) << endl;
	}

	cout << "\t\t" << "groups :  " << dec
			<< unsigned(detail->groups_count) << endl;
	for (unsigned j = 0; j < detail->groups_count; ++j)
	{
		uint32_t g = detail->groups[j];
		cout << "\t\t\t" << dec << g
				<< " (" << cs_group_name(handle, g) << ")" << endl;
	}
}

/**
 * Dump arch dependent details about instruction from @c cs_x86, cs_arm, etc.
 */
void dumpInstructionArchDependent(ProgramOptions& po, csh handle, cs_insn* i)
{
	cout << "\t" << "Architecture-dependent info:" << endl;

	cs_detail* d = i->detail;
	switch (po.arch)
	{
		case CS_ARCH_ARM: dumpInstructionArchDependentArm(handle, &d->arm); return;
		case CS_ARCH_ARM64: dumpInstructionArchDependentArm64(handle, &d->arm64); return;
		case CS_ARCH_MIPS: dumpInstructionArchDependentMips(handle, &d->mips); return;
		case CS_ARCH_X86: dumpInstructionArchDependentX86(handle, &d->x86); return;
		case CS_ARCH_PPC: dumpInstructionArchDependentPpc(handle, &d->ppc); return;
		case CS_ARCH_SPARC: dumpInstructionArchDependentSparc(handle, &d->sparc); return;
		case CS_ARCH_SYSZ: dumpInstructionArchDependentSysz(handle, &d->sysz); return;
		case CS_ARCH_XCORE: dumpInstructionArchDependentXcore(handle, &d->xcore); return;
		case CS_ARCH_M68K: dumpInstructionArchDependentM68k(handle, &d->m68k); return;
		case CS_ARCH_TMS320C64X: dumpInstructionArchDependentTms320c64x(handle, &d->tms320c64x); return;
		default: assert(false && "Unsupported architecture."); return;
	}
}

/**
 * Dump all the information from @a insn instruction array.
 */
void dumpInstructions(ProgramOptions& po, csh handle, cs_insn* insn, size_t count)
{
	cout << endl;
	for (size_t j = 0; j < count; ++j)
	{
		cout << "\n#" << j << endl;

		cs_insn* i = &(insn[j]);

		dumpInstructionGeneral(handle, i);
		dumpInstructionDetail(handle, i);
		dumpInstructionArchDependent(po, handle, i);
	}
}

ks_arch capstoneArchToKeystoneArch(cs_arch a)
{
	switch (a)
	{
		case CS_ARCH_ARM: return KS_ARCH_ARM;
		case CS_ARCH_ARM64: return KS_ARCH_ARM64;
		case CS_ARCH_MIPS: return KS_ARCH_MIPS;
		case CS_ARCH_X86: return KS_ARCH_X86;
		case CS_ARCH_PPC: return KS_ARCH_PPC;
		case CS_ARCH_SPARC: return KS_ARCH_SPARC;
		case CS_ARCH_SYSZ: return KS_ARCH_SYSTEMZ;
		case CS_ARCH_XCORE:
		case CS_ARCH_M68K:
		case CS_ARCH_TMS320C64X:
		case CS_ARCH_MAX:
		case CS_ARCH_ALL:
		default:
			cerr << "Can not convert Capstone arch to Keystone arch." << endl;
			exit(1);
	}
}

ks_mode capstoneModeBasicToKeystoneMode(cs_arch a, cs_mode m)
{
	if (m == CS_MODE_16) // 1 << 1
	{
		return KS_MODE_16;
	}
	else if (m == CS_MODE_32) // 1 << 2 == CS_MODE_MIPS32
	{
		return KS_MODE_32;
	}
	else if (m == CS_MODE_64) // 1 << 3 == CS_MODE_MIPS64
	{
		return KS_MODE_64;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_ARM) // 0
	{
		return KS_MODE_ARM;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_THUMB) // 1 << 4
	{
		return KS_MODE_THUMB;
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MIPS3) // 1 << 5
	{
		return KS_MODE_MIPS3;
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MIPS32R6) // 1 << 6
	{
		return KS_MODE_MIPS32R6;
	}
	else
	{
		cerr << "Can not convert Capstone basic mode to Keystone mode." << endl;
		exit(1);
	}
}

ks_mode capstoneModeExtraToKeystoneMode(cs_arch a, cs_mode m)
{
	if (m == CS_MODE_LITTLE_ENDIAN) // 0
	{
		return KS_MODE_LITTLE_ENDIAN;
	}
	else if (m == CS_MODE_BIG_ENDIAN) // 1 << 31
	{
		return KS_MODE_BIG_ENDIAN;
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_MCLASS) // 1 << 5
	{
		return KS_MODE_LITTLE_ENDIAN; // There is no MCLASS in Keystone.
	}
	else if (a == CS_ARCH_ARM && m == CS_MODE_V8) // 1 << 6
	{
		return KS_MODE_V8;
	}
	else if (a == CS_ARCH_MIPS && m == CS_MODE_MICRO) // 1 << 4
	{
		return KS_MODE_MICRO;
	}
	else if (a == CS_ARCH_SPARC && m == CS_MODE_V9) // 1 << 4
	{
		return KS_MODE_V9;
	}
	else
	{
		cerr << "Can not convert Capstone extra mode to Keystone mode." << endl;
		exit(1);
	}
}

/**
 * Use keystone do assemble input asm into bytes that will be disassembled.
 */
void assemble(ProgramOptions& po)
{
	ks_engine *ks;
	ks_err err;

	ks_arch arch = capstoneArchToKeystoneArch(po.arch);
	ks_mode basic = capstoneModeBasicToKeystoneMode(po.arch, po.basicMode);
	ks_mode extra = capstoneModeExtraToKeystoneMode(po.arch, po.extraMode);

	if ((err = ks_open(arch, basic | extra, &ks)) != KS_ERR_OK)
	{
		cerr << "Keystone Error: " << ks_strerror(err) << endl;
		exit(1);
	}

	unsigned char* enc;
	size_t sz;
	size_t cnt;

	if (ks_asm(ks, po.text.data(), po.base, &enc, &sz, &cnt) != KS_ERR_OK)
	{
		err = ks_errno(ks);
		cerr << "Keystone Error: " << ks_strerror(err) << endl;
		exit(1);
	}

	po.code.clear();
	po.code.reserve(sz);
	for (size_t i = 0; i < sz; ++i)
	{
		po.code.push_back(enc[i]);
	}

	ks_free(enc);
	if ((err = ks_close(ks)) != KS_ERR_OK)
	{
		cerr << "Keystone Error: " << ks_strerror(err) << endl;
		exit(1);
	}

	cout << endl;
	cout << "Keystone input : " << po.text << endl;
	cout << "Keystone output: "
			<< getHexStringRepre(po.code.data(), po.code.size()) << endl;
	cout << endl;
}

} // namespace capstone_dumper

using namespace capstone_dumper;

/**
 * Main function -- just calls all the other functions.
 */
int main(int argc, char *argv[])
{
	ProgramOptions po(argc, argv);

	if (!po.text.empty())
	{
		assemble(po);
	}

	printVersion();

	csh handle = initAndConfigHandle(po);

	cs_insn* insn = nullptr;
	size_t count = 0;
	tie(insn, count) = disassemble(po, handle);

	dumpInstructions(po, handle, insn, count);

	freeAndDestroyHandle(handle, insn, count);

	cout << endl;
	return EXIT_SUCCESS;
}
