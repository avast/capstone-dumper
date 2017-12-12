# Capstone Dumper

A utility that lets you see all the information Capstone can provide about specified instruction(s).

## Usage Example

The following example dumps information about `x86` instructions `add eax, eax` and `mov ebx, eax` located at address `0x1234`:
```
./capstone-dumper -a x86 -b 0x1234 -t "add eax, eax; mov ebx, eax"

Keystone input : add eax, eax; mov ebx, eax
Keystone output: 01 c0 89 c3


Capstone version: 1024 (major: 4, minor: 0)


#0
        General info:
                id     :  8 (add)
                addr   :  1234
                size   :  2
                bytes  :  01 c0
                mnem   :  add
                op str :  eax, eax
        Detail info:
                R regs :  0
                W regs :  1
                        25 (eflags)
                groups :  0
        Architecture-dependent info:
                prefix :  00 00 00 00  (-, -, -, -)
                opcode :  01 00 00 00
                rex    :  0
                addr sz:  4
                modrm  :  192
                sib    :  0
                disp   :  0
                sib idx:  0 (-)
                sib sc :  0
                sib bs :  0 (-)
                sse cc :  X86_SSE_CC_INVALID
                avx cc :  X86_AVX_CC_INVALID
                avx sae:  false
                avx rm :  X86_AVX_RM_INVALID
                op cnt :  2

                        type   :  X86_OP_REG
                        reg    :  19 (eax)
                        size   :  4
                        avx bct:  X86_AVX_BCAST_INVALID
                        avx 0 m:  false

                        type   :  X86_OP_REG
                        reg    :  19 (eax)
                        size   :  4
                        avx bct:  X86_AVX_BCAST_INVALID
                        avx 0 m:  false

#1
        General info:
                id     :  449 (mov)
                addr   :  1236
                size   :  2
                bytes  :  89 c3
                mnem   :  mov
                op str :  ebx, eax
        Detail info:
                R regs :  0
                W regs :  0
                groups :  0
        Architecture-dependent info:
                prefix :  00 00 00 00  (-, -, -, -)
                opcode :  89 00 00 00
                rex    :  0
                addr sz:  4
                modrm  :  195
                sib    :  0
                disp   :  0
                sib idx:  0 (-)
                sib sc :  0
                sib bs :  0 (-)
                sse cc :  X86_SSE_CC_INVALID
                avx cc :  X86_AVX_CC_INVALID
                avx sae:  false
                avx rm :  X86_AVX_RM_INVALID
                op cnt :  2

                        type   :  X86_OP_REG
                        reg    :  21 (ebx)
                        size   :  4
                        avx bct:  X86_AVX_BCAST_INVALID
                        avx 0 m:  false

                        type   :  X86_OP_REG
                        reg    :  19 (eax)
                        size   :  4
                        avx bct:  X86_AVX_BCAST_INVALID
                        avx 0 m:  false
```

The following example dumps information about the `arm` instruction encoded as `04 10 81 e2` located at the default address:
```
./capstone-dumper -a arm -c "04 10 81 e2"

Capstone version: 1024 (major: 4, minor: 0)


#0
        General info:
                id     :  2 (add)
                addr   :  1000
                size   :  4
                bytes  :  04 10 81 e2
                mnem   :  add
                op str :  r1, r1, #4
        Detail info:
                R regs :  0
                W regs :  0
                groups :  1
                        147 (arm)
        Architecture-dependent info:
                usermode  :  false
                vector sz :  0
                vector ty :  ARM_VECTORDATA_INVALID
                cspm ty   :  ARM_CPSMODE_INVALID
                csp flag  :  ARM_CPSFLAG_INVALID
                cond code :  ARM_CC_AL
                update fs :  false
                writeback :  false
                m barrier :  ARM_MB_INVALID
                op count    :  3

                        op type    :  ARM_OP_REG
                        vector idx :  -1
                        shift type :  ARM_SFT_INVALID
                        shift val  :  0
                        reg        :  67 (r1)
                        subtracted :  false
                        access     :  CS_AC_WRITE
                        neon lane  :  -1

                        op type    :  ARM_OP_REG
                        vector idx :  -1
                        shift type :  ARM_SFT_INVALID
                        shift val  :  0
                        reg        :  67 (r1)
                        subtracted :  false
                        access     :  CS_AC_READ
                        neon lane  :  -1

                        op type    :  ARM_OP_IMM
                        vector idx :  -1
                        shift type :  ARM_SFT_INVALID
                        shift val  :  0
                        imm        :  4
                        subtracted :  false
                        access     :  CS_AC_INVALID
                        neon lane  :  ffffffff
```

Run `./capstone-dumper -h` to list all the available options.

## Requirements

* A compiler supporting C++14
  * On Windows, only Microsoft Visual C++ is supported (version >= Visual Studio 2015).
* CMake (version >= 3.6)

## Build and Installation

* Clone the repository or download the sources into a directory named `capstone-dumper`.
  * `git clone https://github.com/avast-tl/capstone-dumper.git`
* Linux:
  * `cd capstone-dumper`
  * `mkdir build && cd build`
  * `cmake ..`
  * `make && make install`
* Windows:
  * Open MSBuild command prompt, or any terminal that is configured to run the `msbuild` command.
  * `cd capstone-dumper`
  * `mkdir build && cd build`
  * `cmake .. -G<generator>`
  * `msbuild /m /p:Configuration=Release capstone-dumper.sln`
  * `msbuild /m /p:Configuration=Release INSTALL.vcxproj`
  * Alternatively, you can open `capstone-dumper.sln` generated by `cmake` in Visual Studio IDE.

You must pass the following parameters to `cmake`:
* (Windows only) `-G<generator>` is `-G"Visual Studio 14 2015"` for 32-bit build using Visual Studio 2015, or `-G"Visual Studio 14 2015 Win64"` for 64-bit build using Visual Studio 2015. Later versions of Visual Studio may be used.

You can pass additional parameters to `cmake`:
* `-DCMAKE_BUILD_TYPE=Debug` to build with debugging information, which is useful during development. By default, the project is built in the `Release` mode. This has no effect on Windows, but the same thing can be achieved by running `msbuild` with `/p:Configuration=Debug` parameter.
* `-DCMAKE_INSTALL_PREFIX=<path>` to set a custom installation path to `<path>`.

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the `LICENSE` file for more details.

Capstone Dumper uses third-party libraries or other resources listed, along with their licenses, in the `LICENSE-THIRD-PARTY` file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast-tl/retdec/wiki/Contribution-Guidelines).
