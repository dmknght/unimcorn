# Generated @ 2023-09-24T22:15:22+07:00
# Command line:
#   /home/dmknght/.nimble/pkgs/nimterop-#head/nimterop/toast --prefix=_ --suffix=_ -s -G__=_ --preprocess -m:c --recurse --pnim --nim:/usr/bin/nim /usr/include/unicorn/unicorn.h --includeDirs+=/usr/include/unicorn/ -o /tmp/unicorn

# const 'DEFAULT_VISIBILITY' has unsupported value '__attribute__((visibility("default")))'
# const 'UNICORN_EXPORT' has unsupported value '__attribute__((visibility("default")))'
# const 'UNICORN_DEPRECATED' has unsupported value '__attribute__((deprecated))'
# const 'UC_VERSION_MAJOR' has unsupported value 'UC_API_MAJOR'
# const 'UC_VERSION_MINOR' has unsupported value 'UC_API_MINOR'
# const 'UC_VERSION_PATCH' has unsupported value 'UC_API_PATCH'
# const 'UC_VERSION_EXTRA' has unsupported value 'UC_API_EXTRA'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}


{.pragma: impunicornHdr, header: "/usr/include/unicorn/unicorn.h".}
{.experimental: "codeReordering".}
{.passC: "-I/usr/include/unicorn/".}
defineEnum(uc_cpu_m68k)      ## ```
                             ##   > M68K CPU
                             ## ```
defineEnum(uc_m68k_reg)      ## ```
                             ##   > M68K registers
                             ## ```
defineEnum(uc_cpu_x86) ## ```
                       ##   This file is released under LGPL2.
                       ##      See COPYING.LGPL2 in root directory for more details
                       ##   
                       ##     
                       ##    This file is to support header files that are missing in MSVC and
                       ##    other non-standard compilers.
                       ##   
                       ##     > X86 CPU
                       ## ```
defineEnum(uc_x86_reg)       ## ```
                             ##   > X86 registers
                             ## ```
defineEnum(uc_x86_insn)      ## ```
                             ##   > X86 instructions
                             ## ```
defineEnum(uc_cpu_arm)       ## ```
                             ##   > ARM CPU
                             ## ```
defineEnum(uc_arm_reg)       ## ```
                             ##   > ARM registers
                             ## ```
defineEnum(uc_cpu_arm64)     ## ```
                             ##   > ARM64 CPU
                             ## ```
defineEnum(uc_arm64_reg)     ## ```
                             ##   > ARM64 registers
                             ## ```
defineEnum(uc_arm64_insn)    ## ```
                             ##   > ARM64 instructions
                             ## ```
defineEnum(uc_cpu_mips32) ## ```
                          ##   GCC MIPS toolchain has a default macro called "mips" which breaks
                          ##      compilation
                          ##     > MIPS32 CPUS
                          ## ```
defineEnum(uc_cpu_mips64)    ## ```
                             ##   > MIPS64 CPUS
                             ## ```
defineEnum(UC_MIPS_REG)      ## ```
                             ##   > MIPS registers
                             ## ```
defineEnum(uc_cpu_sparc32) ## ```
                           ##   GCC SPARC toolchain has a default macro called "sparc" which breaks
                           ##      compilation
                           ##     > SPARC32 CPU
                           ## ```
defineEnum(uc_cpu_sparc64)   ## ```
                             ##   > SPARC64 CPU
                             ## ```
defineEnum(uc_sparc_reg)     ## ```
                             ##   > SPARC registers
                             ## ```
defineEnum(uc_cpu_ppc)       ## ```
                             ##   > PPC CPU
                             ## ```
defineEnum(uc_cpu_ppc64)     ## ```
                             ##   > PPC64 CPU
                             ## ```
defineEnum(uc_ppc_reg)       ## ```
                             ##   > PPC registers
                             ## ```
defineEnum(uc_cpu_riscv32)   ## ```
                             ##   > RISCV32 CPU
                             ## ```
defineEnum(uc_cpu_riscv64)   ## ```
                             ##   > RISCV64 CPU
                             ## ```
defineEnum(uc_riscv_reg)     ## ```
                             ##   > RISCV registers
                             ## ```
defineEnum(uc_cpu_s390x)     ## ```
                             ##   > S390X CPU
                             ## ```
defineEnum(uc_s390x_reg)     ## ```
                             ##   > S390X registers
                             ## ```
defineEnum(uc_cpu_tricore)   ## ```
                             ##   > TRICORE CPU
                             ## ```
defineEnum(uc_tricore_reg)   ## ```
                             ##   > TRICORE registers
                             ## ```
defineEnum(uc_arch)          ## ```
                             ##   Architecture type
                             ## ```
defineEnum(uc_mode)          ## ```
                             ##   Mode type
                             ## ```
defineEnum(uc_err)           ## ```
                             ##   All type of errors encountered by Unicorn API.
                             ##      These are values returned by uc_errno()
                             ## ```
defineEnum(uc_mem_type)      ## ```
                             ##   All type of memory accesses for UC_HOOK_MEM_*
                             ## ```
defineEnum(uc_tcg_op_code) ## ```
                           ##   These are all op codes we support to hook for UC_HOOK_TCG_OP_CODE.
                           ##      Be cautious since it may bring much more overhead than UC_HOOK_CODE without
                           ##      proper flags.
                           ##      TODO: Tracing UC_TCG_OP_CALL should be interesting.
                           ## ```
defineEnum(uc_tcg_op_flag) ## ```
                           ##   These are extra flags to be paired with uc_tcg_op_code which is helpful to
                           ##      instrument in some certain cases.
                           ## ```
defineEnum(uc_hook_type)     ## ```
                             ##   All type of hooks for uc_hook_add() API.
                             ## ```
defineEnum(uc_query_type)    ## ```
                             ##   All type of queries for uc_query() API.
                             ## ```
defineEnum(uc_control_type) ## ```
                            ##   All type of controls for uc_ctl API.
                            ##      The controls are organized in a tree level.
                            ##      If a control don't have Set or Get for @args, it means it's r/o or w/o.
                            ## ```
defineEnum(uc_prot)
const
  MSC_VER_VS2003* = 1310
  MSC_VER_VS2005* = 1400
  MSC_VER_VS2008* = 1500
  MSC_VER_VS2010* = 1600
  MSC_VER_VS2012* = 1700
  MSC_VER_VS2013* = 1800
  MSC_VER_VS2015* = 1900
  UC_CPU_M68K_M5206* = (0).uc_cpu_m68k
  UC_CPU_M68K_M68000* = (UC_CPU_M68K_M5206 + 1).uc_cpu_m68k
  UC_CPU_M68K_M68020* = (UC_CPU_M68K_M68000 + 1).uc_cpu_m68k
  UC_CPU_M68K_M68030* = (UC_CPU_M68K_M68020 + 1).uc_cpu_m68k
  UC_CPU_M68K_M68040* = (UC_CPU_M68K_M68030 + 1).uc_cpu_m68k
  UC_CPU_M68K_M68060* = (UC_CPU_M68K_M68040 + 1).uc_cpu_m68k
  UC_CPU_M68K_M5208* = (UC_CPU_M68K_M68060 + 1).uc_cpu_m68k
  UC_CPU_M68K_CFV4E* = (UC_CPU_M68K_M5208 + 1).uc_cpu_m68k
  UC_CPU_M68K_ANY* = (UC_CPU_M68K_CFV4E + 1).uc_cpu_m68k
  UC_CPU_M68K_ENDING* = (UC_CPU_M68K_ANY + 1).uc_cpu_m68k
  UC_M68K_REG_INVALID* = (0).uc_m68k_reg
  UC_M68K_REG_A0* = (UC_M68K_REG_INVALID + 1).uc_m68k_reg
  UC_M68K_REG_A1* = (UC_M68K_REG_A0 + 1).uc_m68k_reg
  UC_M68K_REG_A2* = (UC_M68K_REG_A1 + 1).uc_m68k_reg
  UC_M68K_REG_A3* = (UC_M68K_REG_A2 + 1).uc_m68k_reg
  UC_M68K_REG_A4* = (UC_M68K_REG_A3 + 1).uc_m68k_reg
  UC_M68K_REG_A5* = (UC_M68K_REG_A4 + 1).uc_m68k_reg
  UC_M68K_REG_A6* = (UC_M68K_REG_A5 + 1).uc_m68k_reg
  UC_M68K_REG_A7* = (UC_M68K_REG_A6 + 1).uc_m68k_reg
  UC_M68K_REG_D0* = (UC_M68K_REG_A7 + 1).uc_m68k_reg
  UC_M68K_REG_D1* = (UC_M68K_REG_D0 + 1).uc_m68k_reg
  UC_M68K_REG_D2* = (UC_M68K_REG_D1 + 1).uc_m68k_reg
  UC_M68K_REG_D3* = (UC_M68K_REG_D2 + 1).uc_m68k_reg
  UC_M68K_REG_D4* = (UC_M68K_REG_D3 + 1).uc_m68k_reg
  UC_M68K_REG_D5* = (UC_M68K_REG_D4 + 1).uc_m68k_reg
  UC_M68K_REG_D6* = (UC_M68K_REG_D5 + 1).uc_m68k_reg
  UC_M68K_REG_D7* = (UC_M68K_REG_D6 + 1).uc_m68k_reg
  UC_M68K_REG_SR* = (UC_M68K_REG_D7 + 1).uc_m68k_reg
  UC_M68K_REG_PC* = (UC_M68K_REG_SR + 1).uc_m68k_reg
  UC_M68K_REG_ENDING* = (UC_M68K_REG_PC + 1).uc_m68k_reg ## ```
                                                         ##   <-- mark the end of the list of registers
                                                         ## ```
  UC_CPU_X86_QEMU64* = (0).uc_cpu_x86
  UC_CPU_X86_PHENOM* = (UC_CPU_X86_QEMU64 + 1).uc_cpu_x86
  UC_CPU_X86_CORE2DUO* = (UC_CPU_X86_PHENOM + 1).uc_cpu_x86
  UC_CPU_X86_KVM64* = (UC_CPU_X86_CORE2DUO + 1).uc_cpu_x86
  UC_CPU_X86_QEMU32* = (UC_CPU_X86_KVM64 + 1).uc_cpu_x86
  UC_CPU_X86_KVM32* = (UC_CPU_X86_QEMU32 + 1).uc_cpu_x86
  UC_CPU_X86_COREDUO* = (UC_CPU_X86_KVM32 + 1).uc_cpu_x86
  UC_CPU_X86_486* = (UC_CPU_X86_COREDUO + 1).uc_cpu_x86
  UC_CPU_X86_PENTIUM* = (UC_CPU_X86_486 + 1).uc_cpu_x86
  UC_CPU_X86_PENTIUM2* = (UC_CPU_X86_PENTIUM + 1).uc_cpu_x86
  UC_CPU_X86_PENTIUM3* = (UC_CPU_X86_PENTIUM2 + 1).uc_cpu_x86
  UC_CPU_X86_ATHLON* = (UC_CPU_X86_PENTIUM3 + 1).uc_cpu_x86
  UC_CPU_X86_N270* = (UC_CPU_X86_ATHLON + 1).uc_cpu_x86
  UC_CPU_X86_CONROE* = (UC_CPU_X86_N270 + 1).uc_cpu_x86
  UC_CPU_X86_PENRYN* = (UC_CPU_X86_CONROE + 1).uc_cpu_x86
  UC_CPU_X86_NEHALEM* = (UC_CPU_X86_PENRYN + 1).uc_cpu_x86
  UC_CPU_X86_WESTMERE* = (UC_CPU_X86_NEHALEM + 1).uc_cpu_x86
  UC_CPU_X86_SANDYBRIDGE* = (UC_CPU_X86_WESTMERE + 1).uc_cpu_x86
  UC_CPU_X86_IVYBRIDGE* = (UC_CPU_X86_SANDYBRIDGE + 1).uc_cpu_x86
  UC_CPU_X86_HASWELL* = (UC_CPU_X86_IVYBRIDGE + 1).uc_cpu_x86
  UC_CPU_X86_BROADWELL* = (UC_CPU_X86_HASWELL + 1).uc_cpu_x86
  UC_CPU_X86_SKYLAKE_CLIENT* = (UC_CPU_X86_BROADWELL + 1).uc_cpu_x86
  UC_CPU_X86_SKYLAKE_SERVER* = (UC_CPU_X86_SKYLAKE_CLIENT + 1).uc_cpu_x86
  UC_CPU_X86_CASCADELAKE_SERVER* = (UC_CPU_X86_SKYLAKE_SERVER + 1).uc_cpu_x86
  UC_CPU_X86_COOPERLAKE* = (UC_CPU_X86_CASCADELAKE_SERVER + 1).uc_cpu_x86
  UC_CPU_X86_ICELAKE_CLIENT* = (UC_CPU_X86_COOPERLAKE + 1).uc_cpu_x86
  UC_CPU_X86_ICELAKE_SERVER* = (UC_CPU_X86_ICELAKE_CLIENT + 1).uc_cpu_x86
  UC_CPU_X86_DENVERTON* = (UC_CPU_X86_ICELAKE_SERVER + 1).uc_cpu_x86
  UC_CPU_X86_SNOWRIDGE* = (UC_CPU_X86_DENVERTON + 1).uc_cpu_x86
  UC_CPU_X86_KNIGHTSMILL* = (UC_CPU_X86_SNOWRIDGE + 1).uc_cpu_x86
  UC_CPU_X86_OPTERON_G1* = (UC_CPU_X86_KNIGHTSMILL + 1).uc_cpu_x86
  UC_CPU_X86_OPTERON_G2* = (UC_CPU_X86_OPTERON_G1 + 1).uc_cpu_x86
  UC_CPU_X86_OPTERON_G3* = (UC_CPU_X86_OPTERON_G2 + 1).uc_cpu_x86
  UC_CPU_X86_OPTERON_G4* = (UC_CPU_X86_OPTERON_G3 + 1).uc_cpu_x86
  UC_CPU_X86_OPTERON_G5* = (UC_CPU_X86_OPTERON_G4 + 1).uc_cpu_x86
  UC_CPU_X86_EPYC* = (UC_CPU_X86_OPTERON_G5 + 1).uc_cpu_x86
  UC_CPU_X86_DHYANA* = (UC_CPU_X86_EPYC + 1).uc_cpu_x86
  UC_CPU_X86_EPYC_ROME* = (UC_CPU_X86_DHYANA + 1).uc_cpu_x86
  UC_CPU_X86_ENDING* = (UC_CPU_X86_EPYC_ROME + 1).uc_cpu_x86
  UC_X86_REG_INVALID* = (0).uc_x86_reg
  UC_X86_REG_AH* = (UC_X86_REG_INVALID + 1).uc_x86_reg
  UC_X86_REG_AL* = (UC_X86_REG_AH + 1).uc_x86_reg
  UC_X86_REG_AX* = (UC_X86_REG_AL + 1).uc_x86_reg
  UC_X86_REG_BH* = (UC_X86_REG_AX + 1).uc_x86_reg
  UC_X86_REG_BL* = (UC_X86_REG_BH + 1).uc_x86_reg
  UC_X86_REG_BP* = (UC_X86_REG_BL + 1).uc_x86_reg
  UC_X86_REG_BPL* = (UC_X86_REG_BP + 1).uc_x86_reg
  UC_X86_REG_BX* = (UC_X86_REG_BPL + 1).uc_x86_reg
  UC_X86_REG_CH* = (UC_X86_REG_BX + 1).uc_x86_reg
  UC_X86_REG_CL* = (UC_X86_REG_CH + 1).uc_x86_reg
  UC_X86_REG_CS* = (UC_X86_REG_CL + 1).uc_x86_reg
  UC_X86_REG_CX* = (UC_X86_REG_CS + 1).uc_x86_reg
  UC_X86_REG_DH* = (UC_X86_REG_CX + 1).uc_x86_reg
  UC_X86_REG_DI* = (UC_X86_REG_DH + 1).uc_x86_reg
  UC_X86_REG_DIL* = (UC_X86_REG_DI + 1).uc_x86_reg
  UC_X86_REG_DL* = (UC_X86_REG_DIL + 1).uc_x86_reg
  UC_X86_REG_DS* = (UC_X86_REG_DL + 1).uc_x86_reg
  UC_X86_REG_DX* = (UC_X86_REG_DS + 1).uc_x86_reg
  UC_X86_REG_EAX* = (UC_X86_REG_DX + 1).uc_x86_reg
  UC_X86_REG_EBP* = (UC_X86_REG_EAX + 1).uc_x86_reg
  UC_X86_REG_EBX* = (UC_X86_REG_EBP + 1).uc_x86_reg
  UC_X86_REG_ECX* = (UC_X86_REG_EBX + 1).uc_x86_reg
  UC_X86_REG_EDI* = (UC_X86_REG_ECX + 1).uc_x86_reg
  UC_X86_REG_EDX* = (UC_X86_REG_EDI + 1).uc_x86_reg
  UC_X86_REG_EFLAGS* = (UC_X86_REG_EDX + 1).uc_x86_reg
  UC_X86_REG_EIP* = (UC_X86_REG_EFLAGS + 1).uc_x86_reg
  UC_X86_REG_ES* = (UC_X86_REG_EIP.uc_x86_reg +
      typeof(UC_X86_REG_EIP.uc_x86_reg)(2)).uc_x86_reg
  UC_X86_REG_ESI* = (UC_X86_REG_ES + 1).uc_x86_reg
  UC_X86_REG_ESP* = (UC_X86_REG_ESI + 1).uc_x86_reg
  UC_X86_REG_FPSW* = (UC_X86_REG_ESP + 1).uc_x86_reg
  UC_X86_REG_FS* = (UC_X86_REG_FPSW + 1).uc_x86_reg
  UC_X86_REG_GS* = (UC_X86_REG_FS + 1).uc_x86_reg
  UC_X86_REG_IP* = (UC_X86_REG_GS + 1).uc_x86_reg
  UC_X86_REG_RAX* = (UC_X86_REG_IP + 1).uc_x86_reg
  UC_X86_REG_RBP* = (UC_X86_REG_RAX + 1).uc_x86_reg
  UC_X86_REG_RBX* = (UC_X86_REG_RBP + 1).uc_x86_reg
  UC_X86_REG_RCX* = (UC_X86_REG_RBX + 1).uc_x86_reg
  UC_X86_REG_RDI* = (UC_X86_REG_RCX + 1).uc_x86_reg
  UC_X86_REG_RDX* = (UC_X86_REG_RDI + 1).uc_x86_reg
  UC_X86_REG_RIP* = (UC_X86_REG_RDX + 1).uc_x86_reg
  UC_X86_REG_RSI* = (UC_X86_REG_RIP.uc_x86_reg +
      typeof(UC_X86_REG_RIP.uc_x86_reg)(2)).uc_x86_reg
  UC_X86_REG_RSP* = (UC_X86_REG_RSI + 1).uc_x86_reg
  UC_X86_REG_SI* = (UC_X86_REG_RSP + 1).uc_x86_reg
  UC_X86_REG_SIL* = (UC_X86_REG_SI + 1).uc_x86_reg
  UC_X86_REG_SP* = (UC_X86_REG_SIL + 1).uc_x86_reg
  UC_X86_REG_SPL* = (UC_X86_REG_SP + 1).uc_x86_reg
  UC_X86_REG_SS* = (UC_X86_REG_SPL + 1).uc_x86_reg
  UC_X86_REG_CR0* = (UC_X86_REG_SS + 1).uc_x86_reg
  UC_X86_REG_CR1* = (UC_X86_REG_CR0 + 1).uc_x86_reg
  UC_X86_REG_CR2* = (UC_X86_REG_CR1 + 1).uc_x86_reg
  UC_X86_REG_CR3* = (UC_X86_REG_CR2 + 1).uc_x86_reg
  UC_X86_REG_CR4* = (UC_X86_REG_CR3 + 1).uc_x86_reg
  UC_X86_REG_CR8* = (UC_X86_REG_CR4.uc_x86_reg +
      typeof(UC_X86_REG_CR4.uc_x86_reg)(4)).uc_x86_reg
  UC_X86_REG_DR0* = (UC_X86_REG_CR8.uc_x86_reg +
      typeof(UC_X86_REG_CR8.uc_x86_reg)(8)).uc_x86_reg
  UC_X86_REG_DR1* = (UC_X86_REG_DR0 + 1).uc_x86_reg
  UC_X86_REG_DR2* = (UC_X86_REG_DR1 + 1).uc_x86_reg
  UC_X86_REG_DR3* = (UC_X86_REG_DR2 + 1).uc_x86_reg
  UC_X86_REG_DR4* = (UC_X86_REG_DR3 + 1).uc_x86_reg
  UC_X86_REG_DR5* = (UC_X86_REG_DR4 + 1).uc_x86_reg
  UC_X86_REG_DR6* = (UC_X86_REG_DR5 + 1).uc_x86_reg
  UC_X86_REG_DR7* = (UC_X86_REG_DR6 + 1).uc_x86_reg
  UC_X86_REG_FP0* = (UC_X86_REG_DR7.uc_x86_reg +
      typeof(UC_X86_REG_DR7.uc_x86_reg)(9)).uc_x86_reg
  UC_X86_REG_FP1* = (UC_X86_REG_FP0 + 1).uc_x86_reg
  UC_X86_REG_FP2* = (UC_X86_REG_FP1 + 1).uc_x86_reg
  UC_X86_REG_FP3* = (UC_X86_REG_FP2 + 1).uc_x86_reg
  UC_X86_REG_FP4* = (UC_X86_REG_FP3 + 1).uc_x86_reg
  UC_X86_REG_FP5* = (UC_X86_REG_FP4 + 1).uc_x86_reg
  UC_X86_REG_FP6* = (UC_X86_REG_FP5 + 1).uc_x86_reg
  UC_X86_REG_FP7* = (UC_X86_REG_FP6 + 1).uc_x86_reg
  UC_X86_REG_K0* = (UC_X86_REG_FP7 + 1).uc_x86_reg
  UC_X86_REG_K1* = (UC_X86_REG_K0 + 1).uc_x86_reg
  UC_X86_REG_K2* = (UC_X86_REG_K1 + 1).uc_x86_reg
  UC_X86_REG_K3* = (UC_X86_REG_K2 + 1).uc_x86_reg
  UC_X86_REG_K4* = (UC_X86_REG_K3 + 1).uc_x86_reg
  UC_X86_REG_K5* = (UC_X86_REG_K4 + 1).uc_x86_reg
  UC_X86_REG_K6* = (UC_X86_REG_K5 + 1).uc_x86_reg
  UC_X86_REG_K7* = (UC_X86_REG_K6 + 1).uc_x86_reg
  UC_X86_REG_MM0* = (UC_X86_REG_K7 + 1).uc_x86_reg
  UC_X86_REG_MM1* = (UC_X86_REG_MM0 + 1).uc_x86_reg
  UC_X86_REG_MM2* = (UC_X86_REG_MM1 + 1).uc_x86_reg
  UC_X86_REG_MM3* = (UC_X86_REG_MM2 + 1).uc_x86_reg
  UC_X86_REG_MM4* = (UC_X86_REG_MM3 + 1).uc_x86_reg
  UC_X86_REG_MM5* = (UC_X86_REG_MM4 + 1).uc_x86_reg
  UC_X86_REG_MM6* = (UC_X86_REG_MM5 + 1).uc_x86_reg
  UC_X86_REG_MM7* = (UC_X86_REG_MM6 + 1).uc_x86_reg
  UC_X86_REG_R8* = (UC_X86_REG_MM7 + 1).uc_x86_reg
  UC_X86_REG_R9* = (UC_X86_REG_R8 + 1).uc_x86_reg
  UC_X86_REG_R10* = (UC_X86_REG_R9 + 1).uc_x86_reg
  UC_X86_REG_R11* = (UC_X86_REG_R10 + 1).uc_x86_reg
  UC_X86_REG_R12* = (UC_X86_REG_R11 + 1).uc_x86_reg
  UC_X86_REG_R13* = (UC_X86_REG_R12 + 1).uc_x86_reg
  UC_X86_REG_R14* = (UC_X86_REG_R13 + 1).uc_x86_reg
  UC_X86_REG_R15* = (UC_X86_REG_R14 + 1).uc_x86_reg
  UC_X86_REG_ST0* = (UC_X86_REG_R15 + 1).uc_x86_reg
  UC_X86_REG_ST1* = (UC_X86_REG_ST0 + 1).uc_x86_reg
  UC_X86_REG_ST2* = (UC_X86_REG_ST1 + 1).uc_x86_reg
  UC_X86_REG_ST3* = (UC_X86_REG_ST2 + 1).uc_x86_reg
  UC_X86_REG_ST4* = (UC_X86_REG_ST3 + 1).uc_x86_reg
  UC_X86_REG_ST5* = (UC_X86_REG_ST4 + 1).uc_x86_reg
  UC_X86_REG_ST6* = (UC_X86_REG_ST5 + 1).uc_x86_reg
  UC_X86_REG_ST7* = (UC_X86_REG_ST6 + 1).uc_x86_reg
  UC_X86_REG_XMM0* = (UC_X86_REG_ST7 + 1).uc_x86_reg
  UC_X86_REG_XMM1* = (UC_X86_REG_XMM0 + 1).uc_x86_reg
  UC_X86_REG_XMM2* = (UC_X86_REG_XMM1 + 1).uc_x86_reg
  UC_X86_REG_XMM3* = (UC_X86_REG_XMM2 + 1).uc_x86_reg
  UC_X86_REG_XMM4* = (UC_X86_REG_XMM3 + 1).uc_x86_reg
  UC_X86_REG_XMM5* = (UC_X86_REG_XMM4 + 1).uc_x86_reg
  UC_X86_REG_XMM6* = (UC_X86_REG_XMM5 + 1).uc_x86_reg
  UC_X86_REG_XMM7* = (UC_X86_REG_XMM6 + 1).uc_x86_reg
  UC_X86_REG_XMM8* = (UC_X86_REG_XMM7 + 1).uc_x86_reg
  UC_X86_REG_XMM9* = (UC_X86_REG_XMM8 + 1).uc_x86_reg
  UC_X86_REG_XMM10* = (UC_X86_REG_XMM9 + 1).uc_x86_reg
  UC_X86_REG_XMM11* = (UC_X86_REG_XMM10 + 1).uc_x86_reg
  UC_X86_REG_XMM12* = (UC_X86_REG_XMM11 + 1).uc_x86_reg
  UC_X86_REG_XMM13* = (UC_X86_REG_XMM12 + 1).uc_x86_reg
  UC_X86_REG_XMM14* = (UC_X86_REG_XMM13 + 1).uc_x86_reg
  UC_X86_REG_XMM15* = (UC_X86_REG_XMM14 + 1).uc_x86_reg
  UC_X86_REG_XMM16* = (UC_X86_REG_XMM15 + 1).uc_x86_reg
  UC_X86_REG_XMM17* = (UC_X86_REG_XMM16 + 1).uc_x86_reg
  UC_X86_REG_XMM18* = (UC_X86_REG_XMM17 + 1).uc_x86_reg
  UC_X86_REG_XMM19* = (UC_X86_REG_XMM18 + 1).uc_x86_reg
  UC_X86_REG_XMM20* = (UC_X86_REG_XMM19 + 1).uc_x86_reg
  UC_X86_REG_XMM21* = (UC_X86_REG_XMM20 + 1).uc_x86_reg
  UC_X86_REG_XMM22* = (UC_X86_REG_XMM21 + 1).uc_x86_reg
  UC_X86_REG_XMM23* = (UC_X86_REG_XMM22 + 1).uc_x86_reg
  UC_X86_REG_XMM24* = (UC_X86_REG_XMM23 + 1).uc_x86_reg
  UC_X86_REG_XMM25* = (UC_X86_REG_XMM24 + 1).uc_x86_reg
  UC_X86_REG_XMM26* = (UC_X86_REG_XMM25 + 1).uc_x86_reg
  UC_X86_REG_XMM27* = (UC_X86_REG_XMM26 + 1).uc_x86_reg
  UC_X86_REG_XMM28* = (UC_X86_REG_XMM27 + 1).uc_x86_reg
  UC_X86_REG_XMM29* = (UC_X86_REG_XMM28 + 1).uc_x86_reg
  UC_X86_REG_XMM30* = (UC_X86_REG_XMM29 + 1).uc_x86_reg
  UC_X86_REG_XMM31* = (UC_X86_REG_XMM30 + 1).uc_x86_reg
  UC_X86_REG_YMM0* = (UC_X86_REG_XMM31 + 1).uc_x86_reg
  UC_X86_REG_YMM1* = (UC_X86_REG_YMM0 + 1).uc_x86_reg
  UC_X86_REG_YMM2* = (UC_X86_REG_YMM1 + 1).uc_x86_reg
  UC_X86_REG_YMM3* = (UC_X86_REG_YMM2 + 1).uc_x86_reg
  UC_X86_REG_YMM4* = (UC_X86_REG_YMM3 + 1).uc_x86_reg
  UC_X86_REG_YMM5* = (UC_X86_REG_YMM4 + 1).uc_x86_reg
  UC_X86_REG_YMM6* = (UC_X86_REG_YMM5 + 1).uc_x86_reg
  UC_X86_REG_YMM7* = (UC_X86_REG_YMM6 + 1).uc_x86_reg
  UC_X86_REG_YMM8* = (UC_X86_REG_YMM7 + 1).uc_x86_reg
  UC_X86_REG_YMM9* = (UC_X86_REG_YMM8 + 1).uc_x86_reg
  UC_X86_REG_YMM10* = (UC_X86_REG_YMM9 + 1).uc_x86_reg
  UC_X86_REG_YMM11* = (UC_X86_REG_YMM10 + 1).uc_x86_reg
  UC_X86_REG_YMM12* = (UC_X86_REG_YMM11 + 1).uc_x86_reg
  UC_X86_REG_YMM13* = (UC_X86_REG_YMM12 + 1).uc_x86_reg
  UC_X86_REG_YMM14* = (UC_X86_REG_YMM13 + 1).uc_x86_reg
  UC_X86_REG_YMM15* = (UC_X86_REG_YMM14 + 1).uc_x86_reg
  UC_X86_REG_YMM16* = (UC_X86_REG_YMM15 + 1).uc_x86_reg
  UC_X86_REG_YMM17* = (UC_X86_REG_YMM16 + 1).uc_x86_reg
  UC_X86_REG_YMM18* = (UC_X86_REG_YMM17 + 1).uc_x86_reg
  UC_X86_REG_YMM19* = (UC_X86_REG_YMM18 + 1).uc_x86_reg
  UC_X86_REG_YMM20* = (UC_X86_REG_YMM19 + 1).uc_x86_reg
  UC_X86_REG_YMM21* = (UC_X86_REG_YMM20 + 1).uc_x86_reg
  UC_X86_REG_YMM22* = (UC_X86_REG_YMM21 + 1).uc_x86_reg
  UC_X86_REG_YMM23* = (UC_X86_REG_YMM22 + 1).uc_x86_reg
  UC_X86_REG_YMM24* = (UC_X86_REG_YMM23 + 1).uc_x86_reg
  UC_X86_REG_YMM25* = (UC_X86_REG_YMM24 + 1).uc_x86_reg
  UC_X86_REG_YMM26* = (UC_X86_REG_YMM25 + 1).uc_x86_reg
  UC_X86_REG_YMM27* = (UC_X86_REG_YMM26 + 1).uc_x86_reg
  UC_X86_REG_YMM28* = (UC_X86_REG_YMM27 + 1).uc_x86_reg
  UC_X86_REG_YMM29* = (UC_X86_REG_YMM28 + 1).uc_x86_reg
  UC_X86_REG_YMM30* = (UC_X86_REG_YMM29 + 1).uc_x86_reg
  UC_X86_REG_YMM31* = (UC_X86_REG_YMM30 + 1).uc_x86_reg
  UC_X86_REG_ZMM0* = (UC_X86_REG_YMM31 + 1).uc_x86_reg
  UC_X86_REG_ZMM1* = (UC_X86_REG_ZMM0 + 1).uc_x86_reg
  UC_X86_REG_ZMM2* = (UC_X86_REG_ZMM1 + 1).uc_x86_reg
  UC_X86_REG_ZMM3* = (UC_X86_REG_ZMM2 + 1).uc_x86_reg
  UC_X86_REG_ZMM4* = (UC_X86_REG_ZMM3 + 1).uc_x86_reg
  UC_X86_REG_ZMM5* = (UC_X86_REG_ZMM4 + 1).uc_x86_reg
  UC_X86_REG_ZMM6* = (UC_X86_REG_ZMM5 + 1).uc_x86_reg
  UC_X86_REG_ZMM7* = (UC_X86_REG_ZMM6 + 1).uc_x86_reg
  UC_X86_REG_ZMM8* = (UC_X86_REG_ZMM7 + 1).uc_x86_reg
  UC_X86_REG_ZMM9* = (UC_X86_REG_ZMM8 + 1).uc_x86_reg
  UC_X86_REG_ZMM10* = (UC_X86_REG_ZMM9 + 1).uc_x86_reg
  UC_X86_REG_ZMM11* = (UC_X86_REG_ZMM10 + 1).uc_x86_reg
  UC_X86_REG_ZMM12* = (UC_X86_REG_ZMM11 + 1).uc_x86_reg
  UC_X86_REG_ZMM13* = (UC_X86_REG_ZMM12 + 1).uc_x86_reg
  UC_X86_REG_ZMM14* = (UC_X86_REG_ZMM13 + 1).uc_x86_reg
  UC_X86_REG_ZMM15* = (UC_X86_REG_ZMM14 + 1).uc_x86_reg
  UC_X86_REG_ZMM16* = (UC_X86_REG_ZMM15 + 1).uc_x86_reg
  UC_X86_REG_ZMM17* = (UC_X86_REG_ZMM16 + 1).uc_x86_reg
  UC_X86_REG_ZMM18* = (UC_X86_REG_ZMM17 + 1).uc_x86_reg
  UC_X86_REG_ZMM19* = (UC_X86_REG_ZMM18 + 1).uc_x86_reg
  UC_X86_REG_ZMM20* = (UC_X86_REG_ZMM19 + 1).uc_x86_reg
  UC_X86_REG_ZMM21* = (UC_X86_REG_ZMM20 + 1).uc_x86_reg
  UC_X86_REG_ZMM22* = (UC_X86_REG_ZMM21 + 1).uc_x86_reg
  UC_X86_REG_ZMM23* = (UC_X86_REG_ZMM22 + 1).uc_x86_reg
  UC_X86_REG_ZMM24* = (UC_X86_REG_ZMM23 + 1).uc_x86_reg
  UC_X86_REG_ZMM25* = (UC_X86_REG_ZMM24 + 1).uc_x86_reg
  UC_X86_REG_ZMM26* = (UC_X86_REG_ZMM25 + 1).uc_x86_reg
  UC_X86_REG_ZMM27* = (UC_X86_REG_ZMM26 + 1).uc_x86_reg
  UC_X86_REG_ZMM28* = (UC_X86_REG_ZMM27 + 1).uc_x86_reg
  UC_X86_REG_ZMM29* = (UC_X86_REG_ZMM28 + 1).uc_x86_reg
  UC_X86_REG_ZMM30* = (UC_X86_REG_ZMM29 + 1).uc_x86_reg
  UC_X86_REG_ZMM31* = (UC_X86_REG_ZMM30 + 1).uc_x86_reg
  UC_X86_REG_R8B* = (UC_X86_REG_ZMM31 + 1).uc_x86_reg
  UC_X86_REG_R9B* = (UC_X86_REG_R8B + 1).uc_x86_reg
  UC_X86_REG_R10B* = (UC_X86_REG_R9B + 1).uc_x86_reg
  UC_X86_REG_R11B* = (UC_X86_REG_R10B + 1).uc_x86_reg
  UC_X86_REG_R12B* = (UC_X86_REG_R11B + 1).uc_x86_reg
  UC_X86_REG_R13B* = (UC_X86_REG_R12B + 1).uc_x86_reg
  UC_X86_REG_R14B* = (UC_X86_REG_R13B + 1).uc_x86_reg
  UC_X86_REG_R15B* = (UC_X86_REG_R14B + 1).uc_x86_reg
  UC_X86_REG_R8D* = (UC_X86_REG_R15B + 1).uc_x86_reg
  UC_X86_REG_R9D* = (UC_X86_REG_R8D + 1).uc_x86_reg
  UC_X86_REG_R10D* = (UC_X86_REG_R9D + 1).uc_x86_reg
  UC_X86_REG_R11D* = (UC_X86_REG_R10D + 1).uc_x86_reg
  UC_X86_REG_R12D* = (UC_X86_REG_R11D + 1).uc_x86_reg
  UC_X86_REG_R13D* = (UC_X86_REG_R12D + 1).uc_x86_reg
  UC_X86_REG_R14D* = (UC_X86_REG_R13D + 1).uc_x86_reg
  UC_X86_REG_R15D* = (UC_X86_REG_R14D + 1).uc_x86_reg
  UC_X86_REG_R8W* = (UC_X86_REG_R15D + 1).uc_x86_reg
  UC_X86_REG_R9W* = (UC_X86_REG_R8W + 1).uc_x86_reg
  UC_X86_REG_R10W* = (UC_X86_REG_R9W + 1).uc_x86_reg
  UC_X86_REG_R11W* = (UC_X86_REG_R10W + 1).uc_x86_reg
  UC_X86_REG_R12W* = (UC_X86_REG_R11W + 1).uc_x86_reg
  UC_X86_REG_R13W* = (UC_X86_REG_R12W + 1).uc_x86_reg
  UC_X86_REG_R14W* = (UC_X86_REG_R13W + 1).uc_x86_reg
  UC_X86_REG_R15W* = (UC_X86_REG_R14W + 1).uc_x86_reg
  UC_X86_REG_IDTR* = (UC_X86_REG_R15W + 1).uc_x86_reg
  UC_X86_REG_GDTR* = (UC_X86_REG_IDTR + 1).uc_x86_reg
  UC_X86_REG_LDTR* = (UC_X86_REG_GDTR + 1).uc_x86_reg
  UC_X86_REG_TR* = (UC_X86_REG_LDTR + 1).uc_x86_reg
  UC_X86_REG_FPCW* = (UC_X86_REG_TR + 1).uc_x86_reg
  UC_X86_REG_FPTAG* = (UC_X86_REG_FPCW + 1).uc_x86_reg
  UC_X86_REG_MSR* = (UC_X86_REG_FPTAG + 1).uc_x86_reg ## ```
                                                      ##   Model-Specific Register
                                                      ## ```
  UC_X86_REG_MXCSR* = (UC_X86_REG_MSR + 1).uc_x86_reg ## ```
                                                      ##   Model-Specific Register
                                                      ## ```
  UC_X86_REG_FS_BASE* = (UC_X86_REG_MXCSR + 1).uc_x86_reg ## ```
                                                          ##   Base regs for x86_64
                                                          ## ```
  UC_X86_REG_GS_BASE* = (UC_X86_REG_FS_BASE + 1).uc_x86_reg ## ```
                                                            ##   Base regs for x86_64
                                                            ## ```
  UC_X86_REG_FLAGS* = (UC_X86_REG_GS_BASE + 1).uc_x86_reg
  UC_X86_REG_RFLAGS* = (UC_X86_REG_FLAGS + 1).uc_x86_reg
  UC_X86_REG_FIP* = (UC_X86_REG_RFLAGS + 1).uc_x86_reg
  UC_X86_REG_FCS* = (UC_X86_REG_FIP + 1).uc_x86_reg
  UC_X86_REG_FDP* = (UC_X86_REG_FCS + 1).uc_x86_reg
  UC_X86_REG_FDS* = (UC_X86_REG_FDP + 1).uc_x86_reg
  UC_X86_REG_FOP* = (UC_X86_REG_FDS + 1).uc_x86_reg
  UC_X86_REG_ENDING* = (UC_X86_REG_FOP + 1).uc_x86_reg ## ```
                                                       ##   <-- mark the end of the list of registers
                                                       ## ```
  UC_X86_INS_INVALID* = (0).uc_x86_insn
  UC_X86_INS_AAA* = (UC_X86_INS_INVALID + 1).uc_x86_insn
  UC_X86_INS_AAD* = (UC_X86_INS_AAA + 1).uc_x86_insn
  UC_X86_INS_AAM* = (UC_X86_INS_AAD + 1).uc_x86_insn
  UC_X86_INS_AAS* = (UC_X86_INS_AAM + 1).uc_x86_insn
  UC_X86_INS_FABS* = (UC_X86_INS_AAS + 1).uc_x86_insn
  UC_X86_INS_ADC* = (UC_X86_INS_FABS + 1).uc_x86_insn
  UC_X86_INS_ADCX* = (UC_X86_INS_ADC + 1).uc_x86_insn
  UC_X86_INS_ADD* = (UC_X86_INS_ADCX + 1).uc_x86_insn
  UC_X86_INS_ADDPD* = (UC_X86_INS_ADD + 1).uc_x86_insn
  UC_X86_INS_ADDPS* = (UC_X86_INS_ADDPD + 1).uc_x86_insn
  UC_X86_INS_ADDSD* = (UC_X86_INS_ADDPS + 1).uc_x86_insn
  UC_X86_INS_ADDSS* = (UC_X86_INS_ADDSD + 1).uc_x86_insn
  UC_X86_INS_ADDSUBPD* = (UC_X86_INS_ADDSS + 1).uc_x86_insn
  UC_X86_INS_ADDSUBPS* = (UC_X86_INS_ADDSUBPD + 1).uc_x86_insn
  UC_X86_INS_FADD* = (UC_X86_INS_ADDSUBPS + 1).uc_x86_insn
  UC_X86_INS_FIADD* = (UC_X86_INS_FADD + 1).uc_x86_insn
  UC_X86_INS_FADDP* = (UC_X86_INS_FIADD + 1).uc_x86_insn
  UC_X86_INS_ADOX* = (UC_X86_INS_FADDP + 1).uc_x86_insn
  UC_X86_INS_AESDECLAST* = (UC_X86_INS_ADOX + 1).uc_x86_insn
  UC_X86_INS_AESDEC* = (UC_X86_INS_AESDECLAST + 1).uc_x86_insn
  UC_X86_INS_AESENCLAST* = (UC_X86_INS_AESDEC + 1).uc_x86_insn
  UC_X86_INS_AESENC* = (UC_X86_INS_AESENCLAST + 1).uc_x86_insn
  UC_X86_INS_AESIMC* = (UC_X86_INS_AESENC + 1).uc_x86_insn
  UC_X86_INS_AESKEYGENASSIST* = (UC_X86_INS_AESIMC + 1).uc_x86_insn
  UC_X86_INS_AND* = (UC_X86_INS_AESKEYGENASSIST + 1).uc_x86_insn
  UC_X86_INS_ANDN* = (UC_X86_INS_AND + 1).uc_x86_insn
  UC_X86_INS_ANDNPD* = (UC_X86_INS_ANDN + 1).uc_x86_insn
  UC_X86_INS_ANDNPS* = (UC_X86_INS_ANDNPD + 1).uc_x86_insn
  UC_X86_INS_ANDPD* = (UC_X86_INS_ANDNPS + 1).uc_x86_insn
  UC_X86_INS_ANDPS* = (UC_X86_INS_ANDPD + 1).uc_x86_insn
  UC_X86_INS_ARPL* = (UC_X86_INS_ANDPS + 1).uc_x86_insn
  UC_X86_INS_BEXTR* = (UC_X86_INS_ARPL + 1).uc_x86_insn
  UC_X86_INS_BLCFILL* = (UC_X86_INS_BEXTR + 1).uc_x86_insn
  UC_X86_INS_BLCI* = (UC_X86_INS_BLCFILL + 1).uc_x86_insn
  UC_X86_INS_BLCIC* = (UC_X86_INS_BLCI + 1).uc_x86_insn
  UC_X86_INS_BLCMSK* = (UC_X86_INS_BLCIC + 1).uc_x86_insn
  UC_X86_INS_BLCS* = (UC_X86_INS_BLCMSK + 1).uc_x86_insn
  UC_X86_INS_BLENDPD* = (UC_X86_INS_BLCS + 1).uc_x86_insn
  UC_X86_INS_BLENDPS* = (UC_X86_INS_BLENDPD + 1).uc_x86_insn
  UC_X86_INS_BLENDVPD* = (UC_X86_INS_BLENDPS + 1).uc_x86_insn
  UC_X86_INS_BLENDVPS* = (UC_X86_INS_BLENDVPD + 1).uc_x86_insn
  UC_X86_INS_BLSFILL* = (UC_X86_INS_BLENDVPS + 1).uc_x86_insn
  UC_X86_INS_BLSI* = (UC_X86_INS_BLSFILL + 1).uc_x86_insn
  UC_X86_INS_BLSIC* = (UC_X86_INS_BLSI + 1).uc_x86_insn
  UC_X86_INS_BLSMSK* = (UC_X86_INS_BLSIC + 1).uc_x86_insn
  UC_X86_INS_BLSR* = (UC_X86_INS_BLSMSK + 1).uc_x86_insn
  UC_X86_INS_BOUND* = (UC_X86_INS_BLSR + 1).uc_x86_insn
  UC_X86_INS_BSF* = (UC_X86_INS_BOUND + 1).uc_x86_insn
  UC_X86_INS_BSR* = (UC_X86_INS_BSF + 1).uc_x86_insn
  UC_X86_INS_BSWAP* = (UC_X86_INS_BSR + 1).uc_x86_insn
  UC_X86_INS_BT* = (UC_X86_INS_BSWAP + 1).uc_x86_insn
  UC_X86_INS_BTC* = (UC_X86_INS_BT + 1).uc_x86_insn
  UC_X86_INS_BTR* = (UC_X86_INS_BTC + 1).uc_x86_insn
  UC_X86_INS_BTS* = (UC_X86_INS_BTR + 1).uc_x86_insn
  UC_X86_INS_BZHI* = (UC_X86_INS_BTS + 1).uc_x86_insn
  UC_X86_INS_CALL* = (UC_X86_INS_BZHI + 1).uc_x86_insn
  UC_X86_INS_CBW* = (UC_X86_INS_CALL + 1).uc_x86_insn
  UC_X86_INS_CDQ* = (UC_X86_INS_CBW + 1).uc_x86_insn
  UC_X86_INS_CDQE* = (UC_X86_INS_CDQ + 1).uc_x86_insn
  UC_X86_INS_FCHS* = (UC_X86_INS_CDQE + 1).uc_x86_insn
  UC_X86_INS_CLAC* = (UC_X86_INS_FCHS + 1).uc_x86_insn
  UC_X86_INS_CLC* = (UC_X86_INS_CLAC + 1).uc_x86_insn
  UC_X86_INS_CLD* = (UC_X86_INS_CLC + 1).uc_x86_insn
  UC_X86_INS_CLFLUSH* = (UC_X86_INS_CLD + 1).uc_x86_insn
  UC_X86_INS_CLFLUSHOPT* = (UC_X86_INS_CLFLUSH + 1).uc_x86_insn
  UC_X86_INS_CLGI* = (UC_X86_INS_CLFLUSHOPT + 1).uc_x86_insn
  UC_X86_INS_CLI* = (UC_X86_INS_CLGI + 1).uc_x86_insn
  UC_X86_INS_CLTS* = (UC_X86_INS_CLI + 1).uc_x86_insn
  UC_X86_INS_CLWB* = (UC_X86_INS_CLTS + 1).uc_x86_insn
  UC_X86_INS_CMC* = (UC_X86_INS_CLWB + 1).uc_x86_insn
  UC_X86_INS_CMOVA* = (UC_X86_INS_CMC + 1).uc_x86_insn
  UC_X86_INS_CMOVAE* = (UC_X86_INS_CMOVA + 1).uc_x86_insn
  UC_X86_INS_CMOVB* = (UC_X86_INS_CMOVAE + 1).uc_x86_insn
  UC_X86_INS_CMOVBE* = (UC_X86_INS_CMOVB + 1).uc_x86_insn
  UC_X86_INS_FCMOVBE* = (UC_X86_INS_CMOVBE + 1).uc_x86_insn
  UC_X86_INS_FCMOVB* = (UC_X86_INS_FCMOVBE + 1).uc_x86_insn
  UC_X86_INS_CMOVE* = (UC_X86_INS_FCMOVB + 1).uc_x86_insn
  UC_X86_INS_FCMOVE* = (UC_X86_INS_CMOVE + 1).uc_x86_insn
  UC_X86_INS_CMOVG* = (UC_X86_INS_FCMOVE + 1).uc_x86_insn
  UC_X86_INS_CMOVGE* = (UC_X86_INS_CMOVG + 1).uc_x86_insn
  UC_X86_INS_CMOVL* = (UC_X86_INS_CMOVGE + 1).uc_x86_insn
  UC_X86_INS_CMOVLE* = (UC_X86_INS_CMOVL + 1).uc_x86_insn
  UC_X86_INS_FCMOVNBE* = (UC_X86_INS_CMOVLE + 1).uc_x86_insn
  UC_X86_INS_FCMOVNB* = (UC_X86_INS_FCMOVNBE + 1).uc_x86_insn
  UC_X86_INS_CMOVNE* = (UC_X86_INS_FCMOVNB + 1).uc_x86_insn
  UC_X86_INS_FCMOVNE* = (UC_X86_INS_CMOVNE + 1).uc_x86_insn
  UC_X86_INS_CMOVNO* = (UC_X86_INS_FCMOVNE + 1).uc_x86_insn
  UC_X86_INS_CMOVNP* = (UC_X86_INS_CMOVNO + 1).uc_x86_insn
  UC_X86_INS_FCMOVNU* = (UC_X86_INS_CMOVNP + 1).uc_x86_insn
  UC_X86_INS_CMOVNS* = (UC_X86_INS_FCMOVNU + 1).uc_x86_insn
  UC_X86_INS_CMOVO* = (UC_X86_INS_CMOVNS + 1).uc_x86_insn
  UC_X86_INS_CMOVP* = (UC_X86_INS_CMOVO + 1).uc_x86_insn
  UC_X86_INS_FCMOVU* = (UC_X86_INS_CMOVP + 1).uc_x86_insn
  UC_X86_INS_CMOVS* = (UC_X86_INS_FCMOVU + 1).uc_x86_insn
  UC_X86_INS_CMP* = (UC_X86_INS_CMOVS + 1).uc_x86_insn
  UC_X86_INS_CMPPD* = (UC_X86_INS_CMP + 1).uc_x86_insn
  UC_X86_INS_CMPPS* = (UC_X86_INS_CMPPD + 1).uc_x86_insn
  UC_X86_INS_CMPSB* = (UC_X86_INS_CMPPS + 1).uc_x86_insn
  UC_X86_INS_CMPSD* = (UC_X86_INS_CMPSB + 1).uc_x86_insn
  UC_X86_INS_CMPSQ* = (UC_X86_INS_CMPSD + 1).uc_x86_insn
  UC_X86_INS_CMPSS* = (UC_X86_INS_CMPSQ + 1).uc_x86_insn
  UC_X86_INS_CMPSW* = (UC_X86_INS_CMPSS + 1).uc_x86_insn
  UC_X86_INS_CMPXCHG16B* = (UC_X86_INS_CMPSW + 1).uc_x86_insn
  UC_X86_INS_CMPXCHG* = (UC_X86_INS_CMPXCHG16B + 1).uc_x86_insn
  UC_X86_INS_CMPXCHG8B* = (UC_X86_INS_CMPXCHG + 1).uc_x86_insn
  UC_X86_INS_COMISD* = (UC_X86_INS_CMPXCHG8B + 1).uc_x86_insn
  UC_X86_INS_COMISS* = (UC_X86_INS_COMISD + 1).uc_x86_insn
  UC_X86_INS_FCOMP* = (UC_X86_INS_COMISS + 1).uc_x86_insn
  UC_X86_INS_FCOMPI* = (UC_X86_INS_FCOMP + 1).uc_x86_insn
  UC_X86_INS_FCOMI* = (UC_X86_INS_FCOMPI + 1).uc_x86_insn
  UC_X86_INS_FCOM* = (UC_X86_INS_FCOMI + 1).uc_x86_insn
  UC_X86_INS_FCOS* = (UC_X86_INS_FCOM + 1).uc_x86_insn
  UC_X86_INS_CPUID* = (UC_X86_INS_FCOS + 1).uc_x86_insn
  UC_X86_INS_CQO* = (UC_X86_INS_CPUID + 1).uc_x86_insn
  UC_X86_INS_CRC32* = (UC_X86_INS_CQO + 1).uc_x86_insn
  UC_X86_INS_CVTDQ2PD* = (UC_X86_INS_CRC32 + 1).uc_x86_insn
  UC_X86_INS_CVTDQ2PS* = (UC_X86_INS_CVTDQ2PD + 1).uc_x86_insn
  UC_X86_INS_CVTPD2DQ* = (UC_X86_INS_CVTDQ2PS + 1).uc_x86_insn
  UC_X86_INS_CVTPD2PS* = (UC_X86_INS_CVTPD2DQ + 1).uc_x86_insn
  UC_X86_INS_CVTPS2DQ* = (UC_X86_INS_CVTPD2PS + 1).uc_x86_insn
  UC_X86_INS_CVTPS2PD* = (UC_X86_INS_CVTPS2DQ + 1).uc_x86_insn
  UC_X86_INS_CVTSD2SI* = (UC_X86_INS_CVTPS2PD + 1).uc_x86_insn
  UC_X86_INS_CVTSD2SS* = (UC_X86_INS_CVTSD2SI + 1).uc_x86_insn
  UC_X86_INS_CVTSI2SD* = (UC_X86_INS_CVTSD2SS + 1).uc_x86_insn
  UC_X86_INS_CVTSI2SS* = (UC_X86_INS_CVTSI2SD + 1).uc_x86_insn
  UC_X86_INS_CVTSS2SD* = (UC_X86_INS_CVTSI2SS + 1).uc_x86_insn
  UC_X86_INS_CVTSS2SI* = (UC_X86_INS_CVTSS2SD + 1).uc_x86_insn
  UC_X86_INS_CVTTPD2DQ* = (UC_X86_INS_CVTSS2SI + 1).uc_x86_insn
  UC_X86_INS_CVTTPS2DQ* = (UC_X86_INS_CVTTPD2DQ + 1).uc_x86_insn
  UC_X86_INS_CVTTSD2SI* = (UC_X86_INS_CVTTPS2DQ + 1).uc_x86_insn
  UC_X86_INS_CVTTSS2SI* = (UC_X86_INS_CVTTSD2SI + 1).uc_x86_insn
  UC_X86_INS_CWD* = (UC_X86_INS_CVTTSS2SI + 1).uc_x86_insn
  UC_X86_INS_CWDE* = (UC_X86_INS_CWD + 1).uc_x86_insn
  UC_X86_INS_DAA* = (UC_X86_INS_CWDE + 1).uc_x86_insn
  UC_X86_INS_DAS* = (UC_X86_INS_DAA + 1).uc_x86_insn
  UC_X86_INS_DATA16* = (UC_X86_INS_DAS + 1).uc_x86_insn
  UC_X86_INS_DEC* = (UC_X86_INS_DATA16 + 1).uc_x86_insn
  UC_X86_INS_DIV* = (UC_X86_INS_DEC + 1).uc_x86_insn
  UC_X86_INS_DIVPD* = (UC_X86_INS_DIV + 1).uc_x86_insn
  UC_X86_INS_DIVPS* = (UC_X86_INS_DIVPD + 1).uc_x86_insn
  UC_X86_INS_FDIVR* = (UC_X86_INS_DIVPS + 1).uc_x86_insn
  UC_X86_INS_FIDIVR* = (UC_X86_INS_FDIVR + 1).uc_x86_insn
  UC_X86_INS_FDIVRP* = (UC_X86_INS_FIDIVR + 1).uc_x86_insn
  UC_X86_INS_DIVSD* = (UC_X86_INS_FDIVRP + 1).uc_x86_insn
  UC_X86_INS_DIVSS* = (UC_X86_INS_DIVSD + 1).uc_x86_insn
  UC_X86_INS_FDIV* = (UC_X86_INS_DIVSS + 1).uc_x86_insn
  UC_X86_INS_FIDIV* = (UC_X86_INS_FDIV + 1).uc_x86_insn
  UC_X86_INS_FDIVP* = (UC_X86_INS_FIDIV + 1).uc_x86_insn
  UC_X86_INS_DPPD* = (UC_X86_INS_FDIVP + 1).uc_x86_insn
  UC_X86_INS_DPPS* = (UC_X86_INS_DPPD + 1).uc_x86_insn
  UC_X86_INS_RET* = (UC_X86_INS_DPPS + 1).uc_x86_insn
  UC_X86_INS_ENCLS* = (UC_X86_INS_RET + 1).uc_x86_insn
  UC_X86_INS_ENCLU* = (UC_X86_INS_ENCLS + 1).uc_x86_insn
  UC_X86_INS_ENTER* = (UC_X86_INS_ENCLU + 1).uc_x86_insn
  UC_X86_INS_EXTRACTPS* = (UC_X86_INS_ENTER + 1).uc_x86_insn
  UC_X86_INS_EXTRQ* = (UC_X86_INS_EXTRACTPS + 1).uc_x86_insn
  UC_X86_INS_F2XM1* = (UC_X86_INS_EXTRQ + 1).uc_x86_insn
  UC_X86_INS_LCALL* = (UC_X86_INS_F2XM1 + 1).uc_x86_insn
  UC_X86_INS_LJMP* = (UC_X86_INS_LCALL + 1).uc_x86_insn
  UC_X86_INS_FBLD* = (UC_X86_INS_LJMP + 1).uc_x86_insn
  UC_X86_INS_FBSTP* = (UC_X86_INS_FBLD + 1).uc_x86_insn
  UC_X86_INS_FCOMPP* = (UC_X86_INS_FBSTP + 1).uc_x86_insn
  UC_X86_INS_FDECSTP* = (UC_X86_INS_FCOMPP + 1).uc_x86_insn
  UC_X86_INS_FEMMS* = (UC_X86_INS_FDECSTP + 1).uc_x86_insn
  UC_X86_INS_FFREE* = (UC_X86_INS_FEMMS + 1).uc_x86_insn
  UC_X86_INS_FICOM* = (UC_X86_INS_FFREE + 1).uc_x86_insn
  UC_X86_INS_FICOMP* = (UC_X86_INS_FICOM + 1).uc_x86_insn
  UC_X86_INS_FINCSTP* = (UC_X86_INS_FICOMP + 1).uc_x86_insn
  UC_X86_INS_FLDCW* = (UC_X86_INS_FINCSTP + 1).uc_x86_insn
  UC_X86_INS_FLDENV* = (UC_X86_INS_FLDCW + 1).uc_x86_insn
  UC_X86_INS_FLDL2E* = (UC_X86_INS_FLDENV + 1).uc_x86_insn
  UC_X86_INS_FLDL2T* = (UC_X86_INS_FLDL2E + 1).uc_x86_insn
  UC_X86_INS_FLDLG2* = (UC_X86_INS_FLDL2T + 1).uc_x86_insn
  UC_X86_INS_FLDLN2* = (UC_X86_INS_FLDLG2 + 1).uc_x86_insn
  UC_X86_INS_FLDPI* = (UC_X86_INS_FLDLN2 + 1).uc_x86_insn
  UC_X86_INS_FNCLEX* = (UC_X86_INS_FLDPI + 1).uc_x86_insn
  UC_X86_INS_FNINIT* = (UC_X86_INS_FNCLEX + 1).uc_x86_insn
  UC_X86_INS_FNOP* = (UC_X86_INS_FNINIT + 1).uc_x86_insn
  UC_X86_INS_FNSTCW* = (UC_X86_INS_FNOP + 1).uc_x86_insn
  UC_X86_INS_FNSTSW* = (UC_X86_INS_FNSTCW + 1).uc_x86_insn
  UC_X86_INS_FPATAN* = (UC_X86_INS_FNSTSW + 1).uc_x86_insn
  UC_X86_INS_FPREM* = (UC_X86_INS_FPATAN + 1).uc_x86_insn
  UC_X86_INS_FPREM1* = (UC_X86_INS_FPREM + 1).uc_x86_insn
  UC_X86_INS_FPTAN* = (UC_X86_INS_FPREM1 + 1).uc_x86_insn
  UC_X86_INS_FFREEP* = (UC_X86_INS_FPTAN + 1).uc_x86_insn
  UC_X86_INS_FRNDINT* = (UC_X86_INS_FFREEP + 1).uc_x86_insn
  UC_X86_INS_FRSTOR* = (UC_X86_INS_FRNDINT + 1).uc_x86_insn
  UC_X86_INS_FNSAVE* = (UC_X86_INS_FRSTOR + 1).uc_x86_insn
  UC_X86_INS_FSCALE* = (UC_X86_INS_FNSAVE + 1).uc_x86_insn
  UC_X86_INS_FSETPM* = (UC_X86_INS_FSCALE + 1).uc_x86_insn
  UC_X86_INS_FSINCOS* = (UC_X86_INS_FSETPM + 1).uc_x86_insn
  UC_X86_INS_FNSTENV* = (UC_X86_INS_FSINCOS + 1).uc_x86_insn
  UC_X86_INS_FXAM* = (UC_X86_INS_FNSTENV + 1).uc_x86_insn
  UC_X86_INS_FXRSTOR* = (UC_X86_INS_FXAM + 1).uc_x86_insn
  UC_X86_INS_FXRSTOR64* = (UC_X86_INS_FXRSTOR + 1).uc_x86_insn
  UC_X86_INS_FXSAVE* = (UC_X86_INS_FXRSTOR64 + 1).uc_x86_insn
  UC_X86_INS_FXSAVE64* = (UC_X86_INS_FXSAVE + 1).uc_x86_insn
  UC_X86_INS_FXTRACT* = (UC_X86_INS_FXSAVE64 + 1).uc_x86_insn
  UC_X86_INS_FYL2X* = (UC_X86_INS_FXTRACT + 1).uc_x86_insn
  UC_X86_INS_FYL2XP1* = (UC_X86_INS_FYL2X + 1).uc_x86_insn
  UC_X86_INS_MOVAPD* = (UC_X86_INS_FYL2XP1 + 1).uc_x86_insn
  UC_X86_INS_MOVAPS* = (UC_X86_INS_MOVAPD + 1).uc_x86_insn
  UC_X86_INS_ORPD* = (UC_X86_INS_MOVAPS + 1).uc_x86_insn
  UC_X86_INS_ORPS* = (UC_X86_INS_ORPD + 1).uc_x86_insn
  UC_X86_INS_VMOVAPD* = (UC_X86_INS_ORPS + 1).uc_x86_insn
  UC_X86_INS_VMOVAPS* = (UC_X86_INS_VMOVAPD + 1).uc_x86_insn
  UC_X86_INS_XORPD* = (UC_X86_INS_VMOVAPS + 1).uc_x86_insn
  UC_X86_INS_XORPS* = (UC_X86_INS_XORPD + 1).uc_x86_insn
  UC_X86_INS_GETSEC* = (UC_X86_INS_XORPS + 1).uc_x86_insn
  UC_X86_INS_HADDPD* = (UC_X86_INS_GETSEC + 1).uc_x86_insn
  UC_X86_INS_HADDPS* = (UC_X86_INS_HADDPD + 1).uc_x86_insn
  UC_X86_INS_HLT* = (UC_X86_INS_HADDPS + 1).uc_x86_insn
  UC_X86_INS_HSUBPD* = (UC_X86_INS_HLT + 1).uc_x86_insn
  UC_X86_INS_HSUBPS* = (UC_X86_INS_HSUBPD + 1).uc_x86_insn
  UC_X86_INS_IDIV* = (UC_X86_INS_HSUBPS + 1).uc_x86_insn
  UC_X86_INS_FILD* = (UC_X86_INS_IDIV + 1).uc_x86_insn
  UC_X86_INS_IMUL* = (UC_X86_INS_FILD + 1).uc_x86_insn
  UC_X86_INS_IN* = (UC_X86_INS_IMUL + 1).uc_x86_insn
  UC_X86_INS_INC* = (UC_X86_INS_IN + 1).uc_x86_insn
  UC_X86_INS_INSB* = (UC_X86_INS_INC + 1).uc_x86_insn
  UC_X86_INS_INSERTPS* = (UC_X86_INS_INSB + 1).uc_x86_insn
  UC_X86_INS_INSERTQ* = (UC_X86_INS_INSERTPS + 1).uc_x86_insn
  UC_X86_INS_INSD* = (UC_X86_INS_INSERTQ + 1).uc_x86_insn
  UC_X86_INS_INSW* = (UC_X86_INS_INSD + 1).uc_x86_insn
  UC_X86_INS_INT* = (UC_X86_INS_INSW + 1).uc_x86_insn
  UC_X86_INS_INT1* = (UC_X86_INS_INT + 1).uc_x86_insn
  UC_X86_INS_INT3* = (UC_X86_INS_INT1 + 1).uc_x86_insn
  UC_X86_INS_INTO* = (UC_X86_INS_INT3 + 1).uc_x86_insn
  UC_X86_INS_INVD* = (UC_X86_INS_INTO + 1).uc_x86_insn
  UC_X86_INS_INVEPT* = (UC_X86_INS_INVD + 1).uc_x86_insn
  UC_X86_INS_INVLPG* = (UC_X86_INS_INVEPT + 1).uc_x86_insn
  UC_X86_INS_INVLPGA* = (UC_X86_INS_INVLPG + 1).uc_x86_insn
  UC_X86_INS_INVPCID* = (UC_X86_INS_INVLPGA + 1).uc_x86_insn
  UC_X86_INS_INVVPID* = (UC_X86_INS_INVPCID + 1).uc_x86_insn
  UC_X86_INS_IRET* = (UC_X86_INS_INVVPID + 1).uc_x86_insn
  UC_X86_INS_IRETD* = (UC_X86_INS_IRET + 1).uc_x86_insn
  UC_X86_INS_IRETQ* = (UC_X86_INS_IRETD + 1).uc_x86_insn
  UC_X86_INS_FISTTP* = (UC_X86_INS_IRETQ + 1).uc_x86_insn
  UC_X86_INS_FIST* = (UC_X86_INS_FISTTP + 1).uc_x86_insn
  UC_X86_INS_FISTP* = (UC_X86_INS_FIST + 1).uc_x86_insn
  UC_X86_INS_UCOMISD* = (UC_X86_INS_FISTP + 1).uc_x86_insn
  UC_X86_INS_UCOMISS* = (UC_X86_INS_UCOMISD + 1).uc_x86_insn
  UC_X86_INS_VCOMISD* = (UC_X86_INS_UCOMISS + 1).uc_x86_insn
  UC_X86_INS_VCOMISS* = (UC_X86_INS_VCOMISD + 1).uc_x86_insn
  UC_X86_INS_VCVTSD2SS* = (UC_X86_INS_VCOMISS + 1).uc_x86_insn
  UC_X86_INS_VCVTSI2SD* = (UC_X86_INS_VCVTSD2SS + 1).uc_x86_insn
  UC_X86_INS_VCVTSI2SS* = (UC_X86_INS_VCVTSI2SD + 1).uc_x86_insn
  UC_X86_INS_VCVTSS2SD* = (UC_X86_INS_VCVTSI2SS + 1).uc_x86_insn
  UC_X86_INS_VCVTTSD2SI* = (UC_X86_INS_VCVTSS2SD + 1).uc_x86_insn
  UC_X86_INS_VCVTTSD2USI* = (UC_X86_INS_VCVTTSD2SI + 1).uc_x86_insn
  UC_X86_INS_VCVTTSS2SI* = (UC_X86_INS_VCVTTSD2USI + 1).uc_x86_insn
  UC_X86_INS_VCVTTSS2USI* = (UC_X86_INS_VCVTTSS2SI + 1).uc_x86_insn
  UC_X86_INS_VCVTUSI2SD* = (UC_X86_INS_VCVTTSS2USI + 1).uc_x86_insn
  UC_X86_INS_VCVTUSI2SS* = (UC_X86_INS_VCVTUSI2SD + 1).uc_x86_insn
  UC_X86_INS_VUCOMISD* = (UC_X86_INS_VCVTUSI2SS + 1).uc_x86_insn
  UC_X86_INS_VUCOMISS* = (UC_X86_INS_VUCOMISD + 1).uc_x86_insn
  UC_X86_INS_JAE* = (UC_X86_INS_VUCOMISS + 1).uc_x86_insn
  UC_X86_INS_JA* = (UC_X86_INS_JAE + 1).uc_x86_insn
  UC_X86_INS_JBE* = (UC_X86_INS_JA + 1).uc_x86_insn
  UC_X86_INS_JB* = (UC_X86_INS_JBE + 1).uc_x86_insn
  UC_X86_INS_JCXZ* = (UC_X86_INS_JB + 1).uc_x86_insn
  UC_X86_INS_JECXZ* = (UC_X86_INS_JCXZ + 1).uc_x86_insn
  UC_X86_INS_JE* = (UC_X86_INS_JECXZ + 1).uc_x86_insn
  UC_X86_INS_JGE* = (UC_X86_INS_JE + 1).uc_x86_insn
  UC_X86_INS_JG* = (UC_X86_INS_JGE + 1).uc_x86_insn
  UC_X86_INS_JLE* = (UC_X86_INS_JG + 1).uc_x86_insn
  UC_X86_INS_JL* = (UC_X86_INS_JLE + 1).uc_x86_insn
  UC_X86_INS_JMP* = (UC_X86_INS_JL + 1).uc_x86_insn
  UC_X86_INS_JNE* = (UC_X86_INS_JMP + 1).uc_x86_insn
  UC_X86_INS_JNO* = (UC_X86_INS_JNE + 1).uc_x86_insn
  UC_X86_INS_JNP* = (UC_X86_INS_JNO + 1).uc_x86_insn
  UC_X86_INS_JNS* = (UC_X86_INS_JNP + 1).uc_x86_insn
  UC_X86_INS_JO* = (UC_X86_INS_JNS + 1).uc_x86_insn
  UC_X86_INS_JP* = (UC_X86_INS_JO + 1).uc_x86_insn
  UC_X86_INS_JRCXZ* = (UC_X86_INS_JP + 1).uc_x86_insn
  UC_X86_INS_JS* = (UC_X86_INS_JRCXZ + 1).uc_x86_insn
  UC_X86_INS_KANDB* = (UC_X86_INS_JS + 1).uc_x86_insn
  UC_X86_INS_KANDD* = (UC_X86_INS_KANDB + 1).uc_x86_insn
  UC_X86_INS_KANDNB* = (UC_X86_INS_KANDD + 1).uc_x86_insn
  UC_X86_INS_KANDND* = (UC_X86_INS_KANDNB + 1).uc_x86_insn
  UC_X86_INS_KANDNQ* = (UC_X86_INS_KANDND + 1).uc_x86_insn
  UC_X86_INS_KANDNW* = (UC_X86_INS_KANDNQ + 1).uc_x86_insn
  UC_X86_INS_KANDQ* = (UC_X86_INS_KANDNW + 1).uc_x86_insn
  UC_X86_INS_KANDW* = (UC_X86_INS_KANDQ + 1).uc_x86_insn
  UC_X86_INS_KMOVB* = (UC_X86_INS_KANDW + 1).uc_x86_insn
  UC_X86_INS_KMOVD* = (UC_X86_INS_KMOVB + 1).uc_x86_insn
  UC_X86_INS_KMOVQ* = (UC_X86_INS_KMOVD + 1).uc_x86_insn
  UC_X86_INS_KMOVW* = (UC_X86_INS_KMOVQ + 1).uc_x86_insn
  UC_X86_INS_KNOTB* = (UC_X86_INS_KMOVW + 1).uc_x86_insn
  UC_X86_INS_KNOTD* = (UC_X86_INS_KNOTB + 1).uc_x86_insn
  UC_X86_INS_KNOTQ* = (UC_X86_INS_KNOTD + 1).uc_x86_insn
  UC_X86_INS_KNOTW* = (UC_X86_INS_KNOTQ + 1).uc_x86_insn
  UC_X86_INS_KORB* = (UC_X86_INS_KNOTW + 1).uc_x86_insn
  UC_X86_INS_KORD* = (UC_X86_INS_KORB + 1).uc_x86_insn
  UC_X86_INS_KORQ* = (UC_X86_INS_KORD + 1).uc_x86_insn
  UC_X86_INS_KORTESTB* = (UC_X86_INS_KORQ + 1).uc_x86_insn
  UC_X86_INS_KORTESTD* = (UC_X86_INS_KORTESTB + 1).uc_x86_insn
  UC_X86_INS_KORTESTQ* = (UC_X86_INS_KORTESTD + 1).uc_x86_insn
  UC_X86_INS_KORTESTW* = (UC_X86_INS_KORTESTQ + 1).uc_x86_insn
  UC_X86_INS_KORW* = (UC_X86_INS_KORTESTW + 1).uc_x86_insn
  UC_X86_INS_KSHIFTLB* = (UC_X86_INS_KORW + 1).uc_x86_insn
  UC_X86_INS_KSHIFTLD* = (UC_X86_INS_KSHIFTLB + 1).uc_x86_insn
  UC_X86_INS_KSHIFTLQ* = (UC_X86_INS_KSHIFTLD + 1).uc_x86_insn
  UC_X86_INS_KSHIFTLW* = (UC_X86_INS_KSHIFTLQ + 1).uc_x86_insn
  UC_X86_INS_KSHIFTRB* = (UC_X86_INS_KSHIFTLW + 1).uc_x86_insn
  UC_X86_INS_KSHIFTRD* = (UC_X86_INS_KSHIFTRB + 1).uc_x86_insn
  UC_X86_INS_KSHIFTRQ* = (UC_X86_INS_KSHIFTRD + 1).uc_x86_insn
  UC_X86_INS_KSHIFTRW* = (UC_X86_INS_KSHIFTRQ + 1).uc_x86_insn
  UC_X86_INS_KUNPCKBW* = (UC_X86_INS_KSHIFTRW + 1).uc_x86_insn
  UC_X86_INS_KXNORB* = (UC_X86_INS_KUNPCKBW + 1).uc_x86_insn
  UC_X86_INS_KXNORD* = (UC_X86_INS_KXNORB + 1).uc_x86_insn
  UC_X86_INS_KXNORQ* = (UC_X86_INS_KXNORD + 1).uc_x86_insn
  UC_X86_INS_KXNORW* = (UC_X86_INS_KXNORQ + 1).uc_x86_insn
  UC_X86_INS_KXORB* = (UC_X86_INS_KXNORW + 1).uc_x86_insn
  UC_X86_INS_KXORD* = (UC_X86_INS_KXORB + 1).uc_x86_insn
  UC_X86_INS_KXORQ* = (UC_X86_INS_KXORD + 1).uc_x86_insn
  UC_X86_INS_KXORW* = (UC_X86_INS_KXORQ + 1).uc_x86_insn
  UC_X86_INS_LAHF* = (UC_X86_INS_KXORW + 1).uc_x86_insn
  UC_X86_INS_LAR* = (UC_X86_INS_LAHF + 1).uc_x86_insn
  UC_X86_INS_LDDQU* = (UC_X86_INS_LAR + 1).uc_x86_insn
  UC_X86_INS_LDMXCSR* = (UC_X86_INS_LDDQU + 1).uc_x86_insn
  UC_X86_INS_LDS* = (UC_X86_INS_LDMXCSR + 1).uc_x86_insn
  UC_X86_INS_FLDZ* = (UC_X86_INS_LDS + 1).uc_x86_insn
  UC_X86_INS_FLD1* = (UC_X86_INS_FLDZ + 1).uc_x86_insn
  UC_X86_INS_FLD* = (UC_X86_INS_FLD1 + 1).uc_x86_insn
  UC_X86_INS_LEA* = (UC_X86_INS_FLD + 1).uc_x86_insn
  UC_X86_INS_LEAVE* = (UC_X86_INS_LEA + 1).uc_x86_insn
  UC_X86_INS_LES* = (UC_X86_INS_LEAVE + 1).uc_x86_insn
  UC_X86_INS_LFENCE* = (UC_X86_INS_LES + 1).uc_x86_insn
  UC_X86_INS_LFS* = (UC_X86_INS_LFENCE + 1).uc_x86_insn
  UC_X86_INS_LGDT* = (UC_X86_INS_LFS + 1).uc_x86_insn
  UC_X86_INS_LGS* = (UC_X86_INS_LGDT + 1).uc_x86_insn
  UC_X86_INS_LIDT* = (UC_X86_INS_LGS + 1).uc_x86_insn
  UC_X86_INS_LLDT* = (UC_X86_INS_LIDT + 1).uc_x86_insn
  UC_X86_INS_LMSW* = (UC_X86_INS_LLDT + 1).uc_x86_insn
  UC_X86_INS_OR* = (UC_X86_INS_LMSW + 1).uc_x86_insn
  UC_X86_INS_SUB* = (UC_X86_INS_OR + 1).uc_x86_insn
  UC_X86_INS_XOR* = (UC_X86_INS_SUB + 1).uc_x86_insn
  UC_X86_INS_LODSB* = (UC_X86_INS_XOR + 1).uc_x86_insn
  UC_X86_INS_LODSD* = (UC_X86_INS_LODSB + 1).uc_x86_insn
  UC_X86_INS_LODSQ* = (UC_X86_INS_LODSD + 1).uc_x86_insn
  UC_X86_INS_LODSW* = (UC_X86_INS_LODSQ + 1).uc_x86_insn
  UC_X86_INS_LOOP* = (UC_X86_INS_LODSW + 1).uc_x86_insn
  UC_X86_INS_LOOPE* = (UC_X86_INS_LOOP + 1).uc_x86_insn
  UC_X86_INS_LOOPNE* = (UC_X86_INS_LOOPE + 1).uc_x86_insn
  UC_X86_INS_RETF* = (UC_X86_INS_LOOPNE + 1).uc_x86_insn
  UC_X86_INS_RETFQ* = (UC_X86_INS_RETF + 1).uc_x86_insn
  UC_X86_INS_LSL* = (UC_X86_INS_RETFQ + 1).uc_x86_insn
  UC_X86_INS_LSS* = (UC_X86_INS_LSL + 1).uc_x86_insn
  UC_X86_INS_LTR* = (UC_X86_INS_LSS + 1).uc_x86_insn
  UC_X86_INS_XADD* = (UC_X86_INS_LTR + 1).uc_x86_insn
  UC_X86_INS_LZCNT* = (UC_X86_INS_XADD + 1).uc_x86_insn
  UC_X86_INS_MASKMOVDQU* = (UC_X86_INS_LZCNT + 1).uc_x86_insn
  UC_X86_INS_MAXPD* = (UC_X86_INS_MASKMOVDQU + 1).uc_x86_insn
  UC_X86_INS_MAXPS* = (UC_X86_INS_MAXPD + 1).uc_x86_insn
  UC_X86_INS_MAXSD* = (UC_X86_INS_MAXPS + 1).uc_x86_insn
  UC_X86_INS_MAXSS* = (UC_X86_INS_MAXSD + 1).uc_x86_insn
  UC_X86_INS_MFENCE* = (UC_X86_INS_MAXSS + 1).uc_x86_insn
  UC_X86_INS_MINPD* = (UC_X86_INS_MFENCE + 1).uc_x86_insn
  UC_X86_INS_MINPS* = (UC_X86_INS_MINPD + 1).uc_x86_insn
  UC_X86_INS_MINSD* = (UC_X86_INS_MINPS + 1).uc_x86_insn
  UC_X86_INS_MINSS* = (UC_X86_INS_MINSD + 1).uc_x86_insn
  UC_X86_INS_CVTPD2PI* = (UC_X86_INS_MINSS + 1).uc_x86_insn
  UC_X86_INS_CVTPI2PD* = (UC_X86_INS_CVTPD2PI + 1).uc_x86_insn
  UC_X86_INS_CVTPI2PS* = (UC_X86_INS_CVTPI2PD + 1).uc_x86_insn
  UC_X86_INS_CVTPS2PI* = (UC_X86_INS_CVTPI2PS + 1).uc_x86_insn
  UC_X86_INS_CVTTPD2PI* = (UC_X86_INS_CVTPS2PI + 1).uc_x86_insn
  UC_X86_INS_CVTTPS2PI* = (UC_X86_INS_CVTTPD2PI + 1).uc_x86_insn
  UC_X86_INS_EMMS* = (UC_X86_INS_CVTTPS2PI + 1).uc_x86_insn
  UC_X86_INS_MASKMOVQ* = (UC_X86_INS_EMMS + 1).uc_x86_insn
  UC_X86_INS_MOVD* = (UC_X86_INS_MASKMOVQ + 1).uc_x86_insn
  UC_X86_INS_MOVDQ2Q* = (UC_X86_INS_MOVD + 1).uc_x86_insn
  UC_X86_INS_MOVNTQ* = (UC_X86_INS_MOVDQ2Q + 1).uc_x86_insn
  UC_X86_INS_MOVQ2DQ* = (UC_X86_INS_MOVNTQ + 1).uc_x86_insn
  UC_X86_INS_MOVQ* = (UC_X86_INS_MOVQ2DQ + 1).uc_x86_insn
  UC_X86_INS_PABSB* = (UC_X86_INS_MOVQ + 1).uc_x86_insn
  UC_X86_INS_PABSD* = (UC_X86_INS_PABSB + 1).uc_x86_insn
  UC_X86_INS_PABSW* = (UC_X86_INS_PABSD + 1).uc_x86_insn
  UC_X86_INS_PACKSSDW* = (UC_X86_INS_PABSW + 1).uc_x86_insn
  UC_X86_INS_PACKSSWB* = (UC_X86_INS_PACKSSDW + 1).uc_x86_insn
  UC_X86_INS_PACKUSWB* = (UC_X86_INS_PACKSSWB + 1).uc_x86_insn
  UC_X86_INS_PADDB* = (UC_X86_INS_PACKUSWB + 1).uc_x86_insn
  UC_X86_INS_PADDD* = (UC_X86_INS_PADDB + 1).uc_x86_insn
  UC_X86_INS_PADDQ* = (UC_X86_INS_PADDD + 1).uc_x86_insn
  UC_X86_INS_PADDSB* = (UC_X86_INS_PADDQ + 1).uc_x86_insn
  UC_X86_INS_PADDSW* = (UC_X86_INS_PADDSB + 1).uc_x86_insn
  UC_X86_INS_PADDUSB* = (UC_X86_INS_PADDSW + 1).uc_x86_insn
  UC_X86_INS_PADDUSW* = (UC_X86_INS_PADDUSB + 1).uc_x86_insn
  UC_X86_INS_PADDW* = (UC_X86_INS_PADDUSW + 1).uc_x86_insn
  UC_X86_INS_PALIGNR* = (UC_X86_INS_PADDW + 1).uc_x86_insn
  UC_X86_INS_PANDN* = (UC_X86_INS_PALIGNR + 1).uc_x86_insn
  UC_X86_INS_PAND* = (UC_X86_INS_PANDN + 1).uc_x86_insn
  UC_X86_INS_PAVGB* = (UC_X86_INS_PAND + 1).uc_x86_insn
  UC_X86_INS_PAVGW* = (UC_X86_INS_PAVGB + 1).uc_x86_insn
  UC_X86_INS_PCMPEQB* = (UC_X86_INS_PAVGW + 1).uc_x86_insn
  UC_X86_INS_PCMPEQD* = (UC_X86_INS_PCMPEQB + 1).uc_x86_insn
  UC_X86_INS_PCMPEQW* = (UC_X86_INS_PCMPEQD + 1).uc_x86_insn
  UC_X86_INS_PCMPGTB* = (UC_X86_INS_PCMPEQW + 1).uc_x86_insn
  UC_X86_INS_PCMPGTD* = (UC_X86_INS_PCMPGTB + 1).uc_x86_insn
  UC_X86_INS_PCMPGTW* = (UC_X86_INS_PCMPGTD + 1).uc_x86_insn
  UC_X86_INS_PEXTRW* = (UC_X86_INS_PCMPGTW + 1).uc_x86_insn
  UC_X86_INS_PHADDSW* = (UC_X86_INS_PEXTRW + 1).uc_x86_insn
  UC_X86_INS_PHADDW* = (UC_X86_INS_PHADDSW + 1).uc_x86_insn
  UC_X86_INS_PHADDD* = (UC_X86_INS_PHADDW + 1).uc_x86_insn
  UC_X86_INS_PHSUBD* = (UC_X86_INS_PHADDD + 1).uc_x86_insn
  UC_X86_INS_PHSUBSW* = (UC_X86_INS_PHSUBD + 1).uc_x86_insn
  UC_X86_INS_PHSUBW* = (UC_X86_INS_PHSUBSW + 1).uc_x86_insn
  UC_X86_INS_PINSRW* = (UC_X86_INS_PHSUBW + 1).uc_x86_insn
  UC_X86_INS_PMADDUBSW* = (UC_X86_INS_PINSRW + 1).uc_x86_insn
  UC_X86_INS_PMADDWD* = (UC_X86_INS_PMADDUBSW + 1).uc_x86_insn
  UC_X86_INS_PMAXSW* = (UC_X86_INS_PMADDWD + 1).uc_x86_insn
  UC_X86_INS_PMAXUB* = (UC_X86_INS_PMAXSW + 1).uc_x86_insn
  UC_X86_INS_PMINSW* = (UC_X86_INS_PMAXUB + 1).uc_x86_insn
  UC_X86_INS_PMINUB* = (UC_X86_INS_PMINSW + 1).uc_x86_insn
  UC_X86_INS_PMOVMSKB* = (UC_X86_INS_PMINUB + 1).uc_x86_insn
  UC_X86_INS_PMULHRSW* = (UC_X86_INS_PMOVMSKB + 1).uc_x86_insn
  UC_X86_INS_PMULHUW* = (UC_X86_INS_PMULHRSW + 1).uc_x86_insn
  UC_X86_INS_PMULHW* = (UC_X86_INS_PMULHUW + 1).uc_x86_insn
  UC_X86_INS_PMULLW* = (UC_X86_INS_PMULHW + 1).uc_x86_insn
  UC_X86_INS_PMULUDQ* = (UC_X86_INS_PMULLW + 1).uc_x86_insn
  UC_X86_INS_POR* = (UC_X86_INS_PMULUDQ + 1).uc_x86_insn
  UC_X86_INS_PSADBW* = (UC_X86_INS_POR + 1).uc_x86_insn
  UC_X86_INS_PSHUFB* = (UC_X86_INS_PSADBW + 1).uc_x86_insn
  UC_X86_INS_PSHUFW* = (UC_X86_INS_PSHUFB + 1).uc_x86_insn
  UC_X86_INS_PSIGNB* = (UC_X86_INS_PSHUFW + 1).uc_x86_insn
  UC_X86_INS_PSIGND* = (UC_X86_INS_PSIGNB + 1).uc_x86_insn
  UC_X86_INS_PSIGNW* = (UC_X86_INS_PSIGND + 1).uc_x86_insn
  UC_X86_INS_PSLLD* = (UC_X86_INS_PSIGNW + 1).uc_x86_insn
  UC_X86_INS_PSLLQ* = (UC_X86_INS_PSLLD + 1).uc_x86_insn
  UC_X86_INS_PSLLW* = (UC_X86_INS_PSLLQ + 1).uc_x86_insn
  UC_X86_INS_PSRAD* = (UC_X86_INS_PSLLW + 1).uc_x86_insn
  UC_X86_INS_PSRAW* = (UC_X86_INS_PSRAD + 1).uc_x86_insn
  UC_X86_INS_PSRLD* = (UC_X86_INS_PSRAW + 1).uc_x86_insn
  UC_X86_INS_PSRLQ* = (UC_X86_INS_PSRLD + 1).uc_x86_insn
  UC_X86_INS_PSRLW* = (UC_X86_INS_PSRLQ + 1).uc_x86_insn
  UC_X86_INS_PSUBB* = (UC_X86_INS_PSRLW + 1).uc_x86_insn
  UC_X86_INS_PSUBD* = (UC_X86_INS_PSUBB + 1).uc_x86_insn
  UC_X86_INS_PSUBQ* = (UC_X86_INS_PSUBD + 1).uc_x86_insn
  UC_X86_INS_PSUBSB* = (UC_X86_INS_PSUBQ + 1).uc_x86_insn
  UC_X86_INS_PSUBSW* = (UC_X86_INS_PSUBSB + 1).uc_x86_insn
  UC_X86_INS_PSUBUSB* = (UC_X86_INS_PSUBSW + 1).uc_x86_insn
  UC_X86_INS_PSUBUSW* = (UC_X86_INS_PSUBUSB + 1).uc_x86_insn
  UC_X86_INS_PSUBW* = (UC_X86_INS_PSUBUSW + 1).uc_x86_insn
  UC_X86_INS_PUNPCKHBW* = (UC_X86_INS_PSUBW + 1).uc_x86_insn
  UC_X86_INS_PUNPCKHDQ* = (UC_X86_INS_PUNPCKHBW + 1).uc_x86_insn
  UC_X86_INS_PUNPCKHWD* = (UC_X86_INS_PUNPCKHDQ + 1).uc_x86_insn
  UC_X86_INS_PUNPCKLBW* = (UC_X86_INS_PUNPCKHWD + 1).uc_x86_insn
  UC_X86_INS_PUNPCKLDQ* = (UC_X86_INS_PUNPCKLBW + 1).uc_x86_insn
  UC_X86_INS_PUNPCKLWD* = (UC_X86_INS_PUNPCKLDQ + 1).uc_x86_insn
  UC_X86_INS_PXOR* = (UC_X86_INS_PUNPCKLWD + 1).uc_x86_insn
  UC_X86_INS_MONITOR* = (UC_X86_INS_PXOR + 1).uc_x86_insn
  UC_X86_INS_MONTMUL* = (UC_X86_INS_MONITOR + 1).uc_x86_insn
  UC_X86_INS_MOV* = (UC_X86_INS_MONTMUL + 1).uc_x86_insn
  UC_X86_INS_MOVABS* = (UC_X86_INS_MOV + 1).uc_x86_insn
  UC_X86_INS_MOVBE* = (UC_X86_INS_MOVABS + 1).uc_x86_insn
  UC_X86_INS_MOVDDUP* = (UC_X86_INS_MOVBE + 1).uc_x86_insn
  UC_X86_INS_MOVDQA* = (UC_X86_INS_MOVDDUP + 1).uc_x86_insn
  UC_X86_INS_MOVDQU* = (UC_X86_INS_MOVDQA + 1).uc_x86_insn
  UC_X86_INS_MOVHLPS* = (UC_X86_INS_MOVDQU + 1).uc_x86_insn
  UC_X86_INS_MOVHPD* = (UC_X86_INS_MOVHLPS + 1).uc_x86_insn
  UC_X86_INS_MOVHPS* = (UC_X86_INS_MOVHPD + 1).uc_x86_insn
  UC_X86_INS_MOVLHPS* = (UC_X86_INS_MOVHPS + 1).uc_x86_insn
  UC_X86_INS_MOVLPD* = (UC_X86_INS_MOVLHPS + 1).uc_x86_insn
  UC_X86_INS_MOVLPS* = (UC_X86_INS_MOVLPD + 1).uc_x86_insn
  UC_X86_INS_MOVMSKPD* = (UC_X86_INS_MOVLPS + 1).uc_x86_insn
  UC_X86_INS_MOVMSKPS* = (UC_X86_INS_MOVMSKPD + 1).uc_x86_insn
  UC_X86_INS_MOVNTDQA* = (UC_X86_INS_MOVMSKPS + 1).uc_x86_insn
  UC_X86_INS_MOVNTDQ* = (UC_X86_INS_MOVNTDQA + 1).uc_x86_insn
  UC_X86_INS_MOVNTI* = (UC_X86_INS_MOVNTDQ + 1).uc_x86_insn
  UC_X86_INS_MOVNTPD* = (UC_X86_INS_MOVNTI + 1).uc_x86_insn
  UC_X86_INS_MOVNTPS* = (UC_X86_INS_MOVNTPD + 1).uc_x86_insn
  UC_X86_INS_MOVNTSD* = (UC_X86_INS_MOVNTPS + 1).uc_x86_insn
  UC_X86_INS_MOVNTSS* = (UC_X86_INS_MOVNTSD + 1).uc_x86_insn
  UC_X86_INS_MOVSB* = (UC_X86_INS_MOVNTSS + 1).uc_x86_insn
  UC_X86_INS_MOVSD* = (UC_X86_INS_MOVSB + 1).uc_x86_insn
  UC_X86_INS_MOVSHDUP* = (UC_X86_INS_MOVSD + 1).uc_x86_insn
  UC_X86_INS_MOVSLDUP* = (UC_X86_INS_MOVSHDUP + 1).uc_x86_insn
  UC_X86_INS_MOVSQ* = (UC_X86_INS_MOVSLDUP + 1).uc_x86_insn
  UC_X86_INS_MOVSS* = (UC_X86_INS_MOVSQ + 1).uc_x86_insn
  UC_X86_INS_MOVSW* = (UC_X86_INS_MOVSS + 1).uc_x86_insn
  UC_X86_INS_MOVSX* = (UC_X86_INS_MOVSW + 1).uc_x86_insn
  UC_X86_INS_MOVSXD* = (UC_X86_INS_MOVSX + 1).uc_x86_insn
  UC_X86_INS_MOVUPD* = (UC_X86_INS_MOVSXD + 1).uc_x86_insn
  UC_X86_INS_MOVUPS* = (UC_X86_INS_MOVUPD + 1).uc_x86_insn
  UC_X86_INS_MOVZX* = (UC_X86_INS_MOVUPS + 1).uc_x86_insn
  UC_X86_INS_MPSADBW* = (UC_X86_INS_MOVZX + 1).uc_x86_insn
  UC_X86_INS_MUL* = (UC_X86_INS_MPSADBW + 1).uc_x86_insn
  UC_X86_INS_MULPD* = (UC_X86_INS_MUL + 1).uc_x86_insn
  UC_X86_INS_MULPS* = (UC_X86_INS_MULPD + 1).uc_x86_insn
  UC_X86_INS_MULSD* = (UC_X86_INS_MULPS + 1).uc_x86_insn
  UC_X86_INS_MULSS* = (UC_X86_INS_MULSD + 1).uc_x86_insn
  UC_X86_INS_MULX* = (UC_X86_INS_MULSS + 1).uc_x86_insn
  UC_X86_INS_FMUL* = (UC_X86_INS_MULX + 1).uc_x86_insn
  UC_X86_INS_FIMUL* = (UC_X86_INS_FMUL + 1).uc_x86_insn
  UC_X86_INS_FMULP* = (UC_X86_INS_FIMUL + 1).uc_x86_insn
  UC_X86_INS_MWAIT* = (UC_X86_INS_FMULP + 1).uc_x86_insn
  UC_X86_INS_NEG* = (UC_X86_INS_MWAIT + 1).uc_x86_insn
  UC_X86_INS_NOP* = (UC_X86_INS_NEG + 1).uc_x86_insn
  UC_X86_INS_NOT* = (UC_X86_INS_NOP + 1).uc_x86_insn
  UC_X86_INS_OUT* = (UC_X86_INS_NOT + 1).uc_x86_insn
  UC_X86_INS_OUTSB* = (UC_X86_INS_OUT + 1).uc_x86_insn
  UC_X86_INS_OUTSD* = (UC_X86_INS_OUTSB + 1).uc_x86_insn
  UC_X86_INS_OUTSW* = (UC_X86_INS_OUTSD + 1).uc_x86_insn
  UC_X86_INS_PACKUSDW* = (UC_X86_INS_OUTSW + 1).uc_x86_insn
  UC_X86_INS_PAUSE* = (UC_X86_INS_PACKUSDW + 1).uc_x86_insn
  UC_X86_INS_PAVGUSB* = (UC_X86_INS_PAUSE + 1).uc_x86_insn
  UC_X86_INS_PBLENDVB* = (UC_X86_INS_PAVGUSB + 1).uc_x86_insn
  UC_X86_INS_PBLENDW* = (UC_X86_INS_PBLENDVB + 1).uc_x86_insn
  UC_X86_INS_PCLMULQDQ* = (UC_X86_INS_PBLENDW + 1).uc_x86_insn
  UC_X86_INS_PCMPEQQ* = (UC_X86_INS_PCLMULQDQ + 1).uc_x86_insn
  UC_X86_INS_PCMPESTRI* = (UC_X86_INS_PCMPEQQ + 1).uc_x86_insn
  UC_X86_INS_PCMPESTRM* = (UC_X86_INS_PCMPESTRI + 1).uc_x86_insn
  UC_X86_INS_PCMPGTQ* = (UC_X86_INS_PCMPESTRM + 1).uc_x86_insn
  UC_X86_INS_PCMPISTRI* = (UC_X86_INS_PCMPGTQ + 1).uc_x86_insn
  UC_X86_INS_PCMPISTRM* = (UC_X86_INS_PCMPISTRI + 1).uc_x86_insn
  UC_X86_INS_PCOMMIT* = (UC_X86_INS_PCMPISTRM + 1).uc_x86_insn
  UC_X86_INS_PDEP* = (UC_X86_INS_PCOMMIT + 1).uc_x86_insn
  UC_X86_INS_PEXT* = (UC_X86_INS_PDEP + 1).uc_x86_insn
  UC_X86_INS_PEXTRB* = (UC_X86_INS_PEXT + 1).uc_x86_insn
  UC_X86_INS_PEXTRD* = (UC_X86_INS_PEXTRB + 1).uc_x86_insn
  UC_X86_INS_PEXTRQ* = (UC_X86_INS_PEXTRD + 1).uc_x86_insn
  UC_X86_INS_PF2ID* = (UC_X86_INS_PEXTRQ + 1).uc_x86_insn
  UC_X86_INS_PF2IW* = (UC_X86_INS_PF2ID + 1).uc_x86_insn
  UC_X86_INS_PFACC* = (UC_X86_INS_PF2IW + 1).uc_x86_insn
  UC_X86_INS_PFADD* = (UC_X86_INS_PFACC + 1).uc_x86_insn
  UC_X86_INS_PFCMPEQ* = (UC_X86_INS_PFADD + 1).uc_x86_insn
  UC_X86_INS_PFCMPGE* = (UC_X86_INS_PFCMPEQ + 1).uc_x86_insn
  UC_X86_INS_PFCMPGT* = (UC_X86_INS_PFCMPGE + 1).uc_x86_insn
  UC_X86_INS_PFMAX* = (UC_X86_INS_PFCMPGT + 1).uc_x86_insn
  UC_X86_INS_PFMIN* = (UC_X86_INS_PFMAX + 1).uc_x86_insn
  UC_X86_INS_PFMUL* = (UC_X86_INS_PFMIN + 1).uc_x86_insn
  UC_X86_INS_PFNACC* = (UC_X86_INS_PFMUL + 1).uc_x86_insn
  UC_X86_INS_PFPNACC* = (UC_X86_INS_PFNACC + 1).uc_x86_insn
  UC_X86_INS_PFRCPIT1* = (UC_X86_INS_PFPNACC + 1).uc_x86_insn
  UC_X86_INS_PFRCPIT2* = (UC_X86_INS_PFRCPIT1 + 1).uc_x86_insn
  UC_X86_INS_PFRCP* = (UC_X86_INS_PFRCPIT2 + 1).uc_x86_insn
  UC_X86_INS_PFRSQIT1* = (UC_X86_INS_PFRCP + 1).uc_x86_insn
  UC_X86_INS_PFRSQRT* = (UC_X86_INS_PFRSQIT1 + 1).uc_x86_insn
  UC_X86_INS_PFSUBR* = (UC_X86_INS_PFRSQRT + 1).uc_x86_insn
  UC_X86_INS_PFSUB* = (UC_X86_INS_PFSUBR + 1).uc_x86_insn
  UC_X86_INS_PHMINPOSUW* = (UC_X86_INS_PFSUB + 1).uc_x86_insn
  UC_X86_INS_PI2FD* = (UC_X86_INS_PHMINPOSUW + 1).uc_x86_insn
  UC_X86_INS_PI2FW* = (UC_X86_INS_PI2FD + 1).uc_x86_insn
  UC_X86_INS_PINSRB* = (UC_X86_INS_PI2FW + 1).uc_x86_insn
  UC_X86_INS_PINSRD* = (UC_X86_INS_PINSRB + 1).uc_x86_insn
  UC_X86_INS_PINSRQ* = (UC_X86_INS_PINSRD + 1).uc_x86_insn
  UC_X86_INS_PMAXSB* = (UC_X86_INS_PINSRQ + 1).uc_x86_insn
  UC_X86_INS_PMAXSD* = (UC_X86_INS_PMAXSB + 1).uc_x86_insn
  UC_X86_INS_PMAXUD* = (UC_X86_INS_PMAXSD + 1).uc_x86_insn
  UC_X86_INS_PMAXUW* = (UC_X86_INS_PMAXUD + 1).uc_x86_insn
  UC_X86_INS_PMINSB* = (UC_X86_INS_PMAXUW + 1).uc_x86_insn
  UC_X86_INS_PMINSD* = (UC_X86_INS_PMINSB + 1).uc_x86_insn
  UC_X86_INS_PMINUD* = (UC_X86_INS_PMINSD + 1).uc_x86_insn
  UC_X86_INS_PMINUW* = (UC_X86_INS_PMINUD + 1).uc_x86_insn
  UC_X86_INS_PMOVSXBD* = (UC_X86_INS_PMINUW + 1).uc_x86_insn
  UC_X86_INS_PMOVSXBQ* = (UC_X86_INS_PMOVSXBD + 1).uc_x86_insn
  UC_X86_INS_PMOVSXBW* = (UC_X86_INS_PMOVSXBQ + 1).uc_x86_insn
  UC_X86_INS_PMOVSXDQ* = (UC_X86_INS_PMOVSXBW + 1).uc_x86_insn
  UC_X86_INS_PMOVSXWD* = (UC_X86_INS_PMOVSXDQ + 1).uc_x86_insn
  UC_X86_INS_PMOVSXWQ* = (UC_X86_INS_PMOVSXWD + 1).uc_x86_insn
  UC_X86_INS_PMOVZXBD* = (UC_X86_INS_PMOVSXWQ + 1).uc_x86_insn
  UC_X86_INS_PMOVZXBQ* = (UC_X86_INS_PMOVZXBD + 1).uc_x86_insn
  UC_X86_INS_PMOVZXBW* = (UC_X86_INS_PMOVZXBQ + 1).uc_x86_insn
  UC_X86_INS_PMOVZXDQ* = (UC_X86_INS_PMOVZXBW + 1).uc_x86_insn
  UC_X86_INS_PMOVZXWD* = (UC_X86_INS_PMOVZXDQ + 1).uc_x86_insn
  UC_X86_INS_PMOVZXWQ* = (UC_X86_INS_PMOVZXWD + 1).uc_x86_insn
  UC_X86_INS_PMULDQ* = (UC_X86_INS_PMOVZXWQ + 1).uc_x86_insn
  UC_X86_INS_PMULHRW* = (UC_X86_INS_PMULDQ + 1).uc_x86_insn
  UC_X86_INS_PMULLD* = (UC_X86_INS_PMULHRW + 1).uc_x86_insn
  UC_X86_INS_POP* = (UC_X86_INS_PMULLD + 1).uc_x86_insn
  UC_X86_INS_POPAW* = (UC_X86_INS_POP + 1).uc_x86_insn
  UC_X86_INS_POPAL* = (UC_X86_INS_POPAW + 1).uc_x86_insn
  UC_X86_INS_POPCNT* = (UC_X86_INS_POPAL + 1).uc_x86_insn
  UC_X86_INS_POPF* = (UC_X86_INS_POPCNT + 1).uc_x86_insn
  UC_X86_INS_POPFD* = (UC_X86_INS_POPF + 1).uc_x86_insn
  UC_X86_INS_POPFQ* = (UC_X86_INS_POPFD + 1).uc_x86_insn
  UC_X86_INS_PREFETCH* = (UC_X86_INS_POPFQ + 1).uc_x86_insn
  UC_X86_INS_PREFETCHNTA* = (UC_X86_INS_PREFETCH + 1).uc_x86_insn
  UC_X86_INS_PREFETCHT0* = (UC_X86_INS_PREFETCHNTA + 1).uc_x86_insn
  UC_X86_INS_PREFETCHT1* = (UC_X86_INS_PREFETCHT0 + 1).uc_x86_insn
  UC_X86_INS_PREFETCHT2* = (UC_X86_INS_PREFETCHT1 + 1).uc_x86_insn
  UC_X86_INS_PREFETCHW* = (UC_X86_INS_PREFETCHT2 + 1).uc_x86_insn
  UC_X86_INS_PSHUFD* = (UC_X86_INS_PREFETCHW + 1).uc_x86_insn
  UC_X86_INS_PSHUFHW* = (UC_X86_INS_PSHUFD + 1).uc_x86_insn
  UC_X86_INS_PSHUFLW* = (UC_X86_INS_PSHUFHW + 1).uc_x86_insn
  UC_X86_INS_PSLLDQ* = (UC_X86_INS_PSHUFLW + 1).uc_x86_insn
  UC_X86_INS_PSRLDQ* = (UC_X86_INS_PSLLDQ + 1).uc_x86_insn
  UC_X86_INS_PSWAPD* = (UC_X86_INS_PSRLDQ + 1).uc_x86_insn
  UC_X86_INS_PTEST* = (UC_X86_INS_PSWAPD + 1).uc_x86_insn
  UC_X86_INS_PUNPCKHQDQ* = (UC_X86_INS_PTEST + 1).uc_x86_insn
  UC_X86_INS_PUNPCKLQDQ* = (UC_X86_INS_PUNPCKHQDQ + 1).uc_x86_insn
  UC_X86_INS_PUSH* = (UC_X86_INS_PUNPCKLQDQ + 1).uc_x86_insn
  UC_X86_INS_PUSHAW* = (UC_X86_INS_PUSH + 1).uc_x86_insn
  UC_X86_INS_PUSHAL* = (UC_X86_INS_PUSHAW + 1).uc_x86_insn
  UC_X86_INS_PUSHF* = (UC_X86_INS_PUSHAL + 1).uc_x86_insn
  UC_X86_INS_PUSHFD* = (UC_X86_INS_PUSHF + 1).uc_x86_insn
  UC_X86_INS_PUSHFQ* = (UC_X86_INS_PUSHFD + 1).uc_x86_insn
  UC_X86_INS_RCL* = (UC_X86_INS_PUSHFQ + 1).uc_x86_insn
  UC_X86_INS_RCPPS* = (UC_X86_INS_RCL + 1).uc_x86_insn
  UC_X86_INS_RCPSS* = (UC_X86_INS_RCPPS + 1).uc_x86_insn
  UC_X86_INS_RCR* = (UC_X86_INS_RCPSS + 1).uc_x86_insn
  UC_X86_INS_RDFSBASE* = (UC_X86_INS_RCR + 1).uc_x86_insn
  UC_X86_INS_RDGSBASE* = (UC_X86_INS_RDFSBASE + 1).uc_x86_insn
  UC_X86_INS_RDMSR* = (UC_X86_INS_RDGSBASE + 1).uc_x86_insn
  UC_X86_INS_RDPMC* = (UC_X86_INS_RDMSR + 1).uc_x86_insn
  UC_X86_INS_RDRAND* = (UC_X86_INS_RDPMC + 1).uc_x86_insn
  UC_X86_INS_RDSEED* = (UC_X86_INS_RDRAND + 1).uc_x86_insn
  UC_X86_INS_RDTSC* = (UC_X86_INS_RDSEED + 1).uc_x86_insn
  UC_X86_INS_RDTSCP* = (UC_X86_INS_RDTSC + 1).uc_x86_insn
  UC_X86_INS_ROL* = (UC_X86_INS_RDTSCP + 1).uc_x86_insn
  UC_X86_INS_ROR* = (UC_X86_INS_ROL + 1).uc_x86_insn
  UC_X86_INS_RORX* = (UC_X86_INS_ROR + 1).uc_x86_insn
  UC_X86_INS_ROUNDPD* = (UC_X86_INS_RORX + 1).uc_x86_insn
  UC_X86_INS_ROUNDPS* = (UC_X86_INS_ROUNDPD + 1).uc_x86_insn
  UC_X86_INS_ROUNDSD* = (UC_X86_INS_ROUNDPS + 1).uc_x86_insn
  UC_X86_INS_ROUNDSS* = (UC_X86_INS_ROUNDSD + 1).uc_x86_insn
  UC_X86_INS_RSM* = (UC_X86_INS_ROUNDSS + 1).uc_x86_insn
  UC_X86_INS_RSQRTPS* = (UC_X86_INS_RSM + 1).uc_x86_insn
  UC_X86_INS_RSQRTSS* = (UC_X86_INS_RSQRTPS + 1).uc_x86_insn
  UC_X86_INS_SAHF* = (UC_X86_INS_RSQRTSS + 1).uc_x86_insn
  UC_X86_INS_SAL* = (UC_X86_INS_SAHF + 1).uc_x86_insn
  UC_X86_INS_SALC* = (UC_X86_INS_SAL + 1).uc_x86_insn
  UC_X86_INS_SAR* = (UC_X86_INS_SALC + 1).uc_x86_insn
  UC_X86_INS_SARX* = (UC_X86_INS_SAR + 1).uc_x86_insn
  UC_X86_INS_SBB* = (UC_X86_INS_SARX + 1).uc_x86_insn
  UC_X86_INS_SCASB* = (UC_X86_INS_SBB + 1).uc_x86_insn
  UC_X86_INS_SCASD* = (UC_X86_INS_SCASB + 1).uc_x86_insn
  UC_X86_INS_SCASQ* = (UC_X86_INS_SCASD + 1).uc_x86_insn
  UC_X86_INS_SCASW* = (UC_X86_INS_SCASQ + 1).uc_x86_insn
  UC_X86_INS_SETAE* = (UC_X86_INS_SCASW + 1).uc_x86_insn
  UC_X86_INS_SETA* = (UC_X86_INS_SETAE + 1).uc_x86_insn
  UC_X86_INS_SETBE* = (UC_X86_INS_SETA + 1).uc_x86_insn
  UC_X86_INS_SETB* = (UC_X86_INS_SETBE + 1).uc_x86_insn
  UC_X86_INS_SETE* = (UC_X86_INS_SETB + 1).uc_x86_insn
  UC_X86_INS_SETGE* = (UC_X86_INS_SETE + 1).uc_x86_insn
  UC_X86_INS_SETG* = (UC_X86_INS_SETGE + 1).uc_x86_insn
  UC_X86_INS_SETLE* = (UC_X86_INS_SETG + 1).uc_x86_insn
  UC_X86_INS_SETL* = (UC_X86_INS_SETLE + 1).uc_x86_insn
  UC_X86_INS_SETNE* = (UC_X86_INS_SETL + 1).uc_x86_insn
  UC_X86_INS_SETNO* = (UC_X86_INS_SETNE + 1).uc_x86_insn
  UC_X86_INS_SETNP* = (UC_X86_INS_SETNO + 1).uc_x86_insn
  UC_X86_INS_SETNS* = (UC_X86_INS_SETNP + 1).uc_x86_insn
  UC_X86_INS_SETO* = (UC_X86_INS_SETNS + 1).uc_x86_insn
  UC_X86_INS_SETP* = (UC_X86_INS_SETO + 1).uc_x86_insn
  UC_X86_INS_SETS* = (UC_X86_INS_SETP + 1).uc_x86_insn
  UC_X86_INS_SFENCE* = (UC_X86_INS_SETS + 1).uc_x86_insn
  UC_X86_INS_SGDT* = (UC_X86_INS_SFENCE + 1).uc_x86_insn
  UC_X86_INS_SHA1MSG1* = (UC_X86_INS_SGDT + 1).uc_x86_insn
  UC_X86_INS_SHA1MSG2* = (UC_X86_INS_SHA1MSG1 + 1).uc_x86_insn
  UC_X86_INS_SHA1NEXTE* = (UC_X86_INS_SHA1MSG2 + 1).uc_x86_insn
  UC_X86_INS_SHA1RNDS4* = (UC_X86_INS_SHA1NEXTE + 1).uc_x86_insn
  UC_X86_INS_SHA256MSG1* = (UC_X86_INS_SHA1RNDS4 + 1).uc_x86_insn
  UC_X86_INS_SHA256MSG2* = (UC_X86_INS_SHA256MSG1 + 1).uc_x86_insn
  UC_X86_INS_SHA256RNDS2* = (UC_X86_INS_SHA256MSG2 + 1).uc_x86_insn
  UC_X86_INS_SHL* = (UC_X86_INS_SHA256RNDS2 + 1).uc_x86_insn
  UC_X86_INS_SHLD* = (UC_X86_INS_SHL + 1).uc_x86_insn
  UC_X86_INS_SHLX* = (UC_X86_INS_SHLD + 1).uc_x86_insn
  UC_X86_INS_SHR* = (UC_X86_INS_SHLX + 1).uc_x86_insn
  UC_X86_INS_SHRD* = (UC_X86_INS_SHR + 1).uc_x86_insn
  UC_X86_INS_SHRX* = (UC_X86_INS_SHRD + 1).uc_x86_insn
  UC_X86_INS_SHUFPD* = (UC_X86_INS_SHRX + 1).uc_x86_insn
  UC_X86_INS_SHUFPS* = (UC_X86_INS_SHUFPD + 1).uc_x86_insn
  UC_X86_INS_SIDT* = (UC_X86_INS_SHUFPS + 1).uc_x86_insn
  UC_X86_INS_FSIN* = (UC_X86_INS_SIDT + 1).uc_x86_insn
  UC_X86_INS_SKINIT* = (UC_X86_INS_FSIN + 1).uc_x86_insn
  UC_X86_INS_SLDT* = (UC_X86_INS_SKINIT + 1).uc_x86_insn
  UC_X86_INS_SMSW* = (UC_X86_INS_SLDT + 1).uc_x86_insn
  UC_X86_INS_SQRTPD* = (UC_X86_INS_SMSW + 1).uc_x86_insn
  UC_X86_INS_SQRTPS* = (UC_X86_INS_SQRTPD + 1).uc_x86_insn
  UC_X86_INS_SQRTSD* = (UC_X86_INS_SQRTPS + 1).uc_x86_insn
  UC_X86_INS_SQRTSS* = (UC_X86_INS_SQRTSD + 1).uc_x86_insn
  UC_X86_INS_FSQRT* = (UC_X86_INS_SQRTSS + 1).uc_x86_insn
  UC_X86_INS_STAC* = (UC_X86_INS_FSQRT + 1).uc_x86_insn
  UC_X86_INS_STC* = (UC_X86_INS_STAC + 1).uc_x86_insn
  UC_X86_INS_STD* = (UC_X86_INS_STC + 1).uc_x86_insn
  UC_X86_INS_STGI* = (UC_X86_INS_STD + 1).uc_x86_insn
  UC_X86_INS_STI* = (UC_X86_INS_STGI + 1).uc_x86_insn
  UC_X86_INS_STMXCSR* = (UC_X86_INS_STI + 1).uc_x86_insn
  UC_X86_INS_STOSB* = (UC_X86_INS_STMXCSR + 1).uc_x86_insn
  UC_X86_INS_STOSD* = (UC_X86_INS_STOSB + 1).uc_x86_insn
  UC_X86_INS_STOSQ* = (UC_X86_INS_STOSD + 1).uc_x86_insn
  UC_X86_INS_STOSW* = (UC_X86_INS_STOSQ + 1).uc_x86_insn
  UC_X86_INS_STR* = (UC_X86_INS_STOSW + 1).uc_x86_insn
  UC_X86_INS_FST* = (UC_X86_INS_STR + 1).uc_x86_insn
  UC_X86_INS_FSTP* = (UC_X86_INS_FST + 1).uc_x86_insn
  UC_X86_INS_FSTPNCE* = (UC_X86_INS_FSTP + 1).uc_x86_insn
  UC_X86_INS_FXCH* = (UC_X86_INS_FSTPNCE + 1).uc_x86_insn
  UC_X86_INS_SUBPD* = (UC_X86_INS_FXCH + 1).uc_x86_insn
  UC_X86_INS_SUBPS* = (UC_X86_INS_SUBPD + 1).uc_x86_insn
  UC_X86_INS_FSUBR* = (UC_X86_INS_SUBPS + 1).uc_x86_insn
  UC_X86_INS_FISUBR* = (UC_X86_INS_FSUBR + 1).uc_x86_insn
  UC_X86_INS_FSUBRP* = (UC_X86_INS_FISUBR + 1).uc_x86_insn
  UC_X86_INS_SUBSD* = (UC_X86_INS_FSUBRP + 1).uc_x86_insn
  UC_X86_INS_SUBSS* = (UC_X86_INS_SUBSD + 1).uc_x86_insn
  UC_X86_INS_FSUB* = (UC_X86_INS_SUBSS + 1).uc_x86_insn
  UC_X86_INS_FISUB* = (UC_X86_INS_FSUB + 1).uc_x86_insn
  UC_X86_INS_FSUBP* = (UC_X86_INS_FISUB + 1).uc_x86_insn
  UC_X86_INS_SWAPGS* = (UC_X86_INS_FSUBP + 1).uc_x86_insn
  UC_X86_INS_SYSCALL* = (UC_X86_INS_SWAPGS + 1).uc_x86_insn
  UC_X86_INS_SYSENTER* = (UC_X86_INS_SYSCALL + 1).uc_x86_insn
  UC_X86_INS_SYSEXIT* = (UC_X86_INS_SYSENTER + 1).uc_x86_insn
  UC_X86_INS_SYSRET* = (UC_X86_INS_SYSEXIT + 1).uc_x86_insn
  UC_X86_INS_T1MSKC* = (UC_X86_INS_SYSRET + 1).uc_x86_insn
  UC_X86_INS_TEST* = (UC_X86_INS_T1MSKC + 1).uc_x86_insn
  UC_X86_INS_UD2* = (UC_X86_INS_TEST + 1).uc_x86_insn
  UC_X86_INS_FTST* = (UC_X86_INS_UD2 + 1).uc_x86_insn
  UC_X86_INS_TZCNT* = (UC_X86_INS_FTST + 1).uc_x86_insn
  UC_X86_INS_TZMSK* = (UC_X86_INS_TZCNT + 1).uc_x86_insn
  UC_X86_INS_FUCOMPI* = (UC_X86_INS_TZMSK + 1).uc_x86_insn
  UC_X86_INS_FUCOMI* = (UC_X86_INS_FUCOMPI + 1).uc_x86_insn
  UC_X86_INS_FUCOMPP* = (UC_X86_INS_FUCOMI + 1).uc_x86_insn
  UC_X86_INS_FUCOMP* = (UC_X86_INS_FUCOMPP + 1).uc_x86_insn
  UC_X86_INS_FUCOM* = (UC_X86_INS_FUCOMP + 1).uc_x86_insn
  UC_X86_INS_UD2B* = (UC_X86_INS_FUCOM + 1).uc_x86_insn
  UC_X86_INS_UNPCKHPD* = (UC_X86_INS_UD2B + 1).uc_x86_insn
  UC_X86_INS_UNPCKHPS* = (UC_X86_INS_UNPCKHPD + 1).uc_x86_insn
  UC_X86_INS_UNPCKLPD* = (UC_X86_INS_UNPCKHPS + 1).uc_x86_insn
  UC_X86_INS_UNPCKLPS* = (UC_X86_INS_UNPCKLPD + 1).uc_x86_insn
  UC_X86_INS_VADDPD* = (UC_X86_INS_UNPCKLPS + 1).uc_x86_insn
  UC_X86_INS_VADDPS* = (UC_X86_INS_VADDPD + 1).uc_x86_insn
  UC_X86_INS_VADDSD* = (UC_X86_INS_VADDPS + 1).uc_x86_insn
  UC_X86_INS_VADDSS* = (UC_X86_INS_VADDSD + 1).uc_x86_insn
  UC_X86_INS_VADDSUBPD* = (UC_X86_INS_VADDSS + 1).uc_x86_insn
  UC_X86_INS_VADDSUBPS* = (UC_X86_INS_VADDSUBPD + 1).uc_x86_insn
  UC_X86_INS_VAESDECLAST* = (UC_X86_INS_VADDSUBPS + 1).uc_x86_insn
  UC_X86_INS_VAESDEC* = (UC_X86_INS_VAESDECLAST + 1).uc_x86_insn
  UC_X86_INS_VAESENCLAST* = (UC_X86_INS_VAESDEC + 1).uc_x86_insn
  UC_X86_INS_VAESENC* = (UC_X86_INS_VAESENCLAST + 1).uc_x86_insn
  UC_X86_INS_VAESIMC* = (UC_X86_INS_VAESENC + 1).uc_x86_insn
  UC_X86_INS_VAESKEYGENASSIST* = (UC_X86_INS_VAESIMC + 1).uc_x86_insn
  UC_X86_INS_VALIGND* = (UC_X86_INS_VAESKEYGENASSIST + 1).uc_x86_insn
  UC_X86_INS_VALIGNQ* = (UC_X86_INS_VALIGND + 1).uc_x86_insn
  UC_X86_INS_VANDNPD* = (UC_X86_INS_VALIGNQ + 1).uc_x86_insn
  UC_X86_INS_VANDNPS* = (UC_X86_INS_VANDNPD + 1).uc_x86_insn
  UC_X86_INS_VANDPD* = (UC_X86_INS_VANDNPS + 1).uc_x86_insn
  UC_X86_INS_VANDPS* = (UC_X86_INS_VANDPD + 1).uc_x86_insn
  UC_X86_INS_VBLENDMPD* = (UC_X86_INS_VANDPS + 1).uc_x86_insn
  UC_X86_INS_VBLENDMPS* = (UC_X86_INS_VBLENDMPD + 1).uc_x86_insn
  UC_X86_INS_VBLENDPD* = (UC_X86_INS_VBLENDMPS + 1).uc_x86_insn
  UC_X86_INS_VBLENDPS* = (UC_X86_INS_VBLENDPD + 1).uc_x86_insn
  UC_X86_INS_VBLENDVPD* = (UC_X86_INS_VBLENDPS + 1).uc_x86_insn
  UC_X86_INS_VBLENDVPS* = (UC_X86_INS_VBLENDVPD + 1).uc_x86_insn
  UC_X86_INS_VBROADCASTF128* = (UC_X86_INS_VBLENDVPS + 1).uc_x86_insn
  UC_X86_INS_VBROADCASTI32X4* = (UC_X86_INS_VBROADCASTF128 + 1).uc_x86_insn
  UC_X86_INS_VBROADCASTI64X4* = (UC_X86_INS_VBROADCASTI32X4 + 1).uc_x86_insn
  UC_X86_INS_VBROADCASTSD* = (UC_X86_INS_VBROADCASTI64X4 + 1).uc_x86_insn
  UC_X86_INS_VBROADCASTSS* = (UC_X86_INS_VBROADCASTSD + 1).uc_x86_insn
  UC_X86_INS_VCMPPD* = (UC_X86_INS_VBROADCASTSS + 1).uc_x86_insn
  UC_X86_INS_VCMPPS* = (UC_X86_INS_VCMPPD + 1).uc_x86_insn
  UC_X86_INS_VCMPSD* = (UC_X86_INS_VCMPPS + 1).uc_x86_insn
  UC_X86_INS_VCMPSS* = (UC_X86_INS_VCMPSD + 1).uc_x86_insn
  UC_X86_INS_VCOMPRESSPD* = (UC_X86_INS_VCMPSS + 1).uc_x86_insn
  UC_X86_INS_VCOMPRESSPS* = (UC_X86_INS_VCOMPRESSPD + 1).uc_x86_insn
  UC_X86_INS_VCVTDQ2PD* = (UC_X86_INS_VCOMPRESSPS + 1).uc_x86_insn
  UC_X86_INS_VCVTDQ2PS* = (UC_X86_INS_VCVTDQ2PD + 1).uc_x86_insn
  UC_X86_INS_VCVTPD2DQX* = (UC_X86_INS_VCVTDQ2PS + 1).uc_x86_insn
  UC_X86_INS_VCVTPD2DQ* = (UC_X86_INS_VCVTPD2DQX + 1).uc_x86_insn
  UC_X86_INS_VCVTPD2PSX* = (UC_X86_INS_VCVTPD2DQ + 1).uc_x86_insn
  UC_X86_INS_VCVTPD2PS* = (UC_X86_INS_VCVTPD2PSX + 1).uc_x86_insn
  UC_X86_INS_VCVTPD2UDQ* = (UC_X86_INS_VCVTPD2PS + 1).uc_x86_insn
  UC_X86_INS_VCVTPH2PS* = (UC_X86_INS_VCVTPD2UDQ + 1).uc_x86_insn
  UC_X86_INS_VCVTPS2DQ* = (UC_X86_INS_VCVTPH2PS + 1).uc_x86_insn
  UC_X86_INS_VCVTPS2PD* = (UC_X86_INS_VCVTPS2DQ + 1).uc_x86_insn
  UC_X86_INS_VCVTPS2PH* = (UC_X86_INS_VCVTPS2PD + 1).uc_x86_insn
  UC_X86_INS_VCVTPS2UDQ* = (UC_X86_INS_VCVTPS2PH + 1).uc_x86_insn
  UC_X86_INS_VCVTSD2SI* = (UC_X86_INS_VCVTPS2UDQ + 1).uc_x86_insn
  UC_X86_INS_VCVTSD2USI* = (UC_X86_INS_VCVTSD2SI + 1).uc_x86_insn
  UC_X86_INS_VCVTSS2SI* = (UC_X86_INS_VCVTSD2USI + 1).uc_x86_insn
  UC_X86_INS_VCVTSS2USI* = (UC_X86_INS_VCVTSS2SI + 1).uc_x86_insn
  UC_X86_INS_VCVTTPD2DQX* = (UC_X86_INS_VCVTSS2USI + 1).uc_x86_insn
  UC_X86_INS_VCVTTPD2DQ* = (UC_X86_INS_VCVTTPD2DQX + 1).uc_x86_insn
  UC_X86_INS_VCVTTPD2UDQ* = (UC_X86_INS_VCVTTPD2DQ + 1).uc_x86_insn
  UC_X86_INS_VCVTTPS2DQ* = (UC_X86_INS_VCVTTPD2UDQ + 1).uc_x86_insn
  UC_X86_INS_VCVTTPS2UDQ* = (UC_X86_INS_VCVTTPS2DQ + 1).uc_x86_insn
  UC_X86_INS_VCVTUDQ2PD* = (UC_X86_INS_VCVTTPS2UDQ + 1).uc_x86_insn
  UC_X86_INS_VCVTUDQ2PS* = (UC_X86_INS_VCVTUDQ2PD + 1).uc_x86_insn
  UC_X86_INS_VDIVPD* = (UC_X86_INS_VCVTUDQ2PS + 1).uc_x86_insn
  UC_X86_INS_VDIVPS* = (UC_X86_INS_VDIVPD + 1).uc_x86_insn
  UC_X86_INS_VDIVSD* = (UC_X86_INS_VDIVPS + 1).uc_x86_insn
  UC_X86_INS_VDIVSS* = (UC_X86_INS_VDIVSD + 1).uc_x86_insn
  UC_X86_INS_VDPPD* = (UC_X86_INS_VDIVSS + 1).uc_x86_insn
  UC_X86_INS_VDPPS* = (UC_X86_INS_VDPPD + 1).uc_x86_insn
  UC_X86_INS_VERR* = (UC_X86_INS_VDPPS + 1).uc_x86_insn
  UC_X86_INS_VERW* = (UC_X86_INS_VERR + 1).uc_x86_insn
  UC_X86_INS_VEXP2PD* = (UC_X86_INS_VERW + 1).uc_x86_insn
  UC_X86_INS_VEXP2PS* = (UC_X86_INS_VEXP2PD + 1).uc_x86_insn
  UC_X86_INS_VEXPANDPD* = (UC_X86_INS_VEXP2PS + 1).uc_x86_insn
  UC_X86_INS_VEXPANDPS* = (UC_X86_INS_VEXPANDPD + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTF128* = (UC_X86_INS_VEXPANDPS + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTF32X4* = (UC_X86_INS_VEXTRACTF128 + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTF64X4* = (UC_X86_INS_VEXTRACTF32X4 + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTI128* = (UC_X86_INS_VEXTRACTF64X4 + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTI32X4* = (UC_X86_INS_VEXTRACTI128 + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTI64X4* = (UC_X86_INS_VEXTRACTI32X4 + 1).uc_x86_insn
  UC_X86_INS_VEXTRACTPS* = (UC_X86_INS_VEXTRACTI64X4 + 1).uc_x86_insn
  UC_X86_INS_VFMADD132PD* = (UC_X86_INS_VEXTRACTPS + 1).uc_x86_insn
  UC_X86_INS_VFMADD132PS* = (UC_X86_INS_VFMADD132PD + 1).uc_x86_insn
  UC_X86_INS_VFMADDPD* = (UC_X86_INS_VFMADD132PS + 1).uc_x86_insn
  UC_X86_INS_VFMADD213PD* = (UC_X86_INS_VFMADDPD + 1).uc_x86_insn
  UC_X86_INS_VFMADD231PD* = (UC_X86_INS_VFMADD213PD + 1).uc_x86_insn
  UC_X86_INS_VFMADDPS* = (UC_X86_INS_VFMADD231PD + 1).uc_x86_insn
  UC_X86_INS_VFMADD213PS* = (UC_X86_INS_VFMADDPS + 1).uc_x86_insn
  UC_X86_INS_VFMADD231PS* = (UC_X86_INS_VFMADD213PS + 1).uc_x86_insn
  UC_X86_INS_VFMADDSD* = (UC_X86_INS_VFMADD231PS + 1).uc_x86_insn
  UC_X86_INS_VFMADD213SD* = (UC_X86_INS_VFMADDSD + 1).uc_x86_insn
  UC_X86_INS_VFMADD132SD* = (UC_X86_INS_VFMADD213SD + 1).uc_x86_insn
  UC_X86_INS_VFMADD231SD* = (UC_X86_INS_VFMADD132SD + 1).uc_x86_insn
  UC_X86_INS_VFMADDSS* = (UC_X86_INS_VFMADD231SD + 1).uc_x86_insn
  UC_X86_INS_VFMADD213SS* = (UC_X86_INS_VFMADDSS + 1).uc_x86_insn
  UC_X86_INS_VFMADD132SS* = (UC_X86_INS_VFMADD213SS + 1).uc_x86_insn
  UC_X86_INS_VFMADD231SS* = (UC_X86_INS_VFMADD132SS + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB132PD* = (UC_X86_INS_VFMADD231SS + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB132PS* = (UC_X86_INS_VFMADDSUB132PD + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUBPD* = (UC_X86_INS_VFMADDSUB132PS + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB213PD* = (UC_X86_INS_VFMADDSUBPD + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB231PD* = (UC_X86_INS_VFMADDSUB213PD + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUBPS* = (UC_X86_INS_VFMADDSUB231PD + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB213PS* = (UC_X86_INS_VFMADDSUBPS + 1).uc_x86_insn
  UC_X86_INS_VFMADDSUB231PS* = (UC_X86_INS_VFMADDSUB213PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB132PD* = (UC_X86_INS_VFMADDSUB231PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB132PS* = (UC_X86_INS_VFMSUB132PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD132PD* = (UC_X86_INS_VFMSUB132PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD132PS* = (UC_X86_INS_VFMSUBADD132PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADDPD* = (UC_X86_INS_VFMSUBADD132PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD213PD* = (UC_X86_INS_VFMSUBADDPD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD231PD* = (UC_X86_INS_VFMSUBADD213PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADDPS* = (UC_X86_INS_VFMSUBADD231PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD213PS* = (UC_X86_INS_VFMSUBADDPS + 1).uc_x86_insn
  UC_X86_INS_VFMSUBADD231PS* = (UC_X86_INS_VFMSUBADD213PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUBPD* = (UC_X86_INS_VFMSUBADD231PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB213PD* = (UC_X86_INS_VFMSUBPD + 1).uc_x86_insn
  UC_X86_INS_VFMSUB231PD* = (UC_X86_INS_VFMSUB213PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBPS* = (UC_X86_INS_VFMSUB231PD + 1).uc_x86_insn
  UC_X86_INS_VFMSUB213PS* = (UC_X86_INS_VFMSUBPS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB231PS* = (UC_X86_INS_VFMSUB213PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUBSD* = (UC_X86_INS_VFMSUB231PS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB213SD* = (UC_X86_INS_VFMSUBSD + 1).uc_x86_insn
  UC_X86_INS_VFMSUB132SD* = (UC_X86_INS_VFMSUB213SD + 1).uc_x86_insn
  UC_X86_INS_VFMSUB231SD* = (UC_X86_INS_VFMSUB132SD + 1).uc_x86_insn
  UC_X86_INS_VFMSUBSS* = (UC_X86_INS_VFMSUB231SD + 1).uc_x86_insn
  UC_X86_INS_VFMSUB213SS* = (UC_X86_INS_VFMSUBSS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB132SS* = (UC_X86_INS_VFMSUB213SS + 1).uc_x86_insn
  UC_X86_INS_VFMSUB231SS* = (UC_X86_INS_VFMSUB132SS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD132PD* = (UC_X86_INS_VFMSUB231SS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD132PS* = (UC_X86_INS_VFNMADD132PD + 1).uc_x86_insn
  UC_X86_INS_VFNMADDPD* = (UC_X86_INS_VFNMADD132PS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD213PD* = (UC_X86_INS_VFNMADDPD + 1).uc_x86_insn
  UC_X86_INS_VFNMADD231PD* = (UC_X86_INS_VFNMADD213PD + 1).uc_x86_insn
  UC_X86_INS_VFNMADDPS* = (UC_X86_INS_VFNMADD231PD + 1).uc_x86_insn
  UC_X86_INS_VFNMADD213PS* = (UC_X86_INS_VFNMADDPS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD231PS* = (UC_X86_INS_VFNMADD213PS + 1).uc_x86_insn
  UC_X86_INS_VFNMADDSD* = (UC_X86_INS_VFNMADD231PS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD213SD* = (UC_X86_INS_VFNMADDSD + 1).uc_x86_insn
  UC_X86_INS_VFNMADD132SD* = (UC_X86_INS_VFNMADD213SD + 1).uc_x86_insn
  UC_X86_INS_VFNMADD231SD* = (UC_X86_INS_VFNMADD132SD + 1).uc_x86_insn
  UC_X86_INS_VFNMADDSS* = (UC_X86_INS_VFNMADD231SD + 1).uc_x86_insn
  UC_X86_INS_VFNMADD213SS* = (UC_X86_INS_VFNMADDSS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD132SS* = (UC_X86_INS_VFNMADD213SS + 1).uc_x86_insn
  UC_X86_INS_VFNMADD231SS* = (UC_X86_INS_VFNMADD132SS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB132PD* = (UC_X86_INS_VFNMADD231SS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB132PS* = (UC_X86_INS_VFNMSUB132PD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUBPD* = (UC_X86_INS_VFNMSUB132PS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB213PD* = (UC_X86_INS_VFNMSUBPD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB231PD* = (UC_X86_INS_VFNMSUB213PD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUBPS* = (UC_X86_INS_VFNMSUB231PD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB213PS* = (UC_X86_INS_VFNMSUBPS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB231PS* = (UC_X86_INS_VFNMSUB213PS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUBSD* = (UC_X86_INS_VFNMSUB231PS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB213SD* = (UC_X86_INS_VFNMSUBSD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB132SD* = (UC_X86_INS_VFNMSUB213SD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB231SD* = (UC_X86_INS_VFNMSUB132SD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUBSS* = (UC_X86_INS_VFNMSUB231SD + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB213SS* = (UC_X86_INS_VFNMSUBSS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB132SS* = (UC_X86_INS_VFNMSUB213SS + 1).uc_x86_insn
  UC_X86_INS_VFNMSUB231SS* = (UC_X86_INS_VFNMSUB132SS + 1).uc_x86_insn
  UC_X86_INS_VFRCZPD* = (UC_X86_INS_VFNMSUB231SS + 1).uc_x86_insn
  UC_X86_INS_VFRCZPS* = (UC_X86_INS_VFRCZPD + 1).uc_x86_insn
  UC_X86_INS_VFRCZSD* = (UC_X86_INS_VFRCZPS + 1).uc_x86_insn
  UC_X86_INS_VFRCZSS* = (UC_X86_INS_VFRCZSD + 1).uc_x86_insn
  UC_X86_INS_VORPD* = (UC_X86_INS_VFRCZSS + 1).uc_x86_insn
  UC_X86_INS_VORPS* = (UC_X86_INS_VORPD + 1).uc_x86_insn
  UC_X86_INS_VXORPD* = (UC_X86_INS_VORPS + 1).uc_x86_insn
  UC_X86_INS_VXORPS* = (UC_X86_INS_VXORPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERDPD* = (UC_X86_INS_VXORPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERDPS* = (UC_X86_INS_VGATHERDPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF0DPD* = (UC_X86_INS_VGATHERDPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF0DPS* = (UC_X86_INS_VGATHERPF0DPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF0QPD* = (UC_X86_INS_VGATHERPF0DPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF0QPS* = (UC_X86_INS_VGATHERPF0QPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF1DPD* = (UC_X86_INS_VGATHERPF0QPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF1DPS* = (UC_X86_INS_VGATHERPF1DPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF1QPD* = (UC_X86_INS_VGATHERPF1DPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERPF1QPS* = (UC_X86_INS_VGATHERPF1QPD + 1).uc_x86_insn
  UC_X86_INS_VGATHERQPD* = (UC_X86_INS_VGATHERPF1QPS + 1).uc_x86_insn
  UC_X86_INS_VGATHERQPS* = (UC_X86_INS_VGATHERQPD + 1).uc_x86_insn
  UC_X86_INS_VHADDPD* = (UC_X86_INS_VGATHERQPS + 1).uc_x86_insn
  UC_X86_INS_VHADDPS* = (UC_X86_INS_VHADDPD + 1).uc_x86_insn
  UC_X86_INS_VHSUBPD* = (UC_X86_INS_VHADDPS + 1).uc_x86_insn
  UC_X86_INS_VHSUBPS* = (UC_X86_INS_VHSUBPD + 1).uc_x86_insn
  UC_X86_INS_VINSERTF128* = (UC_X86_INS_VHSUBPS + 1).uc_x86_insn
  UC_X86_INS_VINSERTF32X4* = (UC_X86_INS_VINSERTF128 + 1).uc_x86_insn
  UC_X86_INS_VINSERTF32X8* = (UC_X86_INS_VINSERTF32X4 + 1).uc_x86_insn
  UC_X86_INS_VINSERTF64X2* = (UC_X86_INS_VINSERTF32X8 + 1).uc_x86_insn
  UC_X86_INS_VINSERTF64X4* = (UC_X86_INS_VINSERTF64X2 + 1).uc_x86_insn
  UC_X86_INS_VINSERTI128* = (UC_X86_INS_VINSERTF64X4 + 1).uc_x86_insn
  UC_X86_INS_VINSERTI32X4* = (UC_X86_INS_VINSERTI128 + 1).uc_x86_insn
  UC_X86_INS_VINSERTI32X8* = (UC_X86_INS_VINSERTI32X4 + 1).uc_x86_insn
  UC_X86_INS_VINSERTI64X2* = (UC_X86_INS_VINSERTI32X8 + 1).uc_x86_insn
  UC_X86_INS_VINSERTI64X4* = (UC_X86_INS_VINSERTI64X2 + 1).uc_x86_insn
  UC_X86_INS_VINSERTPS* = (UC_X86_INS_VINSERTI64X4 + 1).uc_x86_insn
  UC_X86_INS_VLDDQU* = (UC_X86_INS_VINSERTPS + 1).uc_x86_insn
  UC_X86_INS_VLDMXCSR* = (UC_X86_INS_VLDDQU + 1).uc_x86_insn
  UC_X86_INS_VMASKMOVDQU* = (UC_X86_INS_VLDMXCSR + 1).uc_x86_insn
  UC_X86_INS_VMASKMOVPD* = (UC_X86_INS_VMASKMOVDQU + 1).uc_x86_insn
  UC_X86_INS_VMASKMOVPS* = (UC_X86_INS_VMASKMOVPD + 1).uc_x86_insn
  UC_X86_INS_VMAXPD* = (UC_X86_INS_VMASKMOVPS + 1).uc_x86_insn
  UC_X86_INS_VMAXPS* = (UC_X86_INS_VMAXPD + 1).uc_x86_insn
  UC_X86_INS_VMAXSD* = (UC_X86_INS_VMAXPS + 1).uc_x86_insn
  UC_X86_INS_VMAXSS* = (UC_X86_INS_VMAXSD + 1).uc_x86_insn
  UC_X86_INS_VMCALL* = (UC_X86_INS_VMAXSS + 1).uc_x86_insn
  UC_X86_INS_VMCLEAR* = (UC_X86_INS_VMCALL + 1).uc_x86_insn
  UC_X86_INS_VMFUNC* = (UC_X86_INS_VMCLEAR + 1).uc_x86_insn
  UC_X86_INS_VMINPD* = (UC_X86_INS_VMFUNC + 1).uc_x86_insn
  UC_X86_INS_VMINPS* = (UC_X86_INS_VMINPD + 1).uc_x86_insn
  UC_X86_INS_VMINSD* = (UC_X86_INS_VMINPS + 1).uc_x86_insn
  UC_X86_INS_VMINSS* = (UC_X86_INS_VMINSD + 1).uc_x86_insn
  UC_X86_INS_VMLAUNCH* = (UC_X86_INS_VMINSS + 1).uc_x86_insn
  UC_X86_INS_VMLOAD* = (UC_X86_INS_VMLAUNCH + 1).uc_x86_insn
  UC_X86_INS_VMMCALL* = (UC_X86_INS_VMLOAD + 1).uc_x86_insn
  UC_X86_INS_VMOVQ* = (UC_X86_INS_VMMCALL + 1).uc_x86_insn
  UC_X86_INS_VMOVDDUP* = (UC_X86_INS_VMOVQ + 1).uc_x86_insn
  UC_X86_INS_VMOVD* = (UC_X86_INS_VMOVDDUP + 1).uc_x86_insn
  UC_X86_INS_VMOVDQA32* = (UC_X86_INS_VMOVD + 1).uc_x86_insn
  UC_X86_INS_VMOVDQA64* = (UC_X86_INS_VMOVDQA32 + 1).uc_x86_insn
  UC_X86_INS_VMOVDQA* = (UC_X86_INS_VMOVDQA64 + 1).uc_x86_insn
  UC_X86_INS_VMOVDQU16* = (UC_X86_INS_VMOVDQA + 1).uc_x86_insn
  UC_X86_INS_VMOVDQU32* = (UC_X86_INS_VMOVDQU16 + 1).uc_x86_insn
  UC_X86_INS_VMOVDQU64* = (UC_X86_INS_VMOVDQU32 + 1).uc_x86_insn
  UC_X86_INS_VMOVDQU8* = (UC_X86_INS_VMOVDQU64 + 1).uc_x86_insn
  UC_X86_INS_VMOVDQU* = (UC_X86_INS_VMOVDQU8 + 1).uc_x86_insn
  UC_X86_INS_VMOVHLPS* = (UC_X86_INS_VMOVDQU + 1).uc_x86_insn
  UC_X86_INS_VMOVHPD* = (UC_X86_INS_VMOVHLPS + 1).uc_x86_insn
  UC_X86_INS_VMOVHPS* = (UC_X86_INS_VMOVHPD + 1).uc_x86_insn
  UC_X86_INS_VMOVLHPS* = (UC_X86_INS_VMOVHPS + 1).uc_x86_insn
  UC_X86_INS_VMOVLPD* = (UC_X86_INS_VMOVLHPS + 1).uc_x86_insn
  UC_X86_INS_VMOVLPS* = (UC_X86_INS_VMOVLPD + 1).uc_x86_insn
  UC_X86_INS_VMOVMSKPD* = (UC_X86_INS_VMOVLPS + 1).uc_x86_insn
  UC_X86_INS_VMOVMSKPS* = (UC_X86_INS_VMOVMSKPD + 1).uc_x86_insn
  UC_X86_INS_VMOVNTDQA* = (UC_X86_INS_VMOVMSKPS + 1).uc_x86_insn
  UC_X86_INS_VMOVNTDQ* = (UC_X86_INS_VMOVNTDQA + 1).uc_x86_insn
  UC_X86_INS_VMOVNTPD* = (UC_X86_INS_VMOVNTDQ + 1).uc_x86_insn
  UC_X86_INS_VMOVNTPS* = (UC_X86_INS_VMOVNTPD + 1).uc_x86_insn
  UC_X86_INS_VMOVSD* = (UC_X86_INS_VMOVNTPS + 1).uc_x86_insn
  UC_X86_INS_VMOVSHDUP* = (UC_X86_INS_VMOVSD + 1).uc_x86_insn
  UC_X86_INS_VMOVSLDUP* = (UC_X86_INS_VMOVSHDUP + 1).uc_x86_insn
  UC_X86_INS_VMOVSS* = (UC_X86_INS_VMOVSLDUP + 1).uc_x86_insn
  UC_X86_INS_VMOVUPD* = (UC_X86_INS_VMOVSS + 1).uc_x86_insn
  UC_X86_INS_VMOVUPS* = (UC_X86_INS_VMOVUPD + 1).uc_x86_insn
  UC_X86_INS_VMPSADBW* = (UC_X86_INS_VMOVUPS + 1).uc_x86_insn
  UC_X86_INS_VMPTRLD* = (UC_X86_INS_VMPSADBW + 1).uc_x86_insn
  UC_X86_INS_VMPTRST* = (UC_X86_INS_VMPTRLD + 1).uc_x86_insn
  UC_X86_INS_VMREAD* = (UC_X86_INS_VMPTRST + 1).uc_x86_insn
  UC_X86_INS_VMRESUME* = (UC_X86_INS_VMREAD + 1).uc_x86_insn
  UC_X86_INS_VMRUN* = (UC_X86_INS_VMRESUME + 1).uc_x86_insn
  UC_X86_INS_VMSAVE* = (UC_X86_INS_VMRUN + 1).uc_x86_insn
  UC_X86_INS_VMULPD* = (UC_X86_INS_VMSAVE + 1).uc_x86_insn
  UC_X86_INS_VMULPS* = (UC_X86_INS_VMULPD + 1).uc_x86_insn
  UC_X86_INS_VMULSD* = (UC_X86_INS_VMULPS + 1).uc_x86_insn
  UC_X86_INS_VMULSS* = (UC_X86_INS_VMULSD + 1).uc_x86_insn
  UC_X86_INS_VMWRITE* = (UC_X86_INS_VMULSS + 1).uc_x86_insn
  UC_X86_INS_VMXOFF* = (UC_X86_INS_VMWRITE + 1).uc_x86_insn
  UC_X86_INS_VMXON* = (UC_X86_INS_VMXOFF + 1).uc_x86_insn
  UC_X86_INS_VPABSB* = (UC_X86_INS_VMXON + 1).uc_x86_insn
  UC_X86_INS_VPABSD* = (UC_X86_INS_VPABSB + 1).uc_x86_insn
  UC_X86_INS_VPABSQ* = (UC_X86_INS_VPABSD + 1).uc_x86_insn
  UC_X86_INS_VPABSW* = (UC_X86_INS_VPABSQ + 1).uc_x86_insn
  UC_X86_INS_VPACKSSDW* = (UC_X86_INS_VPABSW + 1).uc_x86_insn
  UC_X86_INS_VPACKSSWB* = (UC_X86_INS_VPACKSSDW + 1).uc_x86_insn
  UC_X86_INS_VPACKUSDW* = (UC_X86_INS_VPACKSSWB + 1).uc_x86_insn
  UC_X86_INS_VPACKUSWB* = (UC_X86_INS_VPACKUSDW + 1).uc_x86_insn
  UC_X86_INS_VPADDB* = (UC_X86_INS_VPACKUSWB + 1).uc_x86_insn
  UC_X86_INS_VPADDD* = (UC_X86_INS_VPADDB + 1).uc_x86_insn
  UC_X86_INS_VPADDQ* = (UC_X86_INS_VPADDD + 1).uc_x86_insn
  UC_X86_INS_VPADDSB* = (UC_X86_INS_VPADDQ + 1).uc_x86_insn
  UC_X86_INS_VPADDSW* = (UC_X86_INS_VPADDSB + 1).uc_x86_insn
  UC_X86_INS_VPADDUSB* = (UC_X86_INS_VPADDSW + 1).uc_x86_insn
  UC_X86_INS_VPADDUSW* = (UC_X86_INS_VPADDUSB + 1).uc_x86_insn
  UC_X86_INS_VPADDW* = (UC_X86_INS_VPADDUSW + 1).uc_x86_insn
  UC_X86_INS_VPALIGNR* = (UC_X86_INS_VPADDW + 1).uc_x86_insn
  UC_X86_INS_VPANDD* = (UC_X86_INS_VPALIGNR + 1).uc_x86_insn
  UC_X86_INS_VPANDND* = (UC_X86_INS_VPANDD + 1).uc_x86_insn
  UC_X86_INS_VPANDNQ* = (UC_X86_INS_VPANDND + 1).uc_x86_insn
  UC_X86_INS_VPANDN* = (UC_X86_INS_VPANDNQ + 1).uc_x86_insn
  UC_X86_INS_VPANDQ* = (UC_X86_INS_VPANDN + 1).uc_x86_insn
  UC_X86_INS_VPAND* = (UC_X86_INS_VPANDQ + 1).uc_x86_insn
  UC_X86_INS_VPAVGB* = (UC_X86_INS_VPAND + 1).uc_x86_insn
  UC_X86_INS_VPAVGW* = (UC_X86_INS_VPAVGB + 1).uc_x86_insn
  UC_X86_INS_VPBLENDD* = (UC_X86_INS_VPAVGW + 1).uc_x86_insn
  UC_X86_INS_VPBLENDMB* = (UC_X86_INS_VPBLENDD + 1).uc_x86_insn
  UC_X86_INS_VPBLENDMD* = (UC_X86_INS_VPBLENDMB + 1).uc_x86_insn
  UC_X86_INS_VPBLENDMQ* = (UC_X86_INS_VPBLENDMD + 1).uc_x86_insn
  UC_X86_INS_VPBLENDMW* = (UC_X86_INS_VPBLENDMQ + 1).uc_x86_insn
  UC_X86_INS_VPBLENDVB* = (UC_X86_INS_VPBLENDMW + 1).uc_x86_insn
  UC_X86_INS_VPBLENDW* = (UC_X86_INS_VPBLENDVB + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTB* = (UC_X86_INS_VPBLENDW + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTD* = (UC_X86_INS_VPBROADCASTB + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTMB2Q* = (UC_X86_INS_VPBROADCASTD + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTMW2D* = (UC_X86_INS_VPBROADCASTMB2Q + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTQ* = (UC_X86_INS_VPBROADCASTMW2D + 1).uc_x86_insn
  UC_X86_INS_VPBROADCASTW* = (UC_X86_INS_VPBROADCASTQ + 1).uc_x86_insn
  UC_X86_INS_VPCLMULQDQ* = (UC_X86_INS_VPBROADCASTW + 1).uc_x86_insn
  UC_X86_INS_VPCMOV* = (UC_X86_INS_VPCLMULQDQ + 1).uc_x86_insn
  UC_X86_INS_VPCMPB* = (UC_X86_INS_VPCMOV + 1).uc_x86_insn
  UC_X86_INS_VPCMPD* = (UC_X86_INS_VPCMPB + 1).uc_x86_insn
  UC_X86_INS_VPCMPEQB* = (UC_X86_INS_VPCMPD + 1).uc_x86_insn
  UC_X86_INS_VPCMPEQD* = (UC_X86_INS_VPCMPEQB + 1).uc_x86_insn
  UC_X86_INS_VPCMPEQQ* = (UC_X86_INS_VPCMPEQD + 1).uc_x86_insn
  UC_X86_INS_VPCMPEQW* = (UC_X86_INS_VPCMPEQQ + 1).uc_x86_insn
  UC_X86_INS_VPCMPESTRI* = (UC_X86_INS_VPCMPEQW + 1).uc_x86_insn
  UC_X86_INS_VPCMPESTRM* = (UC_X86_INS_VPCMPESTRI + 1).uc_x86_insn
  UC_X86_INS_VPCMPGTB* = (UC_X86_INS_VPCMPESTRM + 1).uc_x86_insn
  UC_X86_INS_VPCMPGTD* = (UC_X86_INS_VPCMPGTB + 1).uc_x86_insn
  UC_X86_INS_VPCMPGTQ* = (UC_X86_INS_VPCMPGTD + 1).uc_x86_insn
  UC_X86_INS_VPCMPGTW* = (UC_X86_INS_VPCMPGTQ + 1).uc_x86_insn
  UC_X86_INS_VPCMPISTRI* = (UC_X86_INS_VPCMPGTW + 1).uc_x86_insn
  UC_X86_INS_VPCMPISTRM* = (UC_X86_INS_VPCMPISTRI + 1).uc_x86_insn
  UC_X86_INS_VPCMPQ* = (UC_X86_INS_VPCMPISTRM + 1).uc_x86_insn
  UC_X86_INS_VPCMPUB* = (UC_X86_INS_VPCMPQ + 1).uc_x86_insn
  UC_X86_INS_VPCMPUD* = (UC_X86_INS_VPCMPUB + 1).uc_x86_insn
  UC_X86_INS_VPCMPUQ* = (UC_X86_INS_VPCMPUD + 1).uc_x86_insn
  UC_X86_INS_VPCMPUW* = (UC_X86_INS_VPCMPUQ + 1).uc_x86_insn
  UC_X86_INS_VPCMPW* = (UC_X86_INS_VPCMPUW + 1).uc_x86_insn
  UC_X86_INS_VPCOMB* = (UC_X86_INS_VPCMPW + 1).uc_x86_insn
  UC_X86_INS_VPCOMD* = (UC_X86_INS_VPCOMB + 1).uc_x86_insn
  UC_X86_INS_VPCOMPRESSD* = (UC_X86_INS_VPCOMD + 1).uc_x86_insn
  UC_X86_INS_VPCOMPRESSQ* = (UC_X86_INS_VPCOMPRESSD + 1).uc_x86_insn
  UC_X86_INS_VPCOMQ* = (UC_X86_INS_VPCOMPRESSQ + 1).uc_x86_insn
  UC_X86_INS_VPCOMUB* = (UC_X86_INS_VPCOMQ + 1).uc_x86_insn
  UC_X86_INS_VPCOMUD* = (UC_X86_INS_VPCOMUB + 1).uc_x86_insn
  UC_X86_INS_VPCOMUQ* = (UC_X86_INS_VPCOMUD + 1).uc_x86_insn
  UC_X86_INS_VPCOMUW* = (UC_X86_INS_VPCOMUQ + 1).uc_x86_insn
  UC_X86_INS_VPCOMW* = (UC_X86_INS_VPCOMUW + 1).uc_x86_insn
  UC_X86_INS_VPCONFLICTD* = (UC_X86_INS_VPCOMW + 1).uc_x86_insn
  UC_X86_INS_VPCONFLICTQ* = (UC_X86_INS_VPCONFLICTD + 1).uc_x86_insn
  UC_X86_INS_VPERM2F128* = (UC_X86_INS_VPCONFLICTQ + 1).uc_x86_insn
  UC_X86_INS_VPERM2I128* = (UC_X86_INS_VPERM2F128 + 1).uc_x86_insn
  UC_X86_INS_VPERMD* = (UC_X86_INS_VPERM2I128 + 1).uc_x86_insn
  UC_X86_INS_VPERMI2D* = (UC_X86_INS_VPERMD + 1).uc_x86_insn
  UC_X86_INS_VPERMI2PD* = (UC_X86_INS_VPERMI2D + 1).uc_x86_insn
  UC_X86_INS_VPERMI2PS* = (UC_X86_INS_VPERMI2PD + 1).uc_x86_insn
  UC_X86_INS_VPERMI2Q* = (UC_X86_INS_VPERMI2PS + 1).uc_x86_insn
  UC_X86_INS_VPERMIL2PD* = (UC_X86_INS_VPERMI2Q + 1).uc_x86_insn
  UC_X86_INS_VPERMIL2PS* = (UC_X86_INS_VPERMIL2PD + 1).uc_x86_insn
  UC_X86_INS_VPERMILPD* = (UC_X86_INS_VPERMIL2PS + 1).uc_x86_insn
  UC_X86_INS_VPERMILPS* = (UC_X86_INS_VPERMILPD + 1).uc_x86_insn
  UC_X86_INS_VPERMPD* = (UC_X86_INS_VPERMILPS + 1).uc_x86_insn
  UC_X86_INS_VPERMPS* = (UC_X86_INS_VPERMPD + 1).uc_x86_insn
  UC_X86_INS_VPERMQ* = (UC_X86_INS_VPERMPS + 1).uc_x86_insn
  UC_X86_INS_VPERMT2D* = (UC_X86_INS_VPERMQ + 1).uc_x86_insn
  UC_X86_INS_VPERMT2PD* = (UC_X86_INS_VPERMT2D + 1).uc_x86_insn
  UC_X86_INS_VPERMT2PS* = (UC_X86_INS_VPERMT2PD + 1).uc_x86_insn
  UC_X86_INS_VPERMT2Q* = (UC_X86_INS_VPERMT2PS + 1).uc_x86_insn
  UC_X86_INS_VPEXPANDD* = (UC_X86_INS_VPERMT2Q + 1).uc_x86_insn
  UC_X86_INS_VPEXPANDQ* = (UC_X86_INS_VPEXPANDD + 1).uc_x86_insn
  UC_X86_INS_VPEXTRB* = (UC_X86_INS_VPEXPANDQ + 1).uc_x86_insn
  UC_X86_INS_VPEXTRD* = (UC_X86_INS_VPEXTRB + 1).uc_x86_insn
  UC_X86_INS_VPEXTRQ* = (UC_X86_INS_VPEXTRD + 1).uc_x86_insn
  UC_X86_INS_VPEXTRW* = (UC_X86_INS_VPEXTRQ + 1).uc_x86_insn
  UC_X86_INS_VPGATHERDD* = (UC_X86_INS_VPEXTRW + 1).uc_x86_insn
  UC_X86_INS_VPGATHERDQ* = (UC_X86_INS_VPGATHERDD + 1).uc_x86_insn
  UC_X86_INS_VPGATHERQD* = (UC_X86_INS_VPGATHERDQ + 1).uc_x86_insn
  UC_X86_INS_VPGATHERQQ* = (UC_X86_INS_VPGATHERQD + 1).uc_x86_insn
  UC_X86_INS_VPHADDBD* = (UC_X86_INS_VPGATHERQQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDBQ* = (UC_X86_INS_VPHADDBD + 1).uc_x86_insn
  UC_X86_INS_VPHADDBW* = (UC_X86_INS_VPHADDBQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDDQ* = (UC_X86_INS_VPHADDBW + 1).uc_x86_insn
  UC_X86_INS_VPHADDD* = (UC_X86_INS_VPHADDDQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDSW* = (UC_X86_INS_VPHADDD + 1).uc_x86_insn
  UC_X86_INS_VPHADDUBD* = (UC_X86_INS_VPHADDSW + 1).uc_x86_insn
  UC_X86_INS_VPHADDUBQ* = (UC_X86_INS_VPHADDUBD + 1).uc_x86_insn
  UC_X86_INS_VPHADDUBW* = (UC_X86_INS_VPHADDUBQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDUDQ* = (UC_X86_INS_VPHADDUBW + 1).uc_x86_insn
  UC_X86_INS_VPHADDUWD* = (UC_X86_INS_VPHADDUDQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDUWQ* = (UC_X86_INS_VPHADDUWD + 1).uc_x86_insn
  UC_X86_INS_VPHADDWD* = (UC_X86_INS_VPHADDUWQ + 1).uc_x86_insn
  UC_X86_INS_VPHADDWQ* = (UC_X86_INS_VPHADDWD + 1).uc_x86_insn
  UC_X86_INS_VPHADDW* = (UC_X86_INS_VPHADDWQ + 1).uc_x86_insn
  UC_X86_INS_VPHMINPOSUW* = (UC_X86_INS_VPHADDW + 1).uc_x86_insn
  UC_X86_INS_VPHSUBBW* = (UC_X86_INS_VPHMINPOSUW + 1).uc_x86_insn
  UC_X86_INS_VPHSUBDQ* = (UC_X86_INS_VPHSUBBW + 1).uc_x86_insn
  UC_X86_INS_VPHSUBD* = (UC_X86_INS_VPHSUBDQ + 1).uc_x86_insn
  UC_X86_INS_VPHSUBSW* = (UC_X86_INS_VPHSUBD + 1).uc_x86_insn
  UC_X86_INS_VPHSUBWD* = (UC_X86_INS_VPHSUBSW + 1).uc_x86_insn
  UC_X86_INS_VPHSUBW* = (UC_X86_INS_VPHSUBWD + 1).uc_x86_insn
  UC_X86_INS_VPINSRB* = (UC_X86_INS_VPHSUBW + 1).uc_x86_insn
  UC_X86_INS_VPINSRD* = (UC_X86_INS_VPINSRB + 1).uc_x86_insn
  UC_X86_INS_VPINSRQ* = (UC_X86_INS_VPINSRD + 1).uc_x86_insn
  UC_X86_INS_VPINSRW* = (UC_X86_INS_VPINSRQ + 1).uc_x86_insn
  UC_X86_INS_VPLZCNTD* = (UC_X86_INS_VPINSRW + 1).uc_x86_insn
  UC_X86_INS_VPLZCNTQ* = (UC_X86_INS_VPLZCNTD + 1).uc_x86_insn
  UC_X86_INS_VPMACSDD* = (UC_X86_INS_VPLZCNTQ + 1).uc_x86_insn
  UC_X86_INS_VPMACSDQH* = (UC_X86_INS_VPMACSDD + 1).uc_x86_insn
  UC_X86_INS_VPMACSDQL* = (UC_X86_INS_VPMACSDQH + 1).uc_x86_insn
  UC_X86_INS_VPMACSSDD* = (UC_X86_INS_VPMACSDQL + 1).uc_x86_insn
  UC_X86_INS_VPMACSSDQH* = (UC_X86_INS_VPMACSSDD + 1).uc_x86_insn
  UC_X86_INS_VPMACSSDQL* = (UC_X86_INS_VPMACSSDQH + 1).uc_x86_insn
  UC_X86_INS_VPMACSSWD* = (UC_X86_INS_VPMACSSDQL + 1).uc_x86_insn
  UC_X86_INS_VPMACSSWW* = (UC_X86_INS_VPMACSSWD + 1).uc_x86_insn
  UC_X86_INS_VPMACSWD* = (UC_X86_INS_VPMACSSWW + 1).uc_x86_insn
  UC_X86_INS_VPMACSWW* = (UC_X86_INS_VPMACSWD + 1).uc_x86_insn
  UC_X86_INS_VPMADCSSWD* = (UC_X86_INS_VPMACSWW + 1).uc_x86_insn
  UC_X86_INS_VPMADCSWD* = (UC_X86_INS_VPMADCSSWD + 1).uc_x86_insn
  UC_X86_INS_VPMADDUBSW* = (UC_X86_INS_VPMADCSWD + 1).uc_x86_insn
  UC_X86_INS_VPMADDWD* = (UC_X86_INS_VPMADDUBSW + 1).uc_x86_insn
  UC_X86_INS_VPMASKMOVD* = (UC_X86_INS_VPMADDWD + 1).uc_x86_insn
  UC_X86_INS_VPMASKMOVQ* = (UC_X86_INS_VPMASKMOVD + 1).uc_x86_insn
  UC_X86_INS_VPMAXSB* = (UC_X86_INS_VPMASKMOVQ + 1).uc_x86_insn
  UC_X86_INS_VPMAXSD* = (UC_X86_INS_VPMAXSB + 1).uc_x86_insn
  UC_X86_INS_VPMAXSQ* = (UC_X86_INS_VPMAXSD + 1).uc_x86_insn
  UC_X86_INS_VPMAXSW* = (UC_X86_INS_VPMAXSQ + 1).uc_x86_insn
  UC_X86_INS_VPMAXUB* = (UC_X86_INS_VPMAXSW + 1).uc_x86_insn
  UC_X86_INS_VPMAXUD* = (UC_X86_INS_VPMAXUB + 1).uc_x86_insn
  UC_X86_INS_VPMAXUQ* = (UC_X86_INS_VPMAXUD + 1).uc_x86_insn
  UC_X86_INS_VPMAXUW* = (UC_X86_INS_VPMAXUQ + 1).uc_x86_insn
  UC_X86_INS_VPMINSB* = (UC_X86_INS_VPMAXUW + 1).uc_x86_insn
  UC_X86_INS_VPMINSD* = (UC_X86_INS_VPMINSB + 1).uc_x86_insn
  UC_X86_INS_VPMINSQ* = (UC_X86_INS_VPMINSD + 1).uc_x86_insn
  UC_X86_INS_VPMINSW* = (UC_X86_INS_VPMINSQ + 1).uc_x86_insn
  UC_X86_INS_VPMINUB* = (UC_X86_INS_VPMINSW + 1).uc_x86_insn
  UC_X86_INS_VPMINUD* = (UC_X86_INS_VPMINUB + 1).uc_x86_insn
  UC_X86_INS_VPMINUQ* = (UC_X86_INS_VPMINUD + 1).uc_x86_insn
  UC_X86_INS_VPMINUW* = (UC_X86_INS_VPMINUQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVDB* = (UC_X86_INS_VPMINUW + 1).uc_x86_insn
  UC_X86_INS_VPMOVDW* = (UC_X86_INS_VPMOVDB + 1).uc_x86_insn
  UC_X86_INS_VPMOVM2B* = (UC_X86_INS_VPMOVDW + 1).uc_x86_insn
  UC_X86_INS_VPMOVM2D* = (UC_X86_INS_VPMOVM2B + 1).uc_x86_insn
  UC_X86_INS_VPMOVM2Q* = (UC_X86_INS_VPMOVM2D + 1).uc_x86_insn
  UC_X86_INS_VPMOVM2W* = (UC_X86_INS_VPMOVM2Q + 1).uc_x86_insn
  UC_X86_INS_VPMOVMSKB* = (UC_X86_INS_VPMOVM2W + 1).uc_x86_insn
  UC_X86_INS_VPMOVQB* = (UC_X86_INS_VPMOVMSKB + 1).uc_x86_insn
  UC_X86_INS_VPMOVQD* = (UC_X86_INS_VPMOVQB + 1).uc_x86_insn
  UC_X86_INS_VPMOVQW* = (UC_X86_INS_VPMOVQD + 1).uc_x86_insn
  UC_X86_INS_VPMOVSDB* = (UC_X86_INS_VPMOVQW + 1).uc_x86_insn
  UC_X86_INS_VPMOVSDW* = (UC_X86_INS_VPMOVSDB + 1).uc_x86_insn
  UC_X86_INS_VPMOVSQB* = (UC_X86_INS_VPMOVSDW + 1).uc_x86_insn
  UC_X86_INS_VPMOVSQD* = (UC_X86_INS_VPMOVSQB + 1).uc_x86_insn
  UC_X86_INS_VPMOVSQW* = (UC_X86_INS_VPMOVSQD + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXBD* = (UC_X86_INS_VPMOVSQW + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXBQ* = (UC_X86_INS_VPMOVSXBD + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXBW* = (UC_X86_INS_VPMOVSXBQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXDQ* = (UC_X86_INS_VPMOVSXBW + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXWD* = (UC_X86_INS_VPMOVSXDQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVSXWQ* = (UC_X86_INS_VPMOVSXWD + 1).uc_x86_insn
  UC_X86_INS_VPMOVUSDB* = (UC_X86_INS_VPMOVSXWQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVUSDW* = (UC_X86_INS_VPMOVUSDB + 1).uc_x86_insn
  UC_X86_INS_VPMOVUSQB* = (UC_X86_INS_VPMOVUSDW + 1).uc_x86_insn
  UC_X86_INS_VPMOVUSQD* = (UC_X86_INS_VPMOVUSQB + 1).uc_x86_insn
  UC_X86_INS_VPMOVUSQW* = (UC_X86_INS_VPMOVUSQD + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXBD* = (UC_X86_INS_VPMOVUSQW + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXBQ* = (UC_X86_INS_VPMOVZXBD + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXBW* = (UC_X86_INS_VPMOVZXBQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXDQ* = (UC_X86_INS_VPMOVZXBW + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXWD* = (UC_X86_INS_VPMOVZXDQ + 1).uc_x86_insn
  UC_X86_INS_VPMOVZXWQ* = (UC_X86_INS_VPMOVZXWD + 1).uc_x86_insn
  UC_X86_INS_VPMULDQ* = (UC_X86_INS_VPMOVZXWQ + 1).uc_x86_insn
  UC_X86_INS_VPMULHRSW* = (UC_X86_INS_VPMULDQ + 1).uc_x86_insn
  UC_X86_INS_VPMULHUW* = (UC_X86_INS_VPMULHRSW + 1).uc_x86_insn
  UC_X86_INS_VPMULHW* = (UC_X86_INS_VPMULHUW + 1).uc_x86_insn
  UC_X86_INS_VPMULLD* = (UC_X86_INS_VPMULHW + 1).uc_x86_insn
  UC_X86_INS_VPMULLQ* = (UC_X86_INS_VPMULLD + 1).uc_x86_insn
  UC_X86_INS_VPMULLW* = (UC_X86_INS_VPMULLQ + 1).uc_x86_insn
  UC_X86_INS_VPMULUDQ* = (UC_X86_INS_VPMULLW + 1).uc_x86_insn
  UC_X86_INS_VPORD* = (UC_X86_INS_VPMULUDQ + 1).uc_x86_insn
  UC_X86_INS_VPORQ* = (UC_X86_INS_VPORD + 1).uc_x86_insn
  UC_X86_INS_VPOR* = (UC_X86_INS_VPORQ + 1).uc_x86_insn
  UC_X86_INS_VPPERM* = (UC_X86_INS_VPOR + 1).uc_x86_insn
  UC_X86_INS_VPROTB* = (UC_X86_INS_VPPERM + 1).uc_x86_insn
  UC_X86_INS_VPROTD* = (UC_X86_INS_VPROTB + 1).uc_x86_insn
  UC_X86_INS_VPROTQ* = (UC_X86_INS_VPROTD + 1).uc_x86_insn
  UC_X86_INS_VPROTW* = (UC_X86_INS_VPROTQ + 1).uc_x86_insn
  UC_X86_INS_VPSADBW* = (UC_X86_INS_VPROTW + 1).uc_x86_insn
  UC_X86_INS_VPSCATTERDD* = (UC_X86_INS_VPSADBW + 1).uc_x86_insn
  UC_X86_INS_VPSCATTERDQ* = (UC_X86_INS_VPSCATTERDD + 1).uc_x86_insn
  UC_X86_INS_VPSCATTERQD* = (UC_X86_INS_VPSCATTERDQ + 1).uc_x86_insn
  UC_X86_INS_VPSCATTERQQ* = (UC_X86_INS_VPSCATTERQD + 1).uc_x86_insn
  UC_X86_INS_VPSHAB* = (UC_X86_INS_VPSCATTERQQ + 1).uc_x86_insn
  UC_X86_INS_VPSHAD* = (UC_X86_INS_VPSHAB + 1).uc_x86_insn
  UC_X86_INS_VPSHAQ* = (UC_X86_INS_VPSHAD + 1).uc_x86_insn
  UC_X86_INS_VPSHAW* = (UC_X86_INS_VPSHAQ + 1).uc_x86_insn
  UC_X86_INS_VPSHLB* = (UC_X86_INS_VPSHAW + 1).uc_x86_insn
  UC_X86_INS_VPSHLD* = (UC_X86_INS_VPSHLB + 1).uc_x86_insn
  UC_X86_INS_VPSHLQ* = (UC_X86_INS_VPSHLD + 1).uc_x86_insn
  UC_X86_INS_VPSHLW* = (UC_X86_INS_VPSHLQ + 1).uc_x86_insn
  UC_X86_INS_VPSHUFB* = (UC_X86_INS_VPSHLW + 1).uc_x86_insn
  UC_X86_INS_VPSHUFD* = (UC_X86_INS_VPSHUFB + 1).uc_x86_insn
  UC_X86_INS_VPSHUFHW* = (UC_X86_INS_VPSHUFD + 1).uc_x86_insn
  UC_X86_INS_VPSHUFLW* = (UC_X86_INS_VPSHUFHW + 1).uc_x86_insn
  UC_X86_INS_VPSIGNB* = (UC_X86_INS_VPSHUFLW + 1).uc_x86_insn
  UC_X86_INS_VPSIGND* = (UC_X86_INS_VPSIGNB + 1).uc_x86_insn
  UC_X86_INS_VPSIGNW* = (UC_X86_INS_VPSIGND + 1).uc_x86_insn
  UC_X86_INS_VPSLLDQ* = (UC_X86_INS_VPSIGNW + 1).uc_x86_insn
  UC_X86_INS_VPSLLD* = (UC_X86_INS_VPSLLDQ + 1).uc_x86_insn
  UC_X86_INS_VPSLLQ* = (UC_X86_INS_VPSLLD + 1).uc_x86_insn
  UC_X86_INS_VPSLLVD* = (UC_X86_INS_VPSLLQ + 1).uc_x86_insn
  UC_X86_INS_VPSLLVQ* = (UC_X86_INS_VPSLLVD + 1).uc_x86_insn
  UC_X86_INS_VPSLLW* = (UC_X86_INS_VPSLLVQ + 1).uc_x86_insn
  UC_X86_INS_VPSRAD* = (UC_X86_INS_VPSLLW + 1).uc_x86_insn
  UC_X86_INS_VPSRAQ* = (UC_X86_INS_VPSRAD + 1).uc_x86_insn
  UC_X86_INS_VPSRAVD* = (UC_X86_INS_VPSRAQ + 1).uc_x86_insn
  UC_X86_INS_VPSRAVQ* = (UC_X86_INS_VPSRAVD + 1).uc_x86_insn
  UC_X86_INS_VPSRAW* = (UC_X86_INS_VPSRAVQ + 1).uc_x86_insn
  UC_X86_INS_VPSRLDQ* = (UC_X86_INS_VPSRAW + 1).uc_x86_insn
  UC_X86_INS_VPSRLD* = (UC_X86_INS_VPSRLDQ + 1).uc_x86_insn
  UC_X86_INS_VPSRLQ* = (UC_X86_INS_VPSRLD + 1).uc_x86_insn
  UC_X86_INS_VPSRLVD* = (UC_X86_INS_VPSRLQ + 1).uc_x86_insn
  UC_X86_INS_VPSRLVQ* = (UC_X86_INS_VPSRLVD + 1).uc_x86_insn
  UC_X86_INS_VPSRLW* = (UC_X86_INS_VPSRLVQ + 1).uc_x86_insn
  UC_X86_INS_VPSUBB* = (UC_X86_INS_VPSRLW + 1).uc_x86_insn
  UC_X86_INS_VPSUBD* = (UC_X86_INS_VPSUBB + 1).uc_x86_insn
  UC_X86_INS_VPSUBQ* = (UC_X86_INS_VPSUBD + 1).uc_x86_insn
  UC_X86_INS_VPSUBSB* = (UC_X86_INS_VPSUBQ + 1).uc_x86_insn
  UC_X86_INS_VPSUBSW* = (UC_X86_INS_VPSUBSB + 1).uc_x86_insn
  UC_X86_INS_VPSUBUSB* = (UC_X86_INS_VPSUBSW + 1).uc_x86_insn
  UC_X86_INS_VPSUBUSW* = (UC_X86_INS_VPSUBUSB + 1).uc_x86_insn
  UC_X86_INS_VPSUBW* = (UC_X86_INS_VPSUBUSW + 1).uc_x86_insn
  UC_X86_INS_VPTESTMD* = (UC_X86_INS_VPSUBW + 1).uc_x86_insn
  UC_X86_INS_VPTESTMQ* = (UC_X86_INS_VPTESTMD + 1).uc_x86_insn
  UC_X86_INS_VPTESTNMD* = (UC_X86_INS_VPTESTMQ + 1).uc_x86_insn
  UC_X86_INS_VPTESTNMQ* = (UC_X86_INS_VPTESTNMD + 1).uc_x86_insn
  UC_X86_INS_VPTEST* = (UC_X86_INS_VPTESTNMQ + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKHBW* = (UC_X86_INS_VPTEST + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKHDQ* = (UC_X86_INS_VPUNPCKHBW + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKHQDQ* = (UC_X86_INS_VPUNPCKHDQ + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKHWD* = (UC_X86_INS_VPUNPCKHQDQ + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKLBW* = (UC_X86_INS_VPUNPCKHWD + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKLDQ* = (UC_X86_INS_VPUNPCKLBW + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKLQDQ* = (UC_X86_INS_VPUNPCKLDQ + 1).uc_x86_insn
  UC_X86_INS_VPUNPCKLWD* = (UC_X86_INS_VPUNPCKLQDQ + 1).uc_x86_insn
  UC_X86_INS_VPXORD* = (UC_X86_INS_VPUNPCKLWD + 1).uc_x86_insn
  UC_X86_INS_VPXORQ* = (UC_X86_INS_VPXORD + 1).uc_x86_insn
  UC_X86_INS_VPXOR* = (UC_X86_INS_VPXORQ + 1).uc_x86_insn
  UC_X86_INS_VRCP14PD* = (UC_X86_INS_VPXOR + 1).uc_x86_insn
  UC_X86_INS_VRCP14PS* = (UC_X86_INS_VRCP14PD + 1).uc_x86_insn
  UC_X86_INS_VRCP14SD* = (UC_X86_INS_VRCP14PS + 1).uc_x86_insn
  UC_X86_INS_VRCP14SS* = (UC_X86_INS_VRCP14SD + 1).uc_x86_insn
  UC_X86_INS_VRCP28PD* = (UC_X86_INS_VRCP14SS + 1).uc_x86_insn
  UC_X86_INS_VRCP28PS* = (UC_X86_INS_VRCP28PD + 1).uc_x86_insn
  UC_X86_INS_VRCP28SD* = (UC_X86_INS_VRCP28PS + 1).uc_x86_insn
  UC_X86_INS_VRCP28SS* = (UC_X86_INS_VRCP28SD + 1).uc_x86_insn
  UC_X86_INS_VRCPPS* = (UC_X86_INS_VRCP28SS + 1).uc_x86_insn
  UC_X86_INS_VRCPSS* = (UC_X86_INS_VRCPPS + 1).uc_x86_insn
  UC_X86_INS_VRNDSCALEPD* = (UC_X86_INS_VRCPSS + 1).uc_x86_insn
  UC_X86_INS_VRNDSCALEPS* = (UC_X86_INS_VRNDSCALEPD + 1).uc_x86_insn
  UC_X86_INS_VRNDSCALESD* = (UC_X86_INS_VRNDSCALEPS + 1).uc_x86_insn
  UC_X86_INS_VRNDSCALESS* = (UC_X86_INS_VRNDSCALESD + 1).uc_x86_insn
  UC_X86_INS_VROUNDPD* = (UC_X86_INS_VRNDSCALESS + 1).uc_x86_insn
  UC_X86_INS_VROUNDPS* = (UC_X86_INS_VROUNDPD + 1).uc_x86_insn
  UC_X86_INS_VROUNDSD* = (UC_X86_INS_VROUNDPS + 1).uc_x86_insn
  UC_X86_INS_VROUNDSS* = (UC_X86_INS_VROUNDSD + 1).uc_x86_insn
  UC_X86_INS_VRSQRT14PD* = (UC_X86_INS_VROUNDSS + 1).uc_x86_insn
  UC_X86_INS_VRSQRT14PS* = (UC_X86_INS_VRSQRT14PD + 1).uc_x86_insn
  UC_X86_INS_VRSQRT14SD* = (UC_X86_INS_VRSQRT14PS + 1).uc_x86_insn
  UC_X86_INS_VRSQRT14SS* = (UC_X86_INS_VRSQRT14SD + 1).uc_x86_insn
  UC_X86_INS_VRSQRT28PD* = (UC_X86_INS_VRSQRT14SS + 1).uc_x86_insn
  UC_X86_INS_VRSQRT28PS* = (UC_X86_INS_VRSQRT28PD + 1).uc_x86_insn
  UC_X86_INS_VRSQRT28SD* = (UC_X86_INS_VRSQRT28PS + 1).uc_x86_insn
  UC_X86_INS_VRSQRT28SS* = (UC_X86_INS_VRSQRT28SD + 1).uc_x86_insn
  UC_X86_INS_VRSQRTPS* = (UC_X86_INS_VRSQRT28SS + 1).uc_x86_insn
  UC_X86_INS_VRSQRTSS* = (UC_X86_INS_VRSQRTPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERDPD* = (UC_X86_INS_VRSQRTSS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERDPS* = (UC_X86_INS_VSCATTERDPD + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF0DPD* = (UC_X86_INS_VSCATTERDPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF0DPS* = (UC_X86_INS_VSCATTERPF0DPD + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF0QPD* = (UC_X86_INS_VSCATTERPF0DPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF0QPS* = (UC_X86_INS_VSCATTERPF0QPD + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF1DPD* = (UC_X86_INS_VSCATTERPF0QPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF1DPS* = (UC_X86_INS_VSCATTERPF1DPD + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF1QPD* = (UC_X86_INS_VSCATTERPF1DPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERPF1QPS* = (UC_X86_INS_VSCATTERPF1QPD + 1).uc_x86_insn
  UC_X86_INS_VSCATTERQPD* = (UC_X86_INS_VSCATTERPF1QPS + 1).uc_x86_insn
  UC_X86_INS_VSCATTERQPS* = (UC_X86_INS_VSCATTERQPD + 1).uc_x86_insn
  UC_X86_INS_VSHUFPD* = (UC_X86_INS_VSCATTERQPS + 1).uc_x86_insn
  UC_X86_INS_VSHUFPS* = (UC_X86_INS_VSHUFPD + 1).uc_x86_insn
  UC_X86_INS_VSQRTPD* = (UC_X86_INS_VSHUFPS + 1).uc_x86_insn
  UC_X86_INS_VSQRTPS* = (UC_X86_INS_VSQRTPD + 1).uc_x86_insn
  UC_X86_INS_VSQRTSD* = (UC_X86_INS_VSQRTPS + 1).uc_x86_insn
  UC_X86_INS_VSQRTSS* = (UC_X86_INS_VSQRTSD + 1).uc_x86_insn
  UC_X86_INS_VSTMXCSR* = (UC_X86_INS_VSQRTSS + 1).uc_x86_insn
  UC_X86_INS_VSUBPD* = (UC_X86_INS_VSTMXCSR + 1).uc_x86_insn
  UC_X86_INS_VSUBPS* = (UC_X86_INS_VSUBPD + 1).uc_x86_insn
  UC_X86_INS_VSUBSD* = (UC_X86_INS_VSUBPS + 1).uc_x86_insn
  UC_X86_INS_VSUBSS* = (UC_X86_INS_VSUBSD + 1).uc_x86_insn
  UC_X86_INS_VTESTPD* = (UC_X86_INS_VSUBSS + 1).uc_x86_insn
  UC_X86_INS_VTESTPS* = (UC_X86_INS_VTESTPD + 1).uc_x86_insn
  UC_X86_INS_VUNPCKHPD* = (UC_X86_INS_VTESTPS + 1).uc_x86_insn
  UC_X86_INS_VUNPCKHPS* = (UC_X86_INS_VUNPCKHPD + 1).uc_x86_insn
  UC_X86_INS_VUNPCKLPD* = (UC_X86_INS_VUNPCKHPS + 1).uc_x86_insn
  UC_X86_INS_VUNPCKLPS* = (UC_X86_INS_VUNPCKLPD + 1).uc_x86_insn
  UC_X86_INS_VZEROALL* = (UC_X86_INS_VUNPCKLPS + 1).uc_x86_insn
  UC_X86_INS_VZEROUPPER* = (UC_X86_INS_VZEROALL + 1).uc_x86_insn
  UC_X86_INS_WAIT* = (UC_X86_INS_VZEROUPPER + 1).uc_x86_insn
  UC_X86_INS_WBINVD* = (UC_X86_INS_WAIT + 1).uc_x86_insn
  UC_X86_INS_WRFSBASE* = (UC_X86_INS_WBINVD + 1).uc_x86_insn
  UC_X86_INS_WRGSBASE* = (UC_X86_INS_WRFSBASE + 1).uc_x86_insn
  UC_X86_INS_WRMSR* = (UC_X86_INS_WRGSBASE + 1).uc_x86_insn
  UC_X86_INS_XABORT* = (UC_X86_INS_WRMSR + 1).uc_x86_insn
  UC_X86_INS_XACQUIRE* = (UC_X86_INS_XABORT + 1).uc_x86_insn
  UC_X86_INS_XBEGIN* = (UC_X86_INS_XACQUIRE + 1).uc_x86_insn
  UC_X86_INS_XCHG* = (UC_X86_INS_XBEGIN + 1).uc_x86_insn
  UC_X86_INS_XCRYPTCBC* = (UC_X86_INS_XCHG + 1).uc_x86_insn
  UC_X86_INS_XCRYPTCFB* = (UC_X86_INS_XCRYPTCBC + 1).uc_x86_insn
  UC_X86_INS_XCRYPTCTR* = (UC_X86_INS_XCRYPTCFB + 1).uc_x86_insn
  UC_X86_INS_XCRYPTECB* = (UC_X86_INS_XCRYPTCTR + 1).uc_x86_insn
  UC_X86_INS_XCRYPTOFB* = (UC_X86_INS_XCRYPTECB + 1).uc_x86_insn
  UC_X86_INS_XEND* = (UC_X86_INS_XCRYPTOFB + 1).uc_x86_insn
  UC_X86_INS_XGETBV* = (UC_X86_INS_XEND + 1).uc_x86_insn
  UC_X86_INS_XLATB* = (UC_X86_INS_XGETBV + 1).uc_x86_insn
  UC_X86_INS_XRELEASE* = (UC_X86_INS_XLATB + 1).uc_x86_insn
  UC_X86_INS_XRSTOR* = (UC_X86_INS_XRELEASE + 1).uc_x86_insn
  UC_X86_INS_XRSTOR64* = (UC_X86_INS_XRSTOR + 1).uc_x86_insn
  UC_X86_INS_XRSTORS* = (UC_X86_INS_XRSTOR64 + 1).uc_x86_insn
  UC_X86_INS_XRSTORS64* = (UC_X86_INS_XRSTORS + 1).uc_x86_insn
  UC_X86_INS_XSAVE* = (UC_X86_INS_XRSTORS64 + 1).uc_x86_insn
  UC_X86_INS_XSAVE64* = (UC_X86_INS_XSAVE + 1).uc_x86_insn
  UC_X86_INS_XSAVEC* = (UC_X86_INS_XSAVE64 + 1).uc_x86_insn
  UC_X86_INS_XSAVEC64* = (UC_X86_INS_XSAVEC + 1).uc_x86_insn
  UC_X86_INS_XSAVEOPT* = (UC_X86_INS_XSAVEC64 + 1).uc_x86_insn
  UC_X86_INS_XSAVEOPT64* = (UC_X86_INS_XSAVEOPT + 1).uc_x86_insn
  UC_X86_INS_XSAVES* = (UC_X86_INS_XSAVEOPT64 + 1).uc_x86_insn
  UC_X86_INS_XSAVES64* = (UC_X86_INS_XSAVES + 1).uc_x86_insn
  UC_X86_INS_XSETBV* = (UC_X86_INS_XSAVES64 + 1).uc_x86_insn
  UC_X86_INS_XSHA1* = (UC_X86_INS_XSETBV + 1).uc_x86_insn
  UC_X86_INS_XSHA256* = (UC_X86_INS_XSHA1 + 1).uc_x86_insn
  UC_X86_INS_XSTORE* = (UC_X86_INS_XSHA256 + 1).uc_x86_insn
  UC_X86_INS_XTEST* = (UC_X86_INS_XSTORE + 1).uc_x86_insn
  UC_X86_INS_FDISI8087_NOP* = (UC_X86_INS_XTEST + 1).uc_x86_insn
  UC_X86_INS_FENI8087_NOP* = (UC_X86_INS_FDISI8087_NOP + 1).uc_x86_insn
  UC_X86_INS_ENDING* = (UC_X86_INS_FENI8087_NOP + 1).uc_x86_insn ## ```
                                                                 ##   mark the end of the list of insn
                                                                 ## ```
  UC_CPU_ARM_926* = (0).uc_cpu_arm
  UC_CPU_ARM_946* = (UC_CPU_ARM_926 + 1).uc_cpu_arm
  UC_CPU_ARM_1026* = (UC_CPU_ARM_946 + 1).uc_cpu_arm
  UC_CPU_ARM_1136_R2* = (UC_CPU_ARM_1026 + 1).uc_cpu_arm
  UC_CPU_ARM_1136* = (UC_CPU_ARM_1136_R2 + 1).uc_cpu_arm
  UC_CPU_ARM_1176* = (UC_CPU_ARM_1136 + 1).uc_cpu_arm
  UC_CPU_ARM_11MPCORE* = (UC_CPU_ARM_1176 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_M0* = (UC_CPU_ARM_11MPCORE + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_M3* = (UC_CPU_ARM_CORTEX_M0 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_M4* = (UC_CPU_ARM_CORTEX_M3 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_M7* = (UC_CPU_ARM_CORTEX_M4 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_M33* = (UC_CPU_ARM_CORTEX_M7 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_R5* = (UC_CPU_ARM_CORTEX_M33 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_R5F* = (UC_CPU_ARM_CORTEX_R5 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_A7* = (UC_CPU_ARM_CORTEX_R5F + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_A8* = (UC_CPU_ARM_CORTEX_A7 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_A9* = (UC_CPU_ARM_CORTEX_A8 + 1).uc_cpu_arm
  UC_CPU_ARM_CORTEX_A15* = (UC_CPU_ARM_CORTEX_A9 + 1).uc_cpu_arm
  UC_CPU_ARM_TI925T* = (UC_CPU_ARM_CORTEX_A15 + 1).uc_cpu_arm
  UC_CPU_ARM_SA1100* = (UC_CPU_ARM_TI925T + 1).uc_cpu_arm
  UC_CPU_ARM_SA1110* = (UC_CPU_ARM_SA1100 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA250* = (UC_CPU_ARM_SA1110 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA255* = (UC_CPU_ARM_PXA250 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA260* = (UC_CPU_ARM_PXA255 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA261* = (UC_CPU_ARM_PXA260 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA262* = (UC_CPU_ARM_PXA261 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270* = (UC_CPU_ARM_PXA262 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270A0* = (UC_CPU_ARM_PXA270 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270A1* = (UC_CPU_ARM_PXA270A0 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270B0* = (UC_CPU_ARM_PXA270A1 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270B1* = (UC_CPU_ARM_PXA270B0 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270C0* = (UC_CPU_ARM_PXA270B1 + 1).uc_cpu_arm
  UC_CPU_ARM_PXA270C5* = (UC_CPU_ARM_PXA270C0 + 1).uc_cpu_arm
  UC_CPU_ARM_MAX* = (UC_CPU_ARM_PXA270C5 + 1).uc_cpu_arm
  UC_CPU_ARM_ENDING* = (UC_CPU_ARM_MAX + 1).uc_cpu_arm
  UC_ARM_REG_INVALID* = (0).uc_arm_reg
  UC_ARM_REG_APSR* = (UC_ARM_REG_INVALID + 1).uc_arm_reg
  UC_ARM_REG_APSR_NZCV* = (UC_ARM_REG_APSR + 1).uc_arm_reg
  UC_ARM_REG_CPSR* = (UC_ARM_REG_APSR_NZCV + 1).uc_arm_reg
  UC_ARM_REG_FPEXC* = (UC_ARM_REG_CPSR + 1).uc_arm_reg
  UC_ARM_REG_FPINST* = (UC_ARM_REG_FPEXC + 1).uc_arm_reg
  UC_ARM_REG_FPSCR* = (UC_ARM_REG_FPINST + 1).uc_arm_reg
  UC_ARM_REG_FPSCR_NZCV* = (UC_ARM_REG_FPSCR + 1).uc_arm_reg
  UC_ARM_REG_FPSID* = (UC_ARM_REG_FPSCR_NZCV + 1).uc_arm_reg
  UC_ARM_REG_ITSTATE* = (UC_ARM_REG_FPSID + 1).uc_arm_reg
  UC_ARM_REG_LR* = (UC_ARM_REG_ITSTATE + 1).uc_arm_reg
  UC_ARM_REG_PC* = (UC_ARM_REG_LR + 1).uc_arm_reg
  UC_ARM_REG_SP* = (UC_ARM_REG_PC + 1).uc_arm_reg
  UC_ARM_REG_SPSR* = (UC_ARM_REG_SP + 1).uc_arm_reg
  UC_ARM_REG_D0* = (UC_ARM_REG_SPSR + 1).uc_arm_reg
  UC_ARM_REG_D1* = (UC_ARM_REG_D0 + 1).uc_arm_reg
  UC_ARM_REG_D2* = (UC_ARM_REG_D1 + 1).uc_arm_reg
  UC_ARM_REG_D3* = (UC_ARM_REG_D2 + 1).uc_arm_reg
  UC_ARM_REG_D4* = (UC_ARM_REG_D3 + 1).uc_arm_reg
  UC_ARM_REG_D5* = (UC_ARM_REG_D4 + 1).uc_arm_reg
  UC_ARM_REG_D6* = (UC_ARM_REG_D5 + 1).uc_arm_reg
  UC_ARM_REG_D7* = (UC_ARM_REG_D6 + 1).uc_arm_reg
  UC_ARM_REG_D8* = (UC_ARM_REG_D7 + 1).uc_arm_reg
  UC_ARM_REG_D9* = (UC_ARM_REG_D8 + 1).uc_arm_reg
  UC_ARM_REG_D10* = (UC_ARM_REG_D9 + 1).uc_arm_reg
  UC_ARM_REG_D11* = (UC_ARM_REG_D10 + 1).uc_arm_reg
  UC_ARM_REG_D12* = (UC_ARM_REG_D11 + 1).uc_arm_reg
  UC_ARM_REG_D13* = (UC_ARM_REG_D12 + 1).uc_arm_reg
  UC_ARM_REG_D14* = (UC_ARM_REG_D13 + 1).uc_arm_reg
  UC_ARM_REG_D15* = (UC_ARM_REG_D14 + 1).uc_arm_reg
  UC_ARM_REG_D16* = (UC_ARM_REG_D15 + 1).uc_arm_reg
  UC_ARM_REG_D17* = (UC_ARM_REG_D16 + 1).uc_arm_reg
  UC_ARM_REG_D18* = (UC_ARM_REG_D17 + 1).uc_arm_reg
  UC_ARM_REG_D19* = (UC_ARM_REG_D18 + 1).uc_arm_reg
  UC_ARM_REG_D20* = (UC_ARM_REG_D19 + 1).uc_arm_reg
  UC_ARM_REG_D21* = (UC_ARM_REG_D20 + 1).uc_arm_reg
  UC_ARM_REG_D22* = (UC_ARM_REG_D21 + 1).uc_arm_reg
  UC_ARM_REG_D23* = (UC_ARM_REG_D22 + 1).uc_arm_reg
  UC_ARM_REG_D24* = (UC_ARM_REG_D23 + 1).uc_arm_reg
  UC_ARM_REG_D25* = (UC_ARM_REG_D24 + 1).uc_arm_reg
  UC_ARM_REG_D26* = (UC_ARM_REG_D25 + 1).uc_arm_reg
  UC_ARM_REG_D27* = (UC_ARM_REG_D26 + 1).uc_arm_reg
  UC_ARM_REG_D28* = (UC_ARM_REG_D27 + 1).uc_arm_reg
  UC_ARM_REG_D29* = (UC_ARM_REG_D28 + 1).uc_arm_reg
  UC_ARM_REG_D30* = (UC_ARM_REG_D29 + 1).uc_arm_reg
  UC_ARM_REG_D31* = (UC_ARM_REG_D30 + 1).uc_arm_reg
  UC_ARM_REG_FPINST2* = (UC_ARM_REG_D31 + 1).uc_arm_reg
  UC_ARM_REG_MVFR0* = (UC_ARM_REG_FPINST2 + 1).uc_arm_reg
  UC_ARM_REG_MVFR1* = (UC_ARM_REG_MVFR0 + 1).uc_arm_reg
  UC_ARM_REG_MVFR2* = (UC_ARM_REG_MVFR1 + 1).uc_arm_reg
  UC_ARM_REG_Q0* = (UC_ARM_REG_MVFR2 + 1).uc_arm_reg
  UC_ARM_REG_Q1* = (UC_ARM_REG_Q0 + 1).uc_arm_reg
  UC_ARM_REG_Q2* = (UC_ARM_REG_Q1 + 1).uc_arm_reg
  UC_ARM_REG_Q3* = (UC_ARM_REG_Q2 + 1).uc_arm_reg
  UC_ARM_REG_Q4* = (UC_ARM_REG_Q3 + 1).uc_arm_reg
  UC_ARM_REG_Q5* = (UC_ARM_REG_Q4 + 1).uc_arm_reg
  UC_ARM_REG_Q6* = (UC_ARM_REG_Q5 + 1).uc_arm_reg
  UC_ARM_REG_Q7* = (UC_ARM_REG_Q6 + 1).uc_arm_reg
  UC_ARM_REG_Q8* = (UC_ARM_REG_Q7 + 1).uc_arm_reg
  UC_ARM_REG_Q9* = (UC_ARM_REG_Q8 + 1).uc_arm_reg
  UC_ARM_REG_Q10* = (UC_ARM_REG_Q9 + 1).uc_arm_reg
  UC_ARM_REG_Q11* = (UC_ARM_REG_Q10 + 1).uc_arm_reg
  UC_ARM_REG_Q12* = (UC_ARM_REG_Q11 + 1).uc_arm_reg
  UC_ARM_REG_Q13* = (UC_ARM_REG_Q12 + 1).uc_arm_reg
  UC_ARM_REG_Q14* = (UC_ARM_REG_Q13 + 1).uc_arm_reg
  UC_ARM_REG_Q15* = (UC_ARM_REG_Q14 + 1).uc_arm_reg
  UC_ARM_REG_R0* = (UC_ARM_REG_Q15 + 1).uc_arm_reg
  UC_ARM_REG_R1* = (UC_ARM_REG_R0 + 1).uc_arm_reg
  UC_ARM_REG_R2* = (UC_ARM_REG_R1 + 1).uc_arm_reg
  UC_ARM_REG_R3* = (UC_ARM_REG_R2 + 1).uc_arm_reg
  UC_ARM_REG_R4* = (UC_ARM_REG_R3 + 1).uc_arm_reg
  UC_ARM_REG_R5* = (UC_ARM_REG_R4 + 1).uc_arm_reg
  UC_ARM_REG_R6* = (UC_ARM_REG_R5 + 1).uc_arm_reg
  UC_ARM_REG_R7* = (UC_ARM_REG_R6 + 1).uc_arm_reg
  UC_ARM_REG_R8* = (UC_ARM_REG_R7 + 1).uc_arm_reg
  UC_ARM_REG_R9* = (UC_ARM_REG_R8 + 1).uc_arm_reg
  UC_ARM_REG_R10* = (UC_ARM_REG_R9 + 1).uc_arm_reg
  UC_ARM_REG_R11* = (UC_ARM_REG_R10 + 1).uc_arm_reg
  UC_ARM_REG_R12* = (UC_ARM_REG_R11 + 1).uc_arm_reg
  UC_ARM_REG_S0* = (UC_ARM_REG_R12 + 1).uc_arm_reg
  UC_ARM_REG_S1* = (UC_ARM_REG_S0 + 1).uc_arm_reg
  UC_ARM_REG_S2* = (UC_ARM_REG_S1 + 1).uc_arm_reg
  UC_ARM_REG_S3* = (UC_ARM_REG_S2 + 1).uc_arm_reg
  UC_ARM_REG_S4* = (UC_ARM_REG_S3 + 1).uc_arm_reg
  UC_ARM_REG_S5* = (UC_ARM_REG_S4 + 1).uc_arm_reg
  UC_ARM_REG_S6* = (UC_ARM_REG_S5 + 1).uc_arm_reg
  UC_ARM_REG_S7* = (UC_ARM_REG_S6 + 1).uc_arm_reg
  UC_ARM_REG_S8* = (UC_ARM_REG_S7 + 1).uc_arm_reg
  UC_ARM_REG_S9* = (UC_ARM_REG_S8 + 1).uc_arm_reg
  UC_ARM_REG_S10* = (UC_ARM_REG_S9 + 1).uc_arm_reg
  UC_ARM_REG_S11* = (UC_ARM_REG_S10 + 1).uc_arm_reg
  UC_ARM_REG_S12* = (UC_ARM_REG_S11 + 1).uc_arm_reg
  UC_ARM_REG_S13* = (UC_ARM_REG_S12 + 1).uc_arm_reg
  UC_ARM_REG_S14* = (UC_ARM_REG_S13 + 1).uc_arm_reg
  UC_ARM_REG_S15* = (UC_ARM_REG_S14 + 1).uc_arm_reg
  UC_ARM_REG_S16* = (UC_ARM_REG_S15 + 1).uc_arm_reg
  UC_ARM_REG_S17* = (UC_ARM_REG_S16 + 1).uc_arm_reg
  UC_ARM_REG_S18* = (UC_ARM_REG_S17 + 1).uc_arm_reg
  UC_ARM_REG_S19* = (UC_ARM_REG_S18 + 1).uc_arm_reg
  UC_ARM_REG_S20* = (UC_ARM_REG_S19 + 1).uc_arm_reg
  UC_ARM_REG_S21* = (UC_ARM_REG_S20 + 1).uc_arm_reg
  UC_ARM_REG_S22* = (UC_ARM_REG_S21 + 1).uc_arm_reg
  UC_ARM_REG_S23* = (UC_ARM_REG_S22 + 1).uc_arm_reg
  UC_ARM_REG_S24* = (UC_ARM_REG_S23 + 1).uc_arm_reg
  UC_ARM_REG_S25* = (UC_ARM_REG_S24 + 1).uc_arm_reg
  UC_ARM_REG_S26* = (UC_ARM_REG_S25 + 1).uc_arm_reg
  UC_ARM_REG_S27* = (UC_ARM_REG_S26 + 1).uc_arm_reg
  UC_ARM_REG_S28* = (UC_ARM_REG_S27 + 1).uc_arm_reg
  UC_ARM_REG_S29* = (UC_ARM_REG_S28 + 1).uc_arm_reg
  UC_ARM_REG_S30* = (UC_ARM_REG_S29 + 1).uc_arm_reg
  UC_ARM_REG_S31* = (UC_ARM_REG_S30 + 1).uc_arm_reg
  UC_ARM_REG_C1_C0_2* = (UC_ARM_REG_S31 + 1).uc_arm_reg ## ```
                                                        ##   Depreciated, use UC_ARM_REG_CP_REG instead
                                                        ## ```
  UC_ARM_REG_C13_C0_2* = (UC_ARM_REG_C1_C0_2 + 1).uc_arm_reg ## ```
                                                             ##   Depreciated, use UC_ARM_REG_CP_REG instead
                                                             ## ```
  UC_ARM_REG_C13_C0_3* = (UC_ARM_REG_C13_C0_2 + 1).uc_arm_reg ## ```
                                                              ##   Depreciated, use UC_ARM_REG_CP_REG instead
                                                              ## ```
  UC_ARM_REG_IPSR* = (UC_ARM_REG_C13_C0_3 + 1).uc_arm_reg
  UC_ARM_REG_MSP* = (UC_ARM_REG_IPSR + 1).uc_arm_reg
  UC_ARM_REG_PSP* = (UC_ARM_REG_MSP + 1).uc_arm_reg
  UC_ARM_REG_CONTROL* = (UC_ARM_REG_PSP + 1).uc_arm_reg
  UC_ARM_REG_IAPSR* = (UC_ARM_REG_CONTROL + 1).uc_arm_reg
  UC_ARM_REG_EAPSR* = (UC_ARM_REG_IAPSR + 1).uc_arm_reg
  UC_ARM_REG_XPSR* = (UC_ARM_REG_EAPSR + 1).uc_arm_reg
  UC_ARM_REG_EPSR* = (UC_ARM_REG_XPSR + 1).uc_arm_reg
  UC_ARM_REG_IEPSR* = (UC_ARM_REG_EPSR + 1).uc_arm_reg
  UC_ARM_REG_PRIMASK* = (UC_ARM_REG_IEPSR + 1).uc_arm_reg
  UC_ARM_REG_BASEPRI* = (UC_ARM_REG_PRIMASK + 1).uc_arm_reg
  UC_ARM_REG_BASEPRI_MAX* = (UC_ARM_REG_BASEPRI + 1).uc_arm_reg
  UC_ARM_REG_FAULTMASK* = (UC_ARM_REG_BASEPRI_MAX + 1).uc_arm_reg
  UC_ARM_REG_APSR_NZCVQ* = (UC_ARM_REG_FAULTMASK + 1).uc_arm_reg
  UC_ARM_REG_APSR_G* = (UC_ARM_REG_APSR_NZCVQ + 1).uc_arm_reg
  UC_ARM_REG_APSR_NZCVQG* = (UC_ARM_REG_APSR_G + 1).uc_arm_reg
  UC_ARM_REG_IAPSR_NZCVQ* = (UC_ARM_REG_APSR_NZCVQG + 1).uc_arm_reg
  UC_ARM_REG_IAPSR_G* = (UC_ARM_REG_IAPSR_NZCVQ + 1).uc_arm_reg
  UC_ARM_REG_IAPSR_NZCVQG* = (UC_ARM_REG_IAPSR_G + 1).uc_arm_reg
  UC_ARM_REG_EAPSR_NZCVQ* = (UC_ARM_REG_IAPSR_NZCVQG + 1).uc_arm_reg
  UC_ARM_REG_EAPSR_G* = (UC_ARM_REG_EAPSR_NZCVQ + 1).uc_arm_reg
  UC_ARM_REG_EAPSR_NZCVQG* = (UC_ARM_REG_EAPSR_G + 1).uc_arm_reg
  UC_ARM_REG_XPSR_NZCVQ* = (UC_ARM_REG_EAPSR_NZCVQG + 1).uc_arm_reg
  UC_ARM_REG_XPSR_G* = (UC_ARM_REG_XPSR_NZCVQ + 1).uc_arm_reg
  UC_ARM_REG_XPSR_NZCVQG* = (UC_ARM_REG_XPSR_G + 1).uc_arm_reg
  UC_ARM_REG_CP_REG* = (UC_ARM_REG_XPSR_NZCVQG + 1).uc_arm_reg
  UC_ARM_REG_ENDING* = (UC_ARM_REG_CP_REG + 1).uc_arm_reg ## ```
                                                          ##   <-- mark the end of the list or registers
                                                          ##     > alias registers
                                                          ## ```
  UC_ARM_REG_R13* = (UC_ARM_REG_SP).uc_arm_reg ## ```
                                               ##   <-- mark the end of the list or registers
                                               ##     > alias registers
                                               ## ```
  UC_ARM_REG_R14* = (UC_ARM_REG_LR).uc_arm_reg
  UC_ARM_REG_R15* = (UC_ARM_REG_PC).uc_arm_reg
  UC_ARM_REG_SB* = (UC_ARM_REG_R9).uc_arm_reg
  UC_ARM_REG_SL* = (UC_ARM_REG_R10).uc_arm_reg
  UC_ARM_REG_FP* = (UC_ARM_REG_R11).uc_arm_reg
  UC_ARM_REG_IP* = (UC_ARM_REG_R12).uc_arm_reg
  UC_CPU_ARM64_A57* = (0).uc_cpu_arm64
  UC_CPU_ARM64_A53* = (UC_CPU_ARM64_A57 + 1).uc_cpu_arm64
  UC_CPU_ARM64_A72* = (UC_CPU_ARM64_A53 + 1).uc_cpu_arm64
  UC_CPU_ARM64_MAX* = (UC_CPU_ARM64_A72 + 1).uc_cpu_arm64
  UC_CPU_ARM64_ENDING* = (UC_CPU_ARM64_MAX + 1).uc_cpu_arm64
  UC_ARM64_REG_INVALID* = (0).uc_arm64_reg
  UC_ARM64_REG_X29* = (UC_ARM64_REG_INVALID + 1).uc_arm64_reg
  UC_ARM64_REG_X30* = (UC_ARM64_REG_X29 + 1).uc_arm64_reg
  UC_ARM64_REG_NZCV* = (UC_ARM64_REG_X30 + 1).uc_arm64_reg
  UC_ARM64_REG_SP* = (UC_ARM64_REG_NZCV + 1).uc_arm64_reg
  UC_ARM64_REG_WSP* = (UC_ARM64_REG_SP + 1).uc_arm64_reg
  UC_ARM64_REG_WZR* = (UC_ARM64_REG_WSP + 1).uc_arm64_reg
  UC_ARM64_REG_XZR* = (UC_ARM64_REG_WZR + 1).uc_arm64_reg
  UC_ARM64_REG_B0* = (UC_ARM64_REG_XZR + 1).uc_arm64_reg
  UC_ARM64_REG_B1* = (UC_ARM64_REG_B0 + 1).uc_arm64_reg
  UC_ARM64_REG_B2* = (UC_ARM64_REG_B1 + 1).uc_arm64_reg
  UC_ARM64_REG_B3* = (UC_ARM64_REG_B2 + 1).uc_arm64_reg
  UC_ARM64_REG_B4* = (UC_ARM64_REG_B3 + 1).uc_arm64_reg
  UC_ARM64_REG_B5* = (UC_ARM64_REG_B4 + 1).uc_arm64_reg
  UC_ARM64_REG_B6* = (UC_ARM64_REG_B5 + 1).uc_arm64_reg
  UC_ARM64_REG_B7* = (UC_ARM64_REG_B6 + 1).uc_arm64_reg
  UC_ARM64_REG_B8* = (UC_ARM64_REG_B7 + 1).uc_arm64_reg
  UC_ARM64_REG_B9* = (UC_ARM64_REG_B8 + 1).uc_arm64_reg
  UC_ARM64_REG_B10* = (UC_ARM64_REG_B9 + 1).uc_arm64_reg
  UC_ARM64_REG_B11* = (UC_ARM64_REG_B10 + 1).uc_arm64_reg
  UC_ARM64_REG_B12* = (UC_ARM64_REG_B11 + 1).uc_arm64_reg
  UC_ARM64_REG_B13* = (UC_ARM64_REG_B12 + 1).uc_arm64_reg
  UC_ARM64_REG_B14* = (UC_ARM64_REG_B13 + 1).uc_arm64_reg
  UC_ARM64_REG_B15* = (UC_ARM64_REG_B14 + 1).uc_arm64_reg
  UC_ARM64_REG_B16* = (UC_ARM64_REG_B15 + 1).uc_arm64_reg
  UC_ARM64_REG_B17* = (UC_ARM64_REG_B16 + 1).uc_arm64_reg
  UC_ARM64_REG_B18* = (UC_ARM64_REG_B17 + 1).uc_arm64_reg
  UC_ARM64_REG_B19* = (UC_ARM64_REG_B18 + 1).uc_arm64_reg
  UC_ARM64_REG_B20* = (UC_ARM64_REG_B19 + 1).uc_arm64_reg
  UC_ARM64_REG_B21* = (UC_ARM64_REG_B20 + 1).uc_arm64_reg
  UC_ARM64_REG_B22* = (UC_ARM64_REG_B21 + 1).uc_arm64_reg
  UC_ARM64_REG_B23* = (UC_ARM64_REG_B22 + 1).uc_arm64_reg
  UC_ARM64_REG_B24* = (UC_ARM64_REG_B23 + 1).uc_arm64_reg
  UC_ARM64_REG_B25* = (UC_ARM64_REG_B24 + 1).uc_arm64_reg
  UC_ARM64_REG_B26* = (UC_ARM64_REG_B25 + 1).uc_arm64_reg
  UC_ARM64_REG_B27* = (UC_ARM64_REG_B26 + 1).uc_arm64_reg
  UC_ARM64_REG_B28* = (UC_ARM64_REG_B27 + 1).uc_arm64_reg
  UC_ARM64_REG_B29* = (UC_ARM64_REG_B28 + 1).uc_arm64_reg
  UC_ARM64_REG_B30* = (UC_ARM64_REG_B29 + 1).uc_arm64_reg
  UC_ARM64_REG_B31* = (UC_ARM64_REG_B30 + 1).uc_arm64_reg
  UC_ARM64_REG_D0* = (UC_ARM64_REG_B31 + 1).uc_arm64_reg
  UC_ARM64_REG_D1* = (UC_ARM64_REG_D0 + 1).uc_arm64_reg
  UC_ARM64_REG_D2* = (UC_ARM64_REG_D1 + 1).uc_arm64_reg
  UC_ARM64_REG_D3* = (UC_ARM64_REG_D2 + 1).uc_arm64_reg
  UC_ARM64_REG_D4* = (UC_ARM64_REG_D3 + 1).uc_arm64_reg
  UC_ARM64_REG_D5* = (UC_ARM64_REG_D4 + 1).uc_arm64_reg
  UC_ARM64_REG_D6* = (UC_ARM64_REG_D5 + 1).uc_arm64_reg
  UC_ARM64_REG_D7* = (UC_ARM64_REG_D6 + 1).uc_arm64_reg
  UC_ARM64_REG_D8* = (UC_ARM64_REG_D7 + 1).uc_arm64_reg
  UC_ARM64_REG_D9* = (UC_ARM64_REG_D8 + 1).uc_arm64_reg
  UC_ARM64_REG_D10* = (UC_ARM64_REG_D9 + 1).uc_arm64_reg
  UC_ARM64_REG_D11* = (UC_ARM64_REG_D10 + 1).uc_arm64_reg
  UC_ARM64_REG_D12* = (UC_ARM64_REG_D11 + 1).uc_arm64_reg
  UC_ARM64_REG_D13* = (UC_ARM64_REG_D12 + 1).uc_arm64_reg
  UC_ARM64_REG_D14* = (UC_ARM64_REG_D13 + 1).uc_arm64_reg
  UC_ARM64_REG_D15* = (UC_ARM64_REG_D14 + 1).uc_arm64_reg
  UC_ARM64_REG_D16* = (UC_ARM64_REG_D15 + 1).uc_arm64_reg
  UC_ARM64_REG_D17* = (UC_ARM64_REG_D16 + 1).uc_arm64_reg
  UC_ARM64_REG_D18* = (UC_ARM64_REG_D17 + 1).uc_arm64_reg
  UC_ARM64_REG_D19* = (UC_ARM64_REG_D18 + 1).uc_arm64_reg
  UC_ARM64_REG_D20* = (UC_ARM64_REG_D19 + 1).uc_arm64_reg
  UC_ARM64_REG_D21* = (UC_ARM64_REG_D20 + 1).uc_arm64_reg
  UC_ARM64_REG_D22* = (UC_ARM64_REG_D21 + 1).uc_arm64_reg
  UC_ARM64_REG_D23* = (UC_ARM64_REG_D22 + 1).uc_arm64_reg
  UC_ARM64_REG_D24* = (UC_ARM64_REG_D23 + 1).uc_arm64_reg
  UC_ARM64_REG_D25* = (UC_ARM64_REG_D24 + 1).uc_arm64_reg
  UC_ARM64_REG_D26* = (UC_ARM64_REG_D25 + 1).uc_arm64_reg
  UC_ARM64_REG_D27* = (UC_ARM64_REG_D26 + 1).uc_arm64_reg
  UC_ARM64_REG_D28* = (UC_ARM64_REG_D27 + 1).uc_arm64_reg
  UC_ARM64_REG_D29* = (UC_ARM64_REG_D28 + 1).uc_arm64_reg
  UC_ARM64_REG_D30* = (UC_ARM64_REG_D29 + 1).uc_arm64_reg
  UC_ARM64_REG_D31* = (UC_ARM64_REG_D30 + 1).uc_arm64_reg
  UC_ARM64_REG_H0* = (UC_ARM64_REG_D31 + 1).uc_arm64_reg
  UC_ARM64_REG_H1* = (UC_ARM64_REG_H0 + 1).uc_arm64_reg
  UC_ARM64_REG_H2* = (UC_ARM64_REG_H1 + 1).uc_arm64_reg
  UC_ARM64_REG_H3* = (UC_ARM64_REG_H2 + 1).uc_arm64_reg
  UC_ARM64_REG_H4* = (UC_ARM64_REG_H3 + 1).uc_arm64_reg
  UC_ARM64_REG_H5* = (UC_ARM64_REG_H4 + 1).uc_arm64_reg
  UC_ARM64_REG_H6* = (UC_ARM64_REG_H5 + 1).uc_arm64_reg
  UC_ARM64_REG_H7* = (UC_ARM64_REG_H6 + 1).uc_arm64_reg
  UC_ARM64_REG_H8* = (UC_ARM64_REG_H7 + 1).uc_arm64_reg
  UC_ARM64_REG_H9* = (UC_ARM64_REG_H8 + 1).uc_arm64_reg
  UC_ARM64_REG_H10* = (UC_ARM64_REG_H9 + 1).uc_arm64_reg
  UC_ARM64_REG_H11* = (UC_ARM64_REG_H10 + 1).uc_arm64_reg
  UC_ARM64_REG_H12* = (UC_ARM64_REG_H11 + 1).uc_arm64_reg
  UC_ARM64_REG_H13* = (UC_ARM64_REG_H12 + 1).uc_arm64_reg
  UC_ARM64_REG_H14* = (UC_ARM64_REG_H13 + 1).uc_arm64_reg
  UC_ARM64_REG_H15* = (UC_ARM64_REG_H14 + 1).uc_arm64_reg
  UC_ARM64_REG_H16* = (UC_ARM64_REG_H15 + 1).uc_arm64_reg
  UC_ARM64_REG_H17* = (UC_ARM64_REG_H16 + 1).uc_arm64_reg
  UC_ARM64_REG_H18* = (UC_ARM64_REG_H17 + 1).uc_arm64_reg
  UC_ARM64_REG_H19* = (UC_ARM64_REG_H18 + 1).uc_arm64_reg
  UC_ARM64_REG_H20* = (UC_ARM64_REG_H19 + 1).uc_arm64_reg
  UC_ARM64_REG_H21* = (UC_ARM64_REG_H20 + 1).uc_arm64_reg
  UC_ARM64_REG_H22* = (UC_ARM64_REG_H21 + 1).uc_arm64_reg
  UC_ARM64_REG_H23* = (UC_ARM64_REG_H22 + 1).uc_arm64_reg
  UC_ARM64_REG_H24* = (UC_ARM64_REG_H23 + 1).uc_arm64_reg
  UC_ARM64_REG_H25* = (UC_ARM64_REG_H24 + 1).uc_arm64_reg
  UC_ARM64_REG_H26* = (UC_ARM64_REG_H25 + 1).uc_arm64_reg
  UC_ARM64_REG_H27* = (UC_ARM64_REG_H26 + 1).uc_arm64_reg
  UC_ARM64_REG_H28* = (UC_ARM64_REG_H27 + 1).uc_arm64_reg
  UC_ARM64_REG_H29* = (UC_ARM64_REG_H28 + 1).uc_arm64_reg
  UC_ARM64_REG_H30* = (UC_ARM64_REG_H29 + 1).uc_arm64_reg
  UC_ARM64_REG_H31* = (UC_ARM64_REG_H30 + 1).uc_arm64_reg
  UC_ARM64_REG_Q0* = (UC_ARM64_REG_H31 + 1).uc_arm64_reg
  UC_ARM64_REG_Q1* = (UC_ARM64_REG_Q0 + 1).uc_arm64_reg
  UC_ARM64_REG_Q2* = (UC_ARM64_REG_Q1 + 1).uc_arm64_reg
  UC_ARM64_REG_Q3* = (UC_ARM64_REG_Q2 + 1).uc_arm64_reg
  UC_ARM64_REG_Q4* = (UC_ARM64_REG_Q3 + 1).uc_arm64_reg
  UC_ARM64_REG_Q5* = (UC_ARM64_REG_Q4 + 1).uc_arm64_reg
  UC_ARM64_REG_Q6* = (UC_ARM64_REG_Q5 + 1).uc_arm64_reg
  UC_ARM64_REG_Q7* = (UC_ARM64_REG_Q6 + 1).uc_arm64_reg
  UC_ARM64_REG_Q8* = (UC_ARM64_REG_Q7 + 1).uc_arm64_reg
  UC_ARM64_REG_Q9* = (UC_ARM64_REG_Q8 + 1).uc_arm64_reg
  UC_ARM64_REG_Q10* = (UC_ARM64_REG_Q9 + 1).uc_arm64_reg
  UC_ARM64_REG_Q11* = (UC_ARM64_REG_Q10 + 1).uc_arm64_reg
  UC_ARM64_REG_Q12* = (UC_ARM64_REG_Q11 + 1).uc_arm64_reg
  UC_ARM64_REG_Q13* = (UC_ARM64_REG_Q12 + 1).uc_arm64_reg
  UC_ARM64_REG_Q14* = (UC_ARM64_REG_Q13 + 1).uc_arm64_reg
  UC_ARM64_REG_Q15* = (UC_ARM64_REG_Q14 + 1).uc_arm64_reg
  UC_ARM64_REG_Q16* = (UC_ARM64_REG_Q15 + 1).uc_arm64_reg
  UC_ARM64_REG_Q17* = (UC_ARM64_REG_Q16 + 1).uc_arm64_reg
  UC_ARM64_REG_Q18* = (UC_ARM64_REG_Q17 + 1).uc_arm64_reg
  UC_ARM64_REG_Q19* = (UC_ARM64_REG_Q18 + 1).uc_arm64_reg
  UC_ARM64_REG_Q20* = (UC_ARM64_REG_Q19 + 1).uc_arm64_reg
  UC_ARM64_REG_Q21* = (UC_ARM64_REG_Q20 + 1).uc_arm64_reg
  UC_ARM64_REG_Q22* = (UC_ARM64_REG_Q21 + 1).uc_arm64_reg
  UC_ARM64_REG_Q23* = (UC_ARM64_REG_Q22 + 1).uc_arm64_reg
  UC_ARM64_REG_Q24* = (UC_ARM64_REG_Q23 + 1).uc_arm64_reg
  UC_ARM64_REG_Q25* = (UC_ARM64_REG_Q24 + 1).uc_arm64_reg
  UC_ARM64_REG_Q26* = (UC_ARM64_REG_Q25 + 1).uc_arm64_reg
  UC_ARM64_REG_Q27* = (UC_ARM64_REG_Q26 + 1).uc_arm64_reg
  UC_ARM64_REG_Q28* = (UC_ARM64_REG_Q27 + 1).uc_arm64_reg
  UC_ARM64_REG_Q29* = (UC_ARM64_REG_Q28 + 1).uc_arm64_reg
  UC_ARM64_REG_Q30* = (UC_ARM64_REG_Q29 + 1).uc_arm64_reg
  UC_ARM64_REG_Q31* = (UC_ARM64_REG_Q30 + 1).uc_arm64_reg
  UC_ARM64_REG_S0* = (UC_ARM64_REG_Q31 + 1).uc_arm64_reg
  UC_ARM64_REG_S1* = (UC_ARM64_REG_S0 + 1).uc_arm64_reg
  UC_ARM64_REG_S2* = (UC_ARM64_REG_S1 + 1).uc_arm64_reg
  UC_ARM64_REG_S3* = (UC_ARM64_REG_S2 + 1).uc_arm64_reg
  UC_ARM64_REG_S4* = (UC_ARM64_REG_S3 + 1).uc_arm64_reg
  UC_ARM64_REG_S5* = (UC_ARM64_REG_S4 + 1).uc_arm64_reg
  UC_ARM64_REG_S6* = (UC_ARM64_REG_S5 + 1).uc_arm64_reg
  UC_ARM64_REG_S7* = (UC_ARM64_REG_S6 + 1).uc_arm64_reg
  UC_ARM64_REG_S8* = (UC_ARM64_REG_S7 + 1).uc_arm64_reg
  UC_ARM64_REG_S9* = (UC_ARM64_REG_S8 + 1).uc_arm64_reg
  UC_ARM64_REG_S10* = (UC_ARM64_REG_S9 + 1).uc_arm64_reg
  UC_ARM64_REG_S11* = (UC_ARM64_REG_S10 + 1).uc_arm64_reg
  UC_ARM64_REG_S12* = (UC_ARM64_REG_S11 + 1).uc_arm64_reg
  UC_ARM64_REG_S13* = (UC_ARM64_REG_S12 + 1).uc_arm64_reg
  UC_ARM64_REG_S14* = (UC_ARM64_REG_S13 + 1).uc_arm64_reg
  UC_ARM64_REG_S15* = (UC_ARM64_REG_S14 + 1).uc_arm64_reg
  UC_ARM64_REG_S16* = (UC_ARM64_REG_S15 + 1).uc_arm64_reg
  UC_ARM64_REG_S17* = (UC_ARM64_REG_S16 + 1).uc_arm64_reg
  UC_ARM64_REG_S18* = (UC_ARM64_REG_S17 + 1).uc_arm64_reg
  UC_ARM64_REG_S19* = (UC_ARM64_REG_S18 + 1).uc_arm64_reg
  UC_ARM64_REG_S20* = (UC_ARM64_REG_S19 + 1).uc_arm64_reg
  UC_ARM64_REG_S21* = (UC_ARM64_REG_S20 + 1).uc_arm64_reg
  UC_ARM64_REG_S22* = (UC_ARM64_REG_S21 + 1).uc_arm64_reg
  UC_ARM64_REG_S23* = (UC_ARM64_REG_S22 + 1).uc_arm64_reg
  UC_ARM64_REG_S24* = (UC_ARM64_REG_S23 + 1).uc_arm64_reg
  UC_ARM64_REG_S25* = (UC_ARM64_REG_S24 + 1).uc_arm64_reg
  UC_ARM64_REG_S26* = (UC_ARM64_REG_S25 + 1).uc_arm64_reg
  UC_ARM64_REG_S27* = (UC_ARM64_REG_S26 + 1).uc_arm64_reg
  UC_ARM64_REG_S28* = (UC_ARM64_REG_S27 + 1).uc_arm64_reg
  UC_ARM64_REG_S29* = (UC_ARM64_REG_S28 + 1).uc_arm64_reg
  UC_ARM64_REG_S30* = (UC_ARM64_REG_S29 + 1).uc_arm64_reg
  UC_ARM64_REG_S31* = (UC_ARM64_REG_S30 + 1).uc_arm64_reg
  UC_ARM64_REG_W0* = (UC_ARM64_REG_S31 + 1).uc_arm64_reg
  UC_ARM64_REG_W1* = (UC_ARM64_REG_W0 + 1).uc_arm64_reg
  UC_ARM64_REG_W2* = (UC_ARM64_REG_W1 + 1).uc_arm64_reg
  UC_ARM64_REG_W3* = (UC_ARM64_REG_W2 + 1).uc_arm64_reg
  UC_ARM64_REG_W4* = (UC_ARM64_REG_W3 + 1).uc_arm64_reg
  UC_ARM64_REG_W5* = (UC_ARM64_REG_W4 + 1).uc_arm64_reg
  UC_ARM64_REG_W6* = (UC_ARM64_REG_W5 + 1).uc_arm64_reg
  UC_ARM64_REG_W7* = (UC_ARM64_REG_W6 + 1).uc_arm64_reg
  UC_ARM64_REG_W8* = (UC_ARM64_REG_W7 + 1).uc_arm64_reg
  UC_ARM64_REG_W9* = (UC_ARM64_REG_W8 + 1).uc_arm64_reg
  UC_ARM64_REG_W10* = (UC_ARM64_REG_W9 + 1).uc_arm64_reg
  UC_ARM64_REG_W11* = (UC_ARM64_REG_W10 + 1).uc_arm64_reg
  UC_ARM64_REG_W12* = (UC_ARM64_REG_W11 + 1).uc_arm64_reg
  UC_ARM64_REG_W13* = (UC_ARM64_REG_W12 + 1).uc_arm64_reg
  UC_ARM64_REG_W14* = (UC_ARM64_REG_W13 + 1).uc_arm64_reg
  UC_ARM64_REG_W15* = (UC_ARM64_REG_W14 + 1).uc_arm64_reg
  UC_ARM64_REG_W16* = (UC_ARM64_REG_W15 + 1).uc_arm64_reg
  UC_ARM64_REG_W17* = (UC_ARM64_REG_W16 + 1).uc_arm64_reg
  UC_ARM64_REG_W18* = (UC_ARM64_REG_W17 + 1).uc_arm64_reg
  UC_ARM64_REG_W19* = (UC_ARM64_REG_W18 + 1).uc_arm64_reg
  UC_ARM64_REG_W20* = (UC_ARM64_REG_W19 + 1).uc_arm64_reg
  UC_ARM64_REG_W21* = (UC_ARM64_REG_W20 + 1).uc_arm64_reg
  UC_ARM64_REG_W22* = (UC_ARM64_REG_W21 + 1).uc_arm64_reg
  UC_ARM64_REG_W23* = (UC_ARM64_REG_W22 + 1).uc_arm64_reg
  UC_ARM64_REG_W24* = (UC_ARM64_REG_W23 + 1).uc_arm64_reg
  UC_ARM64_REG_W25* = (UC_ARM64_REG_W24 + 1).uc_arm64_reg
  UC_ARM64_REG_W26* = (UC_ARM64_REG_W25 + 1).uc_arm64_reg
  UC_ARM64_REG_W27* = (UC_ARM64_REG_W26 + 1).uc_arm64_reg
  UC_ARM64_REG_W28* = (UC_ARM64_REG_W27 + 1).uc_arm64_reg
  UC_ARM64_REG_W29* = (UC_ARM64_REG_W28 + 1).uc_arm64_reg
  UC_ARM64_REG_W30* = (UC_ARM64_REG_W29 + 1).uc_arm64_reg
  UC_ARM64_REG_X0* = (UC_ARM64_REG_W30 + 1).uc_arm64_reg
  UC_ARM64_REG_X1* = (UC_ARM64_REG_X0 + 1).uc_arm64_reg
  UC_ARM64_REG_X2* = (UC_ARM64_REG_X1 + 1).uc_arm64_reg
  UC_ARM64_REG_X3* = (UC_ARM64_REG_X2 + 1).uc_arm64_reg
  UC_ARM64_REG_X4* = (UC_ARM64_REG_X3 + 1).uc_arm64_reg
  UC_ARM64_REG_X5* = (UC_ARM64_REG_X4 + 1).uc_arm64_reg
  UC_ARM64_REG_X6* = (UC_ARM64_REG_X5 + 1).uc_arm64_reg
  UC_ARM64_REG_X7* = (UC_ARM64_REG_X6 + 1).uc_arm64_reg
  UC_ARM64_REG_X8* = (UC_ARM64_REG_X7 + 1).uc_arm64_reg
  UC_ARM64_REG_X9* = (UC_ARM64_REG_X8 + 1).uc_arm64_reg
  UC_ARM64_REG_X10* = (UC_ARM64_REG_X9 + 1).uc_arm64_reg
  UC_ARM64_REG_X11* = (UC_ARM64_REG_X10 + 1).uc_arm64_reg
  UC_ARM64_REG_X12* = (UC_ARM64_REG_X11 + 1).uc_arm64_reg
  UC_ARM64_REG_X13* = (UC_ARM64_REG_X12 + 1).uc_arm64_reg
  UC_ARM64_REG_X14* = (UC_ARM64_REG_X13 + 1).uc_arm64_reg
  UC_ARM64_REG_X15* = (UC_ARM64_REG_X14 + 1).uc_arm64_reg
  UC_ARM64_REG_X16* = (UC_ARM64_REG_X15 + 1).uc_arm64_reg
  UC_ARM64_REG_X17* = (UC_ARM64_REG_X16 + 1).uc_arm64_reg
  UC_ARM64_REG_X18* = (UC_ARM64_REG_X17 + 1).uc_arm64_reg
  UC_ARM64_REG_X19* = (UC_ARM64_REG_X18 + 1).uc_arm64_reg
  UC_ARM64_REG_X20* = (UC_ARM64_REG_X19 + 1).uc_arm64_reg
  UC_ARM64_REG_X21* = (UC_ARM64_REG_X20 + 1).uc_arm64_reg
  UC_ARM64_REG_X22* = (UC_ARM64_REG_X21 + 1).uc_arm64_reg
  UC_ARM64_REG_X23* = (UC_ARM64_REG_X22 + 1).uc_arm64_reg
  UC_ARM64_REG_X24* = (UC_ARM64_REG_X23 + 1).uc_arm64_reg
  UC_ARM64_REG_X25* = (UC_ARM64_REG_X24 + 1).uc_arm64_reg
  UC_ARM64_REG_X26* = (UC_ARM64_REG_X25 + 1).uc_arm64_reg
  UC_ARM64_REG_X27* = (UC_ARM64_REG_X26 + 1).uc_arm64_reg
  UC_ARM64_REG_X28* = (UC_ARM64_REG_X27 + 1).uc_arm64_reg
  UC_ARM64_REG_V0* = (UC_ARM64_REG_X28 + 1).uc_arm64_reg
  UC_ARM64_REG_V1* = (UC_ARM64_REG_V0 + 1).uc_arm64_reg
  UC_ARM64_REG_V2* = (UC_ARM64_REG_V1 + 1).uc_arm64_reg
  UC_ARM64_REG_V3* = (UC_ARM64_REG_V2 + 1).uc_arm64_reg
  UC_ARM64_REG_V4* = (UC_ARM64_REG_V3 + 1).uc_arm64_reg
  UC_ARM64_REG_V5* = (UC_ARM64_REG_V4 + 1).uc_arm64_reg
  UC_ARM64_REG_V6* = (UC_ARM64_REG_V5 + 1).uc_arm64_reg
  UC_ARM64_REG_V7* = (UC_ARM64_REG_V6 + 1).uc_arm64_reg
  UC_ARM64_REG_V8* = (UC_ARM64_REG_V7 + 1).uc_arm64_reg
  UC_ARM64_REG_V9* = (UC_ARM64_REG_V8 + 1).uc_arm64_reg
  UC_ARM64_REG_V10* = (UC_ARM64_REG_V9 + 1).uc_arm64_reg
  UC_ARM64_REG_V11* = (UC_ARM64_REG_V10 + 1).uc_arm64_reg
  UC_ARM64_REG_V12* = (UC_ARM64_REG_V11 + 1).uc_arm64_reg
  UC_ARM64_REG_V13* = (UC_ARM64_REG_V12 + 1).uc_arm64_reg
  UC_ARM64_REG_V14* = (UC_ARM64_REG_V13 + 1).uc_arm64_reg
  UC_ARM64_REG_V15* = (UC_ARM64_REG_V14 + 1).uc_arm64_reg
  UC_ARM64_REG_V16* = (UC_ARM64_REG_V15 + 1).uc_arm64_reg
  UC_ARM64_REG_V17* = (UC_ARM64_REG_V16 + 1).uc_arm64_reg
  UC_ARM64_REG_V18* = (UC_ARM64_REG_V17 + 1).uc_arm64_reg
  UC_ARM64_REG_V19* = (UC_ARM64_REG_V18 + 1).uc_arm64_reg
  UC_ARM64_REG_V20* = (UC_ARM64_REG_V19 + 1).uc_arm64_reg
  UC_ARM64_REG_V21* = (UC_ARM64_REG_V20 + 1).uc_arm64_reg
  UC_ARM64_REG_V22* = (UC_ARM64_REG_V21 + 1).uc_arm64_reg
  UC_ARM64_REG_V23* = (UC_ARM64_REG_V22 + 1).uc_arm64_reg
  UC_ARM64_REG_V24* = (UC_ARM64_REG_V23 + 1).uc_arm64_reg
  UC_ARM64_REG_V25* = (UC_ARM64_REG_V24 + 1).uc_arm64_reg
  UC_ARM64_REG_V26* = (UC_ARM64_REG_V25 + 1).uc_arm64_reg
  UC_ARM64_REG_V27* = (UC_ARM64_REG_V26 + 1).uc_arm64_reg
  UC_ARM64_REG_V28* = (UC_ARM64_REG_V27 + 1).uc_arm64_reg
  UC_ARM64_REG_V29* = (UC_ARM64_REG_V28 + 1).uc_arm64_reg
  UC_ARM64_REG_V30* = (UC_ARM64_REG_V29 + 1).uc_arm64_reg
  UC_ARM64_REG_V31* = (UC_ARM64_REG_V30 + 1).uc_arm64_reg
  UC_ARM64_REG_PC* = (UC_ARM64_REG_V31 + 1).uc_arm64_reg ## ```
                                                         ##   program counter register
                                                         ## ```
  UC_ARM64_REG_CPACR_EL1* = (UC_ARM64_REG_PC + 1).uc_arm64_reg
  UC_ARM64_REG_TPIDR_EL0* = (UC_ARM64_REG_CPACR_EL1 + 1).uc_arm64_reg ## ```
                                                                      ##   > thread registers, depreciated, use UC_ARM64_REG_CP_REG instead
                                                                      ## ```
  UC_ARM64_REG_TPIDRRO_EL0* = (UC_ARM64_REG_TPIDR_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_TPIDR_EL1* = (UC_ARM64_REG_TPIDRRO_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_PSTATE* = (UC_ARM64_REG_TPIDR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_ELR_EL0* = (UC_ARM64_REG_PSTATE + 1).uc_arm64_reg ## ```
                                                                 ##   > exception link registers, depreciated, use UC_ARM64_REG_CP_REG instead
                                                                 ## ```
  UC_ARM64_REG_ELR_EL1* = (UC_ARM64_REG_ELR_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_ELR_EL2* = (UC_ARM64_REG_ELR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_ELR_EL3* = (UC_ARM64_REG_ELR_EL2 + 1).uc_arm64_reg
  UC_ARM64_REG_SP_EL0* = (UC_ARM64_REG_ELR_EL3 + 1).uc_arm64_reg ## ```
                                                                 ##   > stack pointers registers, depreciated, use UC_ARM64_REG_CP_REG instead
                                                                 ## ```
  UC_ARM64_REG_SP_EL1* = (UC_ARM64_REG_SP_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_SP_EL2* = (UC_ARM64_REG_SP_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_SP_EL3* = (UC_ARM64_REG_SP_EL2 + 1).uc_arm64_reg
  UC_ARM64_REG_TTBR0_EL1* = (UC_ARM64_REG_SP_EL3 + 1).uc_arm64_reg ## ```
                                                                   ##   > other CP15 registers, depreciated, use UC_ARM64_REG_CP_REG instead
                                                                   ## ```
  UC_ARM64_REG_TTBR1_EL1* = (UC_ARM64_REG_TTBR0_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_ESR_EL0* = (UC_ARM64_REG_TTBR1_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_ESR_EL1* = (UC_ARM64_REG_ESR_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_ESR_EL2* = (UC_ARM64_REG_ESR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_ESR_EL3* = (UC_ARM64_REG_ESR_EL2 + 1).uc_arm64_reg
  UC_ARM64_REG_FAR_EL0* = (UC_ARM64_REG_ESR_EL3 + 1).uc_arm64_reg
  UC_ARM64_REG_FAR_EL1* = (UC_ARM64_REG_FAR_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_FAR_EL2* = (UC_ARM64_REG_FAR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_FAR_EL3* = (UC_ARM64_REG_FAR_EL2 + 1).uc_arm64_reg
  UC_ARM64_REG_PAR_EL1* = (UC_ARM64_REG_FAR_EL3 + 1).uc_arm64_reg
  UC_ARM64_REG_MAIR_EL1* = (UC_ARM64_REG_PAR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_VBAR_EL0* = (UC_ARM64_REG_MAIR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_VBAR_EL1* = (UC_ARM64_REG_VBAR_EL0 + 1).uc_arm64_reg
  UC_ARM64_REG_VBAR_EL2* = (UC_ARM64_REG_VBAR_EL1 + 1).uc_arm64_reg
  UC_ARM64_REG_VBAR_EL3* = (UC_ARM64_REG_VBAR_EL2 + 1).uc_arm64_reg
  UC_ARM64_REG_CP_REG* = (UC_ARM64_REG_VBAR_EL3 + 1).uc_arm64_reg
  UC_ARM64_REG_FPCR* = (UC_ARM64_REG_CP_REG + 1).uc_arm64_reg ## ```
                                                              ##   > floating point control and status registers
                                                              ## ```
  UC_ARM64_REG_FPSR* = (UC_ARM64_REG_FPCR + 1).uc_arm64_reg
  UC_ARM64_REG_ENDING* = (UC_ARM64_REG_FPSR + 1).uc_arm64_reg ## ```
                                                              ##   <-- mark the end of the list of registers
                                                              ##     > alias registers
                                                              ## ```
  UC_ARM64_REG_IP0* = (UC_ARM64_REG_X16).uc_arm64_reg
  UC_ARM64_REG_IP1* = (UC_ARM64_REG_X17).uc_arm64_reg
  UC_ARM64_REG_FP* = (UC_ARM64_REG_X29).uc_arm64_reg
  UC_ARM64_REG_LR* = (UC_ARM64_REG_X30).uc_arm64_reg
  UC_ARM64_INS_INVALID* = (0).uc_arm64_insn
  UC_ARM64_INS_MRS* = (UC_ARM64_INS_INVALID + 1).uc_arm64_insn
  UC_ARM64_INS_MSR* = (UC_ARM64_INS_MRS + 1).uc_arm64_insn
  UC_ARM64_INS_SYS* = (UC_ARM64_INS_MSR + 1).uc_arm64_insn
  UC_ARM64_INS_SYSL* = (UC_ARM64_INS_SYS + 1).uc_arm64_insn
  UC_ARM64_INS_ENDING* = (UC_ARM64_INS_SYSL + 1).uc_arm64_insn
  UC_CPU_MIPS32_4KC* = (0).uc_cpu_mips32
  UC_CPU_MIPS32_4KM* = (UC_CPU_MIPS32_4KC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_4KECR1* = (UC_CPU_MIPS32_4KM + 1).uc_cpu_mips32
  UC_CPU_MIPS32_4KEMR1* = (UC_CPU_MIPS32_4KECR1 + 1).uc_cpu_mips32
  UC_CPU_MIPS32_4KEC* = (UC_CPU_MIPS32_4KEMR1 + 1).uc_cpu_mips32
  UC_CPU_MIPS32_4KEM* = (UC_CPU_MIPS32_4KEC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_24KC* = (UC_CPU_MIPS32_4KEM + 1).uc_cpu_mips32
  UC_CPU_MIPS32_24KEC* = (UC_CPU_MIPS32_24KC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_24KF* = (UC_CPU_MIPS32_24KEC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_34KF* = (UC_CPU_MIPS32_24KF + 1).uc_cpu_mips32
  UC_CPU_MIPS32_74KF* = (UC_CPU_MIPS32_34KF + 1).uc_cpu_mips32
  UC_CPU_MIPS32_M14K* = (UC_CPU_MIPS32_74KF + 1).uc_cpu_mips32
  UC_CPU_MIPS32_M14KC* = (UC_CPU_MIPS32_M14K + 1).uc_cpu_mips32
  UC_CPU_MIPS32_P5600* = (UC_CPU_MIPS32_M14KC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_MIPS32R6_GENERIC* = (UC_CPU_MIPS32_P5600 + 1).uc_cpu_mips32
  UC_CPU_MIPS32_I7200* = (UC_CPU_MIPS32_MIPS32R6_GENERIC + 1).uc_cpu_mips32
  UC_CPU_MIPS32_ENDING* = (UC_CPU_MIPS32_I7200 + 1).uc_cpu_mips32
  UC_CPU_MIPS64_R4000* = (0).uc_cpu_mips64
  UC_CPU_MIPS64_VR5432* = (UC_CPU_MIPS64_R4000 + 1).uc_cpu_mips64
  UC_CPU_MIPS64_5KC* = (UC_CPU_MIPS64_VR5432 + 1).uc_cpu_mips64
  UC_CPU_MIPS64_5KF* = (UC_CPU_MIPS64_5KC + 1).uc_cpu_mips64
  UC_CPU_MIPS64_20KC* = (UC_CPU_MIPS64_5KF + 1).uc_cpu_mips64
  UC_CPU_MIPS64_MIPS64R2_GENERIC* = (UC_CPU_MIPS64_20KC + 1).uc_cpu_mips64
  UC_CPU_MIPS64_5KEC* = (UC_CPU_MIPS64_MIPS64R2_GENERIC + 1).uc_cpu_mips64
  UC_CPU_MIPS64_5KEF* = (UC_CPU_MIPS64_5KEC + 1).uc_cpu_mips64
  UC_CPU_MIPS64_I6400* = (UC_CPU_MIPS64_5KEF + 1).uc_cpu_mips64
  UC_CPU_MIPS64_I6500* = (UC_CPU_MIPS64_I6400 + 1).uc_cpu_mips64
  UC_CPU_MIPS64_LOONGSON_2E* = (UC_CPU_MIPS64_I6500 + 1).uc_cpu_mips64
  UC_CPU_MIPS64_LOONGSON_2F* = (UC_CPU_MIPS64_LOONGSON_2E + 1).uc_cpu_mips64
  UC_CPU_MIPS64_MIPS64DSPR2* = (UC_CPU_MIPS64_LOONGSON_2F + 1).uc_cpu_mips64
  UC_CPU_MIPS64_ENDING* = (UC_CPU_MIPS64_MIPS64DSPR2 + 1).uc_cpu_mips64
  UC_MIPS_REG_INVALID* = (0).UC_MIPS_REG ## ```
                                         ##   > General purpose registers
                                         ## ```
  UC_MIPS_REG_PC* = (UC_MIPS_REG_INVALID + 1).UC_MIPS_REG ## ```
                                                          ##   > General purpose registers
                                                          ## ```
  UC_MIPS_REG_0* = (UC_MIPS_REG_PC + 1).UC_MIPS_REG
  UC_MIPS_REG_1* = (UC_MIPS_REG_0 + 1).UC_MIPS_REG
  UC_MIPS_REG_2* = (UC_MIPS_REG_1 + 1).UC_MIPS_REG
  UC_MIPS_REG_3* = (UC_MIPS_REG_2 + 1).UC_MIPS_REG
  UC_MIPS_REG_4* = (UC_MIPS_REG_3 + 1).UC_MIPS_REG
  UC_MIPS_REG_5* = (UC_MIPS_REG_4 + 1).UC_MIPS_REG
  UC_MIPS_REG_6* = (UC_MIPS_REG_5 + 1).UC_MIPS_REG
  UC_MIPS_REG_7* = (UC_MIPS_REG_6 + 1).UC_MIPS_REG
  UC_MIPS_REG_8* = (UC_MIPS_REG_7 + 1).UC_MIPS_REG
  UC_MIPS_REG_9* = (UC_MIPS_REG_8 + 1).UC_MIPS_REG
  UC_MIPS_REG_10* = (UC_MIPS_REG_9 + 1).UC_MIPS_REG
  UC_MIPS_REG_11* = (UC_MIPS_REG_10 + 1).UC_MIPS_REG
  UC_MIPS_REG_12* = (UC_MIPS_REG_11 + 1).UC_MIPS_REG
  UC_MIPS_REG_13* = (UC_MIPS_REG_12 + 1).UC_MIPS_REG
  UC_MIPS_REG_14* = (UC_MIPS_REG_13 + 1).UC_MIPS_REG
  UC_MIPS_REG_15* = (UC_MIPS_REG_14 + 1).UC_MIPS_REG
  UC_MIPS_REG_16* = (UC_MIPS_REG_15 + 1).UC_MIPS_REG
  UC_MIPS_REG_17* = (UC_MIPS_REG_16 + 1).UC_MIPS_REG
  UC_MIPS_REG_18* = (UC_MIPS_REG_17 + 1).UC_MIPS_REG
  UC_MIPS_REG_19* = (UC_MIPS_REG_18 + 1).UC_MIPS_REG
  UC_MIPS_REG_20* = (UC_MIPS_REG_19 + 1).UC_MIPS_REG
  UC_MIPS_REG_21* = (UC_MIPS_REG_20 + 1).UC_MIPS_REG
  UC_MIPS_REG_22* = (UC_MIPS_REG_21 + 1).UC_MIPS_REG
  UC_MIPS_REG_23* = (UC_MIPS_REG_22 + 1).UC_MIPS_REG
  UC_MIPS_REG_24* = (UC_MIPS_REG_23 + 1).UC_MIPS_REG
  UC_MIPS_REG_25* = (UC_MIPS_REG_24 + 1).UC_MIPS_REG
  UC_MIPS_REG_26* = (UC_MIPS_REG_25 + 1).UC_MIPS_REG
  UC_MIPS_REG_27* = (UC_MIPS_REG_26 + 1).UC_MIPS_REG
  UC_MIPS_REG_28* = (UC_MIPS_REG_27 + 1).UC_MIPS_REG
  UC_MIPS_REG_29* = (UC_MIPS_REG_28 + 1).UC_MIPS_REG
  UC_MIPS_REG_30* = (UC_MIPS_REG_29 + 1).UC_MIPS_REG
  UC_MIPS_REG_31* = (UC_MIPS_REG_30 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPCCOND* = (UC_MIPS_REG_31 + 1).UC_MIPS_REG ## ```
                                                           ##   > DSP registers
                                                           ## ```
  UC_MIPS_REG_DSPCARRY* = (UC_MIPS_REG_DSPCCOND + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPEFI* = (UC_MIPS_REG_DSPCARRY + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG* = (UC_MIPS_REG_DSPEFI + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG16_19* = (UC_MIPS_REG_DSPOUTFLAG + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG20* = (UC_MIPS_REG_DSPOUTFLAG16_19 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG21* = (UC_MIPS_REG_DSPOUTFLAG20 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG22* = (UC_MIPS_REG_DSPOUTFLAG21 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPOUTFLAG23* = (UC_MIPS_REG_DSPOUTFLAG22 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPPOS* = (UC_MIPS_REG_DSPOUTFLAG23 + 1).UC_MIPS_REG
  UC_MIPS_REG_DSPSCOUNT* = (UC_MIPS_REG_DSPPOS + 1).UC_MIPS_REG
  UC_MIPS_REG_AC0* = (UC_MIPS_REG_DSPSCOUNT + 1).UC_MIPS_REG ## ```
                                                             ##   > ACC registers
                                                             ## ```
  UC_MIPS_REG_AC1* = (UC_MIPS_REG_AC0 + 1).UC_MIPS_REG
  UC_MIPS_REG_AC2* = (UC_MIPS_REG_AC1 + 1).UC_MIPS_REG
  UC_MIPS_REG_AC3* = (UC_MIPS_REG_AC2 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC0* = (UC_MIPS_REG_AC3 + 1).UC_MIPS_REG ## ```
                                                       ##   > COP registers
                                                       ## ```
  UC_MIPS_REG_CC1* = (UC_MIPS_REG_CC0 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC2* = (UC_MIPS_REG_CC1 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC3* = (UC_MIPS_REG_CC2 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC4* = (UC_MIPS_REG_CC3 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC5* = (UC_MIPS_REG_CC4 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC6* = (UC_MIPS_REG_CC5 + 1).UC_MIPS_REG
  UC_MIPS_REG_CC7* = (UC_MIPS_REG_CC6 + 1).UC_MIPS_REG
  UC_MIPS_REG_F0* = (UC_MIPS_REG_CC7 + 1).UC_MIPS_REG ## ```
                                                      ##   > FPU registers
                                                      ## ```
  UC_MIPS_REG_F1* = (UC_MIPS_REG_F0 + 1).UC_MIPS_REG
  UC_MIPS_REG_F2* = (UC_MIPS_REG_F1 + 1).UC_MIPS_REG
  UC_MIPS_REG_F3* = (UC_MIPS_REG_F2 + 1).UC_MIPS_REG
  UC_MIPS_REG_F4* = (UC_MIPS_REG_F3 + 1).UC_MIPS_REG
  UC_MIPS_REG_F5* = (UC_MIPS_REG_F4 + 1).UC_MIPS_REG
  UC_MIPS_REG_F6* = (UC_MIPS_REG_F5 + 1).UC_MIPS_REG
  UC_MIPS_REG_F7* = (UC_MIPS_REG_F6 + 1).UC_MIPS_REG
  UC_MIPS_REG_F8* = (UC_MIPS_REG_F7 + 1).UC_MIPS_REG
  UC_MIPS_REG_F9* = (UC_MIPS_REG_F8 + 1).UC_MIPS_REG
  UC_MIPS_REG_F10* = (UC_MIPS_REG_F9 + 1).UC_MIPS_REG
  UC_MIPS_REG_F11* = (UC_MIPS_REG_F10 + 1).UC_MIPS_REG
  UC_MIPS_REG_F12* = (UC_MIPS_REG_F11 + 1).UC_MIPS_REG
  UC_MIPS_REG_F13* = (UC_MIPS_REG_F12 + 1).UC_MIPS_REG
  UC_MIPS_REG_F14* = (UC_MIPS_REG_F13 + 1).UC_MIPS_REG
  UC_MIPS_REG_F15* = (UC_MIPS_REG_F14 + 1).UC_MIPS_REG
  UC_MIPS_REG_F16* = (UC_MIPS_REG_F15 + 1).UC_MIPS_REG
  UC_MIPS_REG_F17* = (UC_MIPS_REG_F16 + 1).UC_MIPS_REG
  UC_MIPS_REG_F18* = (UC_MIPS_REG_F17 + 1).UC_MIPS_REG
  UC_MIPS_REG_F19* = (UC_MIPS_REG_F18 + 1).UC_MIPS_REG
  UC_MIPS_REG_F20* = (UC_MIPS_REG_F19 + 1).UC_MIPS_REG
  UC_MIPS_REG_F21* = (UC_MIPS_REG_F20 + 1).UC_MIPS_REG
  UC_MIPS_REG_F22* = (UC_MIPS_REG_F21 + 1).UC_MIPS_REG
  UC_MIPS_REG_F23* = (UC_MIPS_REG_F22 + 1).UC_MIPS_REG
  UC_MIPS_REG_F24* = (UC_MIPS_REG_F23 + 1).UC_MIPS_REG
  UC_MIPS_REG_F25* = (UC_MIPS_REG_F24 + 1).UC_MIPS_REG
  UC_MIPS_REG_F26* = (UC_MIPS_REG_F25 + 1).UC_MIPS_REG
  UC_MIPS_REG_F27* = (UC_MIPS_REG_F26 + 1).UC_MIPS_REG
  UC_MIPS_REG_F28* = (UC_MIPS_REG_F27 + 1).UC_MIPS_REG
  UC_MIPS_REG_F29* = (UC_MIPS_REG_F28 + 1).UC_MIPS_REG
  UC_MIPS_REG_F30* = (UC_MIPS_REG_F29 + 1).UC_MIPS_REG
  UC_MIPS_REG_F31* = (UC_MIPS_REG_F30 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC0* = (UC_MIPS_REG_F31 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC1* = (UC_MIPS_REG_FCC0 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC2* = (UC_MIPS_REG_FCC1 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC3* = (UC_MIPS_REG_FCC2 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC4* = (UC_MIPS_REG_FCC3 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC5* = (UC_MIPS_REG_FCC4 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC6* = (UC_MIPS_REG_FCC5 + 1).UC_MIPS_REG
  UC_MIPS_REG_FCC7* = (UC_MIPS_REG_FCC6 + 1).UC_MIPS_REG
  UC_MIPS_REG_W0* = (UC_MIPS_REG_FCC7 + 1).UC_MIPS_REG ## ```
                                                       ##   > AFPR128
                                                       ## ```
  UC_MIPS_REG_W1* = (UC_MIPS_REG_W0 + 1).UC_MIPS_REG
  UC_MIPS_REG_W2* = (UC_MIPS_REG_W1 + 1).UC_MIPS_REG
  UC_MIPS_REG_W3* = (UC_MIPS_REG_W2 + 1).UC_MIPS_REG
  UC_MIPS_REG_W4* = (UC_MIPS_REG_W3 + 1).UC_MIPS_REG
  UC_MIPS_REG_W5* = (UC_MIPS_REG_W4 + 1).UC_MIPS_REG
  UC_MIPS_REG_W6* = (UC_MIPS_REG_W5 + 1).UC_MIPS_REG
  UC_MIPS_REG_W7* = (UC_MIPS_REG_W6 + 1).UC_MIPS_REG
  UC_MIPS_REG_W8* = (UC_MIPS_REG_W7 + 1).UC_MIPS_REG
  UC_MIPS_REG_W9* = (UC_MIPS_REG_W8 + 1).UC_MIPS_REG
  UC_MIPS_REG_W10* = (UC_MIPS_REG_W9 + 1).UC_MIPS_REG
  UC_MIPS_REG_W11* = (UC_MIPS_REG_W10 + 1).UC_MIPS_REG
  UC_MIPS_REG_W12* = (UC_MIPS_REG_W11 + 1).UC_MIPS_REG
  UC_MIPS_REG_W13* = (UC_MIPS_REG_W12 + 1).UC_MIPS_REG
  UC_MIPS_REG_W14* = (UC_MIPS_REG_W13 + 1).UC_MIPS_REG
  UC_MIPS_REG_W15* = (UC_MIPS_REG_W14 + 1).UC_MIPS_REG
  UC_MIPS_REG_W16* = (UC_MIPS_REG_W15 + 1).UC_MIPS_REG
  UC_MIPS_REG_W17* = (UC_MIPS_REG_W16 + 1).UC_MIPS_REG
  UC_MIPS_REG_W18* = (UC_MIPS_REG_W17 + 1).UC_MIPS_REG
  UC_MIPS_REG_W19* = (UC_MIPS_REG_W18 + 1).UC_MIPS_REG
  UC_MIPS_REG_W20* = (UC_MIPS_REG_W19 + 1).UC_MIPS_REG
  UC_MIPS_REG_W21* = (UC_MIPS_REG_W20 + 1).UC_MIPS_REG
  UC_MIPS_REG_W22* = (UC_MIPS_REG_W21 + 1).UC_MIPS_REG
  UC_MIPS_REG_W23* = (UC_MIPS_REG_W22 + 1).UC_MIPS_REG
  UC_MIPS_REG_W24* = (UC_MIPS_REG_W23 + 1).UC_MIPS_REG
  UC_MIPS_REG_W25* = (UC_MIPS_REG_W24 + 1).UC_MIPS_REG
  UC_MIPS_REG_W26* = (UC_MIPS_REG_W25 + 1).UC_MIPS_REG
  UC_MIPS_REG_W27* = (UC_MIPS_REG_W26 + 1).UC_MIPS_REG
  UC_MIPS_REG_W28* = (UC_MIPS_REG_W27 + 1).UC_MIPS_REG
  UC_MIPS_REG_W29* = (UC_MIPS_REG_W28 + 1).UC_MIPS_REG
  UC_MIPS_REG_W30* = (UC_MIPS_REG_W29 + 1).UC_MIPS_REG
  UC_MIPS_REG_W31* = (UC_MIPS_REG_W30 + 1).UC_MIPS_REG
  UC_MIPS_REG_HI* = (UC_MIPS_REG_W31 + 1).UC_MIPS_REG
  UC_MIPS_REG_LO* = (UC_MIPS_REG_HI + 1).UC_MIPS_REG
  UC_MIPS_REG_P0* = (UC_MIPS_REG_LO + 1).UC_MIPS_REG
  UC_MIPS_REG_P1* = (UC_MIPS_REG_P0 + 1).UC_MIPS_REG
  UC_MIPS_REG_P2* = (UC_MIPS_REG_P1 + 1).UC_MIPS_REG
  UC_MIPS_REG_MPL0* = (UC_MIPS_REG_P2 + 1).UC_MIPS_REG
  UC_MIPS_REG_MPL1* = (UC_MIPS_REG_MPL0 + 1).UC_MIPS_REG
  UC_MIPS_REG_MPL2* = (UC_MIPS_REG_MPL1 + 1).UC_MIPS_REG
  UC_MIPS_REG_CP0_CONFIG3* = (UC_MIPS_REG_MPL2 + 1).UC_MIPS_REG
  UC_MIPS_REG_CP0_USERLOCAL* = (UC_MIPS_REG_CP0_CONFIG3 + 1).UC_MIPS_REG
  UC_MIPS_REG_CP0_STATUS* = (UC_MIPS_REG_CP0_USERLOCAL + 1).UC_MIPS_REG
  UC_MIPS_REG_ENDING* = (UC_MIPS_REG_CP0_STATUS + 1).UC_MIPS_REG ## ```
                                                                 ##   <-- mark the end of the list or registers
                                                                 ##      alias registers
                                                                 ## ```
  UC_MIPS_REG_ZERO* = (UC_MIPS_REG_0).UC_MIPS_REG ## ```
                                                  ##   <-- mark the end of the list or registers
                                                  ##      alias registers
                                                  ## ```
  UC_MIPS_REG_AT* = (UC_MIPS_REG_1).UC_MIPS_REG
  UC_MIPS_REG_V0* = (UC_MIPS_REG_2).UC_MIPS_REG
  UC_MIPS_REG_V1* = (UC_MIPS_REG_3).UC_MIPS_REG
  UC_MIPS_REG_A0* = (UC_MIPS_REG_4).UC_MIPS_REG
  UC_MIPS_REG_A1* = (UC_MIPS_REG_5).UC_MIPS_REG
  UC_MIPS_REG_A2* = (UC_MIPS_REG_6).UC_MIPS_REG
  UC_MIPS_REG_A3* = (UC_MIPS_REG_7).UC_MIPS_REG
  UC_MIPS_REG_T0* = (UC_MIPS_REG_8).UC_MIPS_REG
  UC_MIPS_REG_T1* = (UC_MIPS_REG_9).UC_MIPS_REG
  UC_MIPS_REG_T2* = (UC_MIPS_REG_10).UC_MIPS_REG
  UC_MIPS_REG_T3* = (UC_MIPS_REG_11).UC_MIPS_REG
  UC_MIPS_REG_T4* = (UC_MIPS_REG_12).UC_MIPS_REG
  UC_MIPS_REG_T5* = (UC_MIPS_REG_13).UC_MIPS_REG
  UC_MIPS_REG_T6* = (UC_MIPS_REG_14).UC_MIPS_REG
  UC_MIPS_REG_T7* = (UC_MIPS_REG_15).UC_MIPS_REG
  UC_MIPS_REG_S0* = (UC_MIPS_REG_16).UC_MIPS_REG
  UC_MIPS_REG_S1* = (UC_MIPS_REG_17).UC_MIPS_REG
  UC_MIPS_REG_S2* = (UC_MIPS_REG_18).UC_MIPS_REG
  UC_MIPS_REG_S3* = (UC_MIPS_REG_19).UC_MIPS_REG
  UC_MIPS_REG_S4* = (UC_MIPS_REG_20).UC_MIPS_REG
  UC_MIPS_REG_S5* = (UC_MIPS_REG_21).UC_MIPS_REG
  UC_MIPS_REG_S6* = (UC_MIPS_REG_22).UC_MIPS_REG
  UC_MIPS_REG_S7* = (UC_MIPS_REG_23).UC_MIPS_REG
  UC_MIPS_REG_T8* = (UC_MIPS_REG_24).UC_MIPS_REG
  UC_MIPS_REG_T9* = (UC_MIPS_REG_25).UC_MIPS_REG
  UC_MIPS_REG_K0* = (UC_MIPS_REG_26).UC_MIPS_REG
  UC_MIPS_REG_K1* = (UC_MIPS_REG_27).UC_MIPS_REG
  UC_MIPS_REG_GP* = (UC_MIPS_REG_28).UC_MIPS_REG
  UC_MIPS_REG_SP* = (UC_MIPS_REG_29).UC_MIPS_REG
  UC_MIPS_REG_FP* = (UC_MIPS_REG_30).UC_MIPS_REG
  UC_MIPS_REG_S8* = (UC_MIPS_REG_30).UC_MIPS_REG
  UC_MIPS_REG_RA* = (UC_MIPS_REG_31).UC_MIPS_REG
  UC_MIPS_REG_HI0* = (UC_MIPS_REG_AC0).UC_MIPS_REG
  UC_MIPS_REG_HI1* = (UC_MIPS_REG_AC1).UC_MIPS_REG
  UC_MIPS_REG_HI2* = (UC_MIPS_REG_AC2).UC_MIPS_REG
  UC_MIPS_REG_HI3* = (UC_MIPS_REG_AC3).UC_MIPS_REG
  UC_MIPS_REG_LO0* = (UC_MIPS_REG_HI0).UC_MIPS_REG
  UC_MIPS_REG_LO1* = (UC_MIPS_REG_HI1).UC_MIPS_REG
  UC_MIPS_REG_LO2* = (UC_MIPS_REG_HI2).UC_MIPS_REG
  UC_MIPS_REG_LO3* = (UC_MIPS_REG_HI3).UC_MIPS_REG
  UC_CPU_SPARC32_FUJITSU_MB86904* = (0).uc_cpu_sparc32
  UC_CPU_SPARC32_FUJITSU_MB86907* = (UC_CPU_SPARC32_FUJITSU_MB86904 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_MICROSPARC_I* = (UC_CPU_SPARC32_FUJITSU_MB86907 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_MICROSPARC_II* = (UC_CPU_SPARC32_TI_MICROSPARC_I + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_MICROSPARC_IIEP* = (UC_CPU_SPARC32_TI_MICROSPARC_II + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_40* = (UC_CPU_SPARC32_TI_MICROSPARC_IIEP + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_50* = (UC_CPU_SPARC32_TI_SUPERSPARC_40 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_51* = (UC_CPU_SPARC32_TI_SUPERSPARC_50 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_60* = (UC_CPU_SPARC32_TI_SUPERSPARC_51 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_61* = (UC_CPU_SPARC32_TI_SUPERSPARC_60 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_TI_SUPERSPARC_II* = (UC_CPU_SPARC32_TI_SUPERSPARC_61 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_LEON2* = (UC_CPU_SPARC32_TI_SUPERSPARC_II + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_LEON3* = (UC_CPU_SPARC32_LEON2 + 1).uc_cpu_sparc32
  UC_CPU_SPARC32_ENDING* = (UC_CPU_SPARC32_LEON3 + 1).uc_cpu_sparc32
  UC_CPU_SPARC64_FUJITSU* = (0).uc_cpu_sparc64
  UC_CPU_SPARC64_FUJITSU_III* = (UC_CPU_SPARC64_FUJITSU + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_FUJITSU_IV* = (UC_CPU_SPARC64_FUJITSU_III + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_FUJITSU_V* = (UC_CPU_SPARC64_FUJITSU_IV + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_TI_ULTRASPARC_I* = (UC_CPU_SPARC64_FUJITSU_V + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_TI_ULTRASPARC_II* = (UC_CPU_SPARC64_TI_ULTRASPARC_I + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_TI_ULTRASPARC_III* = (UC_CPU_SPARC64_TI_ULTRASPARC_II + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_TI_ULTRASPARC_IIE* = (UC_CPU_SPARC64_TI_ULTRASPARC_III + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_III* = (UC_CPU_SPARC64_TI_ULTRASPARC_IIE + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_III_CU* = (UC_CPU_SPARC64_SUN_ULTRASPARC_III + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_IIII* = (
      UC_CPU_SPARC64_SUN_ULTRASPARC_III_CU + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_IV* = (UC_CPU_SPARC64_SUN_ULTRASPARC_IIII + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_IV_PLUS* = (UC_CPU_SPARC64_SUN_ULTRASPARC_IV + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_IIII_PLUS* = (
      UC_CPU_SPARC64_SUN_ULTRASPARC_IV_PLUS + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_T1* = (UC_CPU_SPARC64_SUN_ULTRASPARC_IIII_PLUS +
      1).uc_cpu_sparc64
  UC_CPU_SPARC64_SUN_ULTRASPARC_T2* = (UC_CPU_SPARC64_SUN_ULTRASPARC_T1 + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_NEC_ULTRASPARC_I* = (UC_CPU_SPARC64_SUN_ULTRASPARC_T2 + 1).uc_cpu_sparc64
  UC_CPU_SPARC64_ENDING* = (UC_CPU_SPARC64_NEC_ULTRASPARC_I + 1).uc_cpu_sparc64
  UC_SPARC_REG_INVALID* = (0).uc_sparc_reg
  UC_SPARC_REG_F0* = (UC_SPARC_REG_INVALID + 1).uc_sparc_reg
  UC_SPARC_REG_F1* = (UC_SPARC_REG_F0 + 1).uc_sparc_reg
  UC_SPARC_REG_F2* = (UC_SPARC_REG_F1 + 1).uc_sparc_reg
  UC_SPARC_REG_F3* = (UC_SPARC_REG_F2 + 1).uc_sparc_reg
  UC_SPARC_REG_F4* = (UC_SPARC_REG_F3 + 1).uc_sparc_reg
  UC_SPARC_REG_F5* = (UC_SPARC_REG_F4 + 1).uc_sparc_reg
  UC_SPARC_REG_F6* = (UC_SPARC_REG_F5 + 1).uc_sparc_reg
  UC_SPARC_REG_F7* = (UC_SPARC_REG_F6 + 1).uc_sparc_reg
  UC_SPARC_REG_F8* = (UC_SPARC_REG_F7 + 1).uc_sparc_reg
  UC_SPARC_REG_F9* = (UC_SPARC_REG_F8 + 1).uc_sparc_reg
  UC_SPARC_REG_F10* = (UC_SPARC_REG_F9 + 1).uc_sparc_reg
  UC_SPARC_REG_F11* = (UC_SPARC_REG_F10 + 1).uc_sparc_reg
  UC_SPARC_REG_F12* = (UC_SPARC_REG_F11 + 1).uc_sparc_reg
  UC_SPARC_REG_F13* = (UC_SPARC_REG_F12 + 1).uc_sparc_reg
  UC_SPARC_REG_F14* = (UC_SPARC_REG_F13 + 1).uc_sparc_reg
  UC_SPARC_REG_F15* = (UC_SPARC_REG_F14 + 1).uc_sparc_reg
  UC_SPARC_REG_F16* = (UC_SPARC_REG_F15 + 1).uc_sparc_reg
  UC_SPARC_REG_F17* = (UC_SPARC_REG_F16 + 1).uc_sparc_reg
  UC_SPARC_REG_F18* = (UC_SPARC_REG_F17 + 1).uc_sparc_reg
  UC_SPARC_REG_F19* = (UC_SPARC_REG_F18 + 1).uc_sparc_reg
  UC_SPARC_REG_F20* = (UC_SPARC_REG_F19 + 1).uc_sparc_reg
  UC_SPARC_REG_F21* = (UC_SPARC_REG_F20 + 1).uc_sparc_reg
  UC_SPARC_REG_F22* = (UC_SPARC_REG_F21 + 1).uc_sparc_reg
  UC_SPARC_REG_F23* = (UC_SPARC_REG_F22 + 1).uc_sparc_reg
  UC_SPARC_REG_F24* = (UC_SPARC_REG_F23 + 1).uc_sparc_reg
  UC_SPARC_REG_F25* = (UC_SPARC_REG_F24 + 1).uc_sparc_reg
  UC_SPARC_REG_F26* = (UC_SPARC_REG_F25 + 1).uc_sparc_reg
  UC_SPARC_REG_F27* = (UC_SPARC_REG_F26 + 1).uc_sparc_reg
  UC_SPARC_REG_F28* = (UC_SPARC_REG_F27 + 1).uc_sparc_reg
  UC_SPARC_REG_F29* = (UC_SPARC_REG_F28 + 1).uc_sparc_reg
  UC_SPARC_REG_F30* = (UC_SPARC_REG_F29 + 1).uc_sparc_reg
  UC_SPARC_REG_F31* = (UC_SPARC_REG_F30 + 1).uc_sparc_reg
  UC_SPARC_REG_F32* = (UC_SPARC_REG_F31 + 1).uc_sparc_reg
  UC_SPARC_REG_F34* = (UC_SPARC_REG_F32 + 1).uc_sparc_reg
  UC_SPARC_REG_F36* = (UC_SPARC_REG_F34 + 1).uc_sparc_reg
  UC_SPARC_REG_F38* = (UC_SPARC_REG_F36 + 1).uc_sparc_reg
  UC_SPARC_REG_F40* = (UC_SPARC_REG_F38 + 1).uc_sparc_reg
  UC_SPARC_REG_F42* = (UC_SPARC_REG_F40 + 1).uc_sparc_reg
  UC_SPARC_REG_F44* = (UC_SPARC_REG_F42 + 1).uc_sparc_reg
  UC_SPARC_REG_F46* = (UC_SPARC_REG_F44 + 1).uc_sparc_reg
  UC_SPARC_REG_F48* = (UC_SPARC_REG_F46 + 1).uc_sparc_reg
  UC_SPARC_REG_F50* = (UC_SPARC_REG_F48 + 1).uc_sparc_reg
  UC_SPARC_REG_F52* = (UC_SPARC_REG_F50 + 1).uc_sparc_reg
  UC_SPARC_REG_F54* = (UC_SPARC_REG_F52 + 1).uc_sparc_reg
  UC_SPARC_REG_F56* = (UC_SPARC_REG_F54 + 1).uc_sparc_reg
  UC_SPARC_REG_F58* = (UC_SPARC_REG_F56 + 1).uc_sparc_reg
  UC_SPARC_REG_F60* = (UC_SPARC_REG_F58 + 1).uc_sparc_reg
  UC_SPARC_REG_F62* = (UC_SPARC_REG_F60 + 1).uc_sparc_reg
  UC_SPARC_REG_FCC0* = (UC_SPARC_REG_F62 + 1).uc_sparc_reg ## ```
                                                           ##   Floating condition codes
                                                           ## ```
  UC_SPARC_REG_FCC1* = (UC_SPARC_REG_FCC0 + 1).uc_sparc_reg ## ```
                                                            ##   Floating condition codes
                                                            ## ```
  UC_SPARC_REG_FCC2* = (UC_SPARC_REG_FCC1 + 1).uc_sparc_reg
  UC_SPARC_REG_FCC3* = (UC_SPARC_REG_FCC2 + 1).uc_sparc_reg
  UC_SPARC_REG_G0* = (UC_SPARC_REG_FCC3 + 1).uc_sparc_reg
  UC_SPARC_REG_G1* = (UC_SPARC_REG_G0 + 1).uc_sparc_reg
  UC_SPARC_REG_G2* = (UC_SPARC_REG_G1 + 1).uc_sparc_reg
  UC_SPARC_REG_G3* = (UC_SPARC_REG_G2 + 1).uc_sparc_reg
  UC_SPARC_REG_G4* = (UC_SPARC_REG_G3 + 1).uc_sparc_reg
  UC_SPARC_REG_G5* = (UC_SPARC_REG_G4 + 1).uc_sparc_reg
  UC_SPARC_REG_G6* = (UC_SPARC_REG_G5 + 1).uc_sparc_reg
  UC_SPARC_REG_G7* = (UC_SPARC_REG_G6 + 1).uc_sparc_reg
  UC_SPARC_REG_I0* = (UC_SPARC_REG_G7 + 1).uc_sparc_reg
  UC_SPARC_REG_I1* = (UC_SPARC_REG_I0 + 1).uc_sparc_reg
  UC_SPARC_REG_I2* = (UC_SPARC_REG_I1 + 1).uc_sparc_reg
  UC_SPARC_REG_I3* = (UC_SPARC_REG_I2 + 1).uc_sparc_reg
  UC_SPARC_REG_I4* = (UC_SPARC_REG_I3 + 1).uc_sparc_reg
  UC_SPARC_REG_I5* = (UC_SPARC_REG_I4 + 1).uc_sparc_reg
  UC_SPARC_REG_FP* = (UC_SPARC_REG_I5 + 1).uc_sparc_reg
  UC_SPARC_REG_I7* = (UC_SPARC_REG_FP + 1).uc_sparc_reg
  UC_SPARC_REG_ICC* = (UC_SPARC_REG_I7 + 1).uc_sparc_reg ## ```
                                                         ##   Integer condition codes
                                                         ## ```
  UC_SPARC_REG_L0* = (UC_SPARC_REG_ICC + 1).uc_sparc_reg ## ```
                                                         ##   Integer condition codes
                                                         ## ```
  UC_SPARC_REG_L1* = (UC_SPARC_REG_L0 + 1).uc_sparc_reg
  UC_SPARC_REG_L2* = (UC_SPARC_REG_L1 + 1).uc_sparc_reg
  UC_SPARC_REG_L3* = (UC_SPARC_REG_L2 + 1).uc_sparc_reg
  UC_SPARC_REG_L4* = (UC_SPARC_REG_L3 + 1).uc_sparc_reg
  UC_SPARC_REG_L5* = (UC_SPARC_REG_L4 + 1).uc_sparc_reg
  UC_SPARC_REG_L6* = (UC_SPARC_REG_L5 + 1).uc_sparc_reg
  UC_SPARC_REG_L7* = (UC_SPARC_REG_L6 + 1).uc_sparc_reg
  UC_SPARC_REG_O0* = (UC_SPARC_REG_L7 + 1).uc_sparc_reg
  UC_SPARC_REG_O1* = (UC_SPARC_REG_O0 + 1).uc_sparc_reg
  UC_SPARC_REG_O2* = (UC_SPARC_REG_O1 + 1).uc_sparc_reg
  UC_SPARC_REG_O3* = (UC_SPARC_REG_O2 + 1).uc_sparc_reg
  UC_SPARC_REG_O4* = (UC_SPARC_REG_O3 + 1).uc_sparc_reg
  UC_SPARC_REG_O5* = (UC_SPARC_REG_O4 + 1).uc_sparc_reg
  UC_SPARC_REG_SP* = (UC_SPARC_REG_O5 + 1).uc_sparc_reg
  UC_SPARC_REG_O7* = (UC_SPARC_REG_SP + 1).uc_sparc_reg
  UC_SPARC_REG_Y* = (UC_SPARC_REG_O7 + 1).uc_sparc_reg
  UC_SPARC_REG_XCC* = (UC_SPARC_REG_Y + 1).uc_sparc_reg ## ```
                                                        ##   special register
                                                        ## ```
  UC_SPARC_REG_PC* = (UC_SPARC_REG_XCC + 1).uc_sparc_reg ## ```
                                                         ##   program counter register
                                                         ## ```
  UC_SPARC_REG_ENDING* = (UC_SPARC_REG_PC + 1).uc_sparc_reg ## ```
                                                            ##   <-- mark the end of the list of registers
                                                            ##      extras
                                                            ## ```
  UC_SPARC_REG_O6* = (UC_SPARC_REG_SP).uc_sparc_reg ## ```
                                                    ##   <-- mark the end of the list of registers
                                                    ##      extras
                                                    ## ```
  UC_SPARC_REG_I6* = (UC_SPARC_REG_FP).uc_sparc_reg
  UC_CPU_PPC32_401* = (0).uc_cpu_ppc
  UC_CPU_PPC32_401A1* = (UC_CPU_PPC32_401 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401B2* = (UC_CPU_PPC32_401A1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401C2* = (UC_CPU_PPC32_401B2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401D2* = (UC_CPU_PPC32_401C2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401E2* = (UC_CPU_PPC32_401D2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401F2* = (UC_CPU_PPC32_401E2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_401G2* = (UC_CPU_PPC32_401F2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_IOP480* = (UC_CPU_PPC32_401G2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_COBRA* = (UC_CPU_PPC32_IOP480 + 1).uc_cpu_ppc
  UC_CPU_PPC32_403GA* = (UC_CPU_PPC32_COBRA + 1).uc_cpu_ppc
  UC_CPU_PPC32_403GB* = (UC_CPU_PPC32_403GA + 1).uc_cpu_ppc
  UC_CPU_PPC32_403GC* = (UC_CPU_PPC32_403GB + 1).uc_cpu_ppc
  UC_CPU_PPC32_403GCX* = (UC_CPU_PPC32_403GC + 1).uc_cpu_ppc
  UC_CPU_PPC32_405D2* = (UC_CPU_PPC32_403GCX + 1).uc_cpu_ppc
  UC_CPU_PPC32_405D4* = (UC_CPU_PPC32_405D2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_405CRA* = (UC_CPU_PPC32_405D4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_405CRB* = (UC_CPU_PPC32_405CRA + 1).uc_cpu_ppc
  UC_CPU_PPC32_405CRC* = (UC_CPU_PPC32_405CRB + 1).uc_cpu_ppc
  UC_CPU_PPC32_405EP* = (UC_CPU_PPC32_405CRC + 1).uc_cpu_ppc
  UC_CPU_PPC32_405EZ* = (UC_CPU_PPC32_405EP + 1).uc_cpu_ppc
  UC_CPU_PPC32_405GPA* = (UC_CPU_PPC32_405EZ + 1).uc_cpu_ppc
  UC_CPU_PPC32_405GPB* = (UC_CPU_PPC32_405GPA + 1).uc_cpu_ppc
  UC_CPU_PPC32_405GPC* = (UC_CPU_PPC32_405GPB + 1).uc_cpu_ppc
  UC_CPU_PPC32_405GPD* = (UC_CPU_PPC32_405GPC + 1).uc_cpu_ppc
  UC_CPU_PPC32_405GPR* = (UC_CPU_PPC32_405GPD + 1).uc_cpu_ppc
  UC_CPU_PPC32_405LP* = (UC_CPU_PPC32_405GPR + 1).uc_cpu_ppc
  UC_CPU_PPC32_NPE405H* = (UC_CPU_PPC32_405LP + 1).uc_cpu_ppc
  UC_CPU_PPC32_NPE405H2* = (UC_CPU_PPC32_NPE405H + 1).uc_cpu_ppc
  UC_CPU_PPC32_NPE405L* = (UC_CPU_PPC32_NPE405H2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_NPE4GS3* = (UC_CPU_PPC32_NPE405L + 1).uc_cpu_ppc
  UC_CPU_PPC32_STB03* = (UC_CPU_PPC32_NPE4GS3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_STB04* = (UC_CPU_PPC32_STB03 + 1).uc_cpu_ppc
  UC_CPU_PPC32_STB25* = (UC_CPU_PPC32_STB04 + 1).uc_cpu_ppc
  UC_CPU_PPC32_X2VP4* = (UC_CPU_PPC32_STB25 + 1).uc_cpu_ppc
  UC_CPU_PPC32_X2VP20* = (UC_CPU_PPC32_X2VP4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_440_XILINX* = (UC_CPU_PPC32_X2VP20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_440_XILINX_W_DFPU* = (UC_CPU_PPC32_440_XILINX + 1).uc_cpu_ppc
  UC_CPU_PPC32_440EPA* = (UC_CPU_PPC32_440_XILINX_W_DFPU + 1).uc_cpu_ppc
  UC_CPU_PPC32_440EPB* = (UC_CPU_PPC32_440EPA + 1).uc_cpu_ppc
  UC_CPU_PPC32_440EPX* = (UC_CPU_PPC32_440EPB + 1).uc_cpu_ppc
  UC_CPU_PPC32_460EXB* = (UC_CPU_PPC32_440EPX + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2* = (UC_CPU_PPC32_460EXB + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2H4* = (UC_CPU_PPC32_G2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2GP* = (UC_CPU_PPC32_G2H4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LS* = (UC_CPU_PPC32_G2GP + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2HIP3* = (UC_CPU_PPC32_G2LS + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2HIP4* = (UC_CPU_PPC32_G2HIP3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC603* = (UC_CPU_PPC32_G2HIP4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LE* = (UC_CPU_PPC32_MPC603 + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LEGP* = (UC_CPU_PPC32_G2LE + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LELS* = (UC_CPU_PPC32_G2LEGP + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LEGP1* = (UC_CPU_PPC32_G2LELS + 1).uc_cpu_ppc
  UC_CPU_PPC32_G2LEGP3* = (UC_CPU_PPC32_G2LEGP1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC5200_V10* = (UC_CPU_PPC32_G2LEGP3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC5200_V11* = (UC_CPU_PPC32_MPC5200_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC5200_V12* = (UC_CPU_PPC32_MPC5200_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC5200B_V20* = (UC_CPU_PPC32_MPC5200_V12 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC5200B_V21* = (UC_CPU_PPC32_MPC5200B_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E200Z5* = (UC_CPU_PPC32_MPC5200B_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E200Z6* = (UC_CPU_PPC32_E200Z5 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E300C1* = (UC_CPU_PPC32_E200Z6 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E300C2* = (UC_CPU_PPC32_E300C1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E300C3* = (UC_CPU_PPC32_E300C2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E300C4* = (UC_CPU_PPC32_E300C3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8343* = (UC_CPU_PPC32_E300C4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8343A* = (UC_CPU_PPC32_MPC8343 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8343E* = (UC_CPU_PPC32_MPC8343A + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8343EA* = (UC_CPU_PPC32_MPC8343E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347T* = (UC_CPU_PPC32_MPC8343EA + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347P* = (UC_CPU_PPC32_MPC8347T + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347AT* = (UC_CPU_PPC32_MPC8347P + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347AP* = (UC_CPU_PPC32_MPC8347AT + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347ET* = (UC_CPU_PPC32_MPC8347AP + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347EP* = (UC_CPU_PPC32_MPC8347ET + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347EAT* = (UC_CPU_PPC32_MPC8347EP + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8347EAP* = (UC_CPU_PPC32_MPC8347EAT + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8349* = (UC_CPU_PPC32_MPC8347EAP + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8349A* = (UC_CPU_PPC32_MPC8349 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8349E* = (UC_CPU_PPC32_MPC8349A + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8349EA* = (UC_CPU_PPC32_MPC8349E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8377* = (UC_CPU_PPC32_MPC8349EA + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8377E* = (UC_CPU_PPC32_MPC8377 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8378* = (UC_CPU_PPC32_MPC8377E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8378E* = (UC_CPU_PPC32_MPC8378 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8379* = (UC_CPU_PPC32_MPC8378E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8379E* = (UC_CPU_PPC32_MPC8379 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500_V10* = (UC_CPU_PPC32_MPC8379E + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500_V20* = (UC_CPU_PPC32_E500_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500V2_V10* = (UC_CPU_PPC32_E500_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500V2_V20* = (UC_CPU_PPC32_E500V2_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500V2_V21* = (UC_CPU_PPC32_E500V2_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500V2_V22* = (UC_CPU_PPC32_E500V2_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500V2_V30* = (UC_CPU_PPC32_E500V2_V22 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E500MC* = (UC_CPU_PPC32_E500V2_V30 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8533_V10* = (UC_CPU_PPC32_E500MC + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8533_V11* = (UC_CPU_PPC32_MPC8533_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8533E_V10* = (UC_CPU_PPC32_MPC8533_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8533E_V11* = (UC_CPU_PPC32_MPC8533E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8540_V10* = (UC_CPU_PPC32_MPC8533E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8540_V20* = (UC_CPU_PPC32_MPC8540_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8540_V21* = (UC_CPU_PPC32_MPC8540_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8541_V10* = (UC_CPU_PPC32_MPC8540_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8541_V11* = (UC_CPU_PPC32_MPC8541_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8541E_V10* = (UC_CPU_PPC32_MPC8541_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8541E_V11* = (UC_CPU_PPC32_MPC8541E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543_V10* = (UC_CPU_PPC32_MPC8541E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543_V11* = (UC_CPU_PPC32_MPC8543_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543_V20* = (UC_CPU_PPC32_MPC8543_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543_V21* = (UC_CPU_PPC32_MPC8543_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543E_V10* = (UC_CPU_PPC32_MPC8543_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543E_V11* = (UC_CPU_PPC32_MPC8543E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543E_V20* = (UC_CPU_PPC32_MPC8543E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8543E_V21* = (UC_CPU_PPC32_MPC8543E_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8544_V10* = (UC_CPU_PPC32_MPC8543E_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8544_V11* = (UC_CPU_PPC32_MPC8544_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8544E_V10* = (UC_CPU_PPC32_MPC8544_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8544E_V11* = (UC_CPU_PPC32_MPC8544E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8545_V20* = (UC_CPU_PPC32_MPC8544E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8545_V21* = (UC_CPU_PPC32_MPC8545_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8545E_V20* = (UC_CPU_PPC32_MPC8545_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8545E_V21* = (UC_CPU_PPC32_MPC8545E_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8547E_V20* = (UC_CPU_PPC32_MPC8545E_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8547E_V21* = (UC_CPU_PPC32_MPC8547E_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548_V10* = (UC_CPU_PPC32_MPC8547E_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548_V11* = (UC_CPU_PPC32_MPC8548_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548_V20* = (UC_CPU_PPC32_MPC8548_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548_V21* = (UC_CPU_PPC32_MPC8548_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548E_V10* = (UC_CPU_PPC32_MPC8548_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548E_V11* = (UC_CPU_PPC32_MPC8548E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548E_V20* = (UC_CPU_PPC32_MPC8548E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8548E_V21* = (UC_CPU_PPC32_MPC8548E_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8555_V10* = (UC_CPU_PPC32_MPC8548E_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8555_V11* = (UC_CPU_PPC32_MPC8555_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8555E_V10* = (UC_CPU_PPC32_MPC8555_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8555E_V11* = (UC_CPU_PPC32_MPC8555E_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8560_V10* = (UC_CPU_PPC32_MPC8555E_V11 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8560_V20* = (UC_CPU_PPC32_MPC8560_V10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8560_V21* = (UC_CPU_PPC32_MPC8560_V20 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8567* = (UC_CPU_PPC32_MPC8560_V21 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8567E* = (UC_CPU_PPC32_MPC8567 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8568* = (UC_CPU_PPC32_MPC8567E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8568E* = (UC_CPU_PPC32_MPC8568 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8572* = (UC_CPU_PPC32_MPC8568E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8572E* = (UC_CPU_PPC32_MPC8572 + 1).uc_cpu_ppc
  UC_CPU_PPC32_E600* = (UC_CPU_PPC32_MPC8572E + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8610* = (UC_CPU_PPC32_E600 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8641* = (UC_CPU_PPC32_MPC8610 + 1).uc_cpu_ppc
  UC_CPU_PPC32_MPC8641D* = (UC_CPU_PPC32_MPC8641 + 1).uc_cpu_ppc
  UC_CPU_PPC32_601_V0* = (UC_CPU_PPC32_MPC8641D + 1).uc_cpu_ppc
  UC_CPU_PPC32_601_V1* = (UC_CPU_PPC32_601_V0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_601_V2* = (UC_CPU_PPC32_601_V1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_602* = (UC_CPU_PPC32_601_V2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603* = (UC_CPU_PPC32_602 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V1_1* = (UC_CPU_PPC32_603 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V1_2* = (UC_CPU_PPC32_603E_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V1_3* = (UC_CPU_PPC32_603E_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V1_4* = (UC_CPU_PPC32_603E_V1_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V2_2* = (UC_CPU_PPC32_603E_V1_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V3* = (UC_CPU_PPC32_603E_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V4* = (UC_CPU_PPC32_603E_V3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E_V4_1* = (UC_CPU_PPC32_603E_V4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E7* = (UC_CPU_PPC32_603E_V4_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E7T* = (UC_CPU_PPC32_603E7 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E7V* = (UC_CPU_PPC32_603E7T + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E7V1* = (UC_CPU_PPC32_603E7V + 1).uc_cpu_ppc
  UC_CPU_PPC32_603E7V2* = (UC_CPU_PPC32_603E7V1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_603P* = (UC_CPU_PPC32_603E7V2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_604* = (UC_CPU_PPC32_603P + 1).uc_cpu_ppc
  UC_CPU_PPC32_604E_V1_0* = (UC_CPU_PPC32_604 + 1).uc_cpu_ppc
  UC_CPU_PPC32_604E_V2_2* = (UC_CPU_PPC32_604E_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_604E_V2_4* = (UC_CPU_PPC32_604E_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_604R* = (UC_CPU_PPC32_604E_V2_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V1_0* = (UC_CPU_PPC32_604R + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V1_0* = (UC_CPU_PPC32_740_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V2_0* = (UC_CPU_PPC32_750_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V2_0* = (UC_CPU_PPC32_740_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V2_1* = (UC_CPU_PPC32_750_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V2_1* = (UC_CPU_PPC32_740_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V2_2* = (UC_CPU_PPC32_750_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V2_2* = (UC_CPU_PPC32_740_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V3_0* = (UC_CPU_PPC32_750_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V3_0* = (UC_CPU_PPC32_740_V3_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740_V3_1* = (UC_CPU_PPC32_750_V3_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750_V3_1* = (UC_CPU_PPC32_740_V3_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_740E* = (UC_CPU_PPC32_750_V3_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750E* = (UC_CPU_PPC32_740E + 1).uc_cpu_ppc
  UC_CPU_PPC32_740P* = (UC_CPU_PPC32_750E + 1).uc_cpu_ppc
  UC_CPU_PPC32_750P* = (UC_CPU_PPC32_740P + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CL_V1_0* = (UC_CPU_PPC32_750P + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CL_V2_0* = (UC_CPU_PPC32_750CL_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CX_V1_0* = (UC_CPU_PPC32_750CL_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CX_V2_0* = (UC_CPU_PPC32_750CX_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CX_V2_1* = (UC_CPU_PPC32_750CX_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CX_V2_2* = (UC_CPU_PPC32_750CX_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V2_1* = (UC_CPU_PPC32_750CX_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V2_2* = (UC_CPU_PPC32_750CXE_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V2_3* = (UC_CPU_PPC32_750CXE_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V2_4* = (UC_CPU_PPC32_750CXE_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V2_4B* = (UC_CPU_PPC32_750CXE_V2_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V3_0* = (UC_CPU_PPC32_750CXE_V2_4B + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V3_1* = (UC_CPU_PPC32_750CXE_V3_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXE_V3_1B* = (UC_CPU_PPC32_750CXE_V3_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750CXR* = (UC_CPU_PPC32_750CXE_V3_1B + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FL* = (UC_CPU_PPC32_750CXR + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FX_V1_0* = (UC_CPU_PPC32_750FL + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FX_V2_0* = (UC_CPU_PPC32_750FX_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FX_V2_1* = (UC_CPU_PPC32_750FX_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FX_V2_2* = (UC_CPU_PPC32_750FX_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750FX_V2_3* = (UC_CPU_PPC32_750FX_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750GL* = (UC_CPU_PPC32_750FX_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750GX_V1_0* = (UC_CPU_PPC32_750GL + 1).uc_cpu_ppc
  UC_CPU_PPC32_750GX_V1_1* = (UC_CPU_PPC32_750GX_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750GX_V1_2* = (UC_CPU_PPC32_750GX_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750L_V2_0* = (UC_CPU_PPC32_750GX_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750L_V2_1* = (UC_CPU_PPC32_750L_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750L_V2_2* = (UC_CPU_PPC32_750L_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750L_V3_0* = (UC_CPU_PPC32_750L_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_750L_V3_2* = (UC_CPU_PPC32_750L_V3_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V1_0* = (UC_CPU_PPC32_750L_V3_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V1_0* = (UC_CPU_PPC32_745_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V1_1* = (UC_CPU_PPC32_755_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V1_1* = (UC_CPU_PPC32_745_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_0* = (UC_CPU_PPC32_755_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_0* = (UC_CPU_PPC32_745_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_1* = (UC_CPU_PPC32_755_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_1* = (UC_CPU_PPC32_745_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_2* = (UC_CPU_PPC32_755_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_2* = (UC_CPU_PPC32_745_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_3* = (UC_CPU_PPC32_755_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_3* = (UC_CPU_PPC32_745_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_4* = (UC_CPU_PPC32_755_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_4* = (UC_CPU_PPC32_745_V2_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_5* = (UC_CPU_PPC32_755_V2_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_5* = (UC_CPU_PPC32_745_V2_5 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_6* = (UC_CPU_PPC32_755_V2_5 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_6* = (UC_CPU_PPC32_745_V2_6 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_7* = (UC_CPU_PPC32_755_V2_6 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_7* = (UC_CPU_PPC32_745_V2_7 + 1).uc_cpu_ppc
  UC_CPU_PPC32_745_V2_8* = (UC_CPU_PPC32_755_V2_7 + 1).uc_cpu_ppc
  UC_CPU_PPC32_755_V2_8* = (UC_CPU_PPC32_745_V2_8 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V1_0* = (UC_CPU_PPC32_755_V2_8 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V1_1* = (UC_CPU_PPC32_7400_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_0* = (UC_CPU_PPC32_7400_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_1* = (UC_CPU_PPC32_7400_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_2* = (UC_CPU_PPC32_7400_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_6* = (UC_CPU_PPC32_7400_V2_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_7* = (UC_CPU_PPC32_7400_V2_6 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_8* = (UC_CPU_PPC32_7400_V2_7 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7400_V2_9* = (UC_CPU_PPC32_7400_V2_8 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7410_V1_0* = (UC_CPU_PPC32_7400_V2_9 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7410_V1_1* = (UC_CPU_PPC32_7410_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7410_V1_2* = (UC_CPU_PPC32_7410_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7410_V1_3* = (UC_CPU_PPC32_7410_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7410_V1_4* = (UC_CPU_PPC32_7410_V1_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7448_V1_0* = (UC_CPU_PPC32_7410_V1_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7448_V1_1* = (UC_CPU_PPC32_7448_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7448_V2_0* = (UC_CPU_PPC32_7448_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7448_V2_1* = (UC_CPU_PPC32_7448_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7450_V1_0* = (UC_CPU_PPC32_7448_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7450_V1_1* = (UC_CPU_PPC32_7450_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7450_V1_2* = (UC_CPU_PPC32_7450_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7450_V2_0* = (UC_CPU_PPC32_7450_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7450_V2_1* = (UC_CPU_PPC32_7450_V2_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7441_V2_1* = (UC_CPU_PPC32_7450_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7441_V2_3* = (UC_CPU_PPC32_7441_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7451_V2_3* = (UC_CPU_PPC32_7441_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7441_V2_10* = (UC_CPU_PPC32_7451_V2_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7451_V2_10* = (UC_CPU_PPC32_7441_V2_10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7445_V1_0* = (UC_CPU_PPC32_7451_V2_10 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7455_V1_0* = (UC_CPU_PPC32_7445_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7445_V2_1* = (UC_CPU_PPC32_7455_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7455_V2_1* = (UC_CPU_PPC32_7445_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7445_V3_2* = (UC_CPU_PPC32_7455_V2_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7455_V3_2* = (UC_CPU_PPC32_7445_V3_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7445_V3_3* = (UC_CPU_PPC32_7455_V3_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7455_V3_3* = (UC_CPU_PPC32_7445_V3_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7445_V3_4* = (UC_CPU_PPC32_7455_V3_3 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7455_V3_4* = (UC_CPU_PPC32_7445_V3_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7447_V1_0* = (UC_CPU_PPC32_7455_V3_4 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457_V1_0* = (UC_CPU_PPC32_7447_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7447_V1_1* = (UC_CPU_PPC32_7457_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457_V1_1* = (UC_CPU_PPC32_7447_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457_V1_2* = (UC_CPU_PPC32_7457_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7447A_V1_0* = (UC_CPU_PPC32_7457_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457A_V1_0* = (UC_CPU_PPC32_7447A_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7447A_V1_1* = (UC_CPU_PPC32_7457A_V1_0 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457A_V1_1* = (UC_CPU_PPC32_7447A_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7447A_V1_2* = (UC_CPU_PPC32_7457A_V1_1 + 1).uc_cpu_ppc
  UC_CPU_PPC32_7457A_V1_2* = (UC_CPU_PPC32_7447A_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC32_ENDING* = (UC_CPU_PPC32_7457A_V1_2 + 1).uc_cpu_ppc
  UC_CPU_PPC64_E5500* = (0).uc_cpu_ppc64
  UC_CPU_PPC64_E6500* = (UC_CPU_PPC64_E5500 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970_V2_2* = (UC_CPU_PPC64_E6500 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970FX_V1_0* = (UC_CPU_PPC64_970_V2_2 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970FX_V2_0* = (UC_CPU_PPC64_970FX_V1_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970FX_V2_1* = (UC_CPU_PPC64_970FX_V2_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970FX_V3_0* = (UC_CPU_PPC64_970FX_V2_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970FX_V3_1* = (UC_CPU_PPC64_970FX_V3_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970MP_V1_0* = (UC_CPU_PPC64_970FX_V3_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_970MP_V1_1* = (UC_CPU_PPC64_970MP_V1_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER5_V2_1* = (UC_CPU_PPC64_970MP_V1_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER7_V2_3* = (UC_CPU_PPC64_POWER5_V2_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER7_V2_1* = (UC_CPU_PPC64_POWER7_V2_3 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER8E_V2_1* = (UC_CPU_PPC64_POWER7_V2_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER8_V2_0* = (UC_CPU_PPC64_POWER8E_V2_1 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER8NVL_V1_0* = (UC_CPU_PPC64_POWER8_V2_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER9_V1_0* = (UC_CPU_PPC64_POWER8NVL_V1_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER9_V2_0* = (UC_CPU_PPC64_POWER9_V1_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_POWER10_V1_0* = (UC_CPU_PPC64_POWER9_V2_0 + 1).uc_cpu_ppc64
  UC_CPU_PPC64_ENDING* = (UC_CPU_PPC64_POWER10_V1_0 + 1).uc_cpu_ppc64
  UC_PPC_REG_INVALID* = (0).uc_ppc_reg ## ```
                                       ##   > General purpose registers
                                       ## ```
  UC_PPC_REG_PC* = (UC_PPC_REG_INVALID + 1).uc_ppc_reg ## ```
                                                       ##   > General purpose registers
                                                       ## ```
  UC_PPC_REG_0* = (UC_PPC_REG_PC + 1).uc_ppc_reg
  UC_PPC_REG_1* = (UC_PPC_REG_0 + 1).uc_ppc_reg
  UC_PPC_REG_2* = (UC_PPC_REG_1 + 1).uc_ppc_reg
  UC_PPC_REG_3* = (UC_PPC_REG_2 + 1).uc_ppc_reg
  UC_PPC_REG_4* = (UC_PPC_REG_3 + 1).uc_ppc_reg
  UC_PPC_REG_5* = (UC_PPC_REG_4 + 1).uc_ppc_reg
  UC_PPC_REG_6* = (UC_PPC_REG_5 + 1).uc_ppc_reg
  UC_PPC_REG_7* = (UC_PPC_REG_6 + 1).uc_ppc_reg
  UC_PPC_REG_8* = (UC_PPC_REG_7 + 1).uc_ppc_reg
  UC_PPC_REG_9* = (UC_PPC_REG_8 + 1).uc_ppc_reg
  UC_PPC_REG_10* = (UC_PPC_REG_9 + 1).uc_ppc_reg
  UC_PPC_REG_11* = (UC_PPC_REG_10 + 1).uc_ppc_reg
  UC_PPC_REG_12* = (UC_PPC_REG_11 + 1).uc_ppc_reg
  UC_PPC_REG_13* = (UC_PPC_REG_12 + 1).uc_ppc_reg
  UC_PPC_REG_14* = (UC_PPC_REG_13 + 1).uc_ppc_reg
  UC_PPC_REG_15* = (UC_PPC_REG_14 + 1).uc_ppc_reg
  UC_PPC_REG_16* = (UC_PPC_REG_15 + 1).uc_ppc_reg
  UC_PPC_REG_17* = (UC_PPC_REG_16 + 1).uc_ppc_reg
  UC_PPC_REG_18* = (UC_PPC_REG_17 + 1).uc_ppc_reg
  UC_PPC_REG_19* = (UC_PPC_REG_18 + 1).uc_ppc_reg
  UC_PPC_REG_20* = (UC_PPC_REG_19 + 1).uc_ppc_reg
  UC_PPC_REG_21* = (UC_PPC_REG_20 + 1).uc_ppc_reg
  UC_PPC_REG_22* = (UC_PPC_REG_21 + 1).uc_ppc_reg
  UC_PPC_REG_23* = (UC_PPC_REG_22 + 1).uc_ppc_reg
  UC_PPC_REG_24* = (UC_PPC_REG_23 + 1).uc_ppc_reg
  UC_PPC_REG_25* = (UC_PPC_REG_24 + 1).uc_ppc_reg
  UC_PPC_REG_26* = (UC_PPC_REG_25 + 1).uc_ppc_reg
  UC_PPC_REG_27* = (UC_PPC_REG_26 + 1).uc_ppc_reg
  UC_PPC_REG_28* = (UC_PPC_REG_27 + 1).uc_ppc_reg
  UC_PPC_REG_29* = (UC_PPC_REG_28 + 1).uc_ppc_reg
  UC_PPC_REG_30* = (UC_PPC_REG_29 + 1).uc_ppc_reg
  UC_PPC_REG_31* = (UC_PPC_REG_30 + 1).uc_ppc_reg
  UC_PPC_REG_CR0* = (UC_PPC_REG_31 + 1).uc_ppc_reg
  UC_PPC_REG_CR1* = (UC_PPC_REG_CR0 + 1).uc_ppc_reg
  UC_PPC_REG_CR2* = (UC_PPC_REG_CR1 + 1).uc_ppc_reg
  UC_PPC_REG_CR3* = (UC_PPC_REG_CR2 + 1).uc_ppc_reg
  UC_PPC_REG_CR4* = (UC_PPC_REG_CR3 + 1).uc_ppc_reg
  UC_PPC_REG_CR5* = (UC_PPC_REG_CR4 + 1).uc_ppc_reg
  UC_PPC_REG_CR6* = (UC_PPC_REG_CR5 + 1).uc_ppc_reg
  UC_PPC_REG_CR7* = (UC_PPC_REG_CR6 + 1).uc_ppc_reg
  UC_PPC_REG_FPR0* = (UC_PPC_REG_CR7 + 1).uc_ppc_reg
  UC_PPC_REG_FPR1* = (UC_PPC_REG_FPR0 + 1).uc_ppc_reg
  UC_PPC_REG_FPR2* = (UC_PPC_REG_FPR1 + 1).uc_ppc_reg
  UC_PPC_REG_FPR3* = (UC_PPC_REG_FPR2 + 1).uc_ppc_reg
  UC_PPC_REG_FPR4* = (UC_PPC_REG_FPR3 + 1).uc_ppc_reg
  UC_PPC_REG_FPR5* = (UC_PPC_REG_FPR4 + 1).uc_ppc_reg
  UC_PPC_REG_FPR6* = (UC_PPC_REG_FPR5 + 1).uc_ppc_reg
  UC_PPC_REG_FPR7* = (UC_PPC_REG_FPR6 + 1).uc_ppc_reg
  UC_PPC_REG_FPR8* = (UC_PPC_REG_FPR7 + 1).uc_ppc_reg
  UC_PPC_REG_FPR9* = (UC_PPC_REG_FPR8 + 1).uc_ppc_reg
  UC_PPC_REG_FPR10* = (UC_PPC_REG_FPR9 + 1).uc_ppc_reg
  UC_PPC_REG_FPR11* = (UC_PPC_REG_FPR10 + 1).uc_ppc_reg
  UC_PPC_REG_FPR12* = (UC_PPC_REG_FPR11 + 1).uc_ppc_reg
  UC_PPC_REG_FPR13* = (UC_PPC_REG_FPR12 + 1).uc_ppc_reg
  UC_PPC_REG_FPR14* = (UC_PPC_REG_FPR13 + 1).uc_ppc_reg
  UC_PPC_REG_FPR15* = (UC_PPC_REG_FPR14 + 1).uc_ppc_reg
  UC_PPC_REG_FPR16* = (UC_PPC_REG_FPR15 + 1).uc_ppc_reg
  UC_PPC_REG_FPR17* = (UC_PPC_REG_FPR16 + 1).uc_ppc_reg
  UC_PPC_REG_FPR18* = (UC_PPC_REG_FPR17 + 1).uc_ppc_reg
  UC_PPC_REG_FPR19* = (UC_PPC_REG_FPR18 + 1).uc_ppc_reg
  UC_PPC_REG_FPR20* = (UC_PPC_REG_FPR19 + 1).uc_ppc_reg
  UC_PPC_REG_FPR21* = (UC_PPC_REG_FPR20 + 1).uc_ppc_reg
  UC_PPC_REG_FPR22* = (UC_PPC_REG_FPR21 + 1).uc_ppc_reg
  UC_PPC_REG_FPR23* = (UC_PPC_REG_FPR22 + 1).uc_ppc_reg
  UC_PPC_REG_FPR24* = (UC_PPC_REG_FPR23 + 1).uc_ppc_reg
  UC_PPC_REG_FPR25* = (UC_PPC_REG_FPR24 + 1).uc_ppc_reg
  UC_PPC_REG_FPR26* = (UC_PPC_REG_FPR25 + 1).uc_ppc_reg
  UC_PPC_REG_FPR27* = (UC_PPC_REG_FPR26 + 1).uc_ppc_reg
  UC_PPC_REG_FPR28* = (UC_PPC_REG_FPR27 + 1).uc_ppc_reg
  UC_PPC_REG_FPR29* = (UC_PPC_REG_FPR28 + 1).uc_ppc_reg
  UC_PPC_REG_FPR30* = (UC_PPC_REG_FPR29 + 1).uc_ppc_reg
  UC_PPC_REG_FPR31* = (UC_PPC_REG_FPR30 + 1).uc_ppc_reg
  UC_PPC_REG_LR* = (UC_PPC_REG_FPR31 + 1).uc_ppc_reg
  UC_PPC_REG_XER* = (UC_PPC_REG_LR + 1).uc_ppc_reg
  UC_PPC_REG_CTR* = (UC_PPC_REG_XER + 1).uc_ppc_reg
  UC_PPC_REG_MSR* = (UC_PPC_REG_CTR + 1).uc_ppc_reg
  UC_PPC_REG_FPSCR* = (UC_PPC_REG_MSR + 1).uc_ppc_reg
  UC_PPC_REG_CR* = (UC_PPC_REG_FPSCR + 1).uc_ppc_reg
  UC_PPC_REG_ENDING* = (UC_PPC_REG_CR + 1).uc_ppc_reg ## ```
                                                      ##   <-- mark the end of the list or registers
                                                      ## ```
  UC_CPU_RISCV32_ANY* = (0).uc_cpu_riscv32
  UC_CPU_RISCV32_BASE32* = (UC_CPU_RISCV32_ANY + 1).uc_cpu_riscv32
  UC_CPU_RISCV32_SIFIVE_E31* = (UC_CPU_RISCV32_BASE32 + 1).uc_cpu_riscv32
  UC_CPU_RISCV32_SIFIVE_U34* = (UC_CPU_RISCV32_SIFIVE_E31 + 1).uc_cpu_riscv32
  UC_CPU_RISCV32_ENDING* = (UC_CPU_RISCV32_SIFIVE_U34 + 1).uc_cpu_riscv32
  UC_CPU_RISCV64_ANY* = (0).uc_cpu_riscv64
  UC_CPU_RISCV64_BASE64* = (UC_CPU_RISCV64_ANY + 1).uc_cpu_riscv64
  UC_CPU_RISCV64_SIFIVE_E51* = (UC_CPU_RISCV64_BASE64 + 1).uc_cpu_riscv64
  UC_CPU_RISCV64_SIFIVE_U54* = (UC_CPU_RISCV64_SIFIVE_E51 + 1).uc_cpu_riscv64
  UC_CPU_RISCV64_ENDING* = (UC_CPU_RISCV64_SIFIVE_U54 + 1).uc_cpu_riscv64
  UC_RISCV_REG_INVALID* = (0).uc_riscv_reg ## ```
                                           ##   > General purpose registers
                                           ## ```
  UC_RISCV_REG_X0* = (UC_RISCV_REG_INVALID + 1).uc_riscv_reg ## ```
                                                             ##   > General purpose registers
                                                             ## ```
  UC_RISCV_REG_X1* = (UC_RISCV_REG_X0 + 1).uc_riscv_reg
  UC_RISCV_REG_X2* = (UC_RISCV_REG_X1 + 1).uc_riscv_reg
  UC_RISCV_REG_X3* = (UC_RISCV_REG_X2 + 1).uc_riscv_reg
  UC_RISCV_REG_X4* = (UC_RISCV_REG_X3 + 1).uc_riscv_reg
  UC_RISCV_REG_X5* = (UC_RISCV_REG_X4 + 1).uc_riscv_reg
  UC_RISCV_REG_X6* = (UC_RISCV_REG_X5 + 1).uc_riscv_reg
  UC_RISCV_REG_X7* = (UC_RISCV_REG_X6 + 1).uc_riscv_reg
  UC_RISCV_REG_X8* = (UC_RISCV_REG_X7 + 1).uc_riscv_reg
  UC_RISCV_REG_X9* = (UC_RISCV_REG_X8 + 1).uc_riscv_reg
  UC_RISCV_REG_X10* = (UC_RISCV_REG_X9 + 1).uc_riscv_reg
  UC_RISCV_REG_X11* = (UC_RISCV_REG_X10 + 1).uc_riscv_reg
  UC_RISCV_REG_X12* = (UC_RISCV_REG_X11 + 1).uc_riscv_reg
  UC_RISCV_REG_X13* = (UC_RISCV_REG_X12 + 1).uc_riscv_reg
  UC_RISCV_REG_X14* = (UC_RISCV_REG_X13 + 1).uc_riscv_reg
  UC_RISCV_REG_X15* = (UC_RISCV_REG_X14 + 1).uc_riscv_reg
  UC_RISCV_REG_X16* = (UC_RISCV_REG_X15 + 1).uc_riscv_reg
  UC_RISCV_REG_X17* = (UC_RISCV_REG_X16 + 1).uc_riscv_reg
  UC_RISCV_REG_X18* = (UC_RISCV_REG_X17 + 1).uc_riscv_reg
  UC_RISCV_REG_X19* = (UC_RISCV_REG_X18 + 1).uc_riscv_reg
  UC_RISCV_REG_X20* = (UC_RISCV_REG_X19 + 1).uc_riscv_reg
  UC_RISCV_REG_X21* = (UC_RISCV_REG_X20 + 1).uc_riscv_reg
  UC_RISCV_REG_X22* = (UC_RISCV_REG_X21 + 1).uc_riscv_reg
  UC_RISCV_REG_X23* = (UC_RISCV_REG_X22 + 1).uc_riscv_reg
  UC_RISCV_REG_X24* = (UC_RISCV_REG_X23 + 1).uc_riscv_reg
  UC_RISCV_REG_X25* = (UC_RISCV_REG_X24 + 1).uc_riscv_reg
  UC_RISCV_REG_X26* = (UC_RISCV_REG_X25 + 1).uc_riscv_reg
  UC_RISCV_REG_X27* = (UC_RISCV_REG_X26 + 1).uc_riscv_reg
  UC_RISCV_REG_X28* = (UC_RISCV_REG_X27 + 1).uc_riscv_reg
  UC_RISCV_REG_X29* = (UC_RISCV_REG_X28 + 1).uc_riscv_reg
  UC_RISCV_REG_X30* = (UC_RISCV_REG_X29 + 1).uc_riscv_reg
  UC_RISCV_REG_X31* = (UC_RISCV_REG_X30 + 1).uc_riscv_reg
  UC_RISCV_REG_USTATUS* = (UC_RISCV_REG_X31 + 1).uc_riscv_reg ## ```
                                                              ##   > RISCV CSR
                                                              ## ```
  UC_RISCV_REG_UIE* = (UC_RISCV_REG_USTATUS + 1).uc_riscv_reg
  UC_RISCV_REG_UTVEC* = (UC_RISCV_REG_UIE + 1).uc_riscv_reg
  UC_RISCV_REG_USCRATCH* = (UC_RISCV_REG_UTVEC + 1).uc_riscv_reg
  UC_RISCV_REG_UEPC* = (UC_RISCV_REG_USCRATCH + 1).uc_riscv_reg
  UC_RISCV_REG_UCAUSE* = (UC_RISCV_REG_UEPC + 1).uc_riscv_reg
  UC_RISCV_REG_UTVAL* = (UC_RISCV_REG_UCAUSE + 1).uc_riscv_reg
  UC_RISCV_REG_UIP* = (UC_RISCV_REG_UTVAL + 1).uc_riscv_reg
  UC_RISCV_REG_FFLAGS* = (UC_RISCV_REG_UIP + 1).uc_riscv_reg
  UC_RISCV_REG_FRM* = (UC_RISCV_REG_FFLAGS + 1).uc_riscv_reg
  UC_RISCV_REG_FCSR* = (UC_RISCV_REG_FRM + 1).uc_riscv_reg
  UC_RISCV_REG_CYCLE* = (UC_RISCV_REG_FCSR + 1).uc_riscv_reg
  UC_RISCV_REG_TIME* = (UC_RISCV_REG_CYCLE + 1).uc_riscv_reg
  UC_RISCV_REG_INSTRET* = (UC_RISCV_REG_TIME + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER3* = (UC_RISCV_REG_INSTRET + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER4* = (UC_RISCV_REG_HPMCOUNTER3 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER5* = (UC_RISCV_REG_HPMCOUNTER4 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER6* = (UC_RISCV_REG_HPMCOUNTER5 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER7* = (UC_RISCV_REG_HPMCOUNTER6 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER8* = (UC_RISCV_REG_HPMCOUNTER7 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER9* = (UC_RISCV_REG_HPMCOUNTER8 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER10* = (UC_RISCV_REG_HPMCOUNTER9 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER11* = (UC_RISCV_REG_HPMCOUNTER10 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER12* = (UC_RISCV_REG_HPMCOUNTER11 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER13* = (UC_RISCV_REG_HPMCOUNTER12 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER14* = (UC_RISCV_REG_HPMCOUNTER13 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER15* = (UC_RISCV_REG_HPMCOUNTER14 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER16* = (UC_RISCV_REG_HPMCOUNTER15 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER17* = (UC_RISCV_REG_HPMCOUNTER16 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER18* = (UC_RISCV_REG_HPMCOUNTER17 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER19* = (UC_RISCV_REG_HPMCOUNTER18 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER20* = (UC_RISCV_REG_HPMCOUNTER19 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER21* = (UC_RISCV_REG_HPMCOUNTER20 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER22* = (UC_RISCV_REG_HPMCOUNTER21 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER23* = (UC_RISCV_REG_HPMCOUNTER22 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER24* = (UC_RISCV_REG_HPMCOUNTER23 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER25* = (UC_RISCV_REG_HPMCOUNTER24 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER26* = (UC_RISCV_REG_HPMCOUNTER25 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER27* = (UC_RISCV_REG_HPMCOUNTER26 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER28* = (UC_RISCV_REG_HPMCOUNTER27 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER29* = (UC_RISCV_REG_HPMCOUNTER28 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER30* = (UC_RISCV_REG_HPMCOUNTER29 + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER31* = (UC_RISCV_REG_HPMCOUNTER30 + 1).uc_riscv_reg
  UC_RISCV_REG_CYCLEH* = (UC_RISCV_REG_HPMCOUNTER31 + 1).uc_riscv_reg
  UC_RISCV_REG_TIMEH* = (UC_RISCV_REG_CYCLEH + 1).uc_riscv_reg
  UC_RISCV_REG_INSTRETH* = (UC_RISCV_REG_TIMEH + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER3H* = (UC_RISCV_REG_INSTRETH + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER4H* = (UC_RISCV_REG_HPMCOUNTER3H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER5H* = (UC_RISCV_REG_HPMCOUNTER4H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER6H* = (UC_RISCV_REG_HPMCOUNTER5H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER7H* = (UC_RISCV_REG_HPMCOUNTER6H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER8H* = (UC_RISCV_REG_HPMCOUNTER7H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER9H* = (UC_RISCV_REG_HPMCOUNTER8H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER10H* = (UC_RISCV_REG_HPMCOUNTER9H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER11H* = (UC_RISCV_REG_HPMCOUNTER10H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER12H* = (UC_RISCV_REG_HPMCOUNTER11H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER13H* = (UC_RISCV_REG_HPMCOUNTER12H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER14H* = (UC_RISCV_REG_HPMCOUNTER13H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER15H* = (UC_RISCV_REG_HPMCOUNTER14H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER16H* = (UC_RISCV_REG_HPMCOUNTER15H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER17H* = (UC_RISCV_REG_HPMCOUNTER16H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER18H* = (UC_RISCV_REG_HPMCOUNTER17H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER19H* = (UC_RISCV_REG_HPMCOUNTER18H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER20H* = (UC_RISCV_REG_HPMCOUNTER19H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER21H* = (UC_RISCV_REG_HPMCOUNTER20H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER22H* = (UC_RISCV_REG_HPMCOUNTER21H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER23H* = (UC_RISCV_REG_HPMCOUNTER22H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER24H* = (UC_RISCV_REG_HPMCOUNTER23H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER25H* = (UC_RISCV_REG_HPMCOUNTER24H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER26H* = (UC_RISCV_REG_HPMCOUNTER25H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER27H* = (UC_RISCV_REG_HPMCOUNTER26H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER28H* = (UC_RISCV_REG_HPMCOUNTER27H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER29H* = (UC_RISCV_REG_HPMCOUNTER28H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER30H* = (UC_RISCV_REG_HPMCOUNTER29H + 1).uc_riscv_reg
  UC_RISCV_REG_HPMCOUNTER31H* = (UC_RISCV_REG_HPMCOUNTER30H + 1).uc_riscv_reg
  UC_RISCV_REG_MCYCLE* = (UC_RISCV_REG_HPMCOUNTER31H + 1).uc_riscv_reg
  UC_RISCV_REG_MINSTRET* = (UC_RISCV_REG_MCYCLE + 1).uc_riscv_reg
  UC_RISCV_REG_MCYCLEH* = (UC_RISCV_REG_MINSTRET + 1).uc_riscv_reg
  UC_RISCV_REG_MINSTRETH* = (UC_RISCV_REG_MCYCLEH + 1).uc_riscv_reg
  UC_RISCV_REG_MVENDORID* = (UC_RISCV_REG_MINSTRETH + 1).uc_riscv_reg
  UC_RISCV_REG_MARCHID* = (UC_RISCV_REG_MVENDORID + 1).uc_riscv_reg
  UC_RISCV_REG_MIMPID* = (UC_RISCV_REG_MARCHID + 1).uc_riscv_reg
  UC_RISCV_REG_MHARTID* = (UC_RISCV_REG_MIMPID + 1).uc_riscv_reg
  UC_RISCV_REG_MSTATUS* = (UC_RISCV_REG_MHARTID + 1).uc_riscv_reg
  UC_RISCV_REG_MISA* = (UC_RISCV_REG_MSTATUS + 1).uc_riscv_reg
  UC_RISCV_REG_MEDELEG* = (UC_RISCV_REG_MISA + 1).uc_riscv_reg
  UC_RISCV_REG_MIDELEG* = (UC_RISCV_REG_MEDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_MIE* = (UC_RISCV_REG_MIDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_MTVEC* = (UC_RISCV_REG_MIE + 1).uc_riscv_reg
  UC_RISCV_REG_MCOUNTEREN* = (UC_RISCV_REG_MTVEC + 1).uc_riscv_reg
  UC_RISCV_REG_MSTATUSH* = (UC_RISCV_REG_MCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_MUCOUNTEREN* = (UC_RISCV_REG_MSTATUSH + 1).uc_riscv_reg
  UC_RISCV_REG_MSCOUNTEREN* = (UC_RISCV_REG_MUCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_MHCOUNTEREN* = (UC_RISCV_REG_MSCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_MSCRATCH* = (UC_RISCV_REG_MHCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_MEPC* = (UC_RISCV_REG_MSCRATCH + 1).uc_riscv_reg
  UC_RISCV_REG_MCAUSE* = (UC_RISCV_REG_MEPC + 1).uc_riscv_reg
  UC_RISCV_REG_MTVAL* = (UC_RISCV_REG_MCAUSE + 1).uc_riscv_reg
  UC_RISCV_REG_MIP* = (UC_RISCV_REG_MTVAL + 1).uc_riscv_reg
  UC_RISCV_REG_MBADADDR* = (UC_RISCV_REG_MIP + 1).uc_riscv_reg
  UC_RISCV_REG_SSTATUS* = (UC_RISCV_REG_MBADADDR + 1).uc_riscv_reg
  UC_RISCV_REG_SEDELEG* = (UC_RISCV_REG_SSTATUS + 1).uc_riscv_reg
  UC_RISCV_REG_SIDELEG* = (UC_RISCV_REG_SEDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_SIE* = (UC_RISCV_REG_SIDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_STVEC* = (UC_RISCV_REG_SIE + 1).uc_riscv_reg
  UC_RISCV_REG_SCOUNTEREN* = (UC_RISCV_REG_STVEC + 1).uc_riscv_reg
  UC_RISCV_REG_SSCRATCH* = (UC_RISCV_REG_SCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_SEPC* = (UC_RISCV_REG_SSCRATCH + 1).uc_riscv_reg
  UC_RISCV_REG_SCAUSE* = (UC_RISCV_REG_SEPC + 1).uc_riscv_reg
  UC_RISCV_REG_STVAL* = (UC_RISCV_REG_SCAUSE + 1).uc_riscv_reg
  UC_RISCV_REG_SIP* = (UC_RISCV_REG_STVAL + 1).uc_riscv_reg
  UC_RISCV_REG_SBADADDR* = (UC_RISCV_REG_SIP + 1).uc_riscv_reg
  UC_RISCV_REG_SPTBR* = (UC_RISCV_REG_SBADADDR + 1).uc_riscv_reg
  UC_RISCV_REG_SATP* = (UC_RISCV_REG_SPTBR + 1).uc_riscv_reg
  UC_RISCV_REG_HSTATUS* = (UC_RISCV_REG_SATP + 1).uc_riscv_reg
  UC_RISCV_REG_HEDELEG* = (UC_RISCV_REG_HSTATUS + 1).uc_riscv_reg
  UC_RISCV_REG_HIDELEG* = (UC_RISCV_REG_HEDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_HIE* = (UC_RISCV_REG_HIDELEG + 1).uc_riscv_reg
  UC_RISCV_REG_HCOUNTEREN* = (UC_RISCV_REG_HIE + 1).uc_riscv_reg
  UC_RISCV_REG_HTVAL* = (UC_RISCV_REG_HCOUNTEREN + 1).uc_riscv_reg
  UC_RISCV_REG_HIP* = (UC_RISCV_REG_HTVAL + 1).uc_riscv_reg
  UC_RISCV_REG_HTINST* = (UC_RISCV_REG_HIP + 1).uc_riscv_reg
  UC_RISCV_REG_HGATP* = (UC_RISCV_REG_HTINST + 1).uc_riscv_reg
  UC_RISCV_REG_HTIMEDELTA* = (UC_RISCV_REG_HGATP + 1).uc_riscv_reg
  UC_RISCV_REG_HTIMEDELTAH* = (UC_RISCV_REG_HTIMEDELTA + 1).uc_riscv_reg
  UC_RISCV_REG_F0* = (UC_RISCV_REG_HTIMEDELTAH + 1).uc_riscv_reg ## ```
                                                                 ##   "ft0"
                                                                 ## ```
  UC_RISCV_REG_F1* = (UC_RISCV_REG_F0 + 1).uc_riscv_reg ## ```
                                                        ##   "ft1"
                                                        ## ```
  UC_RISCV_REG_F2* = (UC_RISCV_REG_F1 + 1).uc_riscv_reg ## ```
                                                        ##   "ft2"
                                                        ## ```
  UC_RISCV_REG_F3* = (UC_RISCV_REG_F2 + 1).uc_riscv_reg ## ```
                                                        ##   "ft3"
                                                        ## ```
  UC_RISCV_REG_F4* = (UC_RISCV_REG_F3 + 1).uc_riscv_reg ## ```
                                                        ##   "ft4"
                                                        ## ```
  UC_RISCV_REG_F5* = (UC_RISCV_REG_F4 + 1).uc_riscv_reg ## ```
                                                        ##   "ft5"
                                                        ## ```
  UC_RISCV_REG_F6* = (UC_RISCV_REG_F5 + 1).uc_riscv_reg ## ```
                                                        ##   "ft6"
                                                        ## ```
  UC_RISCV_REG_F7* = (UC_RISCV_REG_F6 + 1).uc_riscv_reg ## ```
                                                        ##   "ft7"
                                                        ## ```
  UC_RISCV_REG_F8* = (UC_RISCV_REG_F7 + 1).uc_riscv_reg ## ```
                                                        ##   "fs0"
                                                        ## ```
  UC_RISCV_REG_F9* = (UC_RISCV_REG_F8 + 1).uc_riscv_reg ## ```
                                                        ##   "fs1"
                                                        ## ```
  UC_RISCV_REG_F10* = (UC_RISCV_REG_F9 + 1).uc_riscv_reg ## ```
                                                         ##   "fa0"
                                                         ## ```
  UC_RISCV_REG_F11* = (UC_RISCV_REG_F10 + 1).uc_riscv_reg ## ```
                                                          ##   "fa1"
                                                          ## ```
  UC_RISCV_REG_F12* = (UC_RISCV_REG_F11 + 1).uc_riscv_reg ## ```
                                                          ##   "fa2"
                                                          ## ```
  UC_RISCV_REG_F13* = (UC_RISCV_REG_F12 + 1).uc_riscv_reg ## ```
                                                          ##   "fa3"
                                                          ## ```
  UC_RISCV_REG_F14* = (UC_RISCV_REG_F13 + 1).uc_riscv_reg ## ```
                                                          ##   "fa4"
                                                          ## ```
  UC_RISCV_REG_F15* = (UC_RISCV_REG_F14 + 1).uc_riscv_reg ## ```
                                                          ##   "fa5"
                                                          ## ```
  UC_RISCV_REG_F16* = (UC_RISCV_REG_F15 + 1).uc_riscv_reg ## ```
                                                          ##   "fa6"
                                                          ## ```
  UC_RISCV_REG_F17* = (UC_RISCV_REG_F16 + 1).uc_riscv_reg ## ```
                                                          ##   "fa7"
                                                          ## ```
  UC_RISCV_REG_F18* = (UC_RISCV_REG_F17 + 1).uc_riscv_reg ## ```
                                                          ##   "fs2"
                                                          ## ```
  UC_RISCV_REG_F19* = (UC_RISCV_REG_F18 + 1).uc_riscv_reg ## ```
                                                          ##   "fs3"
                                                          ## ```
  UC_RISCV_REG_F20* = (UC_RISCV_REG_F19 + 1).uc_riscv_reg ## ```
                                                          ##   "fs4"
                                                          ## ```
  UC_RISCV_REG_F21* = (UC_RISCV_REG_F20 + 1).uc_riscv_reg ## ```
                                                          ##   "fs5"
                                                          ## ```
  UC_RISCV_REG_F22* = (UC_RISCV_REG_F21 + 1).uc_riscv_reg ## ```
                                                          ##   "fs6"
                                                          ## ```
  UC_RISCV_REG_F23* = (UC_RISCV_REG_F22 + 1).uc_riscv_reg ## ```
                                                          ##   "fs7"
                                                          ## ```
  UC_RISCV_REG_F24* = (UC_RISCV_REG_F23 + 1).uc_riscv_reg ## ```
                                                          ##   "fs8"
                                                          ## ```
  UC_RISCV_REG_F25* = (UC_RISCV_REG_F24 + 1).uc_riscv_reg ## ```
                                                          ##   "fs9"
                                                          ## ```
  UC_RISCV_REG_F26* = (UC_RISCV_REG_F25 + 1).uc_riscv_reg ## ```
                                                          ##   "fs10"
                                                          ## ```
  UC_RISCV_REG_F27* = (UC_RISCV_REG_F26 + 1).uc_riscv_reg ## ```
                                                          ##   "fs11"
                                                          ## ```
  UC_RISCV_REG_F28* = (UC_RISCV_REG_F27 + 1).uc_riscv_reg ## ```
                                                          ##   "ft8"
                                                          ## ```
  UC_RISCV_REG_F29* = (UC_RISCV_REG_F28 + 1).uc_riscv_reg ## ```
                                                          ##   "ft9"
                                                          ## ```
  UC_RISCV_REG_F30* = (UC_RISCV_REG_F29 + 1).uc_riscv_reg ## ```
                                                          ##   "ft10"
                                                          ## ```
  UC_RISCV_REG_F31* = (UC_RISCV_REG_F30 + 1).uc_riscv_reg ## ```
                                                          ##   "ft11"
                                                          ## ```
  UC_RISCV_REG_PC* = (UC_RISCV_REG_F31 + 1).uc_riscv_reg ## ```
                                                         ##   PC register
                                                         ## ```
  UC_RISCV_REG_ENDING* = (UC_RISCV_REG_PC + 1).uc_riscv_reg ## ```
                                                            ##   <-- mark the end of the list or registers
                                                            ##     > Alias registers
                                                            ## ```
  UC_RISCV_REG_ZERO* = (UC_RISCV_REG_X0).uc_riscv_reg ## ```
                                                      ##   "zero"
                                                      ## ```
  UC_RISCV_REG_RA* = (UC_RISCV_REG_X1).uc_riscv_reg ## ```
                                                    ##   "ra"
                                                    ## ```
  UC_RISCV_REG_SP* = (UC_RISCV_REG_X2).uc_riscv_reg ## ```
                                                    ##   "sp"
                                                    ## ```
  UC_RISCV_REG_GP* = (UC_RISCV_REG_X3).uc_riscv_reg ## ```
                                                    ##   "gp"
                                                    ## ```
  UC_RISCV_REG_TP* = (UC_RISCV_REG_X4).uc_riscv_reg ## ```
                                                    ##   "tp"
                                                    ## ```
  UC_RISCV_REG_T0* = (UC_RISCV_REG_X5).uc_riscv_reg ## ```
                                                    ##   "t0"
                                                    ## ```
  UC_RISCV_REG_T1* = (UC_RISCV_REG_X6).uc_riscv_reg ## ```
                                                    ##   "t1"
                                                    ## ```
  UC_RISCV_REG_T2* = (UC_RISCV_REG_X7).uc_riscv_reg ## ```
                                                    ##   "t2"
                                                    ## ```
  UC_RISCV_REG_S0* = (UC_RISCV_REG_X8).uc_riscv_reg ## ```
                                                    ##   "s0"
                                                    ## ```
  UC_RISCV_REG_FP* = (UC_RISCV_REG_X8).uc_riscv_reg ## ```
                                                    ##   "fp"
                                                    ## ```
  UC_RISCV_REG_S1* = (UC_RISCV_REG_X9).uc_riscv_reg ## ```
                                                    ##   "s1"
                                                    ## ```
  UC_RISCV_REG_A0* = (UC_RISCV_REG_X10).uc_riscv_reg ## ```
                                                     ##   "a0"
                                                     ## ```
  UC_RISCV_REG_A1* = (UC_RISCV_REG_X11).uc_riscv_reg ## ```
                                                     ##   "a1"
                                                     ## ```
  UC_RISCV_REG_A2* = (UC_RISCV_REG_X12).uc_riscv_reg ## ```
                                                     ##   "a2"
                                                     ## ```
  UC_RISCV_REG_A3* = (UC_RISCV_REG_X13).uc_riscv_reg ## ```
                                                     ##   "a3"
                                                     ## ```
  UC_RISCV_REG_A4* = (UC_RISCV_REG_X14).uc_riscv_reg ## ```
                                                     ##   "a4"
                                                     ## ```
  UC_RISCV_REG_A5* = (UC_RISCV_REG_X15).uc_riscv_reg ## ```
                                                     ##   "a5"
                                                     ## ```
  UC_RISCV_REG_A6* = (UC_RISCV_REG_X16).uc_riscv_reg ## ```
                                                     ##   "a6"
                                                     ## ```
  UC_RISCV_REG_A7* = (UC_RISCV_REG_X17).uc_riscv_reg ## ```
                                                     ##   "a7"
                                                     ## ```
  UC_RISCV_REG_S2* = (UC_RISCV_REG_X18).uc_riscv_reg ## ```
                                                     ##   "s2"
                                                     ## ```
  UC_RISCV_REG_S3* = (UC_RISCV_REG_X19).uc_riscv_reg ## ```
                                                     ##   "s3"
                                                     ## ```
  UC_RISCV_REG_S4* = (UC_RISCV_REG_X20).uc_riscv_reg ## ```
                                                     ##   "s4"
                                                     ## ```
  UC_RISCV_REG_S5* = (UC_RISCV_REG_X21).uc_riscv_reg ## ```
                                                     ##   "s5"
                                                     ## ```
  UC_RISCV_REG_S6* = (UC_RISCV_REG_X22).uc_riscv_reg ## ```
                                                     ##   "s6"
                                                     ## ```
  UC_RISCV_REG_S7* = (UC_RISCV_REG_X23).uc_riscv_reg ## ```
                                                     ##   "s7"
                                                     ## ```
  UC_RISCV_REG_S8* = (UC_RISCV_REG_X24).uc_riscv_reg ## ```
                                                     ##   "s8"
                                                     ## ```
  UC_RISCV_REG_S9* = (UC_RISCV_REG_X25).uc_riscv_reg ## ```
                                                     ##   "s9"
                                                     ## ```
  UC_RISCV_REG_S10* = (UC_RISCV_REG_X26).uc_riscv_reg ## ```
                                                      ##   "s10"
                                                      ## ```
  UC_RISCV_REG_S11* = (UC_RISCV_REG_X27).uc_riscv_reg ## ```
                                                      ##   "s11"
                                                      ## ```
  UC_RISCV_REG_T3* = (UC_RISCV_REG_X28).uc_riscv_reg ## ```
                                                     ##   "t3"
                                                     ## ```
  UC_RISCV_REG_T4* = (UC_RISCV_REG_X29).uc_riscv_reg ## ```
                                                     ##   "t4"
                                                     ## ```
  UC_RISCV_REG_T5* = (UC_RISCV_REG_X30).uc_riscv_reg ## ```
                                                     ##   "t5"
                                                     ## ```
  UC_RISCV_REG_T6* = (UC_RISCV_REG_X31).uc_riscv_reg ## ```
                                                     ##   "t6"
                                                     ## ```
  UC_RISCV_REG_FT0* = (UC_RISCV_REG_F0).uc_riscv_reg ## ```
                                                     ##   "ft0"
                                                     ## ```
  UC_RISCV_REG_FT1* = (UC_RISCV_REG_F1).uc_riscv_reg ## ```
                                                     ##   "ft1"
                                                     ## ```
  UC_RISCV_REG_FT2* = (UC_RISCV_REG_F2).uc_riscv_reg ## ```
                                                     ##   "ft2"
                                                     ## ```
  UC_RISCV_REG_FT3* = (UC_RISCV_REG_F3).uc_riscv_reg ## ```
                                                     ##   "ft3"
                                                     ## ```
  UC_RISCV_REG_FT4* = (UC_RISCV_REG_F4).uc_riscv_reg ## ```
                                                     ##   "ft4"
                                                     ## ```
  UC_RISCV_REG_FT5* = (UC_RISCV_REG_F5).uc_riscv_reg ## ```
                                                     ##   "ft5"
                                                     ## ```
  UC_RISCV_REG_FT6* = (UC_RISCV_REG_F6).uc_riscv_reg ## ```
                                                     ##   "ft6"
                                                     ## ```
  UC_RISCV_REG_FT7* = (UC_RISCV_REG_F7).uc_riscv_reg ## ```
                                                     ##   "ft7"
                                                     ## ```
  UC_RISCV_REG_FS0* = (UC_RISCV_REG_F8).uc_riscv_reg ## ```
                                                     ##   "fs0"
                                                     ## ```
  UC_RISCV_REG_FS1* = (UC_RISCV_REG_F9).uc_riscv_reg ## ```
                                                     ##   "fs1"
                                                     ## ```
  UC_RISCV_REG_FA0* = (UC_RISCV_REG_F10).uc_riscv_reg ## ```
                                                      ##   "fa0"
                                                      ## ```
  UC_RISCV_REG_FA1* = (UC_RISCV_REG_F11).uc_riscv_reg ## ```
                                                      ##   "fa1"
                                                      ## ```
  UC_RISCV_REG_FA2* = (UC_RISCV_REG_F12).uc_riscv_reg ## ```
                                                      ##   "fa2"
                                                      ## ```
  UC_RISCV_REG_FA3* = (UC_RISCV_REG_F13).uc_riscv_reg ## ```
                                                      ##   "fa3"
                                                      ## ```
  UC_RISCV_REG_FA4* = (UC_RISCV_REG_F14).uc_riscv_reg ## ```
                                                      ##   "fa4"
                                                      ## ```
  UC_RISCV_REG_FA5* = (UC_RISCV_REG_F15).uc_riscv_reg ## ```
                                                      ##   "fa5"
                                                      ## ```
  UC_RISCV_REG_FA6* = (UC_RISCV_REG_F16).uc_riscv_reg ## ```
                                                      ##   "fa6"
                                                      ## ```
  UC_RISCV_REG_FA7* = (UC_RISCV_REG_F17).uc_riscv_reg ## ```
                                                      ##   "fa7"
                                                      ## ```
  UC_RISCV_REG_FS2* = (UC_RISCV_REG_F18).uc_riscv_reg ## ```
                                                      ##   "fs2"
                                                      ## ```
  UC_RISCV_REG_FS3* = (UC_RISCV_REG_F19).uc_riscv_reg ## ```
                                                      ##   "fs3"
                                                      ## ```
  UC_RISCV_REG_FS4* = (UC_RISCV_REG_F20).uc_riscv_reg ## ```
                                                      ##   "fs4"
                                                      ## ```
  UC_RISCV_REG_FS5* = (UC_RISCV_REG_F21).uc_riscv_reg ## ```
                                                      ##   "fs5"
                                                      ## ```
  UC_RISCV_REG_FS6* = (UC_RISCV_REG_F22).uc_riscv_reg ## ```
                                                      ##   "fs6"
                                                      ## ```
  UC_RISCV_REG_FS7* = (UC_RISCV_REG_F23).uc_riscv_reg ## ```
                                                      ##   "fs7"
                                                      ## ```
  UC_RISCV_REG_FS8* = (UC_RISCV_REG_F24).uc_riscv_reg ## ```
                                                      ##   "fs8"
                                                      ## ```
  UC_RISCV_REG_FS9* = (UC_RISCV_REG_F25).uc_riscv_reg ## ```
                                                      ##   "fs9"
                                                      ## ```
  UC_RISCV_REG_FS10* = (UC_RISCV_REG_F26).uc_riscv_reg ## ```
                                                       ##   "fs10"
                                                       ## ```
  UC_RISCV_REG_FS11* = (UC_RISCV_REG_F27).uc_riscv_reg ## ```
                                                       ##   "fs11"
                                                       ## ```
  UC_RISCV_REG_FT8* = (UC_RISCV_REG_F28).uc_riscv_reg ## ```
                                                      ##   "ft8"
                                                      ## ```
  UC_RISCV_REG_FT9* = (UC_RISCV_REG_F29).uc_riscv_reg ## ```
                                                      ##   "ft9"
                                                      ## ```
  UC_RISCV_REG_FT10* = (UC_RISCV_REG_F30).uc_riscv_reg ## ```
                                                       ##   "ft10"
                                                       ## ```
  UC_RISCV_REG_FT11* = (UC_RISCV_REG_F31).uc_riscv_reg ## ```
                                                       ##   "ft11"
                                                       ## ```
  UC_CPU_S390X_Z900* = (0).uc_cpu_s390x
  UC_CPU_S390X_Z900_2* = (UC_CPU_S390X_Z900 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z900_3* = (UC_CPU_S390X_Z900_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z800* = (UC_CPU_S390X_Z900_3 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z990* = (UC_CPU_S390X_Z800 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z990_2* = (UC_CPU_S390X_Z990 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z990_3* = (UC_CPU_S390X_Z990_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z890* = (UC_CPU_S390X_Z990_3 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z990_4* = (UC_CPU_S390X_Z890 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z890_2* = (UC_CPU_S390X_Z990_4 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z990_5* = (UC_CPU_S390X_Z890_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z890_3* = (UC_CPU_S390X_Z990_5 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z9EC* = (UC_CPU_S390X_Z890_3 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z9EC_2* = (UC_CPU_S390X_Z9EC + 1).uc_cpu_s390x
  UC_CPU_S390X_Z9BC* = (UC_CPU_S390X_Z9EC_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z9EC_3* = (UC_CPU_S390X_Z9BC + 1).uc_cpu_s390x
  UC_CPU_S390X_Z9BC_2* = (UC_CPU_S390X_Z9EC_3 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z10EC* = (UC_CPU_S390X_Z9BC_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z10EC_2* = (UC_CPU_S390X_Z10EC + 1).uc_cpu_s390x
  UC_CPU_S390X_Z10BC* = (UC_CPU_S390X_Z10EC_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z10EC_3* = (UC_CPU_S390X_Z10BC + 1).uc_cpu_s390x
  UC_CPU_S390X_Z10BC_2* = (UC_CPU_S390X_Z10EC_3 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z196* = (UC_CPU_S390X_Z10BC_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z196_2* = (UC_CPU_S390X_Z196 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z114* = (UC_CPU_S390X_Z196_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_ZEC12* = (UC_CPU_S390X_Z114 + 1).uc_cpu_s390x
  UC_CPU_S390X_ZEC12_2* = (UC_CPU_S390X_ZEC12 + 1).uc_cpu_s390x
  UC_CPU_S390X_ZBC12* = (UC_CPU_S390X_ZEC12_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z13* = (UC_CPU_S390X_ZBC12 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z13_2* = (UC_CPU_S390X_Z13 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z13S* = (UC_CPU_S390X_Z13_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z14* = (UC_CPU_S390X_Z13S + 1).uc_cpu_s390x
  UC_CPU_S390X_Z14_2* = (UC_CPU_S390X_Z14 + 1).uc_cpu_s390x
  UC_CPU_S390X_Z14ZR1* = (UC_CPU_S390X_Z14_2 + 1).uc_cpu_s390x
  UC_CPU_S390X_GEN15A* = (UC_CPU_S390X_Z14ZR1 + 1).uc_cpu_s390x
  UC_CPU_S390X_GEN15B* = (UC_CPU_S390X_GEN15A + 1).uc_cpu_s390x
  UC_CPU_S390X_QEMU* = (UC_CPU_S390X_GEN15B + 1).uc_cpu_s390x
  UC_CPU_S390X_MAX* = (UC_CPU_S390X_QEMU + 1).uc_cpu_s390x
  UC_CPU_S390X_ENDING* = (UC_CPU_S390X_MAX + 1).uc_cpu_s390x
  UC_S390X_REG_INVALID* = (0).uc_s390x_reg ## ```
                                           ##   > General purpose registers
                                           ## ```
  UC_S390X_REG_R0* = (UC_S390X_REG_INVALID + 1).uc_s390x_reg ## ```
                                                             ##   > General purpose registers
                                                             ## ```
  UC_S390X_REG_R1* = (UC_S390X_REG_R0 + 1).uc_s390x_reg
  UC_S390X_REG_R2* = (UC_S390X_REG_R1 + 1).uc_s390x_reg
  UC_S390X_REG_R3* = (UC_S390X_REG_R2 + 1).uc_s390x_reg
  UC_S390X_REG_R4* = (UC_S390X_REG_R3 + 1).uc_s390x_reg
  UC_S390X_REG_R5* = (UC_S390X_REG_R4 + 1).uc_s390x_reg
  UC_S390X_REG_R6* = (UC_S390X_REG_R5 + 1).uc_s390x_reg
  UC_S390X_REG_R7* = (UC_S390X_REG_R6 + 1).uc_s390x_reg
  UC_S390X_REG_R8* = (UC_S390X_REG_R7 + 1).uc_s390x_reg
  UC_S390X_REG_R9* = (UC_S390X_REG_R8 + 1).uc_s390x_reg
  UC_S390X_REG_R10* = (UC_S390X_REG_R9 + 1).uc_s390x_reg
  UC_S390X_REG_R11* = (UC_S390X_REG_R10 + 1).uc_s390x_reg
  UC_S390X_REG_R12* = (UC_S390X_REG_R11 + 1).uc_s390x_reg
  UC_S390X_REG_R13* = (UC_S390X_REG_R12 + 1).uc_s390x_reg
  UC_S390X_REG_R14* = (UC_S390X_REG_R13 + 1).uc_s390x_reg
  UC_S390X_REG_R15* = (UC_S390X_REG_R14 + 1).uc_s390x_reg
  UC_S390X_REG_F0* = (UC_S390X_REG_R15 + 1).uc_s390x_reg ## ```
                                                         ##   > Floating point registers
                                                         ## ```
  UC_S390X_REG_F1* = (UC_S390X_REG_F0 + 1).uc_s390x_reg
  UC_S390X_REG_F2* = (UC_S390X_REG_F1 + 1).uc_s390x_reg
  UC_S390X_REG_F3* = (UC_S390X_REG_F2 + 1).uc_s390x_reg
  UC_S390X_REG_F4* = (UC_S390X_REG_F3 + 1).uc_s390x_reg
  UC_S390X_REG_F5* = (UC_S390X_REG_F4 + 1).uc_s390x_reg
  UC_S390X_REG_F6* = (UC_S390X_REG_F5 + 1).uc_s390x_reg
  UC_S390X_REG_F7* = (UC_S390X_REG_F6 + 1).uc_s390x_reg
  UC_S390X_REG_F8* = (UC_S390X_REG_F7 + 1).uc_s390x_reg
  UC_S390X_REG_F9* = (UC_S390X_REG_F8 + 1).uc_s390x_reg
  UC_S390X_REG_F10* = (UC_S390X_REG_F9 + 1).uc_s390x_reg
  UC_S390X_REG_F11* = (UC_S390X_REG_F10 + 1).uc_s390x_reg
  UC_S390X_REG_F12* = (UC_S390X_REG_F11 + 1).uc_s390x_reg
  UC_S390X_REG_F13* = (UC_S390X_REG_F12 + 1).uc_s390x_reg
  UC_S390X_REG_F14* = (UC_S390X_REG_F13 + 1).uc_s390x_reg
  UC_S390X_REG_F15* = (UC_S390X_REG_F14 + 1).uc_s390x_reg
  UC_S390X_REG_F16* = (UC_S390X_REG_F15 + 1).uc_s390x_reg
  UC_S390X_REG_F17* = (UC_S390X_REG_F16 + 1).uc_s390x_reg
  UC_S390X_REG_F18* = (UC_S390X_REG_F17 + 1).uc_s390x_reg
  UC_S390X_REG_F19* = (UC_S390X_REG_F18 + 1).uc_s390x_reg
  UC_S390X_REG_F20* = (UC_S390X_REG_F19 + 1).uc_s390x_reg
  UC_S390X_REG_F21* = (UC_S390X_REG_F20 + 1).uc_s390x_reg
  UC_S390X_REG_F22* = (UC_S390X_REG_F21 + 1).uc_s390x_reg
  UC_S390X_REG_F23* = (UC_S390X_REG_F22 + 1).uc_s390x_reg
  UC_S390X_REG_F24* = (UC_S390X_REG_F23 + 1).uc_s390x_reg
  UC_S390X_REG_F25* = (UC_S390X_REG_F24 + 1).uc_s390x_reg
  UC_S390X_REG_F26* = (UC_S390X_REG_F25 + 1).uc_s390x_reg
  UC_S390X_REG_F27* = (UC_S390X_REG_F26 + 1).uc_s390x_reg
  UC_S390X_REG_F28* = (UC_S390X_REG_F27 + 1).uc_s390x_reg
  UC_S390X_REG_F29* = (UC_S390X_REG_F28 + 1).uc_s390x_reg
  UC_S390X_REG_F30* = (UC_S390X_REG_F29 + 1).uc_s390x_reg
  UC_S390X_REG_F31* = (UC_S390X_REG_F30 + 1).uc_s390x_reg
  UC_S390X_REG_A0* = (UC_S390X_REG_F31 + 1).uc_s390x_reg ## ```
                                                         ##   > Access registers
                                                         ## ```
  UC_S390X_REG_A1* = (UC_S390X_REG_A0 + 1).uc_s390x_reg
  UC_S390X_REG_A2* = (UC_S390X_REG_A1 + 1).uc_s390x_reg
  UC_S390X_REG_A3* = (UC_S390X_REG_A2 + 1).uc_s390x_reg
  UC_S390X_REG_A4* = (UC_S390X_REG_A3 + 1).uc_s390x_reg
  UC_S390X_REG_A5* = (UC_S390X_REG_A4 + 1).uc_s390x_reg
  UC_S390X_REG_A6* = (UC_S390X_REG_A5 + 1).uc_s390x_reg
  UC_S390X_REG_A7* = (UC_S390X_REG_A6 + 1).uc_s390x_reg
  UC_S390X_REG_A8* = (UC_S390X_REG_A7 + 1).uc_s390x_reg
  UC_S390X_REG_A9* = (UC_S390X_REG_A8 + 1).uc_s390x_reg
  UC_S390X_REG_A10* = (UC_S390X_REG_A9 + 1).uc_s390x_reg
  UC_S390X_REG_A11* = (UC_S390X_REG_A10 + 1).uc_s390x_reg
  UC_S390X_REG_A12* = (UC_S390X_REG_A11 + 1).uc_s390x_reg
  UC_S390X_REG_A13* = (UC_S390X_REG_A12 + 1).uc_s390x_reg
  UC_S390X_REG_A14* = (UC_S390X_REG_A13 + 1).uc_s390x_reg
  UC_S390X_REG_A15* = (UC_S390X_REG_A14 + 1).uc_s390x_reg
  UC_S390X_REG_PC* = (UC_S390X_REG_A15 + 1).uc_s390x_reg ## ```
                                                         ##   PC register
                                                         ## ```
  UC_S390X_REG_PSWM* = (UC_S390X_REG_PC + 1).uc_s390x_reg ## ```
                                                          ##   PC register
                                                          ## ```
  UC_S390X_REG_ENDING* = (UC_S390X_REG_PSWM + 1).uc_s390x_reg ## ```
                                                              ##   <-- mark the end of the list or registers
                                                              ##     > Alias registers
                                                              ## ```
  UC_CPU_TRICORE_TC1796* = (0).uc_cpu_tricore
  UC_CPU_TRICORE_TC1797* = (UC_CPU_TRICORE_TC1796 + 1).uc_cpu_tricore
  UC_CPU_TRICORE_TC27X* = (UC_CPU_TRICORE_TC1797 + 1).uc_cpu_tricore
  UC_CPU_TRICORE_ENDING* = (UC_CPU_TRICORE_TC27X + 1).uc_cpu_tricore
  UC_TRICORE_REG_INVALID* = (0).uc_tricore_reg
  UC_TRICORE_REG_A0* = (UC_TRICORE_REG_INVALID + 1).uc_tricore_reg ## ```
                                                                   ##   General purpose registers (GPR)
                                                                   ##      Address GPR
                                                                   ## ```
  UC_TRICORE_REG_A1* = (UC_TRICORE_REG_A0 + 1).uc_tricore_reg
  UC_TRICORE_REG_A2* = (UC_TRICORE_REG_A1 + 1).uc_tricore_reg
  UC_TRICORE_REG_A3* = (UC_TRICORE_REG_A2 + 1).uc_tricore_reg
  UC_TRICORE_REG_A4* = (UC_TRICORE_REG_A3 + 1).uc_tricore_reg
  UC_TRICORE_REG_A5* = (UC_TRICORE_REG_A4 + 1).uc_tricore_reg
  UC_TRICORE_REG_A6* = (UC_TRICORE_REG_A5 + 1).uc_tricore_reg
  UC_TRICORE_REG_A7* = (UC_TRICORE_REG_A6 + 1).uc_tricore_reg
  UC_TRICORE_REG_A8* = (UC_TRICORE_REG_A7 + 1).uc_tricore_reg
  UC_TRICORE_REG_A9* = (UC_TRICORE_REG_A8 + 1).uc_tricore_reg
  UC_TRICORE_REG_A10* = (UC_TRICORE_REG_A9 + 1).uc_tricore_reg
  UC_TRICORE_REG_A11* = (UC_TRICORE_REG_A10 + 1).uc_tricore_reg
  UC_TRICORE_REG_A12* = (UC_TRICORE_REG_A11 + 1).uc_tricore_reg
  UC_TRICORE_REG_A13* = (UC_TRICORE_REG_A12 + 1).uc_tricore_reg
  UC_TRICORE_REG_A14* = (UC_TRICORE_REG_A13 + 1).uc_tricore_reg
  UC_TRICORE_REG_A15* = (UC_TRICORE_REG_A14 + 1).uc_tricore_reg ## ```
                                                                ##   Data GPR
                                                                ## ```
  UC_TRICORE_REG_D0* = (UC_TRICORE_REG_A15 + 1).uc_tricore_reg ## ```
                                                               ##   Data GPR
                                                               ## ```
  UC_TRICORE_REG_D1* = (UC_TRICORE_REG_D0 + 1).uc_tricore_reg
  UC_TRICORE_REG_D2* = (UC_TRICORE_REG_D1 + 1).uc_tricore_reg
  UC_TRICORE_REG_D3* = (UC_TRICORE_REG_D2 + 1).uc_tricore_reg
  UC_TRICORE_REG_D4* = (UC_TRICORE_REG_D3 + 1).uc_tricore_reg
  UC_TRICORE_REG_D5* = (UC_TRICORE_REG_D4 + 1).uc_tricore_reg
  UC_TRICORE_REG_D6* = (UC_TRICORE_REG_D5 + 1).uc_tricore_reg
  UC_TRICORE_REG_D7* = (UC_TRICORE_REG_D6 + 1).uc_tricore_reg
  UC_TRICORE_REG_D8* = (UC_TRICORE_REG_D7 + 1).uc_tricore_reg
  UC_TRICORE_REG_D9* = (UC_TRICORE_REG_D8 + 1).uc_tricore_reg
  UC_TRICORE_REG_D10* = (UC_TRICORE_REG_D9 + 1).uc_tricore_reg
  UC_TRICORE_REG_D11* = (UC_TRICORE_REG_D10 + 1).uc_tricore_reg
  UC_TRICORE_REG_D12* = (UC_TRICORE_REG_D11 + 1).uc_tricore_reg
  UC_TRICORE_REG_D13* = (UC_TRICORE_REG_D12 + 1).uc_tricore_reg
  UC_TRICORE_REG_D14* = (UC_TRICORE_REG_D13 + 1).uc_tricore_reg
  UC_TRICORE_REG_D15* = (UC_TRICORE_REG_D14 + 1).uc_tricore_reg
  UC_TRICORE_REG_PCXI* = (UC_TRICORE_REG_D15 + 1).uc_tricore_reg ## ```
                                                                 ##   CSFR Register
                                                                 ## ```
  UC_TRICORE_REG_PSW* = (UC_TRICORE_REG_PCXI + 1).uc_tricore_reg
  UC_TRICORE_REG_PSW_USB_C* = (UC_TRICORE_REG_PSW + 1).uc_tricore_reg ## ```
                                                                      ##   PSW flag cache for faster execution
                                                                      ## ```
  UC_TRICORE_REG_PSW_USB_V* = (UC_TRICORE_REG_PSW_USB_C + 1).uc_tricore_reg
  UC_TRICORE_REG_PSW_USB_SV* = (UC_TRICORE_REG_PSW_USB_V + 1).uc_tricore_reg
  UC_TRICORE_REG_PSW_USB_AV* = (UC_TRICORE_REG_PSW_USB_SV + 1).uc_tricore_reg
  UC_TRICORE_REG_PSW_USB_SAV* = (UC_TRICORE_REG_PSW_USB_AV + 1).uc_tricore_reg
  UC_TRICORE_REG_PC* = (UC_TRICORE_REG_PSW_USB_SAV + 1).uc_tricore_reg
  UC_TRICORE_REG_SYSCON* = (UC_TRICORE_REG_PC + 1).uc_tricore_reg
  UC_TRICORE_REG_CPU_ID* = (UC_TRICORE_REG_SYSCON + 1).uc_tricore_reg
  UC_TRICORE_REG_BIV* = (UC_TRICORE_REG_CPU_ID + 1).uc_tricore_reg
  UC_TRICORE_REG_BTV* = (UC_TRICORE_REG_BIV + 1).uc_tricore_reg
  UC_TRICORE_REG_ISP* = (UC_TRICORE_REG_BTV + 1).uc_tricore_reg
  UC_TRICORE_REG_ICR* = (UC_TRICORE_REG_ISP + 1).uc_tricore_reg
  UC_TRICORE_REG_FCX* = (UC_TRICORE_REG_ICR + 1).uc_tricore_reg
  UC_TRICORE_REG_LCX* = (UC_TRICORE_REG_FCX + 1).uc_tricore_reg
  UC_TRICORE_REG_COMPAT* = (UC_TRICORE_REG_LCX + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR0_U* = (UC_TRICORE_REG_COMPAT + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR1_U* = (UC_TRICORE_REG_DPR0_U + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR2_U* = (UC_TRICORE_REG_DPR1_U + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR3_U* = (UC_TRICORE_REG_DPR2_U + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR0_L* = (UC_TRICORE_REG_DPR3_U + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR1_L* = (UC_TRICORE_REG_DPR0_L + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR2_L* = (UC_TRICORE_REG_DPR1_L + 1).uc_tricore_reg
  UC_TRICORE_REG_DPR3_L* = (UC_TRICORE_REG_DPR2_L + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR0_U* = (UC_TRICORE_REG_DPR3_L + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR1_U* = (UC_TRICORE_REG_CPR0_U + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR2_U* = (UC_TRICORE_REG_CPR1_U + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR3_U* = (UC_TRICORE_REG_CPR2_U + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR0_L* = (UC_TRICORE_REG_CPR3_U + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR1_L* = (UC_TRICORE_REG_CPR0_L + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR2_L* = (UC_TRICORE_REG_CPR1_L + 1).uc_tricore_reg
  UC_TRICORE_REG_CPR3_L* = (UC_TRICORE_REG_CPR2_L + 1).uc_tricore_reg
  UC_TRICORE_REG_DPM0* = (UC_TRICORE_REG_CPR3_L + 1).uc_tricore_reg
  UC_TRICORE_REG_DPM1* = (UC_TRICORE_REG_DPM0 + 1).uc_tricore_reg
  UC_TRICORE_REG_DPM2* = (UC_TRICORE_REG_DPM1 + 1).uc_tricore_reg
  UC_TRICORE_REG_DPM3* = (UC_TRICORE_REG_DPM2 + 1).uc_tricore_reg
  UC_TRICORE_REG_CPM0* = (UC_TRICORE_REG_DPM3 + 1).uc_tricore_reg
  UC_TRICORE_REG_CPM1* = (UC_TRICORE_REG_CPM0 + 1).uc_tricore_reg
  UC_TRICORE_REG_CPM2* = (UC_TRICORE_REG_CPM1 + 1).uc_tricore_reg
  UC_TRICORE_REG_CPM3* = (UC_TRICORE_REG_CPM2 + 1).uc_tricore_reg
  UC_TRICORE_REG_MMU_CON* = (UC_TRICORE_REG_CPM3 + 1).uc_tricore_reg ## ```
                                                                     ##   Memory Management Registers
                                                                     ## ```
  UC_TRICORE_REG_MMU_ASI* = (UC_TRICORE_REG_MMU_CON + 1).uc_tricore_reg
  UC_TRICORE_REG_MMU_TVA* = (UC_TRICORE_REG_MMU_ASI + 1).uc_tricore_reg
  UC_TRICORE_REG_MMU_TPA* = (UC_TRICORE_REG_MMU_TVA + 1).uc_tricore_reg
  UC_TRICORE_REG_MMU_TPX* = (UC_TRICORE_REG_MMU_TPA + 1).uc_tricore_reg
  UC_TRICORE_REG_MMU_TFA* = (UC_TRICORE_REG_MMU_TPX + 1).uc_tricore_reg
  UC_TRICORE_REG_BMACON* = (UC_TRICORE_REG_MMU_TFA + 1).uc_tricore_reg ## ```
                                                                       ##   1.3.1 Only
                                                                       ## ```
  UC_TRICORE_REG_SMACON* = (UC_TRICORE_REG_BMACON + 1).uc_tricore_reg
  UC_TRICORE_REG_DIEAR* = (UC_TRICORE_REG_SMACON + 1).uc_tricore_reg
  UC_TRICORE_REG_DIETR* = (UC_TRICORE_REG_DIEAR + 1).uc_tricore_reg
  UC_TRICORE_REG_CCDIER* = (UC_TRICORE_REG_DIETR + 1).uc_tricore_reg
  UC_TRICORE_REG_MIECON* = (UC_TRICORE_REG_CCDIER + 1).uc_tricore_reg
  UC_TRICORE_REG_PIEAR* = (UC_TRICORE_REG_MIECON + 1).uc_tricore_reg
  UC_TRICORE_REG_PIETR* = (UC_TRICORE_REG_PIEAR + 1).uc_tricore_reg
  UC_TRICORE_REG_CCPIER* = (UC_TRICORE_REG_PIETR + 1).uc_tricore_reg
  UC_TRICORE_REG_DBGSR* = (UC_TRICORE_REG_CCPIER + 1).uc_tricore_reg ## ```
                                                                     ##   Debug Registers
                                                                     ## ```
  UC_TRICORE_REG_EXEVT* = (UC_TRICORE_REG_DBGSR + 1).uc_tricore_reg
  UC_TRICORE_REG_CREVT* = (UC_TRICORE_REG_EXEVT + 1).uc_tricore_reg
  UC_TRICORE_REG_SWEVT* = (UC_TRICORE_REG_CREVT + 1).uc_tricore_reg
  UC_TRICORE_REG_TR0EVT* = (UC_TRICORE_REG_SWEVT + 1).uc_tricore_reg
  UC_TRICORE_REG_TR1EVT* = (UC_TRICORE_REG_TR0EVT + 1).uc_tricore_reg
  UC_TRICORE_REG_DMS* = (UC_TRICORE_REG_TR1EVT + 1).uc_tricore_reg
  UC_TRICORE_REG_DCX* = (UC_TRICORE_REG_DMS + 1).uc_tricore_reg
  UC_TRICORE_REG_DBGTCR* = (UC_TRICORE_REG_DCX + 1).uc_tricore_reg
  UC_TRICORE_REG_CCTRL* = (UC_TRICORE_REG_DBGTCR + 1).uc_tricore_reg
  UC_TRICORE_REG_CCNT* = (UC_TRICORE_REG_CCTRL + 1).uc_tricore_reg
  UC_TRICORE_REG_ICNT* = (UC_TRICORE_REG_CCNT + 1).uc_tricore_reg
  UC_TRICORE_REG_M1CNT* = (UC_TRICORE_REG_ICNT + 1).uc_tricore_reg
  UC_TRICORE_REG_M2CNT* = (UC_TRICORE_REG_M1CNT + 1).uc_tricore_reg
  UC_TRICORE_REG_M3CNT* = (UC_TRICORE_REG_M2CNT + 1).uc_tricore_reg
  UC_TRICORE_REG_ENDING* = (UC_TRICORE_REG_M3CNT + 1).uc_tricore_reg ## ```
                                                                     ##   <-- mark the end of the list of registers
                                                                     ##      alias registers
                                                                     ## ```
  UC_TRICORE_REG_GA0* = (UC_TRICORE_REG_A0).uc_tricore_reg ## ```
                                                           ##   <-- mark the end of the list of registers
                                                           ##      alias registers
                                                           ## ```
  UC_TRICORE_REG_GA1* = (UC_TRICORE_REG_A1).uc_tricore_reg
  UC_TRICORE_REG_GA8* = (UC_TRICORE_REG_A8).uc_tricore_reg
  UC_TRICORE_REG_GA9* = (UC_TRICORE_REG_A9).uc_tricore_reg
  UC_TRICORE_REG_SP* = (UC_TRICORE_REG_A10).uc_tricore_reg
  UC_TRICORE_REG_LR* = (UC_TRICORE_REG_A11).uc_tricore_reg
  UC_TRICORE_REG_IA* = (UC_TRICORE_REG_A15).uc_tricore_reg
  UC_TRICORE_REG_ID* = (UC_TRICORE_REG_D15).uc_tricore_reg
  UC_API_MAJOR* = 2
  UC_API_MINOR* = 0
  UC_API_PATCH* = 1
  UC_API_EXTRA* = 255
  UC_SECOND_SCALE* = 1000000
  UC_MILISECOND_SCALE* = 1000
  UC_ARCH_ARM* = (1).uc_arch ## ```
                             ##   ARM architecture (including Thumb, Thumb-2)
                             ## ```
  UC_ARCH_ARM64* = (UC_ARCH_ARM + 1).uc_arch ## ```
                                             ##   ARM-64, also called AArch64
                                             ## ```
  UC_ARCH_MIPS* = (UC_ARCH_ARM64 + 1).uc_arch ## ```
                                              ##   Mips architecture
                                              ## ```
  UC_ARCH_X86* = (UC_ARCH_MIPS + 1).uc_arch ## ```
                                            ##   X86 architecture (including x86 & x86-64)
                                            ## ```
  UC_ARCH_PPC* = (UC_ARCH_X86 + 1).uc_arch ## ```
                                           ##   PowerPC architecture
                                           ## ```
  UC_ARCH_SPARC* = (UC_ARCH_PPC + 1).uc_arch ## ```
                                             ##   Sparc architecture
                                             ## ```
  UC_ARCH_M68K* = (UC_ARCH_SPARC + 1).uc_arch ## ```
                                              ##   M68K architecture
                                              ## ```
  UC_ARCH_RISCV* = (UC_ARCH_M68K + 1).uc_arch ## ```
                                              ##   RISCV architecture
                                              ## ```
  UC_ARCH_S390X* = (UC_ARCH_RISCV + 1).uc_arch ## ```
                                               ##   S390X architecture
                                               ## ```
  UC_ARCH_TRICORE* = (UC_ARCH_S390X + 1).uc_arch ## ```
                                                 ##   TriCore architecture
                                                 ## ```
  UC_ARCH_MAX* = (UC_ARCH_TRICORE + 1).uc_arch ## ```
                                               ##   TriCore architecture
                                               ## ```
  UC_MODE_LITTLE_ENDIAN* = (0).uc_mode ## ```
                                       ##   little-endian mode (default mode)
                                       ## ```
  UC_MODE_BIG_ENDIAN* = (1 shl typeof(1)(30)).uc_mode ## ```
                                                      ##   big-endian mode
                                                      ##      arm / arm64
                                                      ## ```
  UC_MODE_ARM* = (0).uc_mode ## ```
                             ##   ARM mode
                             ## ```
  UC_MODE_THUMB* = (1 shl typeof(1)(4)).uc_mode ## ```
                                                ##   THUMB mode (including Thumb-2)
                                                ##      Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
                                                ## ```
  UC_MODE_MCLASS* = (1 shl typeof(1)(5)).uc_mode ## ```
                                                 ##   ARM's Cortex-M series.
                                                 ## ```
  UC_MODE_V8* = (1 shl typeof(1)(6)).uc_mode ## ```
                                             ##   ARMv8 A32 encodings for ARM
                                             ## ```
  UC_MODE_ARMBE8* = (1 shl typeof(1)(10)).uc_mode ## ```
                                                  ##   Big-endian data and Little-endian code.
                                                  ##      Legacy support for UC1 only.
                                                  ##      arm (32bit) cpu types
                                                  ##      Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
                                                  ## ```
  UC_MODE_ARM926* = (1 shl typeof(1)(7)).uc_mode ## ```
                                                 ##   ARM926 CPU type
                                                 ## ```
  UC_MODE_ARM946* = (1 shl typeof(1)(8)).uc_mode ## ```
                                                 ##   ARM946 CPU type
                                                 ## ```
  UC_MODE_ARM1176* = (1 shl typeof(1)(9)).uc_mode ## ```
                                                  ##   ARM1176 CPU type
                                                  ##      mips
                                                  ## ```
  UC_MODE_MICRO* = (1 shl typeof(1)(4)).uc_mode ## ```
                                                ##   MicroMips mode (currently unsupported)
                                                ## ```
  UC_MODE_MIPS3* = (1 shl typeof(1)(5)).uc_mode ## ```
                                                ##   Mips III ISA (currently unsupported)
                                                ## ```
  UC_MODE_MIPS32R6* = (1 shl typeof(1)(6)).uc_mode ## ```
                                                   ##   Mips32r6 ISA (currently unsupported)
                                                   ## ```
  UC_MODE_MIPS32* = (1 shl typeof(1)(2)).uc_mode ## ```
                                                 ##   Mips32 ISA
                                                 ## ```
  UC_MODE_MIPS64* = (1 shl typeof(1)(3)).uc_mode ## ```
                                                 ##   Mips64 ISA
                                                 ##      x86 / x64
                                                 ## ```
  UC_MODE_16* = (1 shl typeof(1)(1)).uc_mode ## ```
                                             ##   16-bit mode
                                             ## ```
  UC_MODE_32* = (1 shl typeof(1)(2)).uc_mode ## ```
                                             ##   32-bit mode
                                             ## ```
  UC_MODE_64* = (1 shl typeof(1)(3)).uc_mode ## ```
                                             ##   64-bit mode
                                             ##      ppc
                                             ## ```
  UC_MODE_PPC32* = (1 shl typeof(1)(2)).uc_mode ## ```
                                                ##   32-bit mode
                                                ## ```
  UC_MODE_PPC64* = (1 shl typeof(1)(3)).uc_mode ## ```
                                                ##   64-bit mode (currently unsupported)
                                                ## ```
  UC_MODE_QPX* = (1 shl typeof(1)(4)).uc_mode ## ```
                                              ##   64-bit mode (currently unsupported)
                                              ## ```
  UC_MODE_SPARC32* = (1 shl typeof(1)(2)).uc_mode ## ```
                                                  ##   32-bit mode
                                                  ## ```
  UC_MODE_SPARC64* = (1 shl typeof(1)(3)).uc_mode ## ```
                                                  ##   64-bit mode
                                                  ## ```
  UC_MODE_V9* = (1 shl typeof(1)(4)).uc_mode ## ```
                                             ##   SparcV9 mode (currently unsupported)
                                             ##      riscv
                                             ## ```
  UC_MODE_RISCV32* = (1 shl typeof(1)(2)).uc_mode ## ```
                                                  ##   32-bit mode
                                                  ## ```
  UC_MODE_RISCV64* = (1 shl typeof(1)(3)).uc_mode ## ```
                                                  ##   64-bit mode
                                                  ##      m68k
                                                  ## ```
  UC_ERR_OK* = (0).uc_err    ## ```
                             ##   No error: everything was fine
                             ## ```
  UC_ERR_NOMEM* = (UC_ERR_OK + 1).uc_err ## ```
                                         ##   Out-Of-Memory error: uc_open(), uc_emulate()
                                         ## ```
  UC_ERR_ARCH* = (UC_ERR_NOMEM + 1).uc_err ## ```
                                           ##   Unsupported architecture: uc_open()
                                           ## ```
  UC_ERR_HANDLE* = (UC_ERR_ARCH + 1).uc_err ## ```
                                            ##   Invalid handle
                                            ## ```
  UC_ERR_MODE* = (UC_ERR_HANDLE + 1).uc_err ## ```
                                            ##   Invalid/unsupported mode: uc_open()
                                            ## ```
  UC_ERR_VERSION* = (UC_ERR_MODE + 1).uc_err ## ```
                                             ##   Unsupported version (bindings)
                                             ## ```
  UC_ERR_READ_UNMAPPED* = (UC_ERR_VERSION + 1).uc_err ## ```
                                                      ##   Quit emulation due to READ on unmapped memory:
                                                      ##      uc_emu_start()
                                                      ## ```
  UC_ERR_WRITE_UNMAPPED* = (UC_ERR_READ_UNMAPPED + 1).uc_err ## ```
                                                             ##   Quit emulation due to WRITE on unmapped memory:
                                                             ##      uc_emu_start()
                                                             ## ```
  UC_ERR_FETCH_UNMAPPED* = (UC_ERR_WRITE_UNMAPPED + 1).uc_err ## ```
                                                              ##   Quit emulation due to FETCH on unmapped memory:
                                                              ##      uc_emu_start()
                                                              ## ```
  UC_ERR_HOOK* = (UC_ERR_FETCH_UNMAPPED + 1).uc_err ## ```
                                                    ##   Invalid hook type: uc_hook_add()
                                                    ## ```
  UC_ERR_INSN_INVALID* = (UC_ERR_HOOK + 1).uc_err ## ```
                                                  ##   Quit emulation due to invalid instruction:
                                                  ##      uc_emu_start()
                                                  ## ```
  UC_ERR_MAP* = (UC_ERR_INSN_INVALID + 1).uc_err ## ```
                                                 ##   Invalid memory mapping: uc_mem_map()
                                                 ## ```
  UC_ERR_WRITE_PROT* = (UC_ERR_MAP + 1).uc_err ## ```
                                               ##   Quit emulation due to UC_MEM_WRITE_PROT violation:
                                               ##      uc_emu_start()
                                               ## ```
  UC_ERR_READ_PROT* = (UC_ERR_WRITE_PROT + 1).uc_err ## ```
                                                     ##   Quit emulation due to UC_MEM_READ_PROT violation:
                                                     ##      uc_emu_start()
                                                     ## ```
  UC_ERR_FETCH_PROT* = (UC_ERR_READ_PROT + 1).uc_err ## ```
                                                     ##   Quit emulation due to UC_MEM_FETCH_PROT violation:
                                                     ##      uc_emu_start()
                                                     ## ```
  UC_ERR_ARG* = (UC_ERR_FETCH_PROT + 1).uc_err ## ```
                                               ##   Inavalid argument provided to uc_xxx function (See specific
                                               ##      function API)
                                               ## ```
  UC_ERR_READ_UNALIGNED* = (UC_ERR_ARG + 1).uc_err ## ```
                                                   ##   Unaligned read
                                                   ## ```
  UC_ERR_WRITE_UNALIGNED* = (UC_ERR_READ_UNALIGNED + 1).uc_err ## ```
                                                               ##   Unaligned write
                                                               ## ```
  UC_ERR_FETCH_UNALIGNED* = (UC_ERR_WRITE_UNALIGNED + 1).uc_err ## ```
                                                                ##   Unaligned fetch
                                                                ## ```
  UC_ERR_HOOK_EXIST* = (UC_ERR_FETCH_UNALIGNED + 1).uc_err ## ```
                                                           ##   hook for this event already existed
                                                           ## ```
  UC_ERR_RESOURCE* = (UC_ERR_HOOK_EXIST + 1).uc_err ## ```
                                                    ##   Insufficient resource: uc_emu_start()
                                                    ## ```
  UC_ERR_EXCEPTION* = (UC_ERR_RESOURCE + 1).uc_err ## ```
                                                   ##   Unhandled CPU exception
                                                   ## ```
  UC_MEM_READ* = (16).uc_mem_type ## ```
                                  ##   Memory is read from
                                  ## ```
  UC_MEM_WRITE* = (UC_MEM_READ + 1).uc_mem_type ## ```
                                                ##   Memory is written to
                                                ## ```
  UC_MEM_FETCH* = (UC_MEM_WRITE + 1).uc_mem_type ## ```
                                                 ##   Memory is fetched
                                                 ## ```
  UC_MEM_READ_UNMAPPED* = (UC_MEM_FETCH + 1).uc_mem_type ## ```
                                                         ##   Unmapped memory is read from
                                                         ## ```
  UC_MEM_WRITE_UNMAPPED* = (UC_MEM_READ_UNMAPPED + 1).uc_mem_type ## ```
                                                                  ##   Unmapped memory is written to
                                                                  ## ```
  UC_MEM_FETCH_UNMAPPED* = (UC_MEM_WRITE_UNMAPPED + 1).uc_mem_type ## ```
                                                                   ##   Unmapped memory is fetched
                                                                   ## ```
  UC_MEM_WRITE_PROT* = (UC_MEM_FETCH_UNMAPPED + 1).uc_mem_type ## ```
                                                               ##   Write to write protected, but mapped, memory
                                                               ## ```
  UC_MEM_READ_PROT* = (UC_MEM_WRITE_PROT + 1).uc_mem_type ## ```
                                                          ##   Read from read protected, but mapped, memory
                                                          ## ```
  UC_MEM_FETCH_PROT* = (UC_MEM_READ_PROT + 1).uc_mem_type ## ```
                                                          ##   Fetch from non-executable, but mapped, memory
                                                          ## ```
  UC_MEM_READ_AFTER* = (UC_MEM_FETCH_PROT + 1).uc_mem_type ## ```
                                                           ##   Memory is read from (successful access)
                                                           ## ```
  UC_TCG_OP_SUB* = (0).uc_tcg_op_code ## ```
                                      ##   Both sub_i32 and sub_i64
                                      ## ```
  UC_TCG_OP_FLAG_CMP* = (1 shl typeof(1)(0)).uc_tcg_op_flag ## ```
                                                            ##   Only instrument opcode if it would set cc_dst, i.e. cmp instruction.
                                                            ## ```
  UC_TCG_OP_FLAG_DIRECT* = (1 shl typeof(1)(1)).uc_tcg_op_flag ## ```
                                                               ##   Only instrument opcode which is directly translated.
                                                               ##      i.e. x86 sub/subc -> tcg sub_i32/64
                                                               ## ```
  UC_HOOK_INTR* = (1 shl typeof(1)(0)).uc_hook_type ## ```
                                                    ##   Hook all interrupt/syscall events
                                                    ## ```
  UC_HOOK_INSN* = (1 shl typeof(1)(1)).uc_hook_type ## ```
                                                    ##   Hook a particular instruction - only a very small subset of instructions
                                                    ##      supported here
                                                    ## ```
  UC_HOOK_CODE* = (1 shl typeof(1)(2)).uc_hook_type ## ```
                                                    ##   Hook a range of code
                                                    ## ```
  UC_HOOK_BLOCK* = (1 shl typeof(1)(3)).uc_hook_type ## ```
                                                     ##   Hook basic blocks
                                                     ## ```
  UC_HOOK_MEM_READ_UNMAPPED* = (1 shl typeof(1)(4)).uc_hook_type ## ```
                                                                 ##   Hook for memory read on unmapped memory
                                                                 ## ```
  UC_HOOK_MEM_WRITE_UNMAPPED* = (1 shl typeof(1)(5)).uc_hook_type ## ```
                                                                  ##   Hook for invalid memory write events
                                                                  ## ```
  UC_HOOK_MEM_FETCH_UNMAPPED* = (1 shl typeof(1)(6)).uc_hook_type ## ```
                                                                  ##   Hook for invalid memory fetch for execution events
                                                                  ## ```
  UC_HOOK_MEM_READ_PROT* = (1 shl typeof(1)(7)).uc_hook_type ## ```
                                                             ##   Hook for memory read on read-protected memory
                                                             ## ```
  UC_HOOK_MEM_WRITE_PROT* = (1 shl typeof(1)(8)).uc_hook_type ## ```
                                                              ##   Hook for memory write on write-protected memory
                                                              ## ```
  UC_HOOK_MEM_FETCH_PROT* = (1 shl typeof(1)(9)).uc_hook_type ## ```
                                                              ##   Hook for memory fetch on non-executable memory
                                                              ## ```
  UC_HOOK_MEM_READ* = (1 shl typeof(1)(10)).uc_hook_type ## ```
                                                         ##   Hook memory read events.
                                                         ## ```
  UC_HOOK_MEM_WRITE* = (1 shl typeof(1)(11)).uc_hook_type ## ```
                                                          ##   Hook memory write events.
                                                          ## ```
  UC_HOOK_MEM_FETCH* = (1 shl typeof(1)(12)).uc_hook_type ## ```
                                                          ##   Hook memory fetch for execution events
                                                          ## ```
  UC_HOOK_MEM_READ_AFTER* = (1 shl typeof(1)(13)).uc_hook_type ## ```
                                                               ##   Hook memory read events, but only successful access.
                                                               ##      The callback will be triggered after successful read.
                                                               ## ```
  UC_HOOK_INSN_INVALID* = (1 shl typeof(1)(14)).uc_hook_type ## ```
                                                             ##   Hook invalid instructions exceptions.
                                                             ## ```
  UC_HOOK_EDGE_GENERATED* = (1 shl typeof(1)(15)).uc_hook_type ## ```
                                                               ##   Hook on new edge generation. Could be useful in program analysis.
                                                               ##     
                                                               ##      NOTE: This is different from UC_HOOK_BLOCK in 2 ways:
                                                               ##            1. The hook is called before executing code.
                                                               ##            2. The hook is only called when generation is triggered.
                                                               ## ```
  UC_HOOK_TCG_OPCODE* = (1 shl typeof(1)(16)).uc_hook_type ## ```
                                                           ##   Hook on specific tcg op code. The usage of this hook is similar to
                                                           ##      UC_HOOK_INSN.
                                                           ## ```
  UC_HOOK_MEM_UNMAPPED* = (UC_HOOK_MEM_READ_UNMAPPED +
      typeof(UC_HOOK_MEM_READ_UNMAPPED)(UC_HOOK_MEM_WRITE_UNMAPPED) +
      typeof(UC_HOOK_MEM_READ_UNMAPPED)(UC_HOOK_MEM_FETCH_UNMAPPED))
  UC_HOOK_MEM_PROT* = (UC_HOOK_MEM_READ_PROT +
      typeof(UC_HOOK_MEM_READ_PROT)(UC_HOOK_MEM_WRITE_PROT) +
      typeof(UC_HOOK_MEM_READ_PROT)(UC_HOOK_MEM_FETCH_PROT))
  UC_HOOK_MEM_READ_INVALID* = (UC_HOOK_MEM_READ_PROT +
      typeof(UC_HOOK_MEM_READ_PROT)(UC_HOOK_MEM_READ_UNMAPPED))
  UC_HOOK_MEM_WRITE_INVALID* = (UC_HOOK_MEM_WRITE_PROT +
      typeof(UC_HOOK_MEM_WRITE_PROT)(UC_HOOK_MEM_WRITE_UNMAPPED))
  UC_HOOK_MEM_FETCH_INVALID* = (UC_HOOK_MEM_FETCH_PROT +
      typeof(UC_HOOK_MEM_FETCH_PROT)(UC_HOOK_MEM_FETCH_UNMAPPED))
  UC_HOOK_MEM_INVALID* = (
    UC_HOOK_MEM_UNMAPPED + typeof(UC_HOOK_MEM_UNMAPPED)(UC_HOOK_MEM_PROT))
  UC_HOOK_MEM_VALID* = (UC_HOOK_MEM_READ +
      typeof(UC_HOOK_MEM_READ)(UC_HOOK_MEM_WRITE) +
      typeof(UC_HOOK_MEM_READ)(UC_HOOK_MEM_FETCH))
  UC_QUERY_MODE* = (1).uc_query_type ## ```
                                     ##   Dynamically query current hardware mode.
                                     ## ```
  UC_QUERY_PAGE_SIZE* = (UC_QUERY_MODE + 1).uc_query_type ## ```
                                                          ##   query pagesize of engine
                                                          ## ```
  UC_QUERY_ARCH* = (UC_QUERY_PAGE_SIZE + 1).uc_query_type ## ```
                                                          ##   query architecture of engine (for ARM to query Thumb mode)
                                                          ## ```
  UC_QUERY_TIMEOUT* = (UC_QUERY_ARCH + 1).uc_query_type ## ```
                                                        ##   query if emulation stops due to timeout (indicated if
                                                        ##      result = True)
                                                        ## ```
  UC_CTL_IO_NONE* = (0)
  UC_CTL_IO_WRITE* = (1)
  UC_CTL_IO_READ* = (2)
  UC_CTL_IO_READ_WRITE* = (
    UC_CTL_IO_WRITE or typeof(UC_CTL_IO_WRITE)(UC_CTL_IO_READ))
  UC_CTL_UC_MODE* = (0).uc_control_type ## ```
                                        ##   Current mode.
                                        ##      Read: @args = (int*)
                                        ## ```
  UC_CTL_UC_PAGE_SIZE* = (UC_CTL_UC_MODE + 1).uc_control_type ## ```
                                                              ##   Curent page size.
                                                              ##      Write: @args = (uint32_t)
                                                              ##      Read: @args = (uint32_t*)
                                                              ## ```
  UC_CTL_UC_ARCH* = (UC_CTL_UC_PAGE_SIZE + 1).uc_control_type ## ```
                                                              ##   Current arch.
                                                              ##      Read: @args = (int*)
                                                              ## ```
  UC_CTL_UC_TIMEOUT* = (UC_CTL_UC_ARCH + 1).uc_control_type ## ```
                                                            ##   Current timeout.
                                                            ##      Read: @args = (uint64_t*)
                                                            ## ```
  UC_CTL_UC_USE_EXITS* = (UC_CTL_UC_TIMEOUT + 1).uc_control_type ## ```
                                                                 ##   Enable multiple exits.
                                                                 ##      Without this control, reading/setting exits won't work.
                                                                 ##      This is for API backward compatibility.
                                                                 ##      Write: @args = (int)
                                                                 ## ```
  UC_CTL_UC_EXITS_CNT* = (UC_CTL_UC_USE_EXITS + 1).uc_control_type ## ```
                                                                   ##   The number of current exits.
                                                                   ##      Read: @args = (size_t*)
                                                                   ## ```
  UC_CTL_UC_EXITS* = (UC_CTL_UC_EXITS_CNT + 1).uc_control_type ## ```
                                                               ##   Current exits.
                                                               ##      Write: @args = (uint64_t* exits, size_t len)
                                                               ##             @len = UC_CTL_UC_EXITS_CNT
                                                               ##      Read: @args = (uint64_t* exits, size_t len)
                                                               ##            @len = UC_CTL_UC_EXITS_CNT
                                                               ## ```
  UC_CTL_CPU_MODEL* = (UC_CTL_UC_EXITS + 1).uc_control_type ## ```
                                                            ##   Set the cpu model of uc.
                                                            ##      Note this option can only be set before any Unicorn
                                                            ##      API is called except for uc_open.
                                                            ##      Write: @args = (int)
                                                            ##      Read:  @args = (int*)
                                                            ## ```
  UC_CTL_TB_REQUEST_CACHE* = (UC_CTL_CPU_MODEL + 1).uc_control_type ## ```
                                                                    ##   Request a tb cache at a specific address
                                                                    ##      Read: @args = (uint64_t, uc_tb*)
                                                                    ## ```
  UC_CTL_TB_REMOVE_CACHE* = (UC_CTL_TB_REQUEST_CACHE + 1).uc_control_type ## ```
                                                                          ##   Invalidate a tb cache at a specific address
                                                                          ##      Write: @args = (uint64_t, uint64_t)
                                                                          ## ```
  UC_CTL_TB_FLUSH* = (UC_CTL_TB_REMOVE_CACHE + 1).uc_control_type ## ```
                                                                  ##   Invalidate all translation blocks.
                                                                  ##      No arguments.
                                                                  ## ```
  UC_PROT_NONE* = (0).uc_prot
  UC_PROT_READ* = (1).uc_prot
  UC_PROT_WRITE* = (2).uc_prot
  UC_PROT_EXEC* = (4).uc_prot
  UC_PROT_ALL* = (7).uc_prot
type
  uc_struct* {.incompleteStruct, impunicornHdr, importc: "struct uc_struct".} = object
  uc_engine* {.importc, impunicornHdr.} = uc_struct
  uc_hook* {.importc, impunicornHdr.} = uint
  uc_x86_mmr* {.bycopy, impunicornHdr, importc: "struct uc_x86_mmr".} = object ## ```
                                                                                ##   Memory-Management Register for instructions IDTR, GDTR, LDTR, TR.
                                                                                ##      Borrow from SegmentCache in qemu/target-i386/cpu.h
                                                                                ## ```
    selector*: uint16        ## ```
                             ##   not used by GDTR and IDTR
                             ## ```
    base*: uint64            ## ```
                             ##   handle 32 or 64 bit CPUs
                             ## ```
    limit*: uint32           ## ```
                             ##   handle 32 or 64 bit CPUs
                             ## ```
    flags*: uint32           ## ```
                             ##   not used by GDTR and IDTR
                             ## ```
  
  uc_x86_msr* {.bycopy, impunicornHdr, importc: "struct uc_x86_msr".} = object ## ```
                                                                                ##   Model-Specific Register structure, use this with UC_X86_REG_MSR (as the
                                                                                ##      register ID) in call to uc_reg_write/uc_reg_read() to manipulate MSRs.
                                                                                ## ```
    rid*: uint32             ## ```
                             ##   MSR id
                             ## ```
    value*: uint64           ## ```
                             ##   MSR value
                             ## ```
  
  uc_cb_insn_syscall_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_struct;
      user_data: pointer) {.cdecl.}
  uc_cb_insn_cpuid_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_struct;
      user_data: pointer): cint {.cdecl.}
  uc_arm_cp_reg* {.bycopy, impunicornHdr, importc: "struct uc_arm_cp_reg".} = object ## ```
                                                                                      ##   ARM coprocessor registers, use this with UC_ARM_REG_CP_REG to
                                                                                      ##      in call to uc_reg_write/read() to access the registers.
                                                                                      ## ```
    cp*: uint32              ## ```
                             ##   The coprocessor identifier
                             ## ```
    is64*: uint32            ## ```
                             ##   Is it a 64 bit control register
                             ## ```
    sec*: uint32             ## ```
                             ##   Security state
                             ## ```
    crn*: uint32             ## ```
                             ##   Coprocessor register number
                             ## ```
    crm*: uint32             ## ```
                             ##   Coprocessor register number
                             ## ```
    opc1*: uint32            ## ```
                             ##   Opcode1
                             ## ```
    opc2*: uint32            ## ```
                             ##   Opcode2
                             ## ```
    val*: uint64             ## ```
                             ##   The value to read/write
                             ## ```
  
  uc_arm64_cp_reg* {.bycopy, impunicornHdr, importc: "struct uc_arm64_cp_reg".} = object ## ```
                                                                                          ##   ARM64 coprocessor registers, use this with UC_ARM64_REG_CP_REG to
                                                                                          ##      in call to uc_reg_write/read() to access the registers.
                                                                                          ## ```
    crn*: uint32             ## ```
                             ##   Coprocessor register number
                             ## ```
    crm*: uint32             ## ```
                             ##   Coprocessor register number
                             ## ```
    op0*: uint32             ## ```
                             ##   Opcode0
                             ## ```
    op1*: uint32             ## ```
                             ##   Opcode1
                             ## ```
    op2*: uint32             ## ```
                             ##   Opcode2
                             ## ```
    val*: uint64             ## ```
                             ##   The value to read/write
                             ## ```
  
  uc_cb_insn_sys_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      reg: uc_arm64_reg; cp_reg: ptr uc_arm64_cp_reg; user_data: pointer): uint32 {.
      cdecl.}
  uc_cb_hookcode_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      address: uint64; size: uint32; user_data: pointer) {.cdecl.}
  uc_cb_hookintr_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      intno: uint32; user_data: pointer) {.cdecl.}
  uc_cb_hookinsn_invalid_t* {.importc, impunicornHdr.} = proc (
      uc: ptr uc_engine; user_data: pointer): bool {.cdecl.}
  uc_cb_insn_in_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      port: uint32; size: cint; user_data: pointer): uint32 {.cdecl.}
  uc_cb_insn_out_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      port: uint32; size: cint; value: uint32; user_data: pointer) {.cdecl.}
  uc_tb* {.bycopy, impunicornHdr, importc: "struct uc_tb".} = object ## ```
                                                                      ##   Represent a TranslationBlock.
                                                                      ## ```
    pc*: uint64
    icount*: uint16
    size*: uint16

  uc_hook_edge_gen_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      cur_tb: ptr uc_tb; prev_tb: ptr uc_tb; user_data: pointer) {.cdecl.}
  uc_hook_tcg_op_2* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      address: uint64; arg1: uint64; arg2: uint64; size: uint32;
      user_data: pointer) {.cdecl.}
  uc_hook_tcg_sub_t* {.importc, impunicornHdr.} = uc_hook_tcg_op_2
  uc_cb_mmio_read_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      offset: uint64; size: cuint; user_data: pointer): uint64 {.cdecl.}
  uc_cb_mmio_write_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      offset: uint64; size: cuint; value: uint64; user_data: pointer) {.cdecl.}
  uc_cb_hookmem_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      `type`: uc_mem_type; address: uint64; size: cint; value: int64;
      user_data: pointer) {.cdecl.}
  uc_cb_eventmem_t* {.importc, impunicornHdr.} = proc (uc: ptr uc_engine;
      `type`: uc_mem_type; address: uint64; size: cint; value: int64;
      user_data: pointer): bool {.cdecl.}
  uc_mem_region* {.bycopy, impunicornHdr, importc: "struct uc_mem_region".} = object ## ```
                                                                                      ##   Memory region mapped by uc_mem_map() and uc_mem_map_ptr()
                                                                                      ##     Retrieve the list of memory regions with uc_mem_regions()
                                                                                      ## ```
    begin*: uint64           ## ```
                             ##   begin address of the region (inclusive)
                             ## ```
    `end`*: uint64           ## ```
                             ##   end address of the region (inclusive)
                             ## ```
    perms*: uint32           ## ```
                             ##   memory permissions of the region
                             ## ```
  
  uc_context* {.incompleteStruct, impunicornHdr, importc: "struct uc_context".} = object
proc uc_version*(major: ptr cuint; minor: ptr cuint): cuint {.importc, cdecl,
    impunicornHdr.}
proc uc_arch_supported*(arch: uc_arch): bool {.importc, cdecl, impunicornHdr.}
proc uc_open*(arch: uc_arch; mode: uc_mode; uc: ptr ptr uc_engine): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_close*(uc: ptr uc_engine): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_query*(uc: ptr uc_engine; `type`: uc_query_type; result: ptr uint): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_ctl*(uc: ptr uc_engine; control: uc_control_type): uc_err {.importc,
    cdecl, impunicornHdr, varargs.}
proc uc_errno*(uc: ptr uc_engine): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_strerror*(code: uc_err): cstring {.importc, cdecl, impunicornHdr.}
proc uc_reg_write*(uc: ptr uc_engine; regid: cint; value: pointer): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_reg_read*(uc: ptr uc_engine; regid: cint; value: pointer): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_reg_write_batch*(uc: ptr uc_engine; regs: ptr cint; vals: ptr pointer;
                         count: cint): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_reg_read_batch*(uc: ptr uc_engine; regs: ptr cint; vals: ptr pointer;
                        count: cint): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_mem_write*(uc: ptr uc_engine; address: uint64; bytes: pointer;
                   size: uint): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_mem_read*(uc: ptr uc_engine; address: uint64; bytes: pointer; size: uint): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_emu_start*(uc: ptr uc_engine; begin: uint64; until: uint64;
                   timeout: uint64; count: uint): uc_err {.importc, cdecl,
    impunicornHdr.}
proc uc_emu_stop*(uc: ptr uc_engine): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_hook_add*(uc: ptr uc_engine; hh: ptr uc_hook; `type`: cint;
                  callback: pointer; user_data: pointer; begin: uint64;
                  `end`: uint64): uc_err {.importc, cdecl, impunicornHdr,
    varargs.}
proc uc_hook_del*(uc: ptr uc_engine; hh: uc_hook): uc_err {.importc, cdecl,
    impunicornHdr.}
proc uc_mem_map*(uc: ptr uc_engine; address: uint64; size: uint; perms: uint32): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_mem_map_ptr*(uc: ptr uc_engine; address: uint64; size: uint;
                     perms: uint32; `ptr`: pointer): uc_err {.importc, cdecl,
    impunicornHdr.}
proc uc_mmio_map*(uc: ptr uc_engine; address: uint64; size: uint;
                  read_cb: uc_cb_mmio_read_t; user_data_read: pointer;
                  write_cb: uc_cb_mmio_write_t; user_data_write: pointer): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_mem_unmap*(uc: ptr uc_engine; address: uint64; size: uint): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_mem_protect*(uc: ptr uc_engine; address: uint64; size: uint;
                     perms: uint32): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_mem_regions*(uc: ptr uc_engine; regions: ptr ptr uc_mem_region;
                     count: ptr uint32): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_context_alloc*(uc: ptr uc_engine; context: ptr ptr uc_context): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_free*(mem: pointer): uc_err {.importc, cdecl, impunicornHdr.}
proc uc_context_save*(uc: ptr uc_engine; context: ptr uc_context): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_reg_write*(ctx: ptr uc_context; regid: cint; value: pointer): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_reg_read*(ctx: ptr uc_context; regid: cint; value: pointer): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_reg_write_batch*(ctx: ptr uc_context; regs: ptr cint;
                                 vals: ptr pointer; count: cint): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_reg_read_batch*(ctx: ptr uc_context; regs: ptr cint;
                                vals: ptr pointer; count: cint): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_restore*(uc: ptr uc_engine; context: ptr uc_context): uc_err {.
    importc, cdecl, impunicornHdr.}
proc uc_context_size*(uc: ptr uc_engine): uint {.importc, cdecl, impunicornHdr.}
proc uc_context_free*(context: ptr uc_context): uc_err {.importc, cdecl,
    impunicornHdr.}
{.pop.}
