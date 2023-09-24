# Nim's unicorn engine binding

`/home/dmknght/.nimble/pkgs/nimterop-#head/nimterop/toast --prefix=_ --suffix=_ -s -G__=_ --preprocess -m:c --recurse --pnim --nim:/usr/bin/nim /usr/include/unicorn/unicorn.h --includeDirs+=/usr/include/unicorn/ -o /tmp/unicorn`

Sample code (compile and run with `nim c -r --passL:-lunicorn <nim src>`). Current code is having a runtime bug, failed to start emu
```
import unimcorn
import strutils


const
  ADDRESS = 0x1000000

var
  uc: ptr uc_engine
  err: uc_err
  r_ecx: cint = 0x1234
  r_edx: cint = 0x7890
  X86_CODE32: cstring = "\x41\x4a"


proc main() =
  if uc_open(UC_ARCH_X86, UC_MODE_32, addr(uc)) != UC_ERR_OK:
    echo "Failed on uc_open()"
    return

  # map 2MB memory for this emulation
  if uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, uint32(UC_PROT_ALL)) != UC_ERR_OK:
    echo "Failed to write mem map"
    return

  if uc_mem_write(uc, ADDRESS, addr(X86_CODE32), uint(len(X86_CODE32))) != UC_ERR_OK:
    echo "Failed to write emulation code to memory"
    return

  if uc_reg_write(uc, cint(UC_X86_REG_ECX), addr(r_ecx)) != UC_ERR_OK:
    echo "Error writing r_ecx"
    return

  if uc_reg_write(uc, cint(UC_X86_REG_EDX), addr(r_edx)) != UC_ERR_OK:
    echo "Error writing r_edx"
    return

  err = uc_emu_start(uc, ADDRESS, ADDRESS + uint(len(X86_CODE32)), 0, 0)
  if err != UC_ERR_OK:
    echo "Failed on emu start, error: ", uc_strerror(err)
    # return

  echo "Emulator done. Reading CPU context"

  if uc_reg_read(uc, cint(UC_X86_REG_ECX), addr(r_ecx)) == UC_ERR_OK:
    echo "ECX: 0x", toHex(r_ecx)
  else:
    echo "Failed to read ECX"

  if uc_reg_read(uc, cint(UC_X86_REG_EDX), addr(r_edx)) == UC_ERR_OK:
    echo "EDX: 0x", toHex(r_edx)
  else:
    echo "Failed to read EDX"

  discard uc_close(uc)

main()
```