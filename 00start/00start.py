# This code is the property of Mantra Information Security and is provided 
# solely for use within the x86/x64 Reverse Engineering training course or
# one of its related workshops.
# It is confidential and proprietary information and should not be distributed
# or shared with anyone else. Any unauthorized distribution, reproduction, 
# or use of this code is strictly prohibited.
#
# Mantra Information Security
# https://mantrainfosec.com
#

from unicorn import *
from unicorn.x86_const import *

# code to be emulated
X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx

# memory address where emulation starts
ADDRESS = 0x1000000

print("Emulate i386 code")
try:
    # Initialize emulator in X86-32bit mode
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # map 2MB memory for this emulation
    uc.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    uc.mem_write(ADDRESS, X86_CODE32)

    # initialize machine registers
    uc.reg_write(UC_X86_REG_ECX, 0x1234)
    uc.reg_write(UC_X86_REG_EDX, 0x7890)

    # emulate code in infinite time & unlimited instructions
    uc.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_ecx = uc.reg_read(UC_X86_REG_ECX)
    r_edx = uc.reg_read(UC_X86_REG_EDX)
    print(">>> ECX = 0x%x" %r_ecx)
    print(">>> EDX = 0x%x" %r_edx)

except UcError as e:
    print("ERROR: %s" % e)