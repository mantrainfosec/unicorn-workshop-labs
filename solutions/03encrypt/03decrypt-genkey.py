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
import struct

# ignore this for now
FSMSR = 0xC0000100
SEGMENT_ADDR = 0x5000
SCRATCH_SIZE = 0x1000
SEGMENT_SIZE = 0x1000
SCRATCH_ADDR = 0xf000

def hook_block(uc, address, size, user_data):
    print(">>> Tracing block at 0x%x, instruction size = 0x%x" %(address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" %rip);

def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" % rip);

def hook_mem_access(uc, access, address, size, value, user_data):
    print(access)
    print(UC_MEM_WRITE)
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
    else:   # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
                %(address, size))

# Read the ELF binary
with open("03encrypt", "rb") as f:
    binary = f.read()

# Set the memory address where the code will be loaded (base address)
BASE = 0x00400000
STACK = 0x00100000
HEAP = 0x00200000

# Create an instance of the Unicorn Engine emulating x64
uc = Uc(UC_ARCH_X86, UC_MODE_64)

# Settings FS
uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)
uc.reg_write(UC_X86_REG_FS_BASE, SEGMENT_ADDR)

# Map memory for the code
uc.mem_map(BASE, 6*1024*1024)  # 6 MB

# Write the ELF binary to the memory
uc.mem_write(BASE, binary)

# Set the string and offset values in memory
seed = 0x65bcea5f
key_length = 16

#void generateAESKey(time_t *seed, unsigned char *key, size_t keySize) 

uc.reg_write(UC_X86_REG_RDI, seed)  # Set the first argument (seed)
uc.reg_write(UC_X86_REG_RSI, HEAP)  # Set the second argument (key output address)
uc.reg_write(UC_X86_REG_RDX, key_length)  # Set the third argument (key length)

uc.reg_write(UC_X86_REG_RSP, STACK + 512)  # Set the stack if needed

#uc.hook_add(UC_HOOK_CODE, hook_code, None, BASE + 0x2de5, BASE + 0x2e4b)
#uc.hook_add(UC_HOOK_MEM_READ, hook_mem_access)

# Emulate code execution
try:
    uc.emu_start(BASE + 0x2de5, BASE + 0x2e4b)  # Address of the call

    # Read the result from memory (assuming the C program prints the result)
    result = uc.mem_read(HEAP, key_length)
    print(f"Deciphered string: {result}")

except UcError as e:
    print("Error: %s" % e)
