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

def hook_block(uc, address, size, user_data):
    print(">>> Tracing block at 0x%x, instruction size = 0x%x" %(address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" %rip);

def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    rip = uc.reg_read(UC_X86_REG_RIP)
    print(">>> RIP is 0x%x" %rip);
#    print(">>> EAX is 0x%x" %uc.reg_read(UC_X86_REG_RAX));

def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
    else:   # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
                %(address, size))

# Read the ELF binary
with open("/home/training/labs/day10/lab/04cipher-unicorn/04cipher-unicorn", "rb") as f:
    binary = f.read()

# Set the memory address where the code will be loaded (base address)
ADDRESS = 0x00100000

# Create an instance of the Unicorn Engine emulating x64
uc = Uc(UC_ARCH_X86, UC_MODE_64)

# Map memory for the code
uc.mem_map(ADDRESS, 1024 * 1024)  # 1 MB

# Write the ELF binary to the memory
uc.mem_write(ADDRESS, binary)

# Set the string and offset values in memory
input_str = b"Uz7oGNz vzx7zY RsHH7zx YeHYN9 NYHNY1Yz9!\x00"
uc.mem_write(ADDRESS + (1024 * 1024) - 50, input_str)  # Address where input_str is stored
uc.reg_write(UC_X86_REG_RDI, ADDRESS + (1024 * 1024) - 50)  # Set the first argument (address of the string)
uc.reg_write(UC_X86_REG_RSP, ADDRESS + (1024 * 1024) - 500)  # Set the second argument (offset)
#uc.hook_add(UC_HOOK_CODE, hook_code, None, ADDRESS, ADDRESS + (3*1024*1024))
#uc.hook_add(UC_HOOK_MEM_READ, hook_mem_access)

# NOP'ing out 001011c4 e8 b7 fe ff ff - CALL <EXTERNAL>::puts
uc.mem_write(ADDRESS + 0x11c4, b"\x90\x90\x90\x90\x90") 
# move 40 (strlen(input)) to RAX. Nop the rest
#        001012c5 48 89 c7        MOV        RDI,RAX
#        001012c8 e8 c3 fd        CALL       <EXTERNAL>::strlen
#                 ff ff
uc.mem_write(ADDRESS + 0x12c5, b"\x48\xC7\xC0\x28\x00\x00\x00\x90") # MOV RAX, 40 + NOP


# Emulate code execution
try:
    uc.emu_start(ADDRESS + 0x011a9, ADDRESS + 0x12dd)  # Address of the caesar_cipher call

    # Read the result from memory (assuming the C program prints the result)
    result = uc.mem_read(ADDRESS + (1024 * 1024) - 50, len(input_str)).decode("utf-8")
    print(f"Deciphered string: {result}")

except UcError as e:
    print("Error: %s" % e)
