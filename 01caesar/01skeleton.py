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

# Read the ELF binary
with open("[HERE]", "rb") as f:
    binary = f.read()

# Set the memory address where the code will be loaded (base address)
BINARY = [HERE]
STACK = [HERE]
HEAP = [HERE]

# Create an instance of the Unicorn Engine emulating x64
uc = Uc(UC_ARCH_X86, UC_MODE_64)

# Map memory for the code
uc.mem_map(BINARY, [HERE])  # 2 MB
uc.mem_map(STACK, [HERE])  # 1 MB
uc.mem_map(HEAP, [HERE])  # 1 MB

# Write the ELF binary to the memory
uc.mem_write(BINARY, binary)

# Set the string and offset values in memory
input_str = b"Hello Unicorn!"
offset = 3
length = len(input_str)
uc.mem_write(HEAP, input_str)  # Address where input_str is stored (binary 16K, string at 17K)
uc.reg_write(UC_X86_REG_[HERE], [HERE])  # Set the first argument (address of the string)
uc.reg_write(UC_X86_REG_[HERE], [HERE])  # Set the second argument (offset)
uc.reg_write(UC_X86_REG_[HERE], [HERE])  # Set the third argument (length)

uc.reg_write(UC_X86_REG_[HERE], [HERE])  # Set the stack (RSP)

# Emulate code execution
try:
    uc.emu_start(BINARY + [HERE], BINARY + [HERE])  # Address of the caesar_cipher call

    # Read the result from memory (assuming the C program prints the result)
    result = uc.mem_read(HEAP, len(input_str)).decode("utf-8")
    print(f"Encoded string: {result}")

except UcError as e:
    print("Error: %s" % e)