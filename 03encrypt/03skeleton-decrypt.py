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

from Crypto.Cipher import AES
import os
import sys

iv = b'[HERE]'
key = b'[HERE]'

def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]

def read_and_decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if len(data) < 8:
        raise ValueError("File content is too short to process.")
    
    # Discard the first 8 bytes
    ciphertext = data[8:]
    
    # Decrypt the content
    decrypted_data = decrypt_aes_cbc(ciphertext, key, iv)
    return decrypted_data


if len(sys.argv) < 2:
    print("Usage: python3 {} encrypted_file".format(sys.argv[0]));
    sys.exit(-1)

try:
    decrypted_content = read_and_decrypt_file(sys.argv[1])
    print("Decrypted content:")
    print(decrypted_content.decode('utf-8', errors='replace'))
except Exception as e:
    print(f"An error occurred: {e}")