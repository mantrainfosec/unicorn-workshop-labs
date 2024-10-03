/*
 * This code is the property of Mantra Information Security and is provided 
 * solely for use within the x86/x64 Reverse Engineering training course or
 * one of its related workshops.
 * It is confidential and proprietary information and should not be distributed
 * or shared with anyone else. Any unauthorized distribution, reproduction, 
 * or use of this code is strictly prohibited.
 *
 * Mantra Information Security
 * https://mantrainfosec.com
 */

// compile: gcc 03decrypt.c -o 03decrypt -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

int decrypt_aes_ecb(unsigned char *ciphertext, int ciphertext_length,
                unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    int plaintext_length = 0;
    int length = 0;

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        perror("EVP_CIPHER_CTX_new()");
        exit(-1);
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        perror("EVP_DecryptInit_ex()");
        exit(-1);
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length))
    {
        perror("EVP_DecryptUpdate()");
        exit(-1);
    }
    plaintext_length += length;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + length, &length))
    {
        perror("EVP_DecryptFinal_ex()");
        exit(-1);
    }
    
    plaintext_length += length;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_length;
}


int main(int argc, char *argv[]) 
{
    time_t seed;
    size_t keySize = 16;
    char *iv = "AAAABBBECCCCDDDD";
    unsigned char aesKey[] = { '<', 0xde, 0x92, '}', 0xa3, '`', 0x07, 0x08, 0xee, 'D', 0x8a, ';', 0xa1, 0x14, 0xdb, 0xda};
    int plaintext_length;

    if (argc != 2) 
    {
        printf("[*] Usage: %s <filename>\n", argv[0]);
        return -1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) 
    {
        printf("[-] Error opening file\n");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file) - 8;
    fseek(file, 0, SEEK_SET);

    unsigned char *file_content = (unsigned char *)malloc(file_size);
    if (!file_content) 
    {
        printf("[-] Memory allocation error\n");
        fclose(file);
        return -1;
    }

    unsigned char *plaintext = (unsigned char *)malloc(file_size);
    if (!plaintext) 
    {
        printf("[-] Memory allocation error\n");
        fclose(file);
        return -1;
    }

    if (fread((unsigned char*)&seed, 1, 8, file) != (size_t)8) 
    {
        printf("[-] Error reading seed\n");
        free(file_content);
        fclose(file);
        return -1;
    }

    if (fread(file_content, 1, file_size, file) != (size_t)file_size) 
    {
        printf("[-] Error reading file\n");
        free(file_content);
        fclose(file);
        return -1;
    }

    fclose(file);

    plaintext_length = decrypt_aes_ecb(file_content, file_size, aesKey, iv, plaintext);    

    free(file_content);

    FILE *output_file = fopen("output_file.decrypted", "wb");
    if (!output_file)
    {
        printf("[-] Error opening output file\n");
        free(plaintext);
        return -1;
    }

    if (fwrite(plaintext, 1, plaintext_length, output_file) != (size_t)plaintext_length) 
    {
        printf("[-] Error writing to output file\n");
        free(plaintext);
        fclose(output_file);
        return -1;
    }

    fclose(output_file);
    free(plaintext);

    return 0;
}