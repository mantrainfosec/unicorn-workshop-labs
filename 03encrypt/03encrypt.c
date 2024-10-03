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

// compile: gcc 03encrypt.c -o 03encrypt -lssl -lcrypto -static -g

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void generateAESKey(time_t seed, unsigned char *key, size_t keySize) 
{
    // removed for obscurity
}

int encrypt_aes_ecb(unsigned char *plaintext, int plaintext_length,
                unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    int ciphertext_length = 0;
    int length = 0;

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        perror("EVP_CIPHER_CTX_new()");
        exit(-1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        perror("EVP_EncryptInit_ex()");
        exit(-1);
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length))
    {
        perror("EVP_EncryptUpdate()");
        exit(-1);
    }
    ciphertext_length += length;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + length, &length))
    {
        perror("EVP_EncryptFinal_ex()");
        exit(-1);
    }
    ciphertext_length += length;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_length;
}


int main(int argc, char *argv[]) 
{
    time_t seed;
    size_t keySize = 16;
    char *iv = "AAAABBBECCCCDDDD";
    unsigned char aesKey[keySize];
    int ciphertext_length;

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
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_content = (unsigned char *)malloc(file_size);
    if (!file_content) 
    {
        printf("[-] Memory allocation error\n");
        fclose(file);
        return -1;
    }

    unsigned char *ciphertext = (unsigned char *)malloc(file_size + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) 
    {
        printf("[-] Memory allocation error\n");
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
    
    seed = time(NULL);
    generateAESKey(seed, aesKey, keySize);

    printf("Generated AES Key: ");
    for (size_t i = 0; i < keySize; ++i)
    {
        printf("%02x", aesKey[i]);
    }
    printf("\n");

    ciphertext_length = encrypt_aes_ecb(file_content, file_size, aesKey, iv, ciphertext);    

    free(file_content);

    FILE *output_file = fopen("output_file.encrypted", "wb");
    if (!output_file)
    {
        printf("[-] Error opening output file\n");
        free(ciphertext);
        return -1;
    }

    if (fwrite(&seed, 1, 8, output_file) != (size_t)8) 
    {
        printf("[-] Error writing seed to output file\n");
        free(ciphertext);
        fclose(output_file);
        return -1;
    }

    if (fwrite(ciphertext, 1, ciphertext_length, output_file) != (size_t)ciphertext_length) 
    {
        printf("[-] Error writing to output file\n");
        free(ciphertext);
        fclose(output_file);
        return -1;
    }

    fclose(output_file);
    free(ciphertext);

    return 0;
}
