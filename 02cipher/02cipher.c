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

// compile: gcc 02cipher.c -o 02cipher

#include <stdio.h>
#include <string.h>

int strlen_internal(char *input)
{
    int i = 0;

    while (*input++ != 0) i++;

    return i;

}


void substitutionCipher(char *input) 
{
    int i, j, b;
    static const char alphabet[] =      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static const char encryptMatrix[] = "aDgFkLJqTtUPu0nQpZy5W1RzG4KemHhN6vO3sSxcwb89o2EI7MVfjBrCiAXlYd";

    for (i = 0; i < strlen_internal(input); i++) 
    {
        if ((input[i] >= 'A' && input[i] <= 'Z') ||
            (input[i] >= 'a' && input[i] <= 'z') ||
            (input[i] >= '0' && input[i] <= '9')) 
        {
        	b = 1;
        	j = 0;
        	while (b)
        	{
        		if (alphabet[j++] == input[i]) 
        		{
        			input[i] = encryptMatrix[j-1];
        			b = 0;
        		}
        	}
        }
    }
}

void substitutionDecipher(char *input) 
{
    static const char encryptMatrix[] = "aDgFkLJqTtUPu0nQpZy5W1RzG4KemHhN6vO3sSxcwb89o2EI7MVfjBrCiAXlYd";
    static const char decryptMatrix[] = "aHJNUS3p25EbWj08QfGA7B946iskuvqcX1wCyozgRDYdnrhOlxILteZmTKMPVF";

    int i, j, b;
    for (i = 0; i < strlen_internal(input); i++) 
    {
        if ((input[i] >= 'A' && input[i] <= 'Z') ||
            (input[i] >= 'a' && input[i] <= 'z') ||
            (input[i] >= '0' && input[i] <= '9')) 
        {
            b = 1;
        	j = 0;
        	while (b)
        	{
        		if (decryptMatrix[j++] == input[i]) 
        		{
        			input[i] = encryptMatrix[j-1];
        			b = 0;
        		}
        	}
        }
    }
}

int main() {
    char message[] = "Hello this is NOT the secret message.";
    char secret[] = "E0TgnZ0 h0JT0k uaQQT0J kzQkZ5 ZkQZkyk05!";

    substitutionCipher(message);

    printf("Ciphered Message: %s\n", message);
    //substitutionDecipher(secret);

    //printf("Deciphered Message: %s\n", secret);

    return 0;
}
