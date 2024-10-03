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

// compile: gcc 05cipher-unicorn.c -o 05cipher-unicorn -s

#include <stdio.h>
#include <string.h>

void substitutionDecipher(char *input) 
{
    static const char encryptMatrix[] = "sWo2YSxc76XlRzGHhN19LJqegFk40nvOZy5QpDfjtEIdmrUPwb8ABKCMVui3Ta";
    static const char decryptMatrix[] = "1wGC8meo3ibldFZycjKaDQhYxOXVBzJtAguIHnS69v52RNUEqWTk4p0fPL7Mrs";

    printf("Nested function to annoy you.\n");

    int i, j, b;
    for (i = 0; i < strlen(input); i++) 
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

int main() 
{
    char message[] = "rNg 9G L1Y Uz7oGNz Yzx7zY SGN 9c71";

    substitutionDecipher(message);

    printf("Deciphered Message: %s\n", message);

    return 0;
}
