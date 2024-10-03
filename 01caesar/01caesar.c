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

 // compile: gcc 00caesar.c -o ../lab/00caesar

#include <stdio.h>
#include <string.h>

void caesar_cipher(char *str, int offset, int length)
{
    for (int i = 0; i < length; ++i)
    {
        if (str[i] >= 'A' && str[i] <= 'Z')
	{
            str[i] = (str[i] - 'A' + offset) % 26 + 'A';
        } 
	else if (str[i] >= 'a' && str[i] <= 'z') 
	{
            str[i] = (str[i] - 'a' + offset) % 26 + 'a';
        }
    }
}

int main() 
{
    char input_str[] = "Hello Unicorn!";
    int offset = 3;

    printf("Original string: %s\n", input_str);

    caesar_cipher(input_str, offset, strlen(input_str));

    printf("Encoded string: %s\n", input_str);

    return 0;
}
