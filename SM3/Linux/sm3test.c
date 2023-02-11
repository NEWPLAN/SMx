/*************************************************************************
       > File Name: sm3test.c
       > Author:NEWPLAN
       > E-mail:newplan001@163.com
       > Created Time: Thu Apr 13 23:55:50 2017
************************************************************************/
#include <string.h>
#include <stdio.h>
#include "sm3.h"

int main( int argc, char *argv[] )
{
	uint8_t *input = "abc";
	int ilen = 3;
	uint8_t output[32];
	int i;
	sm3_context ctx;

	printf("Message:\n");
	printf("%s\n", input);

	sm3(input, ilen, output);
	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4 ) == 0) printf(" ");
	}
	printf("\n");

	printf("Message:\n");
	for (i = 0; i < 16; i++)
		printf("abcd");
	printf("\n");

	sm3_starts( &ctx );
	for (i = 0; i < 16; i++)
		sm3_update( &ctx, "abcd", 4 );
	sm3_finish( &ctx, output );
	memset( &ctx, 0, sizeof( sm3_context ) );

	printf("Hash:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4 ) == 0) printf(" ");
	}
	printf("\n");
	//getch();	//VS2008
}