/*************************************************************************
        > File Name: SM3.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "SM3.h"
#define INFO 0

static unsigned long long total_length = 0;
static BYTE message_buffer[64] = {0};
static DWORD message_buffer_position = 0;
static DWORD hash[8] = {0};
static DWORD V_i[8] = {0};
static DWORD V_i_1[8] = {0};
static DWORD T_j[64] = {0};

static DWORD IV[8] =
{
	0x7380166f,
	0x4914b2b9,
	0x172442d7,
	0xda8a0600,
	0xa96f30bc,
	0x163138aa,
	0xe38dee4d,
	0xb0fb0e4e
};

void out_hex(DWORD *list1)
{
	DWORD i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", list1[i]);
	}
	printf("\r\n");
}

DWORD rotate_left(DWORD a, DWORD k)
{
	k = k % 32;
	return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}

int init_T_j()
{
	DWORD i = 0;
	for (i = 0; i < 16; i++)
	{
		T_j[i] = 0x79cc4519;
	}
	for (i = 16; i < 64; i++)
	{
		T_j[i] = 0x7a879d8a;
	}
	return 1;
}

DWORD FF_j(DWORD X, DWORD Y, DWORD Z, DWORD j)
{
	DWORD ret;
	if (0 <= j && j < 16)
	{
		ret = X ^ Y ^ Z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (X & Y) | (X & Z) | (Y & Z);
	}
	return ret;
}

DWORD GG_j(DWORD X, DWORD Y, DWORD Z, DWORD j)
{
	DWORD ret;
	if (0 <= j && j < 16)
	{
		ret = X ^ Y ^ Z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (X & Y) | ((~ X) & Z);
	}
	return ret;
}

DWORD P_0(DWORD X)
{
	return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17));
}

DWORD P_1(DWORD X)
{
	return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23));
}

int CF(DWORD *V_i, BYTE *B_i, DWORD *V_i_1)
{
	DWORD W[68];
	DWORD W_1[64];
	DWORD j;
	DWORD A, B, C, D, E, F, G, H;
	DWORD SS1, SS2, TT1, TT2;
	for (j = 0; j < 16; j++)
	{
		W[j] = B_i[j * 4 + 0] << 24
		       | B_i[j * 4 + 1] << 16
		       | B_i[j * 4 + 2] << 8
		       | B_i[j * 4 + 3];
	}
	for (j = 16; j < 68; j++)
	{
		W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6];
	}
	for (j = 0; j < 64; j++)
	{
		W_1[j] = W[j] ^ W[j + 4];
	}
	A = V_i[0];
	B = V_i[1];
	C = V_i[2];
	D = V_i[3];
	E = V_i[4];
	F = V_i[5];
	G = V_i[6];
	H = V_i[7];
	for (j = 0; j < 64; j++)
	{
		SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7);
		SS2 = SS1 ^ (rotate_left(A, 12));
		TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
		TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
		D = C;
		C = rotate_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotate_left(F, 19);
		F = E;
		E = P_0(TT2);

#if INFO
		DWORD a[8] = {A, B, C, D, E, F, G, H};
		out_hex(a);
#endif
	}
	V_i_1[0] = (A ^ V_i[0]);
	V_i_1[1] = (B ^ V_i[1]);
	V_i_1[2] = (C ^ V_i[2]);
	V_i_1[3] = (D ^ V_i[3]);
	V_i_1[4] = (E ^ V_i[4]);
	V_i_1[5] = (F ^ V_i[5]);
	V_i_1[6] = (G ^ V_i[6]);
	V_i_1[7] = (H ^ V_i[7]);
	return 1;
}
void SM3_Init()
{
	DWORD i;
	total_length = 0;
	message_buffer_position = 0;
	init_T_j();
	for (i = 0; i < 8; i++)
	{
		V_i[i] = IV[i];
	}
}
void SM3_Update(BYTE *message, DWORD length)
{
	DWORD length_org = length;
	DWORD read_byte_count = 0;
	DWORD message_position = 0;
	DWORD i;
	while (length > 0)
	{
		if (length <= 64 - message_buffer_position)
		{
			read_byte_count = length;
		}
		else   //length > 64
		{
			read_byte_count = 64 - message_buffer_position;
		}
		memcpy(&message_buffer[message_buffer_position], &message[message_position], read_byte_count);
		message_buffer_position = message_buffer_position + read_byte_count;
		if (message_buffer_position == 64)
		{
			CF(V_i, message_buffer, V_i_1);
			for (i = 0; i < 8; i++)
			{
				V_i[i] = V_i_1[i];
			}
			message_buffer_position = 0;
		}
		message_position = message_position + read_byte_count;
		length = length - read_byte_count;
	}
	total_length += length_org;
}
void SM3_Final_dword(DWORD *out_hash)
{
	DWORD i;

	total_length = total_length * 8;
	memset(&message_buffer[message_buffer_position], 0, 64 - message_buffer_position);
	if (message_buffer_position <= 64 - 1 - 8)
	{
		message_buffer[message_buffer_position] = 0x80;
		for (i = 0; i < 8; i++)
		{
			message_buffer[56 + i] = (total_length >> ((8 - 1 - i) * 8)) & 0xFF;
		}
		CF(V_i, message_buffer, V_i_1);
	}
	else
	{
		message_buffer[message_buffer_position] = 0x80;
		CF(V_i, message_buffer, V_i_1);
		for (i = 0; i < 8; i++)
		{
			V_i[i] = V_i_1[i];
		}
		message_buffer_position = 0;
		memset(message_buffer, 0, 64);
		for (i = 0; i < 8; i++)
		{
			message_buffer[56 + i] = (total_length >> ((8 - 1 - i) * 8)) & 0xFF;
		}
		CF(V_i, message_buffer, V_i_1);
	}
	for (i = 0; i < 8; i++)
	{
		out_hash[i] = V_i_1[i];
	}
}
void SM3_Final_byte(BYTE *out_hash)
{
	int i = 0;
	DWORD hash[8] = {0};
	SM3_Final_dword(hash);
	for (i = 0; i < 8; i++)
	{
		out_hash[i * 4] = (hash[i] >> 24) & 0xFF;
		out_hash[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
		out_hash[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
		out_hash[i * 4 + 3] = (hash[i]) & 0xFF;
	}
}
void SM3_Final(DWORD *out_hash)
{
	SM3_Final_dword(out_hash);
}

int SM3_hash(BYTE *msg, DWORD len1, DWORD *out_hash)
{
	SM3_Init();
	SM3_Update(msg, len1);
	SM3_Final(out_hash);
	return 1;
}

int main2(int argc, char* argv[])
{
	DWORD i;

	SM3_Init();
	SM3_Update((BYTE *)"abc", 3);
	SM3_Final(hash);
	out_hex(hash);
	//66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

	SM3_Init();
	for (i = 0; i < 16; i++)
	{
		SM3_Update((BYTE *)"abcd", 4);
	}
	SM3_Final(hash);
	out_hex(hash);
	//debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

	system("pause");
	return 0;
}
