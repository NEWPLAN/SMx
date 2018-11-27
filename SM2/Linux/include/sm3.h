/*************************************************************************
        > File Name: SM2.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef SM3_H
#define SM3_H

#ifndef DWORD
typedef unsigned int DWORD;
#endif
#ifndef BYTE
typedef unsigned char BYTE;
#endif

void SM3_Init();
void SM3_Update(BYTE *message, DWORD length);
void SM3_Final_dword(DWORD *out_hash);
void SM3_Final_byte(BYTE *out_hash);
void SM3_Final(DWORD *out_hash);

#endif
