/*************************************************************************
        > File Name: util.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef UTIL_H
#define UTIL_H

#include "sm2_common.h"

void show_bignum(BIGNUM *bn, int point_byte_length);
void show_string(BYTE *string1, int length1);
BYTE *KDF(BYTE *str1, int klen, int strlen1);

int sm2_hex2bin(BYTE *hex_string, BYTE *bin_string, int point_byte_length);
int sm2_bn2bin(BIGNUM *bn, BYTE *bin_string, int point_byte_length);

#endif