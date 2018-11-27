/*************************************************************************
        > File Name: sm2_common.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef SM2_COMMON_H
#define SM2_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include "sm3.h"

#ifdef WINDOWS
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#endif

#define HASH_BYTE_LENGTH 32
#define HASH_BIT_LENGTH 256

#define ABORT printf("error: line: %d function: %s\n", __LINE__, __FUNCTION__);

#define TYPE_GFp 0
#define TYPE_GF2m 1

#define SUCCESS 1
#define FAIL 0

#define MAX_POINT_BYTE_LENGTH 64 //����x, y������ֽڳ���

#define DEFINE_SHOW_BIGNUM(x)               \
	printf(#x ":\n");                       \
	show_bignum(x, ecp->point_byte_length); \
	printf("\n")

#define DEFINE_SHOW_STRING(x, length1) \
	printf(#x ":\n");                  \
	show_string(x, length1);           \
	printf("\n")

#define BUFFER_APPEND_BIGNUM(buffer1, pos1, point_byte_length, x)       \
	BN_bn2bin(x, &buffer1[pos1 + point_byte_length - BN_num_bytes(x)]); \
	pos1 = pos1 + point_byte_length

#define BUFFER_APPEND_STRING(buffer1, pos1, length1, x) \
	memcpy(&buffer1[pos1], x, length1);                 \
	pos1 = pos1 + length1

typedef struct
{
	BYTE buffer[1024];
	int position;
	BYTE hash[HASH_BYTE_LENGTH];
} sm2_hash;

typedef struct
{
	BIGNUM *x;
	BIGNUM *y;
	EC_POINT *ec_point;
} xy_ecpoint;

/************************************************************************/
/* ������Բ���߲�����Ϣ                                                 */
/************************************************************************/
typedef struct
{
	BN_CTX *ctx;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *n;
	xy_ecpoint *G;
	EC_GROUP *group;
	int type;
	int point_bit_length;
	int point_byte_length;

	EC_GROUP *(*EC_GROUP_new_curve)(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
	int (*EC_POINT_set_affine_coordinates)(const EC_GROUP *group, EC_POINT *p,
	                                       const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
	int (*EC_POINT_get_affine_coordinates)(const EC_GROUP *group,
	                                       const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

} ec_param;

typedef struct
{
	BIGNUM *d;
	xy_ecpoint *P;
} sm2_ec_key;

#endif