/*************************************************************************
        > File Name: part2.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include "part2.h"
#include "sm2_ec_key.h"

typedef struct
{
	BYTE *message;
	int message_byte_length;
	BYTE *ID;
	int ENTL;
	BYTE k[MAX_POINT_BYTE_LENGTH];  //签名中产生随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} public_key;
	BYTE Z[HASH_BYTE_LENGTH];
	BYTE r[MAX_POINT_BYTE_LENGTH];
	BYTE s[MAX_POINT_BYTE_LENGTH];
	BYTE R[MAX_POINT_BYTE_LENGTH];
} sm2_sign_st;

void sm2_sign(ec_param *ecp, sm2_sign_st *sign)
{
	sm2_hash Z_A;
	sm2_hash e;
	BIGNUM *e_bn;

	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *tmp1;

	BIGNUM *P_x;
	BIGNUM *P_y;
	BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *xy1;

	e_bn = BN_new();
	r = BN_new();
	s = BN_new();
	tmp1 = BN_new();
	P_x = BN_new();
	P_y = BN_new();
	d = BN_new();
	k = BN_new();
	xy1 = xy_ecpoint_new(ecp);

	BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(sign->private_key, ecp->point_byte_length, d);
	BN_bin2bn(sign->k, ecp->point_byte_length, k);

	memset(&Z_A, 0, sizeof(Z_A));
	Z_A.buffer[0] = ((sign->ENTL * 8) >> 8) & 0xFF;
	Z_A.buffer[1] = (sign->ENTL * 8) & 0xFF;
	Z_A.position = Z_A.position + 2;
	BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, sign->ENTL, sign->ID);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
	BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
	DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
	SM3_Init();
	SM3_Update(Z_A.buffer, Z_A.position);
	SM3_Final_byte(Z_A.hash);
	memcpy(sign->Z, Z_A.hash, HASH_BYTE_LENGTH);

	DEFINE_SHOW_STRING(Z_A.hash, HASH_BYTE_LENGTH);

	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, Z_A.hash);
	BUFFER_APPEND_STRING(e.buffer, e.position, strlen(message_digest), (BYTE *)message_digest);
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(sign->k, ecp->point_byte_length);

	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);

	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
	BN_zero(r);
	BN_mod_add(r, e_bn, xy1->x, ecp->n, ecp->ctx);

	BN_one(s);
	BN_add(s, s, d);
	BN_mod_inverse(s, s, ecp->n, ecp->ctx);  //求模反

	BN_mul(tmp1, r, d, ecp->ctx);
	BN_sub(tmp1, k, tmp1);
	BN_mod_mul(s, s, tmp1, ecp->n, ecp->ctx);

	sm2_bn2bin(r, sign->r, ecp->point_byte_length);
	sm2_bn2bin(s, sign->s, ecp->point_byte_length);

	DEFINE_SHOW_BIGNUM(r);
	DEFINE_SHOW_BIGNUM(s);

	BN_free(e_bn);
	BN_free(r);
	BN_free(s);
	BN_free(tmp1);
	BN_free(P_x);
	BN_free(P_y);
	BN_free(d);
	BN_free(k);
	xy_ecpoint_free(xy1);
}

void sm2_verify(ec_param *ecp, sm2_sign_st *sign)
{
	sm2_hash e;
	BIGNUM *e_bn;
	BIGNUM *t;
	BIGNUM *R;
	xy_ecpoint *result;
	xy_ecpoint *result1;
	xy_ecpoint *result2;
	xy_ecpoint *P_A;
	BIGNUM *r;
	BIGNUM *s;
	BIGNUM *P_x;
	BIGNUM *P_y;

	e_bn = BN_new();
	t = BN_new();
	R = BN_new();
	result = xy_ecpoint_new(ecp);
	result1 = xy_ecpoint_new(ecp);
	result2 = xy_ecpoint_new(ecp);
	P_A = xy_ecpoint_new(ecp);
	r = BN_new();
	s = BN_new();
	P_x = BN_new();
	P_y = BN_new();

	BN_bin2bn(sign->r, ecp->point_byte_length, r);
	BN_bin2bn(sign->s, ecp->point_byte_length, s);
	BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
	xy_ecpoint_init_xy(P_A, P_x, P_y, ecp);

	memset(&e, 0, sizeof(e));
	BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, sign->Z);
	BUFFER_APPEND_STRING(e.buffer, e.position, sign->message_byte_length, (BYTE*)sign->message);
	SM3_Init();
	SM3_Update(e.buffer, e.position);
	SM3_Final_byte(e.hash);
	BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);
	DEFINE_SHOW_BIGNUM(e_bn);

	BN_mod_add(t, r, s, ecp->n, ecp->ctx);
	xy_ecpoint_mul_bignum(result1, ecp->G, s, ecp);
	xy_ecpoint_mul_bignum(result2, P_A, t, ecp);
	xy_ecpoint_add_xy_ecpoint(result, result1, result2, ecp);

	BN_mod_add(R, e_bn, result->x, ecp->n, ecp->ctx);

	sm2_bn2bin(R, sign->R, ecp->point_byte_length);

	DEFINE_SHOW_STRING(sign->R, ecp->point_byte_length);

	BN_free(e_bn);
	BN_free(t);
	BN_free(R);
	xy_ecpoint_free(result);
	xy_ecpoint_free(result1);
	xy_ecpoint_free(result2);
	xy_ecpoint_free(P_A);
	BN_free(r);
	BN_free(s);
	BN_free(P_x);
	BN_free(P_y);
}

void test_part2(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;
	sm2_ec_key *key_A;
	sm2_sign_st sign;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	key_A = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_A, sm2_param_digest_d_A[ecp->type], ecp);

	memset(&sign, 0, sizeof(sign));
	sign.message = (BYTE *)message_digest;
	sign.message_byte_length = strlen(message_digest);
	sign.ID = (BYTE *)ID_A;
	sign.ENTL = strlen(ID_A);
	sm2_hex2bin((BYTE *)sm2_param_digest_k[ecp->type], sign.k, ecp->point_byte_length);
	sm2_bn2bin(key_A->d, sign.private_key, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->x, sign.public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->y, sign.public_key.y, ecp->point_byte_length);

	DEFINE_SHOW_STRING(sign.public_key.x, ecp->point_byte_length);
	DEFINE_SHOW_STRING(sign.public_key.y, ecp->point_byte_length);
	sm2_sign(ecp, &sign);

	memset(sign.private_key, 0, sizeof(sign.private_key)); //清除私钥
	sm2_verify(ecp, &sign);

	sm2_ec_key_free(key_A);
	ec_param_free(ecp);
}
