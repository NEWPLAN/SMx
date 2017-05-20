/*************************************************************************
        > File Name: part3.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include "part3.h"
#include "sm2_ec_key.h"

#define ORDER_A_B 0
#define ORDER_B_A 1

typedef struct
{
	BYTE *ID;
	int ENTL;

	int klen_bit;

	BYTE r[MAX_POINT_BYTE_LENGTH];  //随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} public_key;
	BYTE K[256];  //共享密钥
	BYTE Z[HASH_BYTE_LENGTH];  //用户hash值
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} R; //r计算后得到的曲线点

	sm2_hash hash_tmp_data;  //保存计算hash的缓冲数据
} sm2_dh_st;

typedef struct
{
	BYTE S_1[HASH_BYTE_LENGTH];  //hash
	BYTE S_A[HASH_BYTE_LENGTH];  //hash
	BYTE S_2[HASH_BYTE_LENGTH];  //hash
	BYTE S_B[HASH_BYTE_LENGTH];  //hash
} sm2_dh_hash_st;

int dh_step1(sm2_dh_st *dh_data, BYTE *dh_d, BYTE *dh_r, ec_param *ecp)
{
	sm2_ec_key *key_A;
	BIGNUM *P_x;
	BIGNUM *P_y;
	BIGNUM *d;
	BIGNUM *r;
	sm2_hash Z_A;
	xy_ecpoint *point_R;

	key_A = sm2_ec_key_new(ecp);
	P_x = BN_new();
	P_y = BN_new();
	d = BN_new();
	r = BN_new();
	point_R = xy_ecpoint_new(ecp);

	sm2_ec_key_init(key_A, (char *)dh_d, ecp);

	sm2_hex2bin((BYTE *)dh_r, dh_data->r, ecp->point_byte_length);
	sm2_bn2bin(key_A->d, dh_data->private_key, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->x, dh_data->public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_A->P->y, dh_data->public_key.y, ecp->point_byte_length);

	BN_bin2bn(dh_data->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(dh_data->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(dh_data->private_key, ecp->point_byte_length, d);
	BN_bin2bn(dh_data->r, ecp->point_byte_length, r);

	memset(&Z_A, 0, sizeof(Z_A));
	Z_A.buffer[0] = ((dh_data->ENTL * 8) >> 8) & 0xFF;
	Z_A.buffer[1] = (dh_data->ENTL * 8) & 0xFF;
	Z_A.position = Z_A.position + 2;
	BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, dh_data->ENTL, dh_data->ID);
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

	memcpy(dh_data->Z, Z_A.hash, HASH_BYTE_LENGTH);

	xy_ecpoint_mul_bignum(point_R, ecp->G, r, ecp);
	sm2_bn2bin(point_R->x, dh_data->R.x, ecp->point_byte_length);
	sm2_bn2bin(point_R->y, dh_data->R.y, ecp->point_byte_length);

	DEFINE_SHOW_STRING(dh_data->Z, HASH_BYTE_LENGTH);
	DEFINE_SHOW_BIGNUM(r);
	DEFINE_SHOW_STRING(dh_data->R.x, ecp->point_byte_length);
	DEFINE_SHOW_STRING(dh_data->R.y, ecp->point_byte_length);

	BN_free(P_x);
	BN_free(P_y);
	BN_free(d);
	BN_free(r);

	sm2_ec_key_free(key_A);
	xy_ecpoint_free(point_R);

	return SUCCESS;
}

//order = 0, A,B顺序
//order = 1, B,A顺序，计算KDF时按不同顺序有变化，其他地方不影响
int dh_step2(sm2_dh_st *dh_data_A, sm2_dh_st *dh_data_B, ec_param *ecp, int order)
{
	BIGNUM *x_1;
	BIGNUM *y_1;
	BIGNUM *x_2;
	BIGNUM *y_2;
	BIGNUM *_x_1;
	BIGNUM *_x_2;
	xy_ecpoint *point_R;
	xy_ecpoint *point_0;
	xy_ecpoint *point_1;
	xy_ecpoint *point_2;
	BIGNUM *P_A_x;
	BIGNUM *P_A_y;
	xy_ecpoint *point_P_A;
	BIGNUM *h;
	BIGNUM *t_B;
	BIGNUM *d_B;
	BIGNUM *r_B;
	BIGNUM *num_2_127;
	BYTE *K;
	BYTE KDF_buffer[1024];
	int pos1;
	sm2_hash hash1;

	x_1 = BN_new();
	y_1 = BN_new();
	x_2 = BN_new();
	y_2 = BN_new();
	_x_1 = BN_new();
	_x_2 = BN_new();
	point_R = xy_ecpoint_new(ecp);
	point_0 = xy_ecpoint_new(ecp);
	point_1 = xy_ecpoint_new(ecp);
	point_2 = xy_ecpoint_new(ecp);
	P_A_x = BN_new();
	P_A_y = BN_new();
	point_P_A = xy_ecpoint_new(ecp);
	h = BN_new();
	t_B = BN_new();
	d_B = BN_new();
	r_B = BN_new();
	num_2_127 = BN_new();

	BN_bin2bn(dh_data_A->R.x, ecp->point_byte_length, x_1);
	BN_bin2bn(dh_data_A->R.y, ecp->point_byte_length, y_1);
	BN_bin2bn(dh_data_A->public_key.x, ecp->point_byte_length, P_A_x);
	BN_bin2bn(dh_data_A->public_key.y, ecp->point_byte_length, P_A_y);
	xy_ecpoint_init_xy(point_P_A, P_A_x, P_A_y, ecp);
	BN_bin2bn(dh_data_B->R.x, ecp->point_byte_length, x_2);
	BN_bin2bn(dh_data_B->R.y, ecp->point_byte_length, y_2);
	BN_bin2bn(dh_data_B->private_key, ecp->point_byte_length, d_B);
	BN_bin2bn(dh_data_B->r, ecp->point_byte_length, r_B);

	BN_hex2bn(&num_2_127, "80000000000000000000000000000000");

	BN_mod(_x_2, x_2, num_2_127, ecp->ctx);
	BN_add(_x_2, _x_2, num_2_127);

	BN_mul(t_B, _x_2, r_B, ecp->ctx);
	BN_add(t_B, t_B, d_B);
	BN_mod(t_B, t_B, ecp->n, ecp->ctx);
	BN_set_word(h, sm2_param_dh_h[ecp->type]);
	BN_mul(t_B, t_B, h, ecp->ctx);

	BN_mod(_x_1, x_1, num_2_127, ecp->ctx);
	BN_add(_x_1, _x_1, num_2_127);

	xy_ecpoint_init_xy(point_R, x_1, y_1, ecp);
	xy_ecpoint_mul_bignum(point_0, point_R, _x_1, ecp);
	xy_ecpoint_add_xy_ecpoint(point_1, point_0, point_P_A, ecp);
	xy_ecpoint_mul_bignum(point_2, point_1, t_B, ecp);

	DEFINE_SHOW_BIGNUM(point_0->x);
	DEFINE_SHOW_BIGNUM(point_0->y);
	DEFINE_SHOW_BIGNUM(point_1->x);
	DEFINE_SHOW_BIGNUM(point_1->y);
	DEFINE_SHOW_BIGNUM(point_2->x);
	DEFINE_SHOW_BIGNUM(point_2->y);

	memset(KDF_buffer, 0, sizeof(KDF_buffer));
	pos1 = 0;
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, point_2->x);
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, point_2->y);
	if (ORDER_A_B == order)
	{
		BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_A->Z);
		BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_B->Z);
	}
	else
	{
		BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_B->Z);
		BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_A->Z);
	}

	K = KDF(KDF_buffer, dh_data_B->klen_bit, pos1);
	memcpy(dh_data_B->K, K, dh_data_B->klen_bit / 8);
	OPENSSL_free(K);

	memset(&hash1, 0, sizeof(hash1));
	BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, point_2->x);
	if (ORDER_A_B == order)
	{
		BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_A->Z);
		BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_B->Z);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_1);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_1);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_2);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_2);
	}
	else
	{
		BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_B->Z);
		BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_A->Z);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_2);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_2);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_1);
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_1);
	}
	SM3_Init();
	SM3_Update(hash1.buffer, hash1.position);
	SM3_Final_byte(hash1.hash);

	DEFINE_SHOW_STRING(hash1.buffer, hash1.position);


	memset(&dh_data_B->hash_tmp_data, 0, sizeof(dh_data_B->hash_tmp_data));
	dh_data_B->hash_tmp_data.position = 1;
	BUFFER_APPEND_BIGNUM(dh_data_B->hash_tmp_data.buffer, dh_data_B->hash_tmp_data.position
	                     , ecp->point_byte_length, point_2->y);
	BUFFER_APPEND_STRING(dh_data_B->hash_tmp_data.buffer, dh_data_B->hash_tmp_data.position
	                     , HASH_BYTE_LENGTH, hash1.hash);

	BN_free(x_1);
	BN_free(y_1);
	BN_free(x_2);
	BN_free(y_2);
	BN_free(_x_1);
	BN_free(_x_2);
	xy_ecpoint_free(point_R);
	xy_ecpoint_free(point_0);
	xy_ecpoint_free(point_1);
	xy_ecpoint_free(point_2);
	BN_free(P_A_x);
	BN_free(P_A_y);
	xy_ecpoint_free(point_P_A);
	BN_free(h);
	BN_free(t_B);
	BN_free(d_B);
	BN_free(r_B);
	BN_free(num_2_127);

	return SUCCESS;
}

void test_part3(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;
	sm2_dh_st dh_A;
	sm2_dh_st dh_B;
	sm2_dh_hash_st dh_hash;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	dh_A.ID = (BYTE *)ID_A;
	dh_A.ENTL = strlen(ID_A);
	dh_B.ID = (BYTE *)ID_B;
	dh_B.ENTL = strlen(ID_B);
	dh_A.klen_bit = 128;
	dh_B.klen_bit = 128;
	dh_step1(
	    &dh_A
	    , (BYTE *)sm2_param_dh_d_A[ecp->type]
	    , (BYTE *)sm2_param_dh_r_A[ecp->type]
	    , ecp);
	dh_step1(
	    &dh_B
	    , (BYTE *)sm2_param_dh_d_B[ecp->type]
	    , (BYTE *)sm2_param_dh_r_B[ecp->type]
	    , ecp);

	dh_step2(&dh_A, &dh_B, ecp, ORDER_A_B);  //K_B, S_B
	dh_B.hash_tmp_data.buffer[0] = 0x02;
	SM3_Init();
	SM3_Update(dh_B.hash_tmp_data.buffer, dh_B.hash_tmp_data.position);
	SM3_Final_byte(dh_B.hash_tmp_data.hash);
	DEFINE_SHOW_STRING(dh_B.hash_tmp_data.buffer, dh_B.hash_tmp_data.position);
	memcpy(dh_hash.S_B, dh_B.hash_tmp_data.hash, HASH_BYTE_LENGTH);

	dh_step2(&dh_B, &dh_A, ecp, ORDER_B_A);  //K_A, S_1
	dh_A.hash_tmp_data.buffer[0] = 0x02;
	SM3_Init();
	SM3_Update(dh_A.hash_tmp_data.buffer, dh_A.hash_tmp_data.position);
	SM3_Final_byte(dh_A.hash_tmp_data.hash);
	DEFINE_SHOW_STRING(dh_A.hash_tmp_data.buffer, dh_B.hash_tmp_data.position);
	memcpy(dh_hash.S_1, dh_A.hash_tmp_data.hash, HASH_BYTE_LENGTH);

	dh_A.hash_tmp_data.buffer[0] = 0x03; //S_A
	SM3_Init();
	SM3_Update(dh_A.hash_tmp_data.buffer, dh_A.hash_tmp_data.position);
	SM3_Final_byte(dh_A.hash_tmp_data.hash);
	memcpy(dh_hash.S_A, dh_A.hash_tmp_data.hash, HASH_BYTE_LENGTH);

	dh_B.hash_tmp_data.buffer[0] = 0x03;  //S_2
	SM3_Init();
	SM3_Update(dh_B.hash_tmp_data.buffer, dh_B.hash_tmp_data.position);
	SM3_Final_byte(dh_B.hash_tmp_data.hash);
	memcpy(dh_hash.S_2, dh_B.hash_tmp_data.hash, HASH_BYTE_LENGTH);

	DEFINE_SHOW_STRING(dh_hash.S_B, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(dh_hash.S_1, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(dh_hash.S_A, HASH_BYTE_LENGTH);
	DEFINE_SHOW_STRING(dh_hash.S_2, HASH_BYTE_LENGTH);

	ec_param_free(ecp);
}