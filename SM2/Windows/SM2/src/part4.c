/*************************************************************************
        > File Name: part4.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include "part4.h"

typedef struct
{
	BYTE *message;
	int message_byte_length;
	//BYTE *encrypt;
	BYTE *decrypt;
	int klen_bit;

	BYTE k[MAX_POINT_BYTE_LENGTH];  //随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct
	{
		BYTE x[MAX_POINT_BYTE_LENGTH];
		BYTE y[MAX_POINT_BYTE_LENGTH];
	} public_key;

	BYTE C[1024];    // C_1 || C_2 || C_3
	BYTE C_1[1024];
	BYTE C_2[1024];  //加密后的消息
	BYTE C_3[1024];

} message_st;


/*sm2加密信息*/
int sm2_encrypt(ec_param *ecp, message_st *message_data)
{
	BIGNUM *P_x;
	BIGNUM *P_y;
	//BIGNUM *d;
	BIGNUM *k;
	xy_ecpoint *P;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	int pos1;
	BYTE *t;
	int i;
	sm2_hash local_C_3;

	P_x = BN_new();
	P_y = BN_new();
	k = BN_new();
	P = xy_ecpoint_new(ecp);
	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);

	BN_bin2bn(message_data->public_key.x, ecp->point_byte_length, P_x);
	BN_bin2bn(message_data->public_key.y, ecp->point_byte_length, P_y);
	BN_bin2bn(message_data->k, ecp->point_byte_length, k);

	xy_ecpoint_init_xy(P, P_x, P_y, ecp);
	xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
	xy_ecpoint_mul_bignum(xy2, P, k, ecp);

	pos1 = 0;
	message_data->C_1[0] = '\x04';
	pos1 = pos1 + 1;
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->x);
	BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->y);

	pos1 = 0;
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->y);

	t = KDF((BYTE *)message_data->C_2, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->C_2[i] = t[i] ^ message_data->message[i];
	}
	OPENSSL_free(t);

	//计算C_3
	memset(&local_C_3, 0, sizeof(local_C_3));
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
	                     , xy2->x);
	BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length
	                     , message_data->message);
	BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
	                     , xy2->y);
	SM3_Init();
	SM3_Update((BYTE *)local_C_3.buffer, local_C_3.position);
	SM3_Final_byte(local_C_3.hash);
	memcpy(message_data->C_3, (char *)local_C_3.hash, HASH_BYTE_LENGTH);

	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
	                     , message_data->C_1);
	BUFFER_APPEND_STRING(message_data->C, pos1, message_data->message_byte_length
	                     , message_data->C_2);
	BUFFER_APPEND_STRING(message_data->C, pos1, HASH_BYTE_LENGTH
	                     , message_data->C_3);

	printf("encrypt: \n");
	DEFINE_SHOW_STRING(message_data->C_2, message_data->message_byte_length);

	BN_free(P_x);
	BN_free(P_y);
	BN_free(k);
	xy_ecpoint_free(P);
	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);

	return SUCCESS;
}

int sm2_decrypt(ec_param *ecp, message_st *message_data)
{
	int pos1;
	int pos2;
	xy_ecpoint *xy1;
	xy_ecpoint *xy2;
	BIGNUM *d;
	BYTE KDF_buffer[MAX_POINT_BYTE_LENGTH * 2];
	BYTE *t;
	int i;

	xy1 = xy_ecpoint_new(ecp);
	xy2 = xy_ecpoint_new(ecp);
	d = BN_new();

	pos1 = 0;
	pos2 = 0;
	BUFFER_APPEND_STRING(message_data->C_1, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
	                     , &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C_2, pos1, message_data->message_byte_length
	                     , &message_data->C[pos2]);
	pos2 = pos2 + pos1;
	pos1 = 0;
	BUFFER_APPEND_STRING(message_data->C_3, pos1, HASH_BYTE_LENGTH
	                     , &message_data->C[pos2]);
	pos2 = pos2 + pos1;

	BN_bin2bn(&message_data->C_1[1], ecp->point_byte_length, xy1->x);
	BN_bin2bn(&message_data->C_1[1 + ecp->point_byte_length], ecp->point_byte_length, xy1->y);

	BN_bin2bn(message_data->private_key, ecp->point_byte_length, d);
	xy_ecpoint_init_xy(xy1, xy1->x, xy1->y, ecp);
	xy_ecpoint_mul_bignum(xy2, xy1, d, ecp);

	pos1 = 0;
	memset(KDF_buffer, 0, sizeof(KDF_buffer));
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->x);
	BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->y);
	DEFINE_SHOW_BIGNUM(d);
	DEFINE_SHOW_BIGNUM(xy2->x);
	DEFINE_SHOW_BIGNUM(xy2->y);
	t = KDF((BYTE *)KDF_buffer, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);

	for (i = 0; i < message_data->message_byte_length; i++)
	{
		message_data->decrypt[i] = t[i] ^ message_data->C_2[i];
	}
	OPENSSL_free(t);

	xy_ecpoint_free(xy1);
	xy_ecpoint_free(xy2);
	BN_free(d);

	return SUCCESS;
}

void test_part4(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;
	sm2_ec_key *key_B;
	message_st message_data;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	key_B = sm2_ec_key_new(ecp);
	sm2_ec_key_init(key_B, sm2_param_d_B[ecp->type], ecp);

	memset(&message_data, 0, sizeof(message_data));
	message_data.message = (BYTE *)message;
	message_data.message_byte_length = strlen((char *)message_data.message);
	message_data.klen_bit = message_data.message_byte_length * 8;
	sm2_hex2bin((BYTE *)sm2_param_k[ecp->type], message_data.k, ecp->point_byte_length);
	sm2_bn2bin(key_B->d, message_data.private_key, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->x, message_data.public_key.x, ecp->point_byte_length);
	sm2_bn2bin(key_B->P->y, message_data.public_key.y, ecp->point_byte_length);
	DEFINE_SHOW_BIGNUM(key_B->d);
	DEFINE_SHOW_BIGNUM(key_B->P->x);
	DEFINE_SHOW_BIGNUM(key_B->P->y);

	message_data.decrypt = (BYTE *)OPENSSL_malloc(message_data.message_byte_length + 1);
	memset(message_data.decrypt, 0, message_data.message_byte_length + 1);

	sm2_encrypt(ecp, &message_data);
	sm2_decrypt(ecp, &message_data);

	printf("decrypt: len: %d\n%s\n", strlen(message_data.decrypt), message_data.decrypt);
	OPENSSL_free(message_data.decrypt);

	sm2_ec_key_free(key_B);
	ec_param_free(ecp);
}
