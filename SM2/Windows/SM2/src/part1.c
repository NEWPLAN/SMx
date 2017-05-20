/*************************************************************************
        > File Name: part1.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/

#include "part1.h"

//曲线验证
//************************************
// Method:    test_part1
// FullName:  test_part1
// Access:    public
// Returns:   void
// Qualifier:曲线认证
// Parameter: char * * sm2_param SM2的椭圆曲线参数
// Parameter: int type 椭圆曲线的类型
// Parameter: int point_bit_length 点的长度
//************************************
void test_part1(char **sm2_param, int type, int point_bit_length)
{
	ec_param *ecp;

	ecp = ec_param_new();
	ec_param_init(ecp, sm2_param, type, point_bit_length);

	//验证G是否在曲线上,库函数
	if (!EC_POINT_is_on_curve(ecp->group, ecp->G->ec_point, ecp->ctx))
	{
		ABORT;
		printf("EC_POINT_is_on_curve: 0\n");
	}
	else
	{
		printf("EC_POINT_is_on_curve: 1\n");
	}

	ec_param_free(ecp);

#if 0
	//GFp曲线用大数计算验证
	if (0)
	{
		BIGNUM *r;
		BIGNUM *tmp1;
		char *left;
		char *right;
		r = BN_new();
		tmp1 = BN_new();

		BN_set_word(r, 0);
		BN_mul(r, G_y, G_y, ctx);
		BN_div(NULL, r, r, p, ctx);

		left = BN_bn2hex(r);
		printf("y^2: %s\n", left);
		OPENSSL_free(left);

		BN_set_word(r, 0);
		BN_mod_mul(tmp1, G_x, G_x, p, ctx);
		BN_mod_mul(tmp1, tmp1, G_x, p, ctx);
		BN_mod_add(r, r, tmp1, p, ctx);
		BN_mod_mul(tmp1, a, G_x, p, ctx);
		BN_mod_add(r, r, tmp1, p, ctx);
		BN_mod_add(r, r, b, p, ctx);
		//BN_div(NULL, r, r, p, ctx);

		right = BN_bn2hex(r);
		printf("x^3+ax+b: %s\n", right);
		OPENSSL_free(right);

		BN_free(r);
		BN_free(tmp1);
	}
#endif
}
