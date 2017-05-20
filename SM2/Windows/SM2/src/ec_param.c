/*************************************************************************
        > File Name: ec_param.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include "ec_param.h"
#include "xy_ecpoint.h"

/*
 *初始化椭圆曲线
 *参数PAB确定的是一条椭圆曲线的参数
 *y2=x3+ax+b（参数的曲线方式）
 *p是素数，一般指的是F(p)中的元素的个数
 *a，b 确定一条椭圆曲线
 *
 *n 基点G的阶(一般要求为素数)
 */
ec_param * ec_param_new(void)
{
	ec_param *ecp;
	ecp = (ec_param *)OPENSSL_malloc(sizeof(ec_param));
	/*申请一个大数上下文环境*/
	ecp->ctx = BN_CTX_new();
	ecp->p = BN_new();
	ecp->a = BN_new();
	ecp->b = BN_new();
	ecp->n = BN_new();
	return ecp;
}
//************************************
// Method:    ec_param_free
// FullName:  ec_param_free
// Access:    public
// Returns:   void
// Qualifier: 释放空间
// Parameter: ec_param * ecp
//************************************
void ec_param_free(ec_param *ecp)
{
	if (ecp)
	{
		BN_free(ecp->p);
		ecp->p = NULL;
		BN_free(ecp->a);
		ecp->a = NULL;
		BN_free(ecp->b);
		ecp->b = NULL;
		BN_free(ecp->n);
		ecp->n = NULL;
		if (ecp->G)
		{
			xy_ecpoint_free(ecp->G);
			ecp->G = NULL;
		}
		if (ecp->group)
		{
			EC_GROUP_free(ecp->group);
			ecp->group = NULL;
		}
		BN_CTX_free(ecp->ctx);
		ecp->ctx = NULL;
		OPENSSL_free(ecp);
	}
}


//************************************
// Method:    ec_param_init
// FullName:  ec_param_init
// Access:    public
// Returns:   int
// Qualifier:初始化椭圆曲线的参数
// Parameter: ec_param * ecp 椭圆曲线参数结构
// Parameter: char * * string_value 要初始化的值
// Parameter: int type 椭圆曲线的类型（共两种GFP金额GF2M）
// Parameter: int point_bit_length 点坐标的长度
//************************************
int ec_param_init(ec_param *ecp, char **string_value, int type, int point_bit_length)
{
	ecp->type = type;
	if (TYPE_GFp == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GFp;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GFp;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GFp;
	}
	else if (TYPE_GF2m == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GF2m;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GF2m;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GF2m;
	}

	/*hex转换成big number*/
	BN_hex2bn(&ecp->p, string_value[0]);
	BN_hex2bn(&ecp->a, string_value[1]);
	BN_hex2bn(&ecp->b, string_value[2]);
	BN_hex2bn(&ecp->n, string_value[5]);

	/*密钥参数group，这个群的概念就是定义曲线上离散的点和相对应的操作*/
	ecp->group = ecp->EC_GROUP_new_curve(ecp->p, ecp->a
	                                     , ecp->b, ecp->ctx);
	/*椭圆参数的基点G*/
	ecp->G = xy_ecpoint_new(ecp);
	BN_hex2bn(&ecp->G->x, string_value[3]);
	BN_hex2bn(&ecp->G->y, string_value[4]);
	if (!ecp->EC_POINT_set_affine_coordinates(ecp->group
	        , ecp->G->ec_point, ecp->G->x
	        , ecp->G->y, ecp->ctx))
		ABORT
		/*椭圆曲线的点的长度*/
		ecp->point_bit_length = point_bit_length;
	ecp->point_byte_length = (point_bit_length + 7) / 8;

	return SUCCESS;
}
