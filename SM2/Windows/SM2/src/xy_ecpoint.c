/*************************************************************************
        > File Name: xy_ecpoint.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#include "xy_ecpoint.h"
#include "sm2_common.h"

xy_ecpoint *xy_ecpoint_new(ec_param *ecp)
{
	xy_ecpoint *xyp;
	xyp = (xy_ecpoint *)OPENSSL_malloc(sizeof(xy_ecpoint));
	xyp->x = BN_new();
	xyp->y = BN_new();
	xyp->ec_point = EC_POINT_new(ecp->group);
	return xyp;
}
void xy_ecpoint_free(xy_ecpoint *xyp)
{
	if (xyp)
	{
		BN_free(xyp->x);
		xyp->x = NULL;
		BN_free(xyp->y);
		xyp->y = NULL;
		EC_POINT_free(xyp->ec_point);
		xyp->ec_point = NULL;
		OPENSSL_free(xyp);
	}
}

int xy_ecpoint_mul_bignum(xy_ecpoint *result, xy_ecpoint *a, BIGNUM *number
                          , ec_param *ecp)
{
	EC_POINT_mul(ecp->group, result->ec_point, NULL, a->ec_point, number, ecp->ctx);
	ecp->EC_POINT_get_affine_coordinates(ecp->group
	                                     , (result)->ec_point
	                                     , (result)->x
	                                     , (result)->y
	                                     , ecp->ctx);

	return SUCCESS;
}

int xy_ecpoint_add_xy_ecpoint(xy_ecpoint *result, xy_ecpoint *a, xy_ecpoint *b
                              , ec_param *ecp)
{
	EC_POINT_add(ecp->group, (result)->ec_point, a->ec_point, b->ec_point, ecp->ctx);
	ecp->EC_POINT_get_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return SUCCESS;
}

int xy_ecpoint_init_xy(xy_ecpoint *result, BIGNUM *x, BIGNUM *y
                       , ec_param *ecp)
{
	//设置ec_point
	ecp->EC_POINT_set_affine_coordinates(ecp->group, (result)->ec_point
	                                     , x, y
	                                     , ecp->ctx);

	//获取x, y
	ecp->EC_POINT_get_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return SUCCESS;
}
int xy_ecpoint_init_ec_point(xy_ecpoint *result, EC_POINT *ec_point
                             , ec_param *ecp)
{
	//获取x, y
	ecp->EC_POINT_get_affine_coordinates(ecp->group, ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);

	//设置ec_point
	ecp->EC_POINT_set_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return SUCCESS;
}