/*************************************************************************
        > File Name: xy_ecpoint.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef XY_ECPOINT_H
#define XY_ECPOINT_H

#include <openssl/ec.h>

#include "ec_param.h"

xy_ecpoint * xy_ecpoint_new(ec_param *);
void xy_ecpoint_free(xy_ecpoint *);

int xy_ecpoint_mul_bignum(xy_ecpoint *result, xy_ecpoint *a, BIGNUM *number
                          , ec_param *ecp);
int xy_ecpoint_add_xy_ecpoint(xy_ecpoint *result, xy_ecpoint *a, xy_ecpoint *b
                              , ec_param *ecp);
int xy_ecpoint_init_xy(xy_ecpoint *result, BIGNUM *x, BIGNUM *y
                       , ec_param *ecp);
int xy_ecpoint_init_ec_point(xy_ecpoint *result, EC_POINT *ec_point
                             , ec_param *ecp);

#endif