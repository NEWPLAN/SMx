/*************************************************************************
        > File Name: ec_param.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef EC_PARAM_H
#define EC_PARAM_H

#include "sm2_common.h"

ec_param * ec_param_new(void);
void ec_param_free(ec_param *ecp);
int ec_param_init(ec_param *ecp, char **string_value, int type, int point_bit_length);

#endif