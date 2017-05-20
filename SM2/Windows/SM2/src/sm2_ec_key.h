/*************************************************************************
        > File Name: sm2_ec_key.h
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/
#ifndef SM2_EC_KEY_H
#define SM2_EC_KEY_H

#include <openssl/ec.h>
#include "xy_ecpoint.h"
#include "ec_param.h"

sm2_ec_key * sm2_ec_key_new(ec_param *ecp);
void sm2_ec_key_free(sm2_ec_key *eck);
int sm2_ec_key_init(sm2_ec_key *eck, char *string_value, ec_param *ecp);

#endif