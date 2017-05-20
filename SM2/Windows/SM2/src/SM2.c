/*************************************************************************
        > File Name: SM2.c
        > Author:NEWPLAN
        > E-mail:newplan001@163.com
        > Created Time: Thu Apr 13 23:55:50 2017
 ************************************************************************/


#include "sm2.h"
#include "part1.h"
#include "part2.h"
#include "part3.h"
#include "part4.h"

/*
  分为曲线验证，数字签名，密钥交换，加解密

  包括 SM2椭圆曲线公钥密码算法 文档上所有示例计算，
  只在f2m_257 密钥交换 计算用户杂凑值Z时不一致

  ecp->point_byte_length表示不同曲线使用的二进制位数

  DEFINE_SHOW_BIGNUM, 16进制显示大整数的值
  DEFINE_SHOW_STRING，16进制显示二进制字符串
*/
int main(int argc, char* argv[])
{
	{
		//曲线验证
		printf("********************曲线验证********************\n");
		test_part1(sm2_param_fp_192, TYPE_GFp, 192);

		test_part1(sm2_param_fp_256, TYPE_GFp, 256);
		test_part1(sm2_param_f2m_193, TYPE_GF2m, 193);
		test_part1(sm2_param_f2m_257, TYPE_GF2m, 257);
		system("pause");
		//数字签名
		printf("********************数字签名********************\n");
		test_part2(sm2_param_fp_256, TYPE_GFp, 256);
		test_part2(sm2_param_f2m_257, TYPE_GF2m, 257);
		system("pause");
		//密钥交换
		printf("********************密钥交换********************\n");
		test_part3(sm2_param_fp_256, TYPE_GFp, 256);
		//a = 0时，用户hash Z计算不一致, 但生成密钥相同
		test_part3(sm2_param_f2m_257, TYPE_GF2m, 257);
		system("pause");
		//加解密
		//192, 193位中使用的d, k被截断处理
		printf("********************加、解密********************\n");
		test_part4(sm2_param_fp_192, TYPE_GFp, 192);
		test_part4(sm2_param_fp_256, TYPE_GFp, 256);
		test_part4(sm2_param_f2m_193, TYPE_GF2m, 193);
		test_part4(sm2_param_f2m_257, TYPE_GF2m, 257);
		system("pause");
	}

	//推荐参数
	printf("********************曲线验证********************\n");
	test_part1(sm2_param_recommand, TYPE_GFp, 256);
	system("pause");
	printf("********************数字签名********************\n");
	test_part2(sm2_param_recommand, TYPE_GFp, 256);
	system("pause");
	printf("********************密钥交换********************\n");
	test_part3(sm2_param_recommand, TYPE_GFp, 256);
	system("pause");
	printf("********************加、解密********************\n");
	test_part4(sm2_param_recommand, TYPE_GFp, 256);

	//system("pause");
	return 0;
}

