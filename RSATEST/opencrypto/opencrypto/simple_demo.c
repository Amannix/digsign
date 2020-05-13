/*
 * =====================================================================================
 *
 *       Filename:  demo.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月25日 20时41分11秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein , danistmein@outlook.com
 *        Company:  none
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include "opc.h"
#include "opcsm2.h"


int main(int argc, char *argv[])
{
	char cipherbuffer[512] = {0};
	unsigned char plain[512];
	char decrypt[256] = {0};
	int decryptlen;
	unsigned int plainlen = 32;
	unsigned int tmplen;
	char *str;
	int ret = 0;

	opcec_t pubk;
	opcbn_t prik;
	opcbn_t rand;
	opcec_group_t sm2group;
	opcsm2_cipher *cipher = (opcsm2_cipher *)cipherbuffer;
	opcsm2_signature sign;


	/* you must be call this function first, init random state */
	opcrand_init();

	opcsm2_create_group(sm2group, OPC_SM2_256_NID);
	opcec_init(pubk);
	opcbn_init(prik);
	opcbn_init(rand);

	opcsm2_generate_key(sm2group, pubk, prik);

	opcrand_generate_b(rand, plainlen);
	opcbn_get_bin(plain, &tmplen, rand, 32);

	opc_printf("---------------opc simple test--------------------\n", rand);
	opc_printf("public key:X= %Zx, Y=%Zx\n", pubk->x, pubk->y);
	opc_printf("private key = %Zx\n", prik);
	opc_printf("plain       = %Zx\n", rand);
	opc_printf("               encrypt test\n", rand);

	if ((ret = opcsm2_encrypt(sm2group, pubk, plain, plainlen, cipher)) != 0)
	{
		opc_printf("sm2 encrypt error ! ret = %d\n", ret);
		return ret;
	}
	opcbn_set_bin(rand, cipher->XCoordinate, 32);
	opc_printf("cipher c1.x = %Zx\n", rand);
	opcbn_set_bin(rand, cipher->YCoordinate, 32);
	opc_printf("cipher c1.y = %Zx\n", rand);
	opcbn_set_bin(rand, cipher->HASH, 32);
	opc_printf("cipher c3   = %Zx\n", rand);
	opcbn_set_bin(rand, cipher->Cipher, cipher->CipherLen);
	opc_printf("cipher c2   = %Zx\n", rand);


	if ((ret = opcsm2_decrypt(sm2group, cipher, prik, decrypt, &decryptlen)) < 0)
	{
		opc_printf("sm2 decrypt error ! ret = %d\n", ret);
		return ret;
	}
	opcbn_set_bin(rand, decrypt, decryptlen);
	opc_printf("decrypt     = %Zx\n", rand);


	if (decryptlen != plainlen || memcmp(decrypt, plain, plainlen))
	{
		opc_printf("sm2 decrypt data not equal!\n");
		return ret;
	}


	opc_printf("               sign test\n", rand);
	if ((ret = opcsm2_sign(sm2group, prik, plain, plainlen, &sign)) != 0)
	{
		opc_printf("sm2 sign error ! ret = %d!\n", ret);
		return ret;
	}
	opcbn_set_bin(rand, sign.r, 32);
	opc_printf("sign.r      = %Zx\n", rand);
	opcbn_set_bin(rand, sign.s, 32);
	opc_printf("sign.s      = %Zx\n", rand);
	
	if ((ret = opcsm2_verify(sm2group, pubk, &sign, plain, plainlen)) != 0)
	{
		opc_printf("sm2 verify error ! ret = %d!\n", ret);
		return ret;
	}
	opc_printf("verify success\n");

	opc_printf("--------------------------------------------------\n", rand);
	opc_printf("sm2 encrypt decrypt sign verify test success!\n");
	opcec_clear_group(sm2group);
	return 0;
}		/* -------------- end function -------------- */
