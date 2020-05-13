/*
 * =====================================================================================
 *
 *       Filename:  opcsm2.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月24日 13时02分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein, danistmein@outlook.com
 *        Company:  none
 *
 * =====================================================================================
 */


#ifndef  OPCSM2_H
#define  OPCSM2_H

#include <opc.h>

#define     OPC_ECCref_MAX_LEN		64
#define     SM3_DIGEST_SIZE			32
#define     OPC_SM2_PARAMETER_LEN	128

#define     SIZEOF_OPCSM2_CIPHER()	(OPC_ECCref_MAX_LEN * 2 + SM3_DIGEST_SIZE + 4 + 1) // 165

#define     OPC_SM2_256_NID			1

typedef struct OPC_ECCCipher_st
{
	unsigned char XCoordinate[OPC_ECCref_MAX_LEN];
	unsigned char YCoordinate[OPC_ECCref_MAX_LEN];
	unsigned char HASH[SM3_DIGEST_SIZE];
	unsigned int CipherLen;
	unsigned char Cipher[1];
}opcsm2_cipher;


typedef struct OPC_ECCSignature_st
{
	unsigned char r[OPC_ECCref_MAX_LEN];
	unsigned char s[OPC_ECCref_MAX_LEN];
}opcsm2_signature;


typedef struct sm2_ecc_parameters
{
	char a[OPC_SM2_PARAMETER_LEN];
	char b[OPC_SM2_PARAMETER_LEN];
	char p[OPC_SM2_PARAMETER_LEN];
	char Gx[OPC_SM2_PARAMETER_LEN];
	char Gy[OPC_SM2_PARAMETER_LEN];
	char n[OPC_SM2_PARAMETER_LEN];
	char h[OPC_SM2_PARAMETER_LEN];
}opcsm2_ecc_parameters_t;

typedef struct opcsm2_parameters
{
	unsigned int nid;
	opcsm2_ecc_parameters_t *param;
}opcsm2_parameters_t;



int opcsm2_get_cipher_size(opcsm2_cipher *cipher);

int opcsm2_create_group(opcec_group_t group, int nid);
int opcsm2_generate_key(opcec_group_t group, opcec_t publickey, opcbn_t privatekey);
int opcsm2_encrypt(opcec_group_t group, opcec_t publickey, unsigned char *plain, unsigned int plainlen, opcsm2_cipher *cipher);
int opcsm2_decrypt(opcec_group_t group, opcsm2_cipher *cipher, opcbn_t privatekey, unsigned char *plain, unsigned int *plainlen);
int opcsm2_sign(opcec_group_t group, opcbn_t privatekey, unsigned char *digst, unsigned int digstlen, opcsm2_signature *sign);
int opcsm2_verify(opcec_group_t group, opcec_t publickey, opcsm2_signature *sign, unsigned char *digst, unsigned int digstlen);

int opcsm2_getz(opcec_group_t group, char *id, unsigned int id_len, opcec_t publickey, unsigned char *za);

#endif  // OPCSM2_H
