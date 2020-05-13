/*
 * =====================================================================================
 *
 *       Filename:  opcsm2.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月24日 13时00分47秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein, danistmein@outlook.com
 *        Company:  none
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <opc.h>
#include <opcsm2.h>
#include <opcsm3.h>

#ifdef CPU_BIGENDIAN
#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#else
#define cpu_to_be16(v) ((v << 8) | (v >> 8))
#define cpu_to_be32(v) ((cpu_to_be16(v) << 16) | cpu_to_be16(v >> 16))
#endif


static opcsm2_ecc_parameters_t sm2_256_parameter =
{
	/* a */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
	/* b */
	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
	/* p */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
	/* Gx */
	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
	/* Gy */
	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
	/* n */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
	/* h */
	"1",
};


static opcsm2_parameters_t sm2_parameters_list[] = 
{
	{OPC_SM2_256_NID, &sm2_256_parameter},
	{0, NULL},
};


int opcsm2_create_group(opcec_group_t group, int nid)
{
	int i;
	opcsm2_ecc_parameters_t *p_param = NULL;
	opcbn_t p, a, b, Gx, Gy, n, h;

	for (i = 0; sm2_parameters_list[i].nid != 0; i++)
	{
		if (sm2_parameters_list[i].nid == nid)
		{
			p_param  = sm2_parameters_list[i].param;
			break;
		}
	}		/* -------- end for -------- */
	
	if (p_param   == NULL)
	{
		return -1;
	}

	opcbn_init(p);
	opcbn_init(a);
	opcbn_init(b);
	opcbn_init(Gx);
	opcbn_init(Gy);
	opcbn_init(n);
	opcbn_init(h);

	opcbn_set_str(p, p_param->p, 16);
	opcbn_set_str(a, p_param->a, 16);
	opcbn_set_str(b, p_param->b, 16);
	opcbn_set_str(Gx, p_param->Gx , 16);
	opcbn_set_str(Gy, p_param->Gy , 16);
	opcbn_set_str(n, p_param->n, 16);
	opcbn_set_str(h, p_param->h, 16);

	opcec_create_group(group, p, a, b, Gx, Gy, n, h);

	return 0;
}


int opcsm2_generate_key(opcec_group_t group, opcec_t publickey, opcbn_t privatekey)
{
	int ret;
	opcec_t G;

	opcec_init(G);
	opcec_set_opcbn(G, group->Gx, group->Gy);

	opcrand_generate_m(privatekey, group->n);
	ret = opcec_mul(group, publickey, G, privatekey);
	opcec_clear(G);
	return ret;
}



int x9_63_kdf_sm3(const unsigned char *share, size_t sharelen, unsigned char *outkey, size_t keylen)
{
	int ret = 0;

	unsigned char new_counter_be_[4]= {0, 0, 0, 1};
	unsigned int new_counter = 1;
	unsigned int new_counter_be = 1;
	unsigned char dgst[32];
	unsigned int dgstlen=32;
	int rlen = (int)keylen;
	unsigned char *SkdfZ = NULL;

	if (keylen > (0xFFFFFFFF * 32))
	{
		return -1;
	}
	if(sharelen > 1024)
	{
		return -1;
	}
	if ((SkdfZ = (unsigned char *)opc_malloc(sharelen+4)) == NULL)
		return -2;

	memcpy(SkdfZ, share, sharelen);
	while (rlen > 0)
	{
		new_counter_be = cpu_to_be32(new_counter);
		memcpy(SkdfZ+sharelen, &new_counter_be, 4);

	    opcsm3(SkdfZ, sharelen+sizeof(new_counter_be), dgst);

		//pp = outkey;
		memcpy(outkey, dgst, (keylen>=dgstlen ? dgstlen:keylen));
		rlen -= dgstlen;
		outkey += dgstlen;
		new_counter++;		
	}
	opc_free(SkdfZ);
	return 0;
}
 
int opcsm2_get_cipher_size(opcsm2_cipher *cipher)
{
	return SIZEOF_OPCSM2_CIPHER() + cipher->CipherLen - 1;
}

int opcsm2_encrypt(opcec_group_t group, opcec_t publickey, unsigned char *plain, unsigned int plainlen, opcsm2_cipher *cipher)
{
	opcbn_t k;
	opcbn_t tbn;
	opcec_t G;
	opcec_t c1;
	opcec_t kPb;
	opcec_t S;
	opcbn_t zero;
	int ret = 0;
	unsigned char *x2y2, *t;
	int eccparam_byte_len = 0;
	int xlen, ylen;
	int i;

	opcbn_init(k);
	opcbn_init(zero);
	opcbn_init(tbn);
	opcec_init(G);
	opcec_init(c1);
	opcec_init(kPb);
	opcec_init(S);


	eccparam_byte_len = opcbn_size_byte(group->n);
	if ((x2y2 = opc_malloc(eccparam_byte_len * 2 + plainlen)) == NULL)
	{
		ret = -4;
		goto x2y2out;
	}

	if ((t = opc_malloc(plainlen)) == NULL)
	{
		ret = -4;
		goto tout;
	}

A1:
	/* A1 generate k */
	opcrand_generate_m(k, group->n);

	/* A2 calculate C1 */
	opcec_set_opcbn(G, group->Gx, group->Gy);
	if ((ret = opcec_mul(group, c1, G, k)) < 0)
		goto out;
	opcec_get_bin(cipher->XCoordinate, &xlen, cipher->YCoordinate, &ylen, c1, eccparam_byte_len);

	/* A3 S = h * Pb */
	if ((ret = opcec_mul(group, S, publickey, group->h)) < 0)
		goto out;

	opcbn_set_str(zero, "0", 16);
	if (!opcbn_cmp(S->x, zero) && !opcbn_cmp(S->y, zero))
	{
		ret = -3;
		goto out;
	}

	/* A4 kPb = k * Pb */
	if ((ret = opcec_mul(group, kPb, publickey, k)) < 0)
		goto out;

	/* A5 calculate t = kdf(x2||y2, klen) */
	/* A5.1 get x2||y2 */
	opcec_get_bin(x2y2, &xlen, x2y2 + eccparam_byte_len, &ylen, kPb, eccparam_byte_len);


	/* A5.2 t = kdf(x2||y2, klen) */
	if ((ret = x9_63_kdf_sm3(x2y2, eccparam_byte_len * 2, t, plainlen)) < 0)
		goto out;

	opcbn_set_bin(tbn, t, plainlen);
	if (!opcbn_cmp(tbn, zero))
		goto A1;

	/* A6 C2 = M ^ t */
	for (i = 0; i < plainlen; i++)
	{
		cipher->Cipher[i] = plain[i] ^ t[i];
	}		/* -------- end for -------- */
	cipher->CipherLen = plainlen;
	
	/* A7 C3 = sm3(x2 || M || y2) */
	opcbn_get_bin(x2y2, &xlen, kPb->x, eccparam_byte_len);
	memcpy(x2y2 + eccparam_byte_len, plain, plainlen);
	opcbn_get_bin(x2y2 + eccparam_byte_len + plainlen, &ylen, kPb->y, eccparam_byte_len);
	
	opcsm3(x2y2, eccparam_byte_len * 2 + plainlen, cipher->HASH);
	
out:
	opcbn_clear(k);
	opcbn_clear(zero);
	opcbn_clear(tbn);
	opcec_clear(G);
	opcec_clear(c1);
	opcec_clear(kPb);
	opcec_clear(S);
	opc_free(t);
tout:
	opc_free(x2y2);
x2y2out:
	return ret;
}




int opcsm2_decrypt(opcec_group_t group, opcsm2_cipher *cipher, opcbn_t privatekey, unsigned char *plain, unsigned int *plainlen)
{
	int eccparam_byte_len = 0;
	int ret = 0;
	unsigned char *x2y2, *t;
	unsigned int i, xlen, ylen;
	unsigned char u[SM3_DIGEST_SIZE] = {0};
	opcec_t c1;
	opcec_t S;
	opcec_t dBc1;
	opcbn_t zero;
	opcbn_t tbn;

	opcbn_init(zero);
	opcbn_init(tbn);
	opcec_init(c1);
	opcec_init(S);
	opcec_init(dBc1);

	eccparam_byte_len = opcbn_size_byte(group->n);
	if ((x2y2 = opc_malloc(eccparam_byte_len * 2 + cipher->CipherLen)) == NULL)
	{
		ret = -4;
		goto x2y2out;
	}


	if ((t = opc_malloc(cipher->CipherLen)) == NULL)
	{
		ret = -4;
		goto tout;
	}


	/* B1 get c1 */
	opcec_set_bin(c1, cipher->XCoordinate, eccparam_byte_len, cipher->YCoordinate, eccparam_byte_len);

	/* B2 calculate S = h * c1 */
	if ((ret = opcec_mul(group, S, c1, group->h)) < 0)
		goto out;

	opcbn_set_str(zero, "0", 16);
	if (!opcbn_cmp(S->x, zero) && !opcbn_cmp(S->y, zero))
	{
		ret = -3;
		goto out;
	}

	/* B3 x2y2 = dB * C1 */
	if ((ret = opcec_mul(group, dBc1, c1, privatekey)) < 0)
		goto out;

	/* B4 calculate t = kdf(x2||y2, klen) */
	opcec_get_bin(x2y2, &xlen, x2y2 + eccparam_byte_len, &ylen, dBc1, eccparam_byte_len);
	if ((ret = x9_63_kdf_sm3(x2y2, eccparam_byte_len * 2, t, cipher->CipherLen)) < 0)
		goto out;

	opcbn_set_bin(tbn, t, cipher->CipherLen);
	if (!opcbn_cmp(tbn, zero))
	{
		ret = -5;
		goto out;
	}

	/* B5 M` = c2 ^ t */
	for (i = 0; i < cipher->CipherLen; i++)
	{
		plain[i] = t[i] ^ cipher->Cipher[i];
	}		/* -------- end for -------- */
	*plainlen = cipher->CipherLen;

	/* B6 u = Hash(x2 || M` || y2 ) */
	opcbn_get_bin(x2y2, &xlen, dBc1->x, eccparam_byte_len);
	memcpy(x2y2 + eccparam_byte_len, plain, *plainlen);
	opcbn_get_bin(x2y2 + eccparam_byte_len + *plainlen, &ylen, dBc1->y, eccparam_byte_len);
	opcsm3(x2y2, *plainlen + eccparam_byte_len * 2, u);
	/* B7 u == C3 */
	if (memcmp(u, cipher->HASH, SM3_DIGEST_SIZE))
	{
#if 0
		int j;
		fprintf(stderr, "eccparam_byte_len = %d\n", eccparam_byte_len);
		fprintf(stderr, "u = ");
		for (j = 0; j < SM3_DIGEST_SIZE; j++)
		{
			fprintf(stderr, "%02hx", u[j]);
		}		/* -------- end for -------- */
		fprintf(stderr, "\n");


		fprintf(stderr, "cipher->HASH = ");
		for (j = 0; j < SM3_DIGEST_SIZE; j++)
		{
			fprintf(stderr, "%02hx", cipher->HASH[j]);
		}		/* -------- end for -------- */
		fprintf(stderr, "\n");

		gmp_printf("ec1  x = %Zx, y = %Zx\n", c1->x->val, c1->y->val);
		gmp_printf("dBc1 x = %Zx, y = %Zx\n", dBc1->x->val, dBc1->y->val);
#endif		/* ------ end if 0 ------ */

		
		ret = -6;
	}
out:
	opcbn_clear(zero);
	opcbn_clear(tbn);
	opcec_clear(c1);
	opcec_clear(S);
	opcec_clear(dBc1);
	opc_free(t);
tout:
	opc_free(x2y2);
x2y2out:
	return ret;
}


int opcsm2_sign(opcec_group_t group, opcbn_t privatekey, unsigned char *digst, unsigned int digstlen, opcsm2_signature *sign)
{
	opcbn_t e, k, r, s, zero, r_k, one, dA_1, dA_1_invert, rda, k_rda;
	opcec_t x1y1, G;
	int eccparam_byte_len = 0;
	int ret = 0;
	int len = 0;

	opcbn_init(e);
	opcbn_init(k);
	opcbn_init(r);
	opcbn_init(s);
	opcbn_init(zero);
	opcbn_init(one);
	opcbn_init(dA_1);
	opcbn_init(dA_1_invert);
	opcbn_init(rda);
	opcbn_init(k_rda);
	opcbn_init(r_k);
	opcec_init(x1y1);
	opcec_init(G);

	eccparam_byte_len = opcbn_size_byte(group->n);
	opcec_set_opcbn(G, group->Gx, group->Gy);
	opcbn_set_str(zero, "0", 16);
	opcbn_set_str(one, "1", 16);

	/* A2 e */
	opcbn_set_bin(e, digst, digstlen);

A3:
	/* A3 generate k */
	opcrand_generate_m(k, group->n);

	/* A4 (x1,y1) = k * G */
	if ((ret = opcec_mul(group, x1y1, G, k)) != 0)
		goto out;

	/* A5 r = (e + x1) mod n */
	opcbn_modadd(r, e, x1y1->x, group->n);
	/* A5.1 if r == 0, return to A3 */
	if (opcbn_cmp(r, zero) == 0)
		goto A3;

	/* A5.1 if r + k == n, return to A3 */
	opcbn_add(r_k, r, k);
	if (opcbn_cmp(r_k, group->n) == 0)
		goto A3;

	/* A6 s = ((1 + dA)^-1 * (k - r*da)) mod n */
	/* A6.1 1 + dA */
	opcbn_add(dA_1, one, privatekey);
	/* A6.2 (1 + dA)^-1 */
	if ((ret = opcbn_invert(dA_1_invert, dA_1, group->n)) != 0)
		goto out;
	/* A6.3 r*da */
	opcbn_mul(rda, r, privatekey);
	/* A6.4 k - r*da */
	opcbn_sub(k_rda, k, rda);
	/* A6.5 ((1 + dA)^-1 * (k - r*da)) */
	opcbn_mul(s, dA_1_invert, k_rda);
	/* A6.6 s = ((1 + dA)^-1 * (k - r*da)) mod n */
	opcbn_mod(s, s, group->n);
	/* A6.7 if s == 0 return A3 */
	if (opcbn_cmp(s, zero) == 0)
		goto A3;

	opcbn_get_bin(sign->r, &len, r, eccparam_byte_len);
	opcbn_get_bin(sign->s, &len, s, eccparam_byte_len);

out:
	opcbn_clear(e);
	opcbn_clear(k);
	opcbn_clear(r);
	opcbn_clear(s);
	opcbn_clear(zero);
	opcbn_clear(one);
	opcbn_clear(dA_1);
	opcbn_clear(dA_1_invert);
	opcbn_clear(rda);
	opcbn_clear(k_rda);
	opcbn_clear(r_k);
	opcec_clear(x1y1);
	opcec_clear(G);
	return ret;
}


int opcsm2_verify(opcec_group_t group, opcec_t publickey, opcsm2_signature *sign, unsigned char *digst, unsigned int digstlen)
{
	opcbn_t one, zero, t;
	opcbn_t r, s, R, e;
	opcec_t x1y1, sG, tPa, G;
	int eccparam_byte_len = 0;
	int ret = 0;

	opcbn_init(one);
	opcbn_init(zero);
	opcbn_init(t);
	opcbn_init(r);
	opcbn_init(R);
	opcbn_init(s);
	opcbn_init(e);
	opcec_init(x1y1);
	opcec_init(sG);
	opcec_init(tPa);
	opcec_init(G);

	eccparam_byte_len = opcbn_size_byte(group->n);
	opcbn_set_str(one, "1", 16);
	opcbn_set_str(zero, "0", 16);
	opcbn_set_bin(r, sign->r, eccparam_byte_len);
	opcbn_set_bin(s, sign->s, eccparam_byte_len);
	opcec_set_opcbn(G, group->Gx, group->Gy);
	/* B1 1 <= r <= n - 1 */
	if ((ret = opcbn_section(one, r, group->n)) != 0)
		goto out;
		
	/* B2 1 <= s <= n - 1 */
	if ((ret = opcbn_section(one, s, group->n)) != 0)
		goto out;

	/* B5 t = r + s */
	opcbn_modadd(t, r, s, group->n);
	if (!opcbn_cmp(t, zero))
	{
		ret = -2;
		goto out;
	}

	/* B6 (x1,y1) = s * G + t * Pa */
	/* B6.1 sG = s * G */
	if ((ret = opcec_mul(group, sG, G, s)) != 0)
	{
		goto out;
	}

	/* B6.2 tPa = t * Pa */
	if ((ret = opcec_mul(group, tPa, publickey, t)) != 0)
	{
		goto out;
	}

	/* B6.3 (x1,y1) = sG + tPa */
	if ((ret = opcec_add(group, x1y1, sG, tPa)) != 0)
	{
		goto out;
	}

	/* B7 r == R, R = (e + x1) mod n */
	opcbn_set_bin(e, digst, digstlen);
	opcbn_modadd(R, e, x1y1->x, group->n);

	if (opcbn_cmp(R, r) == 0)
	{
		ret = 0;
	}
	else
	{
		ret = -7;
	}		/* -------- end else -------- */

out:
	opcbn_clear(one);
	opcbn_clear(zero);
	opcbn_clear(t);
	opcbn_clear(r);
	opcbn_clear(R);
	opcbn_clear(s);
	opcbn_clear(e);
	opcec_clear(x1y1);
	opcec_clear(sG);
	opcec_clear(tPa);
	opcec_clear(G);
	return ret;
}



 /* ZA = (ENTLA || id || a || b || xG || yG || xA || yA) */
int opcsm2_getz(opcec_group_t group, char *id, unsigned int id_len, opcec_t publickey, unsigned char *za)
{
	unsigned char *p, *z;
	unsigned int tmplen;
	unsigned int len;
	unsigned short idBitLen = id_len * 8;
	int eccparam_byte_len = 0;
	eccparam_byte_len = opcbn_size_byte(group->n);

	if ((z = malloc(2 + id_len + eccparam_byte_len * 6 + 1)) == NULL)
		return -1;

	p = z;
	*p = (idBitLen >> 8) & 0xff;
	*(p + 1) = idBitLen & 0xff;
	p += sizeof(idBitLen);

	memcpy(p, id, id_len);
	p += id_len;

	opcbn_get_bin(p, &tmplen, group->a, eccparam_byte_len);
	p += eccparam_byte_len;

	opcbn_get_bin(p, &tmplen, group->b, eccparam_byte_len);
	p += eccparam_byte_len;

	opcbn_get_bin(p, &tmplen, group->Gx, eccparam_byte_len);
	p += eccparam_byte_len;

	opcbn_get_bin(p, &tmplen, group->Gy, eccparam_byte_len);
	p += eccparam_byte_len;

	opcbn_get_bin(p, &tmplen, publickey->x, eccparam_byte_len);
	p += eccparam_byte_len;

	opcbn_get_bin(p, &tmplen, publickey->y, eccparam_byte_len);
	p += eccparam_byte_len;

	len = 2 + id_len + eccparam_byte_len * 6;
	opcsm3(z, len, za);
	free(z);
	return 0;
}


