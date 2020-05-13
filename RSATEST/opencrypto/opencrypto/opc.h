/*
 * =====================================================================================
 *
 *       Filename:  opencrypto.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月23日 21时19分15秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein, danistmein@gmail.com
 *        Company:  none
 *
 * =====================================================================================
 */

#ifndef  OPENCRYPTO_H
#define  OPENCRYPTO_H


#include <gmp.h>

#define OPC_SUCCESS		0
#define OPC_FAILURE		-1
#define OPC_SLOPEERR	-2

#define     opc_printf		gmp_printf

typedef struct opc_bn
{
	mpz_t val;
}opc_bn_st;

typedef opc_bn_st opcbn_t[1];

typedef struct opc_ecc_point
{
	opcbn_t x;
	opcbn_t y;
}opc_ecc_point_st;



typedef struct opc_ecc_group
{
	opcbn_t p;
	opcbn_t a;
	opcbn_t b;
	opcbn_t n;
	opcbn_t Gx;
	opcbn_t Gy;
	opcbn_t h;
}opc_ecc_group_st;

typedef opc_ecc_point_st opcec_t[1];
typedef opc_ecc_group_st opcec_group_t[1];



/* BIG NUMBER Functions */

void *opc_malloc(int size);
void opc_free(void *p);

void opcbn_init(opcbn_t a);
void opcbn_clear(opcbn_t a);

int opcbn_size_byte(opcbn_t op);

int opcbn_set_bin(opcbn_t a, char *bin, int len);
int opcbn_set_str(opcbn_t a, char *str, int redix);

unsigned char *opcbn_get_bin(unsigned char *bin, unsigned int *len, opcbn_t op, unsigned int n);
char *opcbn_get_str(char *str, opcbn_t op);
unsigned long int opcbn_get_ui(opcbn_t op);
void opcbn_cpy(opcbn_t dst, opcbn_t src);
int opcbn_cmp(opcbn_t op1, opcbn_t op2);
int opcbn_section(opcbn_t op1, opcbn_t op2, opcbn_t op3);

void opcbn_add(opcbn_t sum, opcbn_t a, opcbn_t b);
void opcbn_mul(opcbn_t out, opcbn_t a, opcbn_t b);
void opcbn_pow_ui(opcbn_t rop, opcbn_t base, unsigned long int exp);
void opcbn_sub(opcbn_t sub, opcbn_t a, opcbn_t b);
void opcbn_fdiv_q(opcbn_t q, opcbn_t n, opcbn_t d);
void opcbn_fdiv_q_ui(opcbn_t q, opcbn_t r, unsigned long int n);
int opcbn_invert(opcbn_t rop, opcbn_t a, opcbn_t n);

void opcbn_mod(opcbn_t out, opcbn_t a, opcbn_t n);
void opcbn_mod_ui(opcbn_t out, opcbn_t a, unsigned long int n);

void opcbn_modadd(opcbn_t sum, opcbn_t a, opcbn_t b, opcbn_t n);
void opcbn_modsub(opcbn_t sub, opcbn_t a, opcbn_t b, opcbn_t n);
void opcbn_modmul(opcbn_t out, opcbn_t a, opcbn_t b, opcbn_t n);
void opcbn_powm(opcbn_t rop, opcbn_t base, opcbn_t exp, opcbn_t mod);
void opcbn_powm_ui(opcbn_t rop, opcbn_t base, unsigned long int exp, opcbn_t mod);






/* ECC Functions */

void opcec_init(opcec_t p);
void opcec_clear(opcec_t p);
void opcec_cpy(opcec_t dst, opcec_t src);

int opcec_set_bin(opcec_t p, char *x, int xlen, char *y, int ylen);
int opcec_set_str(opcec_t p, char *x, int xredix, char *y, int yredix);
void opcec_set_opcbn(opcec_t rop, opcbn_t x, opcbn_t y);


void opcec_get_opcbn(opcbn_t x, opcbn_t y, opcec_t p);
void opcec_get_bin(unsigned char *x, int *xlen, unsigned char *y, int *ylen, opcec_t p, unsigned int n);
void opcec_get_str(char *x, char *y, opcec_t p);

void opcec_create_group(opcec_group_t group, opcbn_t p, opcbn_t a, opcbn_t b, opcbn_t Gx, opcbn_t Gy, opcbn_t n, opcbn_t h);
void opcec_clear_group(opcec_group_t group);
int opcec_add(opcec_group_t group, opcec_t r, opcec_t p, opcec_t q);
int opcec_mul(opcec_group_t group, opcec_t r, opcec_t p, opcbn_t k);




/* Random Functions */

/*
 * Description:	you must be call this function first, init random state
 */
void opcrand_init(void);
void opcrand_generate_b(opcbn_t op, unsigned long int byte_len);
void opcrand_generate_m(opcbn_t op, opcbn_t n);
void opcrand_clear(void);

#endif  // OPENCRYPTO_H
