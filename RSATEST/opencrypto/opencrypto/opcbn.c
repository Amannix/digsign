/*
 * =====================================================================================
 *
 *       Filename:  opcbn.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月17日 14时07分52秒
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



void *opc_malloc(int size)
{
	return calloc(1, size);
}

void opc_free(void *p)
{
	return free(p);
}

void i2a_byte(char b, char *dst)
{
	int i;
	unsigned char val;

	for (i = 0; i < 2; i++)
	{
		val = (b & 0xf0) >> 4;
		if (0 <= val && val <= 9)
			dst[i] = val + '0';
		else
			dst[i] = val - 10 + 'A';
		b = b << 4;
	}		/* -------- end for -------- */
	//dst[i] = '\0';
}


void i2a(char *str, unsigned char *hex, unsigned int len)
{
	int i;
	for (i = 0; i < len; i ++)
	{
		i2a_byte(hex[i], str+i*2);
	}		/* -------- end for -------- */
	str[len * 2] = '\0';
	
}

/*
 * Name:		Set the value of rop from bin
 * Parameters:	
 * return:		
 */
int mpz_set_bin(mpz_t a, unsigned char *bin, int len)
{
	char *str;
	int ret;

	str = (unsigned char *)opc_malloc(len * 2 + 1);
	if (str == NULL)
	{
		return OPC_FAILURE;
	}

	i2a(str, bin, len);
	ret = mpz_set_str(a, str, 16);// != 0
	free(str);
	return ret;
}




void a2i_byte(char *src, unsigned char *b, int cnt)
{
	int i;
	unsigned char val;

	*b = 0;
	for (i = 0; i < cnt && src[i] != '\0'; i++)
	{
		*b = *b << 4;
		val = src[i];
		if ('0' <= val && val <= '9')
			*b |= val - '0';
		else
			*b |= val + 10 - 'a';
	}		/* -------- end for -------- */
}


void a2i(char *str, unsigned char *bin, unsigned int *binlen)
{
	int i;
	int slen = strlen(str);

	if (slen % 2)
	{
		a2i_byte(str, bin, 1);
		str++;
		bin++;
		(*binlen)++;
	}

	for (i = 0; i < slen / 2; i++)
	{
		a2i_byte(str+i*2, bin + i, 2);
	}		/* -------- end for -------- */

	*binlen += i;
}


/*
 * Description:	if bin == NULL, the function will in functions create the area for bin
 * Parameters:	 
 * return:		 
 */
unsigned char *mpz_get_bin(unsigned char *bin, unsigned int *binlen, mpz_t op, unsigned int n)
{
	char *str = NULL;
	int str_bytlen = 0; 
	int slen = 0;
	int right_offset = 0;

	*binlen = 0;
	str = mpz_get_str(str, 16, op);
	if (bin == NULL)
	{
		//bin = (unsigned char *)opc_malloc(strlen(str) / 2 + 1);
		bin = (unsigned char *)opc_malloc(n);
		if (bin == NULL)
		{
			return NULL;
		}
	}
	slen = strlen(str);
	str_bytlen = slen / 2 + slen % 2;

	if (n > str_bytlen)
	{
		right_offset = n - str_bytlen;
		*binlen +=  n - str_bytlen;
		memset(bin, 0x00, *binlen);
	}

	a2i(str, bin + right_offset, binlen);
	free(str);
	return bin;
}


int opcbn_set_bin(opcbn_t a, char *bin, int len)
{
	return mpz_set_bin(a->val, bin, len);
}


int opcbn_set_str(opcbn_t a, char *str, int redix)
{
	return mpz_set_str(a->val, str, redix);
}

char *opcbn_get_str(char *str, opcbn_t op)
{
	return mpz_get_str(str, 16, op->val);
}


unsigned char *opcbn_get_bin(unsigned char *bin, unsigned int *len, opcbn_t op, unsigned int n)
{
	return mpz_get_bin(bin, len, op->val, n);
}


/*
 * Name:		get the op size
 * Parameters:	
 * return:		
 */
int opcbn_size_byte(opcbn_t op)
{
	int bytelen = mpz_sizeinbase(op->val, 16);
	return bytelen % 2 ? bytelen / 2 + 1 : bytelen / 2;
}




/*
 * Name:		Return the value of op as an unsigned long. 
 * Parameters:	
 * return:		
 */
unsigned long int opcbn_get_ui(opcbn_t op)
{
	return mpz_get_ui(op->val);
}


void opcbn_cpy(opcbn_t dst, opcbn_t src)
{
	mpz_set(dst->val, src->val);
}
/*
 * Name:		Compare op1 and op2. Return a positive value if op1 > op2, zero if op1 = op2, or a negative
 *				value if op1 < op2.
 * Parameters:	 
 * return:		 
 */
int opcbn_cmp(opcbn_t op1, opcbn_t op2)
{
	return mpz_cmp(op1->val, op2->val);
}

/*
 * Description:	return 0 if op1 <= op2 <= op3,  else return -1
 * Parameters:	 
 * return:		 
 */
int opcbn_section(opcbn_t op1, opcbn_t op2, opcbn_t op3)
{
	if ((opcbn_cmp(op1, op2) <= 0) && (opcbn_cmp(op2, op3) <= 0))
		return 0;
	else
		return -1;
}


void opcbn_init(opcbn_t a)
{
	return mpz_init(a->val);
}

void opcbn_clear(opcbn_t a)
{
	return mpz_clear(a->val);
}




void opcbn_add(opcbn_t sum, opcbn_t a, opcbn_t b)
{
	return mpz_add(sum->val, a->val, b->val);
}

/*
 * Name:		opcbn_modadd sub = a - b
 * Parameters:	
 * return:		success or error
 */
void opcbn_sub(opcbn_t sub, opcbn_t a, opcbn_t b)
{
	return mpz_sub(sub->val, a->val, b->val);
}



void opcbn_fdiv_q(opcbn_t q, opcbn_t n, opcbn_t d)
{
	return mpz_fdiv_q(q->val, n->val, d->val);
}



void opcbn_fdiv_q_ui(opcbn_t q, opcbn_t r, unsigned long int n)
{
	mpz_fdiv_q_ui (q->val, r->val, n);
	return;
}

void opcbn_pow_ui(opcbn_t rop, opcbn_t base, unsigned long int exp)
{
	return mpz_pow_ui(rop->val, base->val, exp);
}




void opcbn_mul(opcbn_t out, opcbn_t a, opcbn_t b)
{
	return mpz_mul(out->val, a->val, b->val);
}



/*
 * Description:	rop * a (mod n) = 1
 * Parameters:	
 * return:		0:		success
 *				other:	inverse doesn't exit
 */
int opcbn_invert(opcbn_t rop, opcbn_t a, opcbn_t n)
{
	if (mpz_invert(rop->val, a->val, n->val))
		return 0;
	else
		return -2;
}



void opcbn_mod(opcbn_t out, opcbn_t a, opcbn_t n)
{
	return mpz_mod(out->val, a->val, n->val);
}



void opcbn_mod_ui(opcbn_t out, opcbn_t a, unsigned long int n)
{
	mpz_mod_ui(out->val, a->val, n);
	return;
}



void opcbn_powm(opcbn_t rop, opcbn_t base, opcbn_t exp, opcbn_t mod)
{
	return mpz_powm(rop->val, base->val, exp->val, mod->val);
}




void opcbn_powm_ui(opcbn_t rop, opcbn_t base, unsigned long int exp, opcbn_t mod)
{
	return mpz_powm_ui(rop->val, base->val, exp, mod->val);
}

/*
 * Description:	opcbn_modadd sum = (a + b) mod n
 * Parameters:	
 * return:		success or error
 */
void opcbn_modadd(opcbn_t sum, opcbn_t a, opcbn_t b, opcbn_t n)
{
	mpz_add(sum->val, a->val, b->val);
	return mpz_mod(sum->val, sum->val, n->val);
	
}

/*
 * Description:	opcbn_modadd sub = (a - b) mod n
 * Parameters:	
 * return:		success or error
 */
void opcbn_modsub(opcbn_t sub, opcbn_t a, opcbn_t b, opcbn_t n)
{
	mpz_sub(sub->val, a->val, b->val);
	return mpz_mod(sub->val, sub->val, n->val);
}

/*
 * Description:	opcbn_modadd out = (a * b) mod n
 * Parameters:	
 * return:		success or error
 */
void opcbn_modmul(opcbn_t out, opcbn_t a, opcbn_t b, opcbn_t n)
{
	mpz_mul(out->val, a->val, b->val);
	return mpz_mod(out->val, out->val, n->val);
}






