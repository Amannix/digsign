/*
 * =====================================================================================
 *
 *       Filename:  opcrandom.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月23日 14时32分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein, danistmein@outlook.com
 *        Company:  none
 *
 * =====================================================================================
 */



#include <stdio.h>
#include <time.h>
#include <opc.h>


#ifdef __linux
#include <sys/time.h>
#define HAVE_GETTIMEOFDAY 1
#endif

static gmp_randstate_t base_rand_st;

void opcrand_init(void)
{
	gmp_randinit_default(base_rand_st);
#if HAVE_GETTIMEOFDAY
    struct timeval tv;
    gettimeofday (&tv, NULL);
    gmp_randseed_ui (base_rand_st, tv.tv_sec + tv.tv_usec);
#else
    time_t t;
    time (&t);
    gmp_randseed_ui (base_rand_st, t);
#endif
}



/*
 * Description:	generate byte_len random
 * Parameters:	  
 * return:		 
 */
void opcrand_generate_b(opcbn_t op, unsigned long int byte_len)
{
	return mpz_urandomb(op->val, base_rand_st, byte_len*8);
}

/*
 * Description:	Generate a uniform random integer in the range 0 to n − 1, inclusive.
 * Parameters:	 
 * return:		 
 */
void opcrand_generate_m(opcbn_t op, opcbn_t n)
{
	return mpz_urandomm(op->val, base_rand_st, n->val);
}


void opcrand_clear(void)
{
	gmp_randclear(base_rand_st);
}
