/*
 * =====================================================================================
 *
 *       Filename:  opcec.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2016年11月17日 14时49分31秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Danistmein, danistmein@outlook.com
 *        Company:  none
 *
 * =====================================================================================
 */


#include <stdio.h>
#include <opc.h>



int get_slope_equal(opcec_group_t group, opcbn_t slope, opcec_t p)
{
	opcbn_t three, two;
	opcbn_t rop, y2, y2_invert;
	int ret = 0;

	/* slope = (3x^2 + a) / (2y) */
	opcbn_init(three);
	opcbn_init(two);
	opcbn_init(rop);
	opcbn_init(y2);
	opcbn_init(y2_invert);

	opcbn_set_str(two, "2", 16);
	opcbn_set_str(three, "3", 16);

	/* 1. x^2 */
	opcbn_pow_ui(rop, p->x, 2);

	/* 2. 3x^2 */
	opcbn_mul(rop, rop, three);

	/* 3. 3x^2 + a */
	opcbn_add(rop, rop, group->a);
	//opcbn_sub(rop, rop, group->p);

	/* 5. 2y */
	opcbn_mul(y2, p->y, two);
	
	/* 6. (2y)^-1 */
	//opcbn_invert(y2_invert, y2, group->p);
	if ((ret = opcbn_invert(y2_invert, y2, group->p)) < 0)
		goto out;

	/* 7. (3x^2 + a) * (2y)^-1 */
	opcbn_mul(slope, rop, y2_invert);
	opcbn_mod(slope, slope, group->p);

out:
	opcbn_clear(three);
	opcbn_clear(two);
	opcbn_clear(rop);
	opcbn_clear(y2);
	opcbn_clear(y2_invert);
	return ret;
}



int get_slope_other(opcec_group_t group, opcbn_t slope, opcec_t p, opcec_t q)
{
	int ret = 0;
	opcbn_t a, b, b_1;
	/* slope = (Yq - Yp) / (Xq - Xp) */

	opcbn_init(a);
	opcbn_init(b);
	opcbn_init(b_1);

	/* 1. a = Yq - Yp*/
	opcbn_sub(a, q->y, p->y);

	/* 2. b = Xq - Xp*/
	opcbn_sub(b, q->x, p->x);

	/* 3. b^-1 */
	//opcbn_invert(b_1, b, group->p);
	if ((ret = opcbn_invert(b_1, b, group->p) < 0))
		goto out;

	/* 4. slope = a * b^-1 */
	opcbn_mul(slope, a, b_1);
	opcbn_mod(slope, slope, group->p);

out:
	opcbn_clear(a);
	opcbn_clear(b);
	opcbn_clear(b_1);
	return ret;
}




void calculate_Xr(opcec_group_t group, opcec_t r, opcbn_t slope, opcec_t p, opcec_t q)
{
	/* Xr = slope^2 - Xp - Xq */
	opcbn_t slope_2;

	opcbn_init(slope_2);

	/* 1. slope^2 */
	opcbn_pow_ui(slope_2, slope, 2);

	/* 2. slope^2 - Xp*/
	opcbn_sub(r->x, slope_2, p->x);

	/* 2. slope^2 - Xp - Xq*/
	opcbn_sub(r->x, r->x, q->x);
	opcbn_mod(r->x, r->x, group->p);

	opcbn_clear(slope_2);
	return;
}


void calculate_Yr(opcec_group_t group, opcec_t r, opcbn_t slope, opcec_t p, opcec_t q)
{
	/* Yr = slope*(Xp - Rx) - Yp */

	/* 1. Xp - Rx */
	opcbn_sub(r->y, p->x, r->x);

	/* 2. slope*(Xp - Rx) */
	opcbn_mul(r->y, r->y, slope);

	/* 3. slope*(Xp - Rx) - Yp*/
	opcbn_sub(r->y, r->y, p->y);
	opcbn_mod(r->y, r->y, group->p);
	return;
}


void opcec_init(opcec_t p)
{
	opcbn_init(p->x);
	opcbn_init(p->y);
	return;
}


void opcec_clear(opcec_t p)
{
	opcbn_clear(p->x);
	opcbn_clear(p->y);
	return;
}


void opcec_cpy(opcec_t dst, opcec_t src)
{
	opcbn_cpy(dst->x, src->x);
	opcbn_cpy(dst->y, src->y);
	return;
}


void opcec_set_opcbn(opcec_t rop, opcbn_t x, opcbn_t y)
{
	opcbn_cpy(rop->x, x);
	opcbn_cpy(rop->y, y);
}


int opcec_set_bin(opcec_t p, char *x, int xlen, char *y, int ylen)
{
	opcbn_set_bin(p->x, x, xlen);
	return opcbn_set_bin(p->y, y, ylen);
}

int opcec_set_str(opcec_t p, char *x, int xredix, char *y, int yredix)
{
	opcbn_set_str(p->x, x, xredix);
	return opcbn_set_str(p->y, y, yredix);
}


void opcec_get_opcbn(opcbn_t x, opcbn_t y, opcec_t p)
{
	opcbn_cpy(x, p->x);
	opcbn_cpy(y, p->y);
	return;
}

void opcec_get_bin(unsigned char *x, int *xlen, unsigned char *y, int *ylen, opcec_t p, unsigned int n)
{
	opcbn_get_bin(x, xlen, p->x, n);
	opcbn_get_bin(y, ylen, p->y, n);
}

void opcec_get_str(char *x, char *y, opcec_t p)
{
	if (x == NULL)
		x = opcbn_get_str(x, p->x);
	else
		opcbn_get_str(x, p->x);

	if (y == NULL)
		y = opcbn_get_str(x, p->y);
	else
		opcbn_get_str(x, p->y);

}




/*
 * Description:	create a ecc group and set p a b G n parameters
 * Parameters:	
 * return:		
 */
void opcec_create_group(opcec_group_t group, opcbn_t p, opcbn_t a, opcbn_t b, opcbn_t Gx, opcbn_t Gy, opcbn_t n, opcbn_t h)
{
	opcbn_init(group->Gx);
	opcbn_init(group->Gy);
	opcbn_init(group->a);
	opcbn_init(group->b);
	opcbn_init(group->n);
	opcbn_init(group->p);
	opcbn_init(group->h);


	opcbn_cpy(group->Gx, Gx);
	opcbn_cpy(group->Gy, Gy);
	opcbn_cpy(group->a, a);
	opcbn_cpy(group->b, b);
	opcbn_cpy(group->n, n);
	opcbn_cpy(group->p, p);
	opcbn_cpy(group->h, h);
	return;
}


void opcec_clear_group(opcec_group_t group)
{
	opcbn_clear(group->Gx);
	opcbn_clear(group->Gy);
	opcbn_clear(group->a);
	opcbn_clear(group->b);
	opcbn_clear(group->n);
	opcbn_clear(group->p);
	opcbn_clear(group->h);
	return;
}
	

/*
 * Description:	r = p + q
 * Parameters:	
 * return:		
 */
int opcec_add(opcec_group_t group, opcec_t r, opcec_t p, opcec_t q)
{
	opcbn_t zero;
	opcbn_t _Yq;
	opcbn_t slope; //斜率
	opcec_t sum;
	int ret = 0;

	/* 计算 -Yq */
	opcbn_init(zero);
	opcbn_init(_Yq);
	opcbn_init(slope);
	opcec_init(sum);

	opcbn_set_str(zero, "0", 10);
	opcbn_modsub(_Yq, zero, q->y, group->p);

	if (!opcbn_cmp(p->x, zero) && !opcbn_cmp(p->y, zero))
	{
		/* 1. p->x 和 p->y 为0的情况, sum = 0 + q = q */
		opcbn_cpy(sum->x, q->x);
		opcbn_cpy(sum->y, q->y);
		goto out;
	}
	else if (!opcbn_cmp(q->x, zero) && !opcbn_cmp(q->y, zero))
	{
		/* 2. q->x 和 q->y 为0的情况, sum = p + 0 = p */
		opcbn_cpy(sum->x, p->x);
		opcbn_cpy(sum->y, p->y);
		goto out;
	}
	else if((!opcbn_cmp(p->x, q->x)) && (!opcbn_cmp(p->y, _Yq)))
	{
		/* 3. Xp = Xq, Yp = -Yq的情况, sum = 0 */
		opcbn_cpy(sum->x, zero);
		opcbn_cpy(sum->y, zero);
		goto out;
	}
	else
	{
		/* 4. 计算sum */
		/* 4.1 计算斜率(slope) */
		if ((!opcbn_cmp(p->x, q->x)) && (!opcbn_cmp(p->y, q->y)))
		{
			/* 4.1.1 Xp = Xq, Yp = Yq的情况, slope = (3x^2 + a) / (2y) */
			if ((ret = get_slope_equal(group, slope, p)) < 0)
				goto errout;
		}
		else
		{
			/* 4.1.2 其他的的情况, slope = (Yq - Yp) / (Xq - Xp) */
			if ((ret = get_slope_other(group, slope, p, q)) < 0)
				goto errout;
		}		/* -------- end else -------- */

		/* 4.3 Xr = slope^2 - Xp - Xq */
		calculate_Xr(group, sum, slope, p, q);

		/* 4.4 Yr = slope*(Xp - Rx) - Yp */
		calculate_Yr(group, sum, slope, p, q);

	}
out:
	opcec_cpy(r, sum);
errout:
	opcbn_clear(zero);
	opcbn_clear(_Yq);
	opcbn_clear(slope);
	opcec_clear(sum);
	return ret;
}





/*
 * Description:	r = p * k
 * Parameters:	 
 * return:		 
 */
int opcec_mul(opcec_group_t group, opcec_t r, opcec_t p, opcbn_t k)
{
	int ret = 0;
	opcec_t sum;
	opcbn_t k_2;

	opcec_init(sum);
	opcbn_init(k_2);

	if (opcbn_get_ui(k) == 1)
	{
		opcec_cpy(sum, p);
		goto out;
	}


	opcbn_fdiv_q_ui(k_2, k, 2);
	if ((ret = opcec_mul(group, sum, p, k_2)) < 0)
		goto errout;
	

	if ((ret = opcec_add(group, sum, sum, sum)) < 0)
		goto errout;


	opcbn_mod_ui(k_2, k, 2);
	if (opcbn_get_ui(k_2) != 0)
	{
		if ((ret = opcec_add(group, sum, sum, p)) < 0)
			goto errout;
	}

out:
	opcec_cpy(r, sum);
errout:
	opcec_clear(sum);
	opcbn_clear(k_2);
	return ret;
}


