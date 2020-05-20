/*************************************************************************
  > File Name: digsig.c
  > Author: xmb
  > Mail: 1785175681@qq.com 
  > Created Time: 2020年04月16日 星期四 21时22分10秒
 ************************************************************************/

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "elfrw/elfrw.h"
#include "digsig/digver.h"
#include "digsig/sigtype.h"

/* A simple error-handling function. FALSE is always returned for the
 * convenience of the caller.
 */
static int err(char const *thefilename, char const *errmsg)
{
	pr_info("%s : %s\n",thefilename, errmsg);
	return FALSE;
}


int digver (const char *filename)
{
    char *sh_buff = kzalloc(ELF_SIG_SH_BUFF_SIZE, GFP_KERNEL);
    struct file thefile = filp_open(filename, O_RDONLY, 0);
    

    kfree(sh_buff);
}
