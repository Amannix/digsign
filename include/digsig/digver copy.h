/*************************************************************************
	> File Name: digsig.h
	> Author: xmb
	> Mail: 1785175681@qq.com 
	> Created Time: 2020年04月16日 星期四 21时25分17秒
 ************************************************************************/

#ifndef _DIGSIG_H
#define _DIGSIG_H

#include "digsig/sigtype.h"
#include "../sm2sig/sm2_genkey.h"
#include "../sm2sig/sm2_sig.h"

#ifndef TRUE
#define	TRUE	1
#define	FALSE	0
#endif

/* A macro for I/O errors: The given error message is used only when
 * errno is not set.
 */
#define	ferr(msg) (err(ferror(thefile) ? strerror(errno) : (msg)))

static int err(char const *thefilename, char const *errmsg);//打印错误信息
static int read_elf_header(struct file *thefile);//读取文件头
static int read_shdr_table(struct file *thefile);//读取节头表
static int show_shdr_table(struct file *thefile);//打印节头表
static int read_phdr_table(struct file *thefile);//读取程序头表
static int get_memory_size(struct file *thefile);//获取文件大小
static int analy_shstrtable(void);//解析节名字表的信息
static int get_text_data(void);
static int elf_text_verify(void);

#endif

