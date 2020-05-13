/*************************************************************************
	> File Name: digsig.h
	> Author: xmb
	> Mail: 1785175681@qq.com 
	> Created Time: 2020年04月16日 星期四 21时25分17秒
 ************************************************************************/

#ifndef _DIGSIG_H
#define _DIGSIG_H

#include "sigtype.h"
#include "../sm2sig/sm2_genkey.h"
#include "../sm2sig/sm2_sig.h"

#ifndef TRUE
#define	TRUE	1
#define	FALSE	0
#endif

/* The online help text.
*/
static char const *yowzitch =
"Usage: sstrip [OPTIONS] FILE...\n"
"Remove all nonessential bytes from executable ELF files.\n\n"
"  -z, --zeroes        Also discard trailing zero bytes.\n"
"      --help          Display this help and exit.\n"
"      --version       Display version information and exit.\n";


/* The name of the program.
*/
static char const *theprogram;

/* TRUE if we should attempt to truncate zero bytes from the end of
 * the file.
 */
static int dozerotrunc = FALSE;

/* A macro for I/O errors: The given error message is used only when
 * errno is not set.
 */
#define	ferr(msg) (err(ferror(thefile) ? strerror(errno) : (msg)))

static int err(char const *errmsg);//打印错误信息
static int read_elf_header(void);//读取文件头
static int read_shdr_table(void);//读取节头表
static int show_shdr_table(void);//打印节头表
static int read_phdr_table(void);//读取程序头表
static int get_memory_size(void);//获取文件大小
static int analy_shstrtable(void);//解析节名字表的信息
static int get_text_data(void);
static int elf_text_verify(void);

#endif

