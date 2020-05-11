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

/* Information for each executable operated upon.
*/
static char const  *thefilename;	/* the name of the current file */
static FILE        *thefile;		/* the currently open file handle */
static Elf64_Ehdr   ehdr;		/* the current file's ELF header */
static Elf64_Phdr  *phdrs;		/* the program segment header table */
static Elf64_Shdr  *shdrs;		/*the program section header table*/
static unsigned long       newsize;		/* the proposed new file size */

static Elf64_Shdr apped_shdr; /*新增的秘钥节*/
static int shstrndx = -1;	/*维护节名字表的索引*/
static int shstroff = -1;	/*维护节名字表的偏移量*/
static int shstrsize = 0;	/*维护节名字表的大小*/
static int curr_file_size = 0; /*维护初始文件大小*/
static int sh_sig_off = 0;//秘钥节的偏移量
static char sh_sig_buff[ELF_SIG_SH_BUFF_SIZE];
static int pre_shdrs_off;//修改文件前的节头表偏移量
static int now_shdrs_off;//修改后的节头表偏移量
static unsigned char *elf_text_data = NULL;
static unsigned int elf_text_data_len;
static unsigned char *user_id = NULL;
static unsigned int user_id_len = ELF_SIG_USER_ID_LEN;

SM2_KEY_PAIR key_pair;
SM2_SIGNATURE_STRUCT sm2_sig;



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
static int modify_headers(void);//修改文件头
static int analy_shstrtable(void);//解析节名字表的信息
static int insert_shname(void);//节名字表中插入一个名字
static int commit_changes(void);//
static int modify_shdrs(void);//修改并插入节头表
static int get_new_shoffset(void);//
static int insert_sh_sig(void);
static int get_text_data(void);
static int elf_text_sign(void);
static int elf_text_verify(void);

#endif

