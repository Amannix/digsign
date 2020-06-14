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

char *theprogram = NULL;

/* Information for each executable operated upon.
*/
static char         thefilename[1024];	/* the name of the current file */
static FILE        *thefile;		/* the currently open file handle */
static Elf64_Ehdr   ehdr;		/* the current file's ELF header */
static Elf64_Phdr  *phdrs;		/* the program segment header table */
static Elf64_Shdr  *shdrs;		/*the program section header table*/

static Elf64_Shdr apped_shdr; /*新增的秘钥节*/
static unsigned int shstrndx = 0;	/*维护节名字表的索引*/
static unsigned int shstroff = 0;	/*维护节名字表的偏移量*/
static unsigned int shstrsize = 0;	/*维护节名字表的大小*/
static unsigned int curr_file_size = 0; /*维护初始文件大小*/
static unsigned int sh_sig_off = 0;//秘钥节的偏移量
static unsigned int pre_shdrs_off;//修改文件前的节头表偏移量
static unsigned int now_shdrs_off;//修改后的节头表偏移量

static unsigned char sh_sig_buff[4096];
static unsigned int sh_sig_buff_size;

static unsigned char *elf_text_data = NULL;
static unsigned int elf_text_data_len;


/*static SM2_KEY_PAIR key_pair;
static SM2_SIGNATURE_STRUCT sm2_sig;
*/

static char *def_pem_privkey = 
"-----BEGIN PRIVATE KEY-----"\
"\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDvH2p+PMuehQs9"\
"\nvpTsc9EdevjBB5GBTUt4ngIujHqnHhmEMd9oo5D7WwGwdrVUTSol5bd6/pdcf9qG"\
"\nrPZxWTPMh4AHgObR/P5pnagUeimsxvG1B0OmKDZh4pSjmieoFUcy+hHFHH771iu/"\
"\nJ3IvLxxMEhefL1FGOqk36FuXv8Hxarb4FYsaSkM3JPFpvXiPVE4KiXBdpb0POHAj"\
"\nAI4SuJ+W0MorvDHgLwnIiZwDU6ChlwotYpToZpPuWEIfUVNB9UwouljT4MEMsgqt"\
"\nf9KiXZwV8QU4Z8KNl1TQfS4ETIwE6cvmhlSl3G6r9F5MvpwM64itLc+q5WVrUmzp"\
"\nyDFByRlvAgMBAAECggEAFm+HKWMA49Wt0VRBWtIfC7oO/uV75HrhGucQY1ew5l8v"\
"\nm7SmNoYqQzsttGXe65L14mpkRbj/cKFaWop98PKipo0MGSgiAA/Ruw0cyRcRM/HS"\
"\nmd6dnUhmmdaNhbAgCmg8ru7BnhHnZC+bGStVTlIIQKbt6nShForId8NoXJuUUdc3"\
"\n9YWVhtRRRJcLEf3q5fBmXHjrOzKSuVhQhUQXAnftj7LQWeymIqwHOuxiVmpxk4q7"\
"\nCOEmAvG3mHK5GZKW+EyPpBhbcwdI20vm9zv0kO4Ab9gSPlpcuFCqIRl+B8CRjQKW"\
"\n5WoBmrKTV0jkRMSSHx03lHeE7LKPbXYvzMuTGVf/0QKBgQD8bPoBTtULnkbuCfR8"\
"\na2k2xluNXHNd/HhoD8YMIkk3V/RplgxlYS6fOsoKY5USAaSd9Kf+86t0h6cVy82t"\
"\nKBuhVIoD8ubZP/LTcTdrEhi1kw03LZ4i/NrkfaKrMOqCwRNHNrBH12IXp62wMjmd"\
"\n3z03dUVFHO6xsIav28u+lS4jRwKBgQDygjeYw+3IG79tXqlZPLgUBjfOxCvWmrig"\
"\nYqNzzWyzKJJaJHy2gCkYdLORV0VSoe68LDs8URVxfn4mcZYHJtFNNgaibLT3Y00W"\
"\n4ZF6eDkvtUk3+tvQVK+DnASjVKtha0zNC2QEXg/XdayS+SL+cPyu0nH0au4pggZY"\
"\nuGpHlnPcmQKBgFBVekcaSJEXASnWfzltkaF+BTr61jhuFf/ALV5FNxnm4wELYMyO"\
"\n3iCMvCoMQS/m1/XxG9n2wHUoitNT9hQKdKimV/ojvrYbNPN3z5RCwRxgPU93NCGc"\
"\naSlYloF24ttUCQeb7wQeFrjCg3NUuKN2nWvd5Xq2V3yzWlnzUGdJ4NIXAoGAawz0"\
"\ngekrlAQ7sonw88WL9Lrx88JBH9DY42Pnh30NGOE2CbjFnMJiYbtScTw3C80T19km"\
"\npO+eKaWPBmVptup5xj2tHBIkqHgbVZhpYcikZdz+30lLs2FOwSgkG/2KUczN8E2w"\
"\n7wSetZvqfE6iFfPGd13Kk/yH+aa+Knft4oAV0TECgYEAkf29XtAEUTqa1VPLOvd9"\
"\nDx902IatdjHF5YQhXQZANP5eoFA32HOHW71QGVL5LqZ18lZiZfDYNBv9LH115gKA"\
"\nYKN2Xm/qzPu3m7LZ0sQu2gjlwZ+vQT6goTlHrp5LaI6wLOg2CGJ7VKLgmzTiyKKx"\
"\nWzKDOlxOUOXzaivjVLpIfpE="\
"\n-----END PRIVATE KEY-----";
static char pem_crt[4096];
static long int pem_crt_len;
static char pem_pubkey[4096];
static int pem_pubkey_len;
static char pem_privkey[4096];
static int pem_privkey_len;

static unsigned char *der_pubkey;
static int der_pubkey_len;
static unsigned char *der_privkey;
static int der_privkey_len;

static int rsakey_flag;//公私钥模式
static int crt_flag;//证书模式
static int outpub_flag;//输出公钥
static int outpriv_flag;//输出私钥
static int in_flag;//输入可执行文件
static int help_flag;//帮助信息
static int erropt_flag;//参数错误
static int inpriv_flag;//输入私钥文件

static char outpubfilename[1024];//公钥文件输出路径
static char outprivfilename[1024];//私钥文件输出路径
static char crtfilename[1024];//证书输入路径
static char privatefilename[1024];//私钥输入路径

/* A macro for I/O errors: The given error message is used only when
 * errno is not set.
 */
#define	ferr(msg) (err(ferror(thefile) ? strerror(errno) : (msg)))

static int err(char const *errmsg);//打印错误信息
static int read_elf_header(void);//读取文件头
static int read_shdr_table(void);//读取节头表
static int read_phdr_table(void);//读取程序头表
static int get_memory_size(void);//获取文件大小
static int modify_headers(void);//修改文件头
static int analy_shstrtable(void);//解析节名字表的信息
static int insert_shname(void);//节名字表中插入一个名字
static int commit_changes(void);//
static int modify_shdrs(void);//修改并插入节头表
static int insert_sh_sig(void);
static int get_text_data(void);
static int elf_text_sign(void);
static int check_arg(char *execname);
#endif

