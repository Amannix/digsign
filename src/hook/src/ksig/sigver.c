/*************************************************************************
  > File Name: digsig.c
  > Author: xmb
  > Mail: 1785175681@qq.com 
  > Created Time: 2020年04月16日 星期四 21时22分10秒
 ************************************************************************/

#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../../include/ksig/sigver.h"
#include "../../include/kstd/kstdio.h"
#include "../../include/kelf/elfrw.h"
#include "../../include/ksig/rdx_crypto.h"
#include "../../include/ksig/sha256.h"
#include "../../include/ksig/crtver.h"
#include "../../include/kcrt/base64.h"

static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr);
static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr *shdrs);
static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char *sha256_h);
static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char *sh_sig_buff, int *sh_sig_buff_size);
static int get_encrypto(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size);

static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr)
{
    fseek(thefile, 0, SEEK_SET);
	if (elfrw_read_Ehdr(thefile, ehdr) != 1){
        pr_warn("not a valid ELF file");
        return FALSE;
    }
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN){
        pr_warn("not an executable or shared-object library.");
        return FALSE;
    }

	return TRUE;
}

static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr *shdrs)
{
    int count;
	if (!ehdr.e_shoff || !ehdr.e_shnum){
        pr_warn("ELF文件没有节头表!");
        return FALSE;
    }

	if (fseek(thefile,ehdr.e_shoff,SEEK_SET)){
        pr_warn("fseek 调用失败！");
		return FALSE;
	}

	count = elfrw_read_Shdrs(thefile, shdrs, ehdr.e_shnum);
	if (count != ehdr.e_shnum){
		pr_warn("missing or incomplete program section header table.");
        return FALSE;
	}
	return TRUE;
}

static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                            unsigned char *sha256_h)
{
	int i;
	int shstrndx = ehdr.e_shstrndx;
	char *sh_name_temp = kmalloc(shdrs[shstrndx].sh_size, GFP_ATOMIC);
	int count = ehdr.e_shnum;

    if (IS_ERR(sh_name_temp)){
        return FALSE;
    }

	if (count <= 0){
		return FALSE;
	}
	//memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);
   // printk("%d-%x %x %x",shdrs[shstrndx].sh_size, sh_name_temp, elf_text_data, hash_temp);
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);
	if (!fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile)){
        kfree(sh_name_temp);
        return FALSE;
    }

	for (i = 0;i < count; ++i){
		int name = shdrs[i].sh_name;
        int ssize;
		//pr_warn ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".text", &sh_name_temp[name]) == 0){
            unsigned char *data = kmalloc(1024*1024, GFP_ATOMIC);
            if (IS_ERR(data)){
                kfree(sh_name_temp);
                return FALSE;
            }
            fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
            ssize = shdrs[i].sh_size > 1024*1024 ? 1024*1024 : shdrs[i].sh_size;
            if (fread(data, ssize, 1, thefile) == 0){
                kfree(data);
                kfree(sh_name_temp);
                return FALSE;
            }
            sha256(data, ssize, sha256_h);
            kfree(data);
            kfree(sh_name_temp);
			return TRUE;
        }
	}
    kfree(sh_name_temp);
	return FALSE;
}

static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                    unsigned char *sh_sig_buff, int *sh_sig_buff_size)
{
	int i;
	int shstrndx = ehdr.e_shstrndx;
	char *sh_name_temp = kmalloc(shdrs[shstrndx].sh_size, GFP_ATOMIC);
	int count = ehdr.e_shnum;
	memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);

	if (sh_name_temp == NULL || count == -1){
        kfree(sh_name_temp);
		return err("elf_sm2_sign err");
	}
	
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);
	fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);
    for (i = 0;i < count; ++i){
        //int j = 0;
		int name = shdrs[i].sh_name;
		//pr_warn ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".digsig", &sh_name_temp[name]) == 0){
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(sh_sig_buff, shdrs[i].sh_size, 1, thefile);
			*sh_sig_buff_size = shdrs[i].sh_size;
            kfree(sh_name_temp);
			return TRUE;
		}
    }
    kfree(sh_name_temp);
	return FALSE;
}

static int get_encrypto(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size)
{
    int i,j;
    if (sh_sig_buff_size < 256){
        return FALSE;
    }
    for (i = 0;i < 256; ++i){
        encrypto[i] = sh_sig_buff[i];
    }
    return TRUE;
}

void memoryclean(void *buf)
{
    if (buf != NULL){
        vfree(buf);
    }
}

static int checkcrt(const unsigned char *sh_sig_buff,int sh_sig_buff_size, unsigned char *key)
{

    static char asciicrt[2048] = {0};
    static int asciicrt_len = 0;

    int i = 0;

	unsigned char buffer[2048] = {0};
	unsigned int keylen = 0;

	unsigned char id[512] = {0};
	unsigned int idlen;
	
	size_t len = 0;
	int ret;

    //  获取证书中的pem编码部分，不包含头尾的固定格式。
    asciicrt_len = sh_sig_buff_size - 256;
    for (i = 256;i < sh_sig_buff_size; ++i){
        asciicrt[i-256] = sh_sig_buff[i];
    }

    //进行base64解码
	memset(buffer, 0x00, sizeof(buffer));
   	mbedtls_base64_decode(buffer, sizeof(buffer), &len, asciicrt, asciicrt_len - 1);

    //利用解码后的数据获取证书的公钥信息
    key[0] = 0x30;//公钥的第一个字节固定为0x30,
	ret = x509_crt_get_id_pubkey((const unsigned char *)buffer, len, key+1, &keylen, id, &idlen);
	if (ret) {
        goto err;
	}



    return keylen+1;
    err:
	return FALSE;
}

int digver (const char *filename)
{
    static FILE        *thefile;		/* the currently open file handle */
    static Elf64_Ehdr   ehdr;		/* the current file's ELF header */
    static Elf64_Shdr  shdrs[100];		/*the program section header table*/
    static unsigned char ELFMAGIC[16];
    static unsigned char sh_sig_buff[4096];//密钥节数据区
    static unsigned int sh_sig_buff_size;//密钥节大小
    static unsigned char encrypto[256];//密文缓冲区
    static unsigned char pub_key[1024];//rsa私钥
    static unsigned int pub_key_len;//rsa私钥长度
    static unsigned char *def_pub_key = "\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xef\x1f\x6a\x7e\x3c\xcb\x9e\x85\x0b\x3d\xbe\x94\xec\x73\xd1\x1d\x7a\xf8\xc1\x07\x91\x81\x4d\x4b\x78\x9e\x02\x2e\x8c\x7a\xa7\x1e\x19\x84\x31\xdf\x68\xa3\x90\xfb\x5b\x01\xb0\x76\xb5\x54\x4d\x2a\x25\xe5\xb7\x7a\xfe\x97\x5c\x7f\xda\x86\xac\xf6\x71\x59\x33\xcc\x87\x80\x07\x80\xe6\xd1\xfc\xfe\x69\x9d\xa8\x14\x7a\x29\xac\xc6\xf1\xb5\x07\x43\xa6\x28\x36\x61\xe2\x94\xa3\x9a\x27\xa8\x15\x47\x32\xfa\x11\xc5\x1c\x7e\xfb\xd6\x2b\xbf\x27\x72\x2f\x2f\x1c\x4c\x12\x17\x9f\x2f\x51\x46\x3a\xa9\x37\xe8\x5b\x97\xbf\xc1\xf1\x6a\xb6\xf8\x15\x8b\x1a\x4a\x43\x37\x24\xf1\x69\xbd\x78\x8f\x54\x4e\x0a\x89\x70\x5d\xa5\xbd\x0f\x38\x70\x23\x00\x8e\x12\xb8\x9f\x96\xd0\xca\x2b\xbc\x31\xe0\x2f\x09\xc8\x89\x9c\x03\x53\xa0\xa1\x97\x0a\x2d\x62\x94\xe8\x66\x93\xee\x58\x42\x1f\x51\x53\x41\xf5\x4c\x28\xba\x58\xd3\xe0\xc1\x0c\xb2\x0a\xad\x7f\xd2\xa2\x5d\x9c\x15\xf1\x05\x38\x67\xc2\x8d\x97\x54\xd0\x7d\x2e\x04\x4c\x8c\x04\xe9\xcb\xe6\x86\x54\xa5\xdc\x6e\xab\xf4\x5e\x4c\xbe\x9c\x0c\xeb\x88\xad\x2d\xcf\xaa\xe5\x65\x6b\x52\x6c\xe9\xc8\x31\x41\xc9\x19\x6f\x02\x03\x01\x00\x01";
    static unsigned int def_pub_key_len = 270;
    static unsigned char *def_pem_pubkey = 
    "-----BEGIN PUBLIC KEY-----"\
    "\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7x9qfjzLnoULPb6U7HPR"\
    "\nHXr4wQeRgU1LeJ4CLox6px4ZhDHfaKOQ+1sBsHa1VE0qJeW3ev6XXH/ahqz2cVkz"\
    "\nzIeAB4Dm0fz+aZ2oFHoprMbxtQdDpig2YeKUo5onqBVHMvoRxRx++9YrvydyLy8c"\
    "\nTBIXny9RRjqpN+hbl7/B8Wq2+BWLGkpDNyTxab14j1ROColwXaW9DzhwIwCOErif"\
    "\nltDKK7wx4C8JyImcA1OgoZcKLWKU6GaT7lhCH1FTQfVMKLpY0+DBDLIKrX/Sol2c"\
    "\nFfEFOGfCjZdU0H0uBEyMBOnL5oZUpdxuq/ReTL6cDOuIrS3PquVla1Js6cgxQckZ"\
    "\nbwIDAQAB"\
    "\n-----END PUBLIC KEY-----";
    static unsigned char crt_pub_key[512];
    static int crt_pub_key_len = 0;
    static unsigned char *key;
    static int keylen = 270;
    static unsigned char m[256] = {0};
    static unsigned char sha256_h[32];
    static unsigned char sha256_hs[32];
    //static unsigned char user_id[ELF_SIG_USER_ID_LEN];//签名
    //static unsigned int user_id_len = ELF_SIG_USER_ID_LEN;//签名长度
    int i;

    thefile = fopen(filename, O_RDONLY, 0);
    if (thefile == NULL){
        //pr_warn("file not exit");
        return FILEERR;
    }

    if (!fread(ELFMAGIC, 4, 1, thefile)){
        fclose(thefile);
        return FILEERR;
    }
    if (ELFMAGIC[0] != ELFMAG0 || 
        ELFMAGIC[1] != ELFMAG1 || 
        ELFMAGIC[2] != ELFMAG2 || 
        ELFMAGIC[3] != ELFMAG3){
        fclose(thefile);
        //pr_warn("not is a elf file");
        return OTHERERR;
    }

	//1. 读取文件头
	if (read_elf_header(thefile, &ehdr) == FALSE){
        fclose(thefile);
        //pr_warn("1");
		return OTHERERR;
	}

	//2. 读取节头表
	if (read_shdr_table(thefile, ehdr,shdrs ) == FALSE){
        fclose(thefile);
        //pr_warn("2");
		return OTHERERR;
	}
    if (get_sig_buff(thefile, ehdr, shdrs, sh_sig_buff, &sh_sig_buff_size) == FALSE){
        //pr_warn("3");
		return NOSIGERR;
	}
    //printk("%d",ehdr.e_shstrndx);
	//3. 获取text节数据
	if (get_text_data(thefile, ehdr, shdrs, sha256_h) == FALSE){
        pr_warn("4");
		return OTHERERR;
	}

    if (get_encrypto(encrypto, sh_sig_buff, sh_sig_buff_size) == FALSE){
        return OTHERERR;
    }

    if (sh_sig_buff_size > 256){//如果大于256字节说明节区包含了一张数字证书的内容
        crt_pub_key_len = checkcrt(sh_sig_buff, sh_sig_buff_size, crt_pub_key);
        if (crt_pub_key_len == 0){
            return CRTERR;
        } else {
            key = crt_pub_key;
            keylen = crt_pub_key_len;
        }
    } else {
        key = def_pub_key;
        keylen = def_pub_key_len;
    }

    memset (m, 0, 256);
	if (rdx_akcrypto_sign_ver(encrypto, 256, m, RDX_RSA_VERIFY, key, keylen)) {
		pr_err ("RSA verify error\n");
        pr_warn("5");
        return OTHERERR;
	}
    memcpy(sha256_hs, m+256-32, 32);
    pr_warn("\n");
    hexdump(sha256_hs, 32);
    hexdump(sha256_h, 32);
    for (i = 0;i < 32; ++i){
        if (sha256_h[i] != sha256_hs[i]){
            return FAULTERR;
        }
    }

    fclose(thefile);
    return SUCCESS;
}
