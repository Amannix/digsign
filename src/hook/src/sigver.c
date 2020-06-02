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
#include "../include/sigver.h"
#include "../include/kstdio.h"
#include "../include/elfrw.h"
#include "../include/rdx_crypto.h"
#include "../include/sha256.h"

static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr);
static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr *shdrs);
static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char *sha256_h);
static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char **sh_sig_buff, int *sh_sig_buff_size);
static int get_key_and_sha(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size,unsigned char **pri_key, int *pri_key_len);

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
	if (!ehdr.e_shoff || !ehdr.e_shnum){
        pr_warn("ELF文件没有节头表!");
        return FALSE;
    }

	if (fseek(thefile,ehdr.e_shoff,SEEK_SET)){
        pr_warn("fseek 调用失败！");
		return FALSE;
	}

	int count = elfrw_read_Shdrs(thefile, shdrs, ehdr.e_shnum);
	if (count != ehdr.e_shnum){
		pr_warn("missing or incomplete program section header table.");
        return FALSE;
	}
	return TRUE;
}

static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                            unsigned char *sha256_h)
{
	int i,j;
	int shstrndx = ehdr.e_shstrndx;
	char sh_name_temp[4096] = {0};
	int count = ehdr.e_shnum;

	if (count <= 0){
		return FALSE;
	}
	//memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);
   // printk("%d-%x %x %x",shdrs[shstrndx].sh_size, sh_name_temp, elf_text_data, hash_temp);
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);
	if (!fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile)){
        return FALSE;
    }

	for (i = 0;i < count; ++i){
		int name = shdrs[i].sh_name;
		//pr_warn ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".text", &sh_name_temp[name]) == 0){
            fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
            sha256(thefile,shdrs[i].sh_offset ,shdrs[i].sh_size, sha256_h);
            hexdump(sha256_h, 32);
			return TRUE;
        }
	}
	return FALSE;
}

static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                    unsigned char **sh_sig_buff, int *sh_sig_buff_size)
{
	int i;
	int shstrndx = ehdr.e_shstrndx;
	char *sh_name_temp = vmalloc(shdrs[shstrndx].sh_size);
	int count = ehdr.e_shnum;
	memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);

	if (sh_name_temp == NULL || count == -1){
		return err("elf_sm2_sign err");
	}
	
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);
	fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);

    for (i = 0;i < count; ++i){
        //int j = 0;
		int name = shdrs[i].sh_name;
		//pr_warn ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".digsig", &sh_name_temp[name]) == 0){
			*sh_sig_buff = vmalloc(shdrs[i].sh_size+1);
			if (*sh_sig_buff == NULL){
				pr_warn ("内存分配失败");
				goto er;
			}
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(*sh_sig_buff, shdrs[i].sh_size, 1, thefile);
			*sh_sig_buff_size = shdrs[i].sh_size;
            /*for (j = 0;j < shdrs[i].sh_size; ++j){
                pr_warn("%d %02x",j, (*sh_sig_buff)[j]);
            }*/
            if (sh_name_temp)
                vfree(sh_name_temp);
			return TRUE;
		}
    }
er:
    if (sh_name_temp)
	    vfree(sh_name_temp);
	return FALSE;
}

static int get_key_and_sha(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size,
                    unsigned char **pri_key, int *pri_key_len)
{
    
    int i,j;
    for (i = 0;i < 256; ++i){
        encrypto[i] = sh_sig_buff[i];
    }
    *pri_key_len = sh_sig_buff_size - 256;
    *pri_key = vmalloc((*pri_key_len)+1);
    if (*pri_key == NULL){
        pr_warn("内存分配失败");
        goto err;
    }
    for (i = 256,j = 0;i < sh_sig_buff_size; ++i,++j){
        (*pri_key)[j] = sh_sig_buff[i];
    }
    return TRUE;
    err:
    return FALSE;
}

void memoryclean(void *buf)
{
    if (buf != NULL){
        vfree(buf);
    }
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
    static unsigned char pri_key[4096];//rsa私钥
    static unsigned int pri_key_len;//rsa私钥长度
    static unsigned char m[256] = {0};
    static unsigned char sha256_h[32];
    //static unsigned char user_id[ELF_SIG_USER_ID_LEN];//签名
    //static unsigned int user_id_len = ELF_SIG_USER_ID_LEN;//签名长度
    int i;

    thefile = fopen(filename, O_RDONLY, 0);
    if (thefile == NULL){
        pr_warn("file not exit");
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
        pr_warn("not is a elf file");
        return OTHERERR;
    }

	//1. 读取文件头
	if (read_elf_header(thefile, &ehdr) == FALSE){
        fclose(thefile);
        pr_warn("1");
		return OTHERERR;
	}

	//2. 读取节头表
	if (read_shdr_table(thefile, ehdr,shdrs ) == FALSE){
        fclose(thefile);
        pr_warn("2");
		return OTHERERR;
	}
    //printk("%d",ehdr.e_shstrndx);
	//3. 获取text节数据
	if (get_text_data(thefile, ehdr, shdrs, sha256_h) == FALSE){
        pr_warn("3");
		return OTHERERR;
	}
	
    /*if (get_sig_buff(thefile, ehdr, shdrs, &sh_sig_buff, &sh_sig_buff_size) == FALSE){
        vfree(sh_sig_buff);
        vfree(shdrs);
        vfree(elf_text_data);
        pr_warn("4");
		return NOSIGERR;
	}
    get_key_and_sha(encrypto, sh_sig_buff, sh_sig_buff_size, &pri_key, &pri_key_len);
    
    memset (m, 0, 256);
	if (rdx_akcrypto_sign_ver(encrypto, 256, m, RDX_RSA_VERIFY, pri_key, pri_key_len)) {
		pr_err ("RSA verify error\n");
        pr_warn("5");
		goto err;
	}

    //sha256(elf_text_data, elf_text_data_len, sha256_h);

    for (i = 0;i < 32; ++i){
        printk("%d %d", i, 256-32+i);
}*/

    fclose(thefile);
    //vfree(sh_sig_buff);
    //vfree(pri_key);
    return SUCCESS;
}
