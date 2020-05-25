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

static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr);
static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr **shdrs);
static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char **elf_text_data, int *elf_text_data_len);
static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char **sh_sig_buff, int *sh_sig_buff_size);
static int get_key_and_sha(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size,unsigned char **pri_key, int *pri_key_len);



static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr)
{
	if (elfrw_read_Ehdr(thefile, ehdr) != 1)
		return ferr("not a valid ELF file");

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		return err("not an executable or shared-object library.");

	return TRUE;
}

static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr **shdrs)
{
	if (!ehdr.e_shoff || !ehdr.e_shnum)
		return err("ELF文件没有节头表！\n");

	if (fseek(thefile,ehdr.e_shoff,SEEK_SET)){
		return ferr("fseek 调用失败！\n");
	}

	if ((*shdrs = kmalloc((ehdr.e_shnum+1) * sizeof **shdrs, GFP_KERNEL)) == NULL)
		return err("内存分配失败！\n");
	//printk ("读取节头表 %u \n",(unsigned int)*shdrs);
	if (elfrw_read_Shdrs(thefile, *shdrs, ehdr.e_shnum) != ehdr.e_shnum){
		kfree(*shdrs);//释放内存
		return ferr("missing or incomplete program section header table.");
	}
	return TRUE;
}

static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                            unsigned char **elf_text_data, int *elf_text_data_len)
{
	int i;
	int shstrndx = ehdr.e_shstrndx;
	char *sh_name_temp = kmalloc(shdrs[shstrndx].sh_size, GFP_KERNEL);
	int count = ehdr.e_shnum;
	memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);

	if (sh_name_temp == NULL || count == -1){
		return err("elf_sm2_sign err");
	}
	
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);
	fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);

	for (i = 0;i < count; ++i){
		int name = shdrs[i].sh_name;
		//printk ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".text", &sh_name_temp[name]) == 0){
			*elf_text_data = kmalloc(shdrs[i].sh_size, GFP_KERNEL);
			if (elf_text_data == NULL){
				printk ("内存分配失败");
				goto er;
			}
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(*elf_text_data, shdrs[i].sh_size, 1, thefile);
			*elf_text_data_len = shdrs[i].sh_size;
			break;
		}
	}
	kfree(sh_name_temp);
	return TRUE;
er:

	kfree(sh_name_temp);
	return FALSE;
}

static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, 
                    unsigned char **sh_sig_buff, int *sh_sig_buff_size)
{
	int i;
	int shstrndx = ehdr.e_shstrndx;
	char *sh_name_temp = kmalloc(shdrs[shstrndx].sh_size, GFP_KERNEL);
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
		//printk ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".digsig", &sh_name_temp[name]) == 0){
			*sh_sig_buff = kmalloc(shdrs[i].sh_size+1, GFP_KERNEL);
			if (*sh_sig_buff == NULL){
				printk ("内存分配失败");
				goto er;
			}
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(*sh_sig_buff, shdrs[i].sh_size, 1, thefile);
			*sh_sig_buff_size = shdrs[i].sh_size;
            /*for (j = 0;j < shdrs[i].sh_size; ++j){
                printk("%d %02x",j, (*sh_sig_buff)[j]);
            }*/
            kfree(sh_name_temp);
			return TRUE;
		}
    }
er:
	kfree(sh_name_temp);
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
    *pri_key = kmalloc((*pri_key_len)+1, GFP_KERNEL);
    if (*pri_key == NULL){
        printk("内存分配失败");
        goto err;
    }
    printk("%d",*pri_key_len);
    for (i = 256,j = 0;i < sh_sig_buff_size; ++i,++j){
        (*pri_key)[j] = sh_sig_buff[i];
    }
    return TRUE;
    err:
    return FALSE;
}

int digver (const char *filename)
{
    static FILE        *thefile;		/* the currently open file handle */
    static Elf64_Ehdr   ehdr;		/* the current file's ELF header */
    static Elf64_Shdr  *shdrs;		/*the program section header table*/

    static unsigned char *sh_sig_buff;//密钥节数据区
    static unsigned int sh_sig_buff_size;//密钥节大小
    static unsigned char encrypto[256];//密文缓冲区
    static unsigned char *pri_key;//rsa私钥
    static unsigned int pri_key_len;//rsa私钥长度

    static unsigned char *elf_text_data = NULL;//text段数据
    static unsigned int elf_text_data_len;//text段数据大小
    //static unsigned char user_id[ELF_SIG_USER_ID_LEN];//签名
    //static unsigned int user_id_len = ELF_SIG_USER_ID_LEN;//签名长度

    thefile = fopen(filename, O_RDONLY|O_EXCL, 0);
    if (thefile == NULL){
        goto err;
    }
/*
static int read_elf_header(FILE *thefile, Elf64_Ehdr *ehdr);
static int read_shdr_table(FILE *thefile, Elf64_Ehdr ehdr, Elf64_Shdr **shdrs);
static int get_text_data(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char **elf_text_data, int *elf_text_data_len);
static int get_sig_buff(FILE *thefile, Elf64_Ehdr ehdr,Elf64_Shdr *shdrs, unsigned char *sh_sig_buff, int *sh_sig_buff_size);
static int get_key_and_sha(unsigned char *encrypto, unsigned char *sh_sig_buff,int sh_sig_buff_size,unsigned char **pri_key, int *pri_key_len);
*/

	//1. 读取文件头
	if (read_elf_header(thefile, &ehdr) == FALSE){
		goto err;
	}
    pdbug((unsigned char*)(&ehdr), sizeof ehdr);
	//2. 读取节头表
	if (read_shdr_table(thefile, ehdr,&shdrs ) == FALSE){
		goto err;
	}

	//3. 获取text节数据
	if (get_text_data(thefile, ehdr, shdrs, &elf_text_data, &elf_text_data_len) == FALSE){
		goto err;
	}
	if (get_sig_buff(thefile, ehdr, shdrs, &sh_sig_buff, &sh_sig_buff_size) == FALSE){
		goto err;
	}
    get_key_and_sha(encrypto, sh_sig_buff, sh_sig_buff_size, &pri_key, &pri_key_len);

    fclose(thefile);
    kfree(shdrs);
    kfree(sh_sig_buff);
    kfree(pri_key);
    kfree(elf_text_data);
    return 0;

err:
    fclose(thefile);
    kfree(shdrs);
    kfree(sh_sig_buff);
    kfree(pri_key);
    kfree(elf_text_data);
    pr_warn("file_open error");
    return -1;
}
