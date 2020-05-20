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

static int read_elf_header(void)
{
	if (elfrw_read_Ehdr(thefile, &ehdr) != 1)
		return ferr("not a valid ELF file");

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
		return err("not an executable or shared-object library.");

	get_memory_size();
	return TRUE;
}

/* read elf file section header table
*/
static int read_shdr_table(void)
{
	if (!ehdr.e_shoff || !ehdr.e_shnum)
		return err("ELF文件没有节头表！\n");

	pre_shdrs_off = ehdr.e_shoff;

	if (fseek(thefile,ehdr.e_shoff,SEEK_SET)){
		return ferr("fseek 调用失败！\n");
	}

	if ((shdrs = realloc(shdrs, (ehdr.e_shnum+1) * sizeof *shdrs)) == FALSE)
		return err("内存分配失败！\n");
	if (elfrw_read_Shdrs(thefile, shdrs, ehdr.e_shnum) != ehdr.e_shnum){
		realloc(shdrs, 0);//释放内存
		return ferr("missing or incomplete program section header table.");
	}

	if (analy_shstrtable() == FALSE){
		return FALSE;
	}
	return TRUE;
}

static int show_shdr_table(void)
{
	/*unsigned char index = shdrs;
	  for (int i = 0;i < ehdr.e_shnum; ++i){
	  printf ("%d:=======================\n",i);
	  printf ("%d\n",shdrs[i].sh_type);
	  printf ("%d\n",shdrs[i].sh_flags);
	  printf ("%d\n",shdrs[i].sh_addr);
	  printf ("%d\n",shdrs[i].sh_offset);
	  printf ("%d\n",shdrs[i].sh_size);
	  printf ("%d\n",shdrs[i].sh_link);
	  printf ("%d\n",shdrs[i].sh_info);
	  printf ("%d\n",shdrs[i].sh_addralign);
	  printf ("%d\n",shdrs[i].sh_entsize);
	  }*/
	return 0;
}

/* readphdrtable() loads the program segment header table into memory.
*/
static int read_phdr_table(void)
{
	if (!ehdr.e_phoff || !ehdr.e_phnum)
		return err("ELF file has no program header table.");

	if ((phdrs = realloc(phdrs, (ehdr.e_phnum+1) * sizeof (*phdrs))) == FALSE)
		return err("Out of memory!");
	if (elfrw_read_Phdrs(thefile, phdrs, ehdr.e_phnum) != ehdr.e_phnum)
		return ferr("missing or incomplete program segment header table.");

	return TRUE;
}

static int get_memory_size(void)
{
	fpos_t ps;
	fgetpos(thefile, &ps);
	fseek(thefile, 0, SEEK_END);
	curr_file_size = ftell(thefile);
	fsetpos(thefile, &ps);
	return TRUE;
}

static int analy_shstrtable(void)
{
	shstrndx = ehdr.e_shstrndx;
	if (shstrndx < 0 || shstrndx > ehdr.e_shnum){
		return err("解析节名字表索引失败!\n");
	}

	shstroff = shdrs[shstrndx].sh_offset;
	shstrsize = shdrs[shstrndx].sh_size;
	if (shstroff + shstrsize > curr_file_size){
		return err("解析节名字表偏移失败!\n");
	}
	return TRUE;
}

static int get_text_data(void)
{
	int i;
	char *sh_name_temp = realloc(0, shdrs[shstrndx].sh_size);
	int count = ehdr.e_shnum;
	fpos_t ps;
	memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);
	printf ("==========%lx %lx\n",shdrs[shstrndx].sh_size, shdrs[shstrndx].sh_offset);
	if (sh_name_temp == NULL || count == -1){
		return err("elf_sm2_sign err");
	}

	fgetpos(thefile, &ps);
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);

	fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);
	/*for (i = 0;i < shdrs[shstrndx].sh_size; ++i){
	  printf ("%x ", *(sh_name_temp+i));
	  }*/
	printf ("\n");

	for (i = 0;i < count; ++i){
		int name = shdrs[i].sh_name;
		printf ("%d %s\n",name, &sh_name_temp[name]);
		if (strcmp(".text", &sh_name_temp[name]) == 0){
			elf_text_data = realloc(elf_text_data, shdrs[i].sh_size);
			if (elf_text_data == NULL){
				printf ("内存分配失败");
				goto er;
			}
			printf ("%lx\n",shdrs[i].sh_offset);
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(elf_text_data, shdrs[i].sh_size, 1, thefile);
			printf ("%lx\n",shdrs[i].sh_size);
			elf_text_data_len = shdrs[i].sh_size;
			printf ("size = = = == = %x\n",elf_text_data_len);
			for (unsigned int j = 0;j < shdrs[i].sh_size; ++j){
				printf ("0x%02x",elf_text_data[j]);
			}
			break;
		}
	}

	fsetpos(thefile, &ps);
	realloc(sh_name_temp, 0);
	return TRUE;
er:
	fsetpos(thefile, &ps);
	realloc(sh_name_temp, 0);
	return FALSE;
}

static int elf_text_verify(void)
{
	return TRUE;
}

/* main() loops over the cmdline arguments, leaving all the real work
 * to the other functions.
 */
int main(int argc, char *argv[])
{
	static FILE        *thefile;	/* the currently open file handle */
	static Elf64_Ehdr	ehdr;		/* the current file's ELF header */
	static Elf64_Phdr  *phdrs;		/* the program segment header table */
	static Elf64_Shdr  *shdrs;		/*the program section header table*/
	static unsigned char *elf_text_data = NULL;
	static unsigned int elf_text_data_len;
	static unsigned char *user_id = NULL;
	static unsigned int user_id_len = ELF_SIG_USER_ID_LEN;

	SM2_KEY_PAIR key_pair;
	SM2_SIGNATURE_STRUCT sm2_sig;

	printf ("程序开始\n");
	user_id = realloc(user_id, ELF_SIG_USER_ID_LEN);

	if (user_id == NULL){
		printf ("内存错误\n");
		return -1;
	}

	if (thefile == NULL){
		err(strerror(errno));
		return -1;
	}

	//1. 读取文件头
	if (read_elf_header(static FILE *thefile) == FALSE){
		goto er;
	}
	//2. 读取程序头表
	if (read_phdr_table(static FILE *thefile) == FALSE){
		goto er;
	}

	//2. 读取节头表
	if (read_shdr_table(static FILE *thefile) == FALSE){
		goto er;
	}

	//5. 获取text节数据
	if (get_text_data() == FALSE){
		goto er;
	}

er:
	realloc(user_id, 0);
	realloc(elf_text_data, 0);
	realloc(shdrs, 0);
	realloc(phdrs, 0);

	//强制写入硬盘
	fclose(thefile);
	//return failures ? EXIT_FAILURE : EXIT_SUCCESS;
	return 0;
}
