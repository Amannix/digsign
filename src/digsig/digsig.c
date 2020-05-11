/*************************************************************************
	> File Name: digsig.c
	> Author: xmb
	> Mail: 1785175681@qq.com 
	> Created Time: 2020年04月16日 星期四 21时22分10秒
 ************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>

#include "elfrw/elfrw.h"
#include "digsig/digsig.h"
#include "digsig/sigtype.h"

/* A simple error-handling function. FALSE is always returned for the
 * convenience of the caller.
 */
static int err(char const *errmsg)
{
	fprintf(stderr, "%s: %s: %s\n", theprogram, thefilename, errmsg);
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
	printf ("读取节头表 %x \n",(unsigned int)shdrs);
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
	unsigned char index = shdrs;
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
	}
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

static int modify_headers(void)
{
	int i = 0;
	
	for (i = 0;i < ehdr.e_phnum; ++i){
		if (phdrs[i].p_offset >= shstroff+shstrsize){
			phdrs[i].p_offset += ELF_SIG_SH_TAB_ADD_OFF;
		}
		if (phdrs[i].p_offset >= ehdr.e_shoff+(ehdr.e_shnum*ehdr.e_shentsize)){
			phdrs[i].p_offset += ehdr.e_shentsize;
		}
	}
	if (ehdr.e_shoff >= shstroff+shstrsize){
		ehdr.e_shoff += ELF_SIG_SH_TAB_ADD_OFF;
	}
	if (ehdr.e_shoff >= ehdr.e_shoff+(ehdr.e_shnum*ehdr.e_shentsize)){
		ehdr.e_shoff += ehdr.e_shentsize;
	}

	if (ehdr.e_phoff >= shstroff+shstrsize){
		ehdr.e_phoff += ELF_SIG_SH_TAB_ADD_OFF;
	}
	fseek(thefile, ehdr.e_phoff, SEEK_SET);
	if (ehdr.e_phoff >= ehdr.e_shoff+(ehdr.e_shnum*ehdr.e_shentsize)){
		ehdr.e_phoff += ehdr.e_shentsize;
	}
	now_shdrs_off = ehdr.e_shoff;
	ehdr.e_shnum++;//追加一个新的节
	
	if (elfrw_write_Phdrs(thefile, phdrs, ehdr.e_phnum) != ehdr.e_phnum){
		return ferr("修改段头表失败");
	}
	return elfrw_write_Ehdr(thefile, (Elf64_Ehdr*)(&ehdr));
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

static int insert_shname(void)
{
	int offset = -1;//从文件起始位置到节名字表的末尾偏移量

	/*temp 备份了从节名字表的末尾一直到节头表中间的数据*/
	char *temp = NULL, shname[ELF_SIG_SH_NAME_SIZE+1];
	int temp_size = -1;
	
	
	if (analy_shstrtable() == FALSE){
		return FALSE;
	}
	offset = shstroff + shstrsize;
	temp_size = curr_file_size - offset;
	printf ("文件备份%d字节\n",temp_size);
	if (temp_size <= 0){
		return err("temp_size 计算错误");
	}
	
	if ((temp = realloc(temp, temp_size+1)) == NULL){
		return err("内存分配失败！\n");
	}
	
	fseek(thefile, offset, SEEK_SET);
	if (fread(temp, temp_size, 1, thefile) != 1) {
		ferr("备份文件失败！\n");
		goto err;
	}

	strncpy(shname, ELF_SIG_SH_NAME, ELF_SIG_SH_NAME_SIZE);
	shname[ELF_SIG_SH_NAME_SIZE] = 0;
	
	fseek(thefile, offset, SEEK_SET);
	if (fwrite(shname, ELF_SIG_SH_NAME_SIZE + 1, 1, thefile) != 1){
		ferr("节名字写入失败！");
		goto err;
	}
	if (fwrite(temp, temp_size, 1, thefile) != 1){
		ferr("备份恢复失败！");
		goto err;
	}

	realloc(temp,0);

	return TRUE;
err:	
	realloc(temp,0);
	return FALSE;
}

static int commit_changes(void)
{
	int temp_size = -1;
	char *temp = NULL;
	if (modify_headers() == FALSE){
		return ferr("修改文件头失败");
	}

	get_memory_size();
	temp_size = curr_file_size - now_shdrs_off - (ehdr.e_shentsize*(ehdr.e_shnum-1));
	
	printf ("备份字节数size = %x\n", temp_size);
	if (temp_size < 0){
		return err("文件备份失败1");
	}
	if (temp_size != 0){
		temp = realloc(temp, temp_size);
		if (temp == NULL){
			return err("内存分配失败");
		}

		fseek(thefile, (now_shdrs_off+(ehdr.e_shentsize*(ehdr.e_shnum-1))), SEEK_SET);

		fread(temp, temp_size, 1, thefile);
	}

	if (modify_shdrs() == FALSE){
		return FALSE;
	}
	if (temp_size != 0){
		fwrite(temp, temp_size, 1, thefile);
		temp = realloc(temp, 0);
	}
	return TRUE;

warning:
	return err("ELF file may have been corrupted!");
}

static int modify_shdrs(void)
{
	//如果modify_headrs比这个函数更早调用就必须-1否则不用
	int count = ehdr.e_shnum-1;
	int i = 0;
	int shdrs_end_off = ehdr.e_shoff + (count*ehdr.e_shentsize) - ELF_SIG_SH_TAB_ADD_OFF;

	for (i = 0;i < count; ++i){
		if (shdrs[i].sh_offset > shstroff){
			shdrs[i].sh_offset += ELF_SIG_SH_TAB_ADD_OFF;
		}
		printf ("off %x %x\n",shdrs[i].sh_offset, shdrs_end_off);
		if (shdrs[i].sh_offset > shdrs_end_off){
			shdrs[i].sh_offset += ehdr.e_shentsize;
		}
		if (i == shstrndx){
			apped_shdr.sh_name = shdrs[i].sh_size;
			shdrs[i].sh_size += ELF_SIG_SH_TAB_ADD_OFF;
			shstrsize += ELF_SIG_SH_TAB_ADD_OFF;
		}
	}
	apped_shdr.sh_type = SHT_STRTAB;
	apped_shdr.sh_flags = SHF_MASKOS;
	apped_shdr.sh_addr = 0;
	apped_shdr.sh_offset = curr_file_size+64;
	apped_shdr.sh_size = ELF_SIG_SH_SIZE;
	apped_shdr.sh_link = 0;
	apped_shdr.sh_info = 0;
	apped_shdr.sh_addralign = 1;
	apped_shdr.sh_entsize = 0;
	memcpy(&shdrs[i],&apped_shdr,sizeof(apped_shdr));
	printf ("%x %x - %x\n",sizeof (shdrs), sizeof(apped_shdr),thefile);
	fseek(thefile, ehdr.e_shoff, SEEK_SET);
	if (elfrw_write_Shdrs(thefile, shdrs, count+1) != count+1){
		return ferr("修改节头表失败!");
	}
	return TRUE;
}

static int insert_sh_sig(void)
{
	int i = 0;
	sh_sig_off = pre_shdrs_off + ELF_SIG_SH_TAB_ADD_OFF;//计算秘钥节的偏移量

	fseek(thefile, 0, SEEK_END);
	if (fwrite(sh_sig_buff, ELF_SIG_SH_SIZE, 1, thefile) != 1){
		return ferr("秘钥写入失败！");
	}

	
	curr_file_size += (ELF_SIG_SH_TAB_ADD_OFF + ELF_SIG_SH_SIZE);
	return TRUE;
}

static int get_text_data(void)
{
	int i;
	char *sh_name_temp = realloc(0, shdrs[shstrndx].sh_size);
	int count = ehdr.e_shnum;
	fpos_t ps;
	memset(sh_name_temp, 0,sizeof sh_name_temp);
	printf ("==========%x %x\n",shdrs[shstrndx].sh_size, shdrs[shstrndx].sh_offset);
	if (sh_name_temp == NULL || count == -1){
		return err("elf_sm2_sign err");
	}
	
	fgetpos(thefile, &ps);
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);

	int res = fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);
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
			printf ("%x\n",shdrs[i].sh_offset);
			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(elf_text_data, shdrs[i].sh_size, 1, thefile);
			printf ("%x\n",shdrs[i].sh_size);
			elf_text_data_len = shdrs[i].sh_size;
			/*for (int j = 0;j < shdrs[i].sh_size; ++j){
				printf ("0x%02x",elf_text_data[j]);
			}*/
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

static int elf_text_sign(void)
{
    int error_code,i;
	//SM2_SIGNATURE_STRUCT sm2_sig;
	
	if (error_code = sm2_create_key_pair(&key_pair) ){
		printf ("SM2密钥创建失败\n");
		return FALSE;
	}
	printf ("SM2密钥创建成功\n");
	printf("Private key:\n");
	for (i = 0; i < sizeof(key_pair.pri_key); i++){
	   printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("Public key:\n");
	FILE *hex = fopen("./sig.key", "rb+");
	for (i = 0; i < sizeof(key_pair.pub_key); i++){
	   printf("0x%x  ", key_pair.pub_key[i]);
	}
	if (hex != NULL){
		printf ("write hex\n");
		fwrite(key_pair.pub_key, sizeof(key_pair.pub_key), 1, hex);
		fclose(hex);
	}
	printf ("\n\n");
	printf ("len = %d",elf_text_data_len);
	if ( error_code = sm2_sign_data(elf_text_data,
		                        elf_text_data_len,
								user_id,
								user_id_len,
								key_pair.pub_key,
								key_pair.pri_key,
								&sm2_sig) ){
	   printf("Create SM2 signature failed!\n");
	   return FALSE;
	}

	memcpy(sh_sig_buff, user_id, ELF_SIG_USER_ID_LEN);
	memcpy(&sh_sig_buff[ELF_SIG_USER_ID_LEN], key_pair.pub_key, ELF_SIG_SM2_PUBKEY_LEN);
	memcpy(&sh_sig_buff[ELF_SIG_USER_ID_LEN+ELF_SIG_SM2_PUBKEY_LEN], &sm2_sig, ELF_SIG_SM2_G_COOR_LEN);
/*	printf("Create SM2 signature succeeded!\n");
	printf("SM2 signature:\n");
	printf("r coordinate:\n");
	for (i = 0; i < sizeof(sm2_sig.r_coordinate); i++){
	   printf("0x%x,", sm2_sig.r_coordinate[i]);
	}
	printf("\n");
	printf("s coordinate:\n");
	for (i = 0; i < sizeof(sm2_sig.s_coordinate); i++){
	   printf("0x%x,", sm2_sig.s_coordinate[i]);
	}
	printf("\n\n");

	if ( error_code = sm2_verify_sig(elf_text_data,
									 elf_text_data_len,
									 user_id,
									 user_id_len,
									 key_pair.pub_key,
									 &sm2_sig) ){
	   printf("Verify SM2 signature failed!\n");
	   return FALSE;
	}
	printf("Verify SM2 signature succeeded!\n");*/

	return TRUE;

}

static int elf_text_verify(void)
{

}

/* main() loops over the cmdline arguments, leaving all the real work
 * to the other functions.
 */
int main(int argc, char *argv[])
{
	printf ("程序开始\n");
	user_id = realloc(user_id, ELF_SIG_USER_ID_LEN);
	
	if (user_id == NULL){
		printf ("内存错误\n");
		return -1;
	}

	memcpy(user_id, ELF_SIG_USER_ID, ELF_SIG_USER_ID_LEN);
	thefile = fopen("./010editorback","rb+");
	
	if (thefile == NULL){
		err(strerror(errno));
		return -1;
	}

	//1. 读取文件头
	if (read_elf_header() == FALSE){
		goto er;
	}
	//2. 读取程序头表
	if (read_phdr_table() == FALSE){
		goto er;
	}
	
	//2. 读取节头表
	if (read_shdr_table() == FALSE){
		goto er;
	}

	//3. 插入节名字
	if (insert_shname() == FALSE){
		goto er;
	}
	
	//4. 修改节头表与文件头
	if (commit_changes() == FALSE){
		goto er;
	}

	//5. 获取text节数据
	if (get_text_data() == FALSE){
		goto er;
	}

	//6. 签名并获取密钥
	if(elf_text_sign() == FALSE){
		goto er;
	}

	//7. 插入密钥
	if (insert_sh_sig() == FALSE){
		goto er;
	}

er:
	realloc(user_id, 0);
	realloc(elf_text_data, 0);
	realloc(shdrs, 0);
	realloc(phdrs, 0);

	//强制写入硬盘
	fflush(thefile);
	int fd = fileno(thefile);
	fsync(fd);
	fclose(thefile);
	close(fd);
	//return failures ? EXIT_FAILURE : EXIT_SUCCESS;
	return 0;
}