#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>

#include "rsasig/rsa_genkey.h"
#include "elfrw/elfrw.h"
#include "digsig/digsig.h"
#include "digsig/sigtype.h"
#include "rsasig/sha256.h"
#include "rsasig/md5.h"
#include "rsasig/rsasig.h"
#include "rsasig/base64.h"

#include "digsig/hexdump.h"
#include "crt/x509.h"
#include "crt/x509_crt.h"

#define	ferr(msg) (err(ferror(thefile) ? strerror(errno) : (msg)))

static int err(char const *errmsg)
{
	fprintf(stderr, "%s: %s: %s\n", theprogram, thefilename, errmsg);
	return FALSE;
}

static int read_elf_header(void)
{
	if (elfrw_read_Ehdr(thefile, &ehdr) != 1)
		return ferr("非法ELF文件头");

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
		return err("非可执行文件");

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
		return ferr("程序节头表丢失或不完整。");
	}
	
	if (analy_shstrtable() == FALSE){
		return FALSE;
	}
	return TRUE;
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
	if (shstrndx > ehdr.e_shnum){
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
	//printf ("文件备份%d字节\n",temp_size);
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
	
	//printf ("备份字节数size = %x\n", temp_size);
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
}

static int modify_shdrs(void)
{
	//如果modify_headrs比这个函数更早调用就必须-1否则不用
	int count = ehdr.e_shnum-1;
	int i = 0;
	unsigned int shdrs_end_off = ehdr.e_shoff + (count*ehdr.e_shentsize) - ELF_SIG_SH_TAB_ADD_OFF;

	for (i = 0;i < count; ++i){
		if (shdrs[i].sh_offset > shstroff){
			shdrs[i].sh_offset += ELF_SIG_SH_TAB_ADD_OFF;
		}
		//printf ("off %lu %lu\n",(unsigned long int)shdrs[i].sh_offset, (unsigned long int)shdrs_end_off);
		if (shdrs[i].sh_offset > shdrs_end_off){
			shdrs[i].sh_offset += ehdr.e_shentsize;
		}
		if ((unsigned int)i == shstrndx){
			apped_shdr.sh_name = shdrs[i].sh_size;
			shdrs[i].sh_size += ELF_SIG_SH_TAB_ADD_OFF;
			shstrsize += ELF_SIG_SH_TAB_ADD_OFF;
		}
	}
	apped_shdr.sh_type = SHT_STRTAB;
	apped_shdr.sh_flags = SHF_MASKOS;
	apped_shdr.sh_addr = 0;
	apped_shdr.sh_offset = curr_file_size+64;
	apped_shdr.sh_size = sh_sig_buff_size;
	apped_shdr.sh_link = 0;
	apped_shdr.sh_info = 0;
	apped_shdr.sh_addralign = 1;
	apped_shdr.sh_entsize = 0;
	memcpy(&shdrs[i],&apped_shdr,sizeof(apped_shdr));
	//printf ("%lu %lu\n",sizeof (shdrs), sizeof(apped_shdr));
	fseek(thefile, ehdr.e_shoff, SEEK_SET);
	if (elfrw_write_Shdrs(thefile, shdrs, count+1) != count+1){
		return ferr("修改节头表失败!");
	}
	return TRUE;
}

static int insert_sh_sig(void)
{
	sh_sig_off = pre_shdrs_off + ELF_SIG_SH_TAB_ADD_OFF;//计算秘钥节的偏移量

	fseek(thefile, 0, SEEK_END);//密钥节放在最尾部的位置
	if (fwrite(sh_sig_buff, sh_sig_buff_size, 1, thefile) != 1){
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

	if (sh_name_temp == NULL || count == -1){
		return err("get_text_data err");
	}
	memset(sh_name_temp, 0, shdrs[shstrndx].sh_size);
	fgetpos(thefile, &ps);
	fseek(thefile, shdrs[shstrndx].sh_offset, SEEK_SET);

	fread(sh_name_temp, shdrs[shstrndx].sh_size, 1, thefile);

	for (i = 0;i < count; ++i){
		int name = shdrs[i].sh_name;

		if (strcmp(".text", &sh_name_temp[name]) == 0){
            unsigned long ssize = shdrs[i].sh_size > 256*1024 ? 256*1024 : shdrs[i].sh_size;
			elf_text_data = realloc(elf_text_data, ssize);
			if (elf_text_data == NULL){
				printf ("内存分配失败");
				goto er;
			}

			fseek(thefile, shdrs[i].sh_offset, SEEK_SET);
			fread(elf_text_data, ssize, 1, thefile);

			elf_text_data_len = ssize;
		}
        if (strcmp(".digsig", &sh_name_temp[name]) == 0){
            printf ("digsig节已经存在，请重新编译可执行文件后再次进行签名\n");
            goto er;
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
    unsigned char  encrypted[4098];
    int encrypted_length;
    unsigned char sha256_h[ELF_SIG_SH_SHA_LEN] = {0};

    sha256(elf_text_data, elf_text_data_len, sha256_h);
    
    if (!crt_flag){//公私钥模式下使用默认的私钥进行加密
        pem_privkey_len = strlen(def_pem_privkey);
        memcpy(pem_privkey, def_pem_privkey, pem_privkey_len);
        printf ("默认私钥为：\n%s\n",pem_privkey);
    }else{
        FILE* privfile = fopen(privatefilename, "r");
        if (privfile == NULL){
            return FALSE;
        }
        fseek(privfile, 0, SEEK_END);
        pem_privkey_len = ftell(privfile);
        fseek(privfile, 0, SEEK_SET);
        fread(pem_privkey, pem_privkey_len, 1, privfile);
        pem_privkey[pem_privkey_len] = 0;
        printf("输入私钥为：\n%s",pem_privkey);
        fclose(privfile);
        /*如果密钥生成失败，则使用默认密钥 */
        /*if (Generate_RSA_Keys(2048, pem_pubkey, pem_privkey)){
            printf ("RSA密钥生成失败\n");
            return FALSE;
        }else{
            pem_privkey_len = strlen(pem_privkey);
            pem_pubkey_len  = strlen(pem_pubkey);
            printf ("%s\n",pem_pubkey);
            der_pubkey_len = pubkey_pemtoder(pem_pubkey, &der_pubkey);
            printf ("%s\n",pem_privkey);
            der_privkey_len = privkey_pemtoder(pem_privkey, &der_privkey);

            printf ("\n=======pubkey========\n");
            for (int i = 0;i < der_pubkey_len; ++i){
                printf ("\\x%02x", der_pubkey[i]);
            }
            printf ("\n=======privkey========\n");
            for (int i = 0;i < der_privkey_len; ++i){
                printf ("\\x%02x", der_privkey[i]);
            }
        }*/
    }
    
    encrypted_length = private_encrypt(sha256_h,ELF_SIG_SH_SHA_LEN, (unsigned char *)pem_privkey, (unsigned char *)encrypted);
    //printf("encr %d\n",encrypted_length);
    memcpy(sh_sig_buff, encrypted, encrypted_length);
    sh_sig_buff_size = encrypted_length;
    if (crt_flag){
        FILE* crtfile = fopen(crtfilename, "r");
        long int crtfile_len;
        char tbuff[2048];
        fseek(crtfile, 0, SEEK_END);
        crtfile_len = ftell(crtfile);
        fseek(crtfile, 0, SEEK_SET);
        fread(tbuff, crtfile_len, 1, crtfile);
        fclose(crtfile);
        if (check_crt(tbuff, crtfile_len, pem_privkey) == FALSE){
            printf ("请输入正确的私钥文件以及证书文件\n");
            return FALSE;
        }
        /*printf("\n\n%s\n\n", tbuff);
        printf ("\n\n%d\n", crtfile_len-26-28);
        memcpy(sh_sig_buff+sh_sig_buff_size, tbuff+28, crtfile_len-26-28);
        printf ("%d\n\n", sh_sig_buff_size);
        sh_sig_buff_size += crtfile_len-25-27;
        printf ("%d\n\n", sh_sig_buff_size);
        
        printf ("\n\ntbuf = \n %s \n\n", tbuff);
        printf ("crtfile_len %ld \n\n", crtfile_len);
        */
        memcpy(sh_sig_buff+sh_sig_buff_size, tbuff, crtfile_len);
        //printf ("%d\n\n", sh_sig_buff_size);
        sh_sig_buff_size += crtfile_len;
        //printf ("%d\n\n", sh_sig_buff_size);
        
    }

    return TRUE;
}

static int check_arg(char *execname)
{
    if (erropt_flag){
        printf ("%s 参数错误：未知的参数\n", execname);
        return FALSE;
    }
    if (help_flag){
        printf("%s ：digsig -[opt] filename\n", execname);
        return FALSE;
    }
    if (rsakey_flag && crt_flag){
        printf("%s 不能同时选择公私钥模式和数字证书模式\n", execname);
        return FALSE;
    }
    if (crt_flag && !inpriv_flag){
        printf("%s 证书验证模式下必须输入私钥文件\n", execname);
        return FALSE;
    }
    if (in_flag == 0){
        printf("%s 必须输入可执行程序路径\n",execname);
        return FALSE;
    }

    return TRUE;
}
static int x509_crt_get_id_pubkey(const unsigned char *buf, size_t buflen, 
	unsigned char *pkey, unsigned int *pkeylen, unsigned char *id, unsigned int *idlen)
{
	mbedtls_x509_crt cert;
	int ret;

	mbedtls_x509_crt_init(&cert);

    
	/* parse certificate derectly */
	ret = mbedtls_x509_crt_parse(&cert, buf, buflen);
    if(ret != 0) {
        goto exit;
    }
	if (pkey && pkeylen) {
		*pkeylen = cert.pk.pk_len - 1;
		memcpy(pkey, (unsigned char *)(cert.pk.pk_ctx + 1), cert.pk.pk_len);
	}
	if (id && idlen) {
		*idlen = cert.serial.len;
		memcpy(id, cert.serial.p, cert.serial.len);
	}
exit:
	mbedtls_x509_crt_free(&cert);
	return ret;
}

static int check_crt(char *crt, int crtfile_len, char *key)
{
	unsigned char temp_pub_key[1024] = {0x30};
	unsigned int temp_pub_keylen;
	unsigned char id[512];
	unsigned int idlen;
    unsigned char asciicrt[1024];
    int asciicrt_len = 0;
	int ret,i;
    unsigned char data[6];
	unsigned char encrypted[512] = {0};
	int encrypted_length;
	unsigned char decrypted[512];
	int decrypted_length;
    char *temp_pem_key, pem_key[2048];
	char *pub_begin = "-----BEGIN PUBLIC KEY-----\n";
	char *pub_end = "-----END PUBLIC KEY-----\n";
    int index = 0;

    memcpy(data, "12345", 5);

    for (i = 0;i < crtfile_len; ++i){
        if (crt[i] == 0x0A){
            asciicrt[asciicrt_len++] = 0x0D;
        }
        asciicrt[asciicrt_len++] = crt[i];
    }

    asciicrt[asciicrt_len++] = 0;

    memcpy(temp_pub_key, "\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30", 25);

	ret = x509_crt_get_id_pubkey((const unsigned char *)asciicrt, asciicrt_len ,\
     temp_pub_key+25, &temp_pub_keylen, id, &idlen);

    temp_pub_keylen += 25;
    
	if (ret) {
        printf ("\n证书解析失败\n");
        return FALSE;
	}
    printf ("\n证书解析成功\n");
    printf ("\n证书公钥如下\n");
    hexdump(temp_pub_key, temp_pub_keylen);

    temp_pem_key = (char *)base64_encode(temp_pub_key, temp_pub_keylen);

	encrypted_length = private_encrypt(data,5, (unsigned char *)key, (unsigned char *)encrypted);
    memcpy(pem_key, pub_begin, strlen(pub_begin));

    index = strlen(pub_begin);
    for (unsigned int i = 0;i < strlen(temp_pem_key); ++i){
        pem_key[index++] = temp_pem_key[i];
        if ((i+1) % 64 == 0){pem_key[index++] = '\n';}
    }
    pem_key[index++] = '\n';
    memcpy(pem_key+index, pub_end, strlen(pub_end));
    
    

	decrypted_length = public_decrypt(encrypted ,encrypted_length ,(unsigned char *)pem_key, decrypted);
    if (decrypted_length == -1){
        printf("证书公私钥校验失败\n");
        return FALSE;
    }
    for (i = 0;i < decrypted_length; ++i){
        if (data[i] != decrypted[i]){
            free(temp_pem_key);
            printf("证书公私钥校验失败\n");
            return FALSE;
        }
    }
    free(temp_pem_key);
	return TRUE;
}

/* main() loops over the cmdline arguments, leaving all the real work
 * to the other functions.
 */
int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
    char *string = "";
    static struct option long_options[] =
    {
        {"help", no_argument,NULL, '0'},
        {"crt", required_argument,NULL, '1'},
        {"rsakey",  no_argument, NULL,'2'},
        {"outpub", required_argument, NULL, '3'},
        {"outpriv", required_argument, NULL, '4'},
        {"in", required_argument, NULL, '5'},
        {"inkey", required_argument, NULL, '6'},
        {NULL, 0, NULL, 0},
    };
    while((opt =getopt_long_only(argc,argv,string,long_options,&option_index))!= -1)
    {
        switch (opt)
        {
        case '0':
            help_flag = 1;
            break;
        case '1':
            crt_flag = 1;
            memcpy(crtfilename, optarg, strlen(optarg));
            break;
        case '2':
            rsakey_flag = 1;
            break;
        case '3':
            outpub_flag = 1;
            memcpy(outpubfilename, optarg, strlen(optarg));
            break;
        case '4':
            outpriv_flag = 1;
            memcpy(outprivfilename, optarg, strlen(optarg));
            break;
        case '5':
            in_flag = 1;
            memcpy(thefilename, optarg, strlen(optarg));
            break;
        case '6':
            inpriv_flag = 1;
            memcpy(privatefilename, optarg, strlen(optarg));
            break;
        default:
            erropt_flag = 1;
            break;
        }
    }
    if (check_arg(argv[0]) == FALSE){
        return 0;
    }
    //return 0;

	thefile = fopen(thefilename,"rb+");
	
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

	//3. 获取text节数据
	if (get_text_data() == FALSE){
		goto er;
	}

	//4. 签名并获取密钥
	if(elf_text_sign() == FALSE){
		goto er;
	}

	//5. 插入节名字
	if (insert_shname() == FALSE){
		goto er;
	}

	//6. 修改节头表与文件头
	if (commit_changes() == FALSE){
		goto er;
	}

	//7. 插入密钥
	if (insert_sh_sig() == FALSE){
		goto er;
    }
    printf ("%s 加密成功\n", thefilename);
    printf ("密钥节内容为：\n");
    hexdump(sh_sig_buff, sh_sig_buff_size);
er:
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
