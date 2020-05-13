#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "hs_rsa.h"
#include "hs_rsa_tools.h"


/*-------------------------------------------------------
 生成密钥对的过程
-------------------------------------------------------*/
int Generate_RSA_Keys(const int g_nBits,char *pubkey,char *privkey)
{
	/*---------------------------------------------------
	 *说明：
	 *g_nBits表示加密长度，意味着最多可以编解码g_nBits/8-11=117个字节，
	 *RSA_F4即65537，为公钥指数，一般情况下使用RSA_F4即可，其它两个参数
	 *可以设置为NULL，为了兼容Crypto++密码库生成的密钥，公钥使用传统PEM
	 *公钥格式进行存取，私钥则采用PKCS#8非加密私钥格式进行存取
	---------------------------------------------------*/

	/*对RSA和EVP_KEY结构体进行初始化*/
	RSA *pRsa = RSA_new();
	EVP_PKEY *eRsa = EVP_PKEY_new();

	/*生成密钥对并保存在RSA结构体中*/
	pRsa = RSA_generate_key(g_nBits,RSA_F4,NULL,NULL);
	if (pRsa == NULL)
	{   
		/*printf("RSA_generate_key error\n");*/
		return -1;
	}

	/*建立一个保存公钥的可读/写内存BIO*/
	BIO *pub = NULL;
	pub = BIO_new(BIO_s_mem());

	/*从RSA结构体中提取公钥到BIO中*/
	PEM_write_bio_RSA_PUBKEY(pub,pRsa);
    
	/*将BIO中的公钥保存到char数组中*/
	int pub_len = BIO_read(pub,pubkey,4096);
	if(pub_len == 0)
	{
		/*printf("Generate Publickey error\n");*/
		return -2;
	}
	pubkey[pub_len] = '\0';

	/*释放存放公钥的BIO内存*/
	BIO_free(pub);

	/*建立一个保存私钥的可读/写内存BIO*/
	BIO *pri = NULL;
	pri = BIO_new(BIO_s_mem());

	/*用EVP_PKEY结构体替换RSA结构体*/
	EVP_PKEY_assign_RSA(eRsa,pRsa);

	/*从结构体EVP_PKEY中提取私钥到BIO中*/
	PEM_write_bio_PKCS8PrivateKey(pri,eRsa,NULL,NULL,0,NULL,NULL);

	/*将BIO中的公钥保存到char数组中*/
	int pri_len = BIO_read(pri,privkey,4096);
	if(pri_len == 0)
	{
		/*printf("Generate Privatekey error\n");*/
		return -3;
	}
	privkey[pri_len] = '\0';

	/*释放存放私钥的BIO内存和EVP_PKEY结构体*/
	BIO_free(pri);
	EVP_PKEY_free(eRsa);		/*EVP_PKEY结构体已经替换了RSA结构体，无需再释放RSA结构体*/
}


/*-------------------------------------------------------
 利用公钥加密明文的过程
-------------------------------------------------------*/
int PublicEncrypt(char *pubkey,char *in_plain,char *cipher)
{
	char plain[4096];			/*存放分段后的每一段明文*/
	char encrypted[4096];		/*存放每一段明文的解密结果*/
	char result[4096];			/*存放拼接后的密文*/
	char plain_rest[4096];		/*存放分段之后剩余部分的明文*/
	char encrypted_rest[4096];		/*存放对剩余部分明文的解密结果*/
	int pubKeyLen = 0,CryLen = 0,maxPlain = 0,cipherLen = 0;
	
	/*对字符串数组进行初始化*/
	memset(plain,0,sizeof(plain));
	memset(encrypted,0,sizeof(encrypted));
	memset(result,0,sizeof(result));
	memset(plain_rest,0,sizeof(plain_rest));
	memset(encrypted_rest,0,sizeof(encrypted_rest));
	
	/*对公钥进行PEM格式化*/
	PubKeyPEMFormat(pubkey);
	
	/*根据公钥长度进行相关的计算*/
	pubKeyLen = strlen(pubkey);							/*计算公钥长度*/
	CryLen = getEncryptLengthByPubKey(pubKeyLen);				/*通过公钥长度获取加密长度*/
	maxPlain = CryLen / 8 - 11;							/*通过加密长度获取明文的最大加密长度*/
	cipherLen = CryLen / 8;							/*通过加密长度获取密文的长度*/

	/*从字符串读取RSA公钥*/
	BIO *enc = NULL; 
	if ((enc = BIO_new_mem_buf(pubkey, -1)) == NULL)        
	{     
		/*printf("BIO_new_mem_buf failed!\n");*/
		return -4;    
	}

	/*解析公钥*/
	RSA *rsa_pub = RSA_new();	
	rsa_pub = PEM_read_bio_RSA_PUBKEY(enc, NULL, NULL, NULL);
	if(rsa_pub == NULL)
	{
		/*printf("Unable to read public key!\n");*/
		return -5; 
	}

	/******************
	 分段循环加密过程
	******************/
	int label = 0, index = 0, index_rest = 0, segment = 0, rest = 0;
	segment = strlen(in_plain) / maxPlain;   /*分段数*/
	rest = strlen(in_plain) % maxPlain;      /*余数*/

	/*明文长度大于最大加密长度且非整数倍*/
	if(strlen(in_plain) > maxPlain && rest != 0)
	{
		for(label = 0;label < segment; label++)
		{
			memset(plain,0,maxPlain);
			memset(encrypted,0,cipherLen);
			memcpy(plain, in_plain+index, maxPlain);		/*对明文进行分段*/
			plain[maxPlain] = '\0';
			int EncryptedLen = RSA_public_encrypt(maxPlain, plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
			if(EncryptedLen == -1 )
			{
				/*printf("Failed to encrypt!\n");*/
				return -6;
			} 
			
			/*对每一段定长密文进行拼接*/
			memcpy(result+label*cipherLen,encrypted,cipherLen);
			
			index += maxPlain;
		}
		
		/*对剩余部分明文进行加密*/
		index_rest = segment*maxPlain;
		memset(plain_rest,0,rest);
		memcpy(plain_rest, in_plain+index_rest, rest);		/*获取剩余部分明文*/
		plain_rest[rest] = '\0';
		memset(encrypted_rest,0,cipherLen);
		int EncryptedLen = RSA_public_encrypt(rest, plain_rest, encrypted_rest, rsa_pub, RSA_PKCS1_PADDING);
		if(EncryptedLen == -1 )
		{
			/*printf("Failed to encrypt!\n");*/
			return -7;
		}
		/*将剩余部分的密文拼接到整段密文中*/
		memcpy(result+label*cipherLen,encrypted_rest,cipherLen);
		
		/*对整段密文进行Base64编码*/
		Base64Encode_rsa(result, (label+1)*cipherLen, cipher);
	}

	/*明文长度等于最大加密长度的整数倍*/
	else if(strlen(in_plain) >= maxPlain && rest == 0)
	{
		for(label = 0;label < segment; label++)
		{
			memset(plain,0,maxPlain);
			memset(encrypted,0,cipherLen);
			memcpy(plain, in_plain+index, maxPlain);		/*对明文进行分段*/
			plain[maxPlain] = '\0';
			int EncryptedLen = RSA_public_encrypt(maxPlain, plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
			if(EncryptedLen == -1 )
			{
				/*printf("Failed to encrypt!\n");*/
				return -8;
			} 			
			/*拼接每段密文*/
			memcpy(result+label*cipherLen,encrypted,cipherLen);
		}
		/*对整段密文进行Base64编码*/
		Base64Encode_rsa(result, label*cipherLen, cipher);
	}

	/*明文长度小于最大加密长度*/
	else
	{
		int EncryptedLen = RSA_public_encrypt(strlen(in_plain), in_plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
		if(EncryptedLen == -1 )
		{
			/*printf("Failed to encrypt!\n");*/
			return -9;
		}
		/*对密文进行Base64编码*/
		Base64Encode_rsa(encrypted, cipherLen, cipher);
	}

	/*释放BIO内存和RSA结构体*/
	BIO_free_all(enc);
	RSA_free(rsa_pub);
	
	return 0;
}


/*-------------------------------------------------------
 利用私钥解密密文的过程
-------------------------------------------------------*/
int PrivateDecrypt(char *privkey,char *cipher,char *out_plain)
{
	char encrypted[4096];			/*存放解码后的整段密文*/
	char encrypted_result[4096];		/*存放分段后的每一段密文*/
	char decrypted[4096];			/*存放每一段密文的解密结果*/
	int priKeyLen = 0,CipherRealLen = 0,plainLen = 0;
	
	/*对字符串数组进行初始化*/
	memset(encrypted,0,sizeof(encrypted));
	memset(encrypted_result,0,sizeof(encrypted_result));
	memset(decrypted,0,sizeof(decrypted));
	
	/*对私钥进行PEM格式化*/
	PrivKeyPEMFormat(privkey);

	/*根据私钥长度进行相关的计算*/
	priKeyLen = strlen(privkey);						/*私钥长度*/
	CipherRealLen = getCipherRealLenByPriKey(priKeyLen);			/*通过私钥长度获取每段密文实际长度*/
	plainLen = CipherRealLen - 11;

	/*从字符串读取RSA私钥*/
	BIO *dec = NULL;  
	if ((dec = BIO_new_mem_buf(privkey, -1)) == NULL)
	{     
		/*printf("BIO_new_mem_buf failed!\n");*/
		return -10;      
	}       
	
	/*解析私钥*/
	RSA *rsa_pri = RSA_new();
	EVP_PKEY *pri = EVP_PKEY_new();	
	pri = PEM_read_bio_PrivateKey(dec, NULL, NULL, NULL);
	if(pri == NULL)
	{
		/*printf("Unable to read private key!\n");*/
		return -11; 
	}
	
	/*将EVP_PKEY结构体转换成RSA结构体*/
	rsa_pri = EVP_PKEY_get1_RSA(pri);

	/******************
	 分段循环解密过程
	 ******************/ 
	int index = 0, label = 0, out_plainLen = 0, CipherLen = 0, segment = 0;
	
	/*Base64编码的密文长度*/
	CipherLen = strlen(cipher);
	
	/*计算真实密文的段数*/
	segment = CipherLen * 3 / 4 / CipherRealLen;
	
	/*对整段密文进行Base64解码*/
	Base64Decode_rsa(cipher, CipherLen, encrypted);
	
	/*将解码后的密文分段解密后合并*/
	while(label < segment)
	{
		memset(encrypted_result,0,CipherRealLen);
		memcpy(encrypted_result,encrypted+index,CipherRealLen);		/*对密文进行分段*/
		encrypted_result[CipherRealLen] = '\0';		
		memset(decrypted, 0, plainLen);		
		int DecryptedLen = RSA_private_decrypt(CipherRealLen, encrypted_result, decrypted, rsa_pri, RSA_PKCS1_PADDING);
		if(DecryptedLen == -1)
		{
			/*printf("Failed to decrypt!\n");*/
			return -12;
		}
		decrypted[DecryptedLen] = '\0';
		strcat(out_plain, decrypted);		/*将每一段的解密结果拼接到整段输出明文中*/
		out_plainLen += DecryptedLen;
		out_plain[out_plainLen] = '\0';
		index += CipherRealLen;
		label++;
	}

	/*释放BIO内存以及RSA和EVP_PKEY结构体*/
	BIO_free_all(dec);
	RSA_free(rsa_pri);
	EVP_PKEY_free(pri);
	
	return 0;
}