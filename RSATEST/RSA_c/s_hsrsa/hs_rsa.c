#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "hs_rsa.h"
#include "hs_rsa_tools.h"


/*-------------------------------------------------------
 ������Կ�ԵĹ���
-------------------------------------------------------*/
int Generate_RSA_Keys(const int g_nBits,char *pubkey,char *privkey)
{
	/*---------------------------------------------------
	 *˵����
	 *g_nBits��ʾ���ܳ��ȣ���ζ�������Ա����g_nBits/8-11=117���ֽڣ�
	 *RSA_F4��65537��Ϊ��Կָ����һ�������ʹ��RSA_F4���ɣ�������������
	 *��������ΪNULL��Ϊ�˼���Crypto++��������ɵ���Կ����Կʹ�ô�ͳPEM
	 *��Կ��ʽ���д�ȡ��˽Կ�����PKCS#8�Ǽ���˽Կ��ʽ���д�ȡ
	---------------------------------------------------*/

	/*��RSA��EVP_KEY�ṹ����г�ʼ��*/
	RSA *pRsa = RSA_new();
	EVP_PKEY *eRsa = EVP_PKEY_new();

	/*������Կ�Բ�������RSA�ṹ����*/
	pRsa = RSA_generate_key(g_nBits,RSA_F4,NULL,NULL);
	if (pRsa == NULL)
	{   
		/*printf("RSA_generate_key error\n");*/
		return -1;
	}

	/*����һ�����湫Կ�Ŀɶ�/д�ڴ�BIO*/
	BIO *pub = NULL;
	pub = BIO_new(BIO_s_mem());

	/*��RSA�ṹ������ȡ��Կ��BIO��*/
	PEM_write_bio_RSA_PUBKEY(pub,pRsa);
    
	/*��BIO�еĹ�Կ���浽char������*/
	int pub_len = BIO_read(pub,pubkey,4096);
	if(pub_len == 0)
	{
		/*printf("Generate Publickey error\n");*/
		return -2;
	}
	pubkey[pub_len] = '\0';

	/*�ͷŴ�Ź�Կ��BIO�ڴ�*/
	BIO_free(pub);

	/*����һ������˽Կ�Ŀɶ�/д�ڴ�BIO*/
	BIO *pri = NULL;
	pri = BIO_new(BIO_s_mem());

	/*��EVP_PKEY�ṹ���滻RSA�ṹ��*/
	EVP_PKEY_assign_RSA(eRsa,pRsa);

	/*�ӽṹ��EVP_PKEY����ȡ˽Կ��BIO��*/
	PEM_write_bio_PKCS8PrivateKey(pri,eRsa,NULL,NULL,0,NULL,NULL);

	/*��BIO�еĹ�Կ���浽char������*/
	int pri_len = BIO_read(pri,privkey,4096);
	if(pri_len == 0)
	{
		/*printf("Generate Privatekey error\n");*/
		return -3;
	}
	privkey[pri_len] = '\0';

	/*�ͷŴ��˽Կ��BIO�ڴ��EVP_PKEY�ṹ��*/
	BIO_free(pri);
	EVP_PKEY_free(eRsa);		/*EVP_PKEY�ṹ���Ѿ��滻��RSA�ṹ�壬�������ͷ�RSA�ṹ��*/
}


/*-------------------------------------------------------
 ���ù�Կ�������ĵĹ���
-------------------------------------------------------*/
int PublicEncrypt(char *pubkey,char *in_plain,char *cipher)
{
	char plain[4096];			/*��ŷֶκ��ÿһ������*/
	char encrypted[4096];		/*���ÿһ�����ĵĽ��ܽ��*/
	char result[4096];			/*���ƴ�Ӻ������*/
	char plain_rest[4096];		/*��ŷֶ�֮��ʣ�ಿ�ֵ�����*/
	char encrypted_rest[4096];		/*��Ŷ�ʣ�ಿ�����ĵĽ��ܽ��*/
	int pubKeyLen = 0,CryLen = 0,maxPlain = 0,cipherLen = 0;
	
	/*���ַ���������г�ʼ��*/
	memset(plain,0,sizeof(plain));
	memset(encrypted,0,sizeof(encrypted));
	memset(result,0,sizeof(result));
	memset(plain_rest,0,sizeof(plain_rest));
	memset(encrypted_rest,0,sizeof(encrypted_rest));
	
	/*�Թ�Կ����PEM��ʽ��*/
	PubKeyPEMFormat(pubkey);
	
	/*���ݹ�Կ���Ƚ�����صļ���*/
	pubKeyLen = strlen(pubkey);							/*���㹫Կ����*/
	CryLen = getEncryptLengthByPubKey(pubKeyLen);				/*ͨ����Կ���Ȼ�ȡ���ܳ���*/
	maxPlain = CryLen / 8 - 11;							/*ͨ�����ܳ��Ȼ�ȡ���ĵ������ܳ���*/
	cipherLen = CryLen / 8;							/*ͨ�����ܳ��Ȼ�ȡ���ĵĳ���*/

	/*���ַ�����ȡRSA��Կ*/
	BIO *enc = NULL; 
	if ((enc = BIO_new_mem_buf(pubkey, -1)) == NULL)        
	{     
		/*printf("BIO_new_mem_buf failed!\n");*/
		return -4;    
	}

	/*������Կ*/
	RSA *rsa_pub = RSA_new();	
	rsa_pub = PEM_read_bio_RSA_PUBKEY(enc, NULL, NULL, NULL);
	if(rsa_pub == NULL)
	{
		/*printf("Unable to read public key!\n");*/
		return -5; 
	}

	/******************
	 �ֶ�ѭ�����ܹ���
	******************/
	int label = 0, index = 0, index_rest = 0, segment = 0, rest = 0;
	segment = strlen(in_plain) / maxPlain;   /*�ֶ���*/
	rest = strlen(in_plain) % maxPlain;      /*����*/

	/*���ĳ��ȴ��������ܳ����ҷ�������*/
	if(strlen(in_plain) > maxPlain && rest != 0)
	{
		for(label = 0;label < segment; label++)
		{
			memset(plain,0,maxPlain);
			memset(encrypted,0,cipherLen);
			memcpy(plain, in_plain+index, maxPlain);		/*�����Ľ��зֶ�*/
			plain[maxPlain] = '\0';
			int EncryptedLen = RSA_public_encrypt(maxPlain, plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
			if(EncryptedLen == -1 )
			{
				/*printf("Failed to encrypt!\n");*/
				return -6;
			} 
			
			/*��ÿһ�ζ������Ľ���ƴ��*/
			memcpy(result+label*cipherLen,encrypted,cipherLen);
			
			index += maxPlain;
		}
		
		/*��ʣ�ಿ�����Ľ��м���*/
		index_rest = segment*maxPlain;
		memset(plain_rest,0,rest);
		memcpy(plain_rest, in_plain+index_rest, rest);		/*��ȡʣ�ಿ������*/
		plain_rest[rest] = '\0';
		memset(encrypted_rest,0,cipherLen);
		int EncryptedLen = RSA_public_encrypt(rest, plain_rest, encrypted_rest, rsa_pub, RSA_PKCS1_PADDING);
		if(EncryptedLen == -1 )
		{
			/*printf("Failed to encrypt!\n");*/
			return -7;
		}
		/*��ʣ�ಿ�ֵ�����ƴ�ӵ�����������*/
		memcpy(result+label*cipherLen,encrypted_rest,cipherLen);
		
		/*���������Ľ���Base64����*/
		Base64Encode_rsa(result, (label+1)*cipherLen, cipher);
	}

	/*���ĳ��ȵ��������ܳ��ȵ�������*/
	else if(strlen(in_plain) >= maxPlain && rest == 0)
	{
		for(label = 0;label < segment; label++)
		{
			memset(plain,0,maxPlain);
			memset(encrypted,0,cipherLen);
			memcpy(plain, in_plain+index, maxPlain);		/*�����Ľ��зֶ�*/
			plain[maxPlain] = '\0';
			int EncryptedLen = RSA_public_encrypt(maxPlain, plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
			if(EncryptedLen == -1 )
			{
				/*printf("Failed to encrypt!\n");*/
				return -8;
			} 			
			/*ƴ��ÿ������*/
			memcpy(result+label*cipherLen,encrypted,cipherLen);
		}
		/*���������Ľ���Base64����*/
		Base64Encode_rsa(result, label*cipherLen, cipher);
	}

	/*���ĳ���С�������ܳ���*/
	else
	{
		int EncryptedLen = RSA_public_encrypt(strlen(in_plain), in_plain, encrypted, rsa_pub, RSA_PKCS1_PADDING);
		if(EncryptedLen == -1 )
		{
			/*printf("Failed to encrypt!\n");*/
			return -9;
		}
		/*�����Ľ���Base64����*/
		Base64Encode_rsa(encrypted, cipherLen, cipher);
	}

	/*�ͷ�BIO�ڴ��RSA�ṹ��*/
	BIO_free_all(enc);
	RSA_free(rsa_pub);
	
	return 0;
}


/*-------------------------------------------------------
 ����˽Կ�������ĵĹ���
-------------------------------------------------------*/
int PrivateDecrypt(char *privkey,char *cipher,char *out_plain)
{
	char encrypted[4096];			/*��Ž�������������*/
	char encrypted_result[4096];		/*��ŷֶκ��ÿһ������*/
	char decrypted[4096];			/*���ÿһ�����ĵĽ��ܽ��*/
	int priKeyLen = 0,CipherRealLen = 0,plainLen = 0;
	
	/*���ַ���������г�ʼ��*/
	memset(encrypted,0,sizeof(encrypted));
	memset(encrypted_result,0,sizeof(encrypted_result));
	memset(decrypted,0,sizeof(decrypted));
	
	/*��˽Կ����PEM��ʽ��*/
	PrivKeyPEMFormat(privkey);

	/*����˽Կ���Ƚ�����صļ���*/
	priKeyLen = strlen(privkey);						/*˽Կ����*/
	CipherRealLen = getCipherRealLenByPriKey(priKeyLen);			/*ͨ��˽Կ���Ȼ�ȡÿ������ʵ�ʳ���*/
	plainLen = CipherRealLen - 11;

	/*���ַ�����ȡRSA˽Կ*/
	BIO *dec = NULL;  
	if ((dec = BIO_new_mem_buf(privkey, -1)) == NULL)
	{     
		/*printf("BIO_new_mem_buf failed!\n");*/
		return -10;      
	}       
	
	/*����˽Կ*/
	RSA *rsa_pri = RSA_new();
	EVP_PKEY *pri = EVP_PKEY_new();	
	pri = PEM_read_bio_PrivateKey(dec, NULL, NULL, NULL);
	if(pri == NULL)
	{
		/*printf("Unable to read private key!\n");*/
		return -11; 
	}
	
	/*��EVP_PKEY�ṹ��ת����RSA�ṹ��*/
	rsa_pri = EVP_PKEY_get1_RSA(pri);

	/******************
	 �ֶ�ѭ�����ܹ���
	 ******************/ 
	int index = 0, label = 0, out_plainLen = 0, CipherLen = 0, segment = 0;
	
	/*Base64��������ĳ���*/
	CipherLen = strlen(cipher);
	
	/*������ʵ���ĵĶ���*/
	segment = CipherLen * 3 / 4 / CipherRealLen;
	
	/*���������Ľ���Base64����*/
	Base64Decode_rsa(cipher, CipherLen, encrypted);
	
	/*�����������ķֶν��ܺ�ϲ�*/
	while(label < segment)
	{
		memset(encrypted_result,0,CipherRealLen);
		memcpy(encrypted_result,encrypted+index,CipherRealLen);		/*�����Ľ��зֶ�*/
		encrypted_result[CipherRealLen] = '\0';		
		memset(decrypted, 0, plainLen);		
		int DecryptedLen = RSA_private_decrypt(CipherRealLen, encrypted_result, decrypted, rsa_pri, RSA_PKCS1_PADDING);
		if(DecryptedLen == -1)
		{
			/*printf("Failed to decrypt!\n");*/
			return -12;
		}
		decrypted[DecryptedLen] = '\0';
		strcat(out_plain, decrypted);		/*��ÿһ�εĽ��ܽ��ƴ�ӵ��������������*/
		out_plainLen += DecryptedLen;
		out_plain[out_plainLen] = '\0';
		index += CipherRealLen;
		label++;
	}

	/*�ͷ�BIO�ڴ��Լ�RSA��EVP_PKEY�ṹ��*/
	BIO_free_all(dec);
	RSA_free(rsa_pri);
	EVP_PKEY_free(pri);
	
	return 0;
}