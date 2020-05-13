#include<stdio.h>
#include<string.h>
	
/*-------------------------
	说明：
	将整串的密钥进行PEM格式化
	1.添加头尾说明
	2.每64个字符一换行
-------------------------*/
	
/*-------------------------------------------------------
 对公钥进行PEM格式化
-------------------------------------------------------*/
void PubKeyPEMFormat(char *pubkey)
{
	char format_pubkey[4096];
	char pub_tem[4096];
	int index = 0,publength = 0,nPublicKeyLen = 0;
	
	/*对字符串数组进行初始化*/
	memset(format_pubkey, 0, sizeof(format_pubkey));
	memset(pub_tem, 0, sizeof(pub_tem));
	
	char *pub_begin = "-----BEGIN PUBLIC KEY-----\n";
	char *pub_end = "-----END PUBLIC KEY-----\n";
	char *check = strstr(pubkey,pub_begin);
	if(check)
	{
		return;
	}
	else
	{
		nPublicKeyLen = strlen(pubkey); 		
		memcpy(format_pubkey,pub_begin,27);
		for(index = 0; index < nPublicKeyLen; index += 64)
		{			
			memcpy(pub_tem,pubkey+index,64);
			strcat(format_pubkey,pub_tem);
			publength = strlen(format_pubkey);
			format_pubkey[publength] = '\n';
			memset(pub_tem, 0, sizeof(pub_tem));
		}
		strcat(format_pubkey,pub_end);
		memcpy(pubkey,format_pubkey,strlen(format_pubkey));
	}
}
	
/*-------------------------------------------------------
 对私钥进行PCKS#8非加密的PEM格式化
-------------------------------------------------------*/
void PrivKeyPEMFormat(char *privkey)
{
	char format_privkey[4096];
	char priv_tem[4096];
	int index = 0,privlength = 0,nPrivateKeyLen = 0;
	
	/*对字符串数组进行初始化*/
	memset(format_privkey, 0, sizeof(format_privkey));
	memset(priv_tem, 0, sizeof(priv_tem));
	
	char *priv_begin = "-----BEGIN PRIVATE KEY-----\n";
	char *priv_end = "-----END PRIVATE KEY-----\n";
	char *check = strstr(privkey, priv_begin); 
	if(check)
	{
		return;
	}
	else
	{
		nPrivateKeyLen = strlen(privkey); 
		memcpy(format_privkey,priv_begin,28);
		for(index = 0; index < nPrivateKeyLen; index += 64)
		{			
			memcpy(priv_tem,privkey+index,64);
			strcat(format_privkey,priv_tem);
			privlength = strlen(format_privkey);
			format_privkey[privlength] = '\n';
			memset(priv_tem, 0, sizeof(priv_tem));
		}
		strcat(format_privkey,priv_end);
		memcpy(privkey,format_privkey,strlen(format_privkey));
	}
}
	
	int main()
	{
		char pubkey[4096] = {0};
		char privkey[4096] = {0};
		
		printf("Please input Publickey:\n");
		scanf("%s",pubkey);
		printf("Please input Privatekey:\n");
		scanf("%s",privkey);
		
		PubKeyPEMFormat(pubkey);
		PrivKeyPEMFormat(privkey);
		
		printf("\n%s",pubkey);
		printf("PublicKey Length is:%d\n\n",strlen(pubkey));
		printf("%s",privkey);
		printf("PrivateKey Length is:%d\n\n",strlen(privkey));
		return 0;
	}
		