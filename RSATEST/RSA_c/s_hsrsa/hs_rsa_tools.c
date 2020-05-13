#include <string.h>
#include "hs_rsa_tools.h"

/*-------------------------------------------------------
 �Թ�Կ����PEM��ʽ��
-------------------------------------------------------*/
void PubKeyPEMFormat(char *pubkey)
{
	char format_pubkey[4096];
	char pub_tem[4096];
	int index = 0,publength = 0,nPublicKeyLen = 0;
	
	/*���ַ���������г�ʼ��*/
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
 ��˽Կ����PEM��ʽ��
-------------------------------------------------------*/
void PrivKeyPEMFormat(char *privkey)
{
	char format_privkey[4096];
	char priv_tem[4096];
	int index = 0,privlength = 0,nPrivateKeyLen = 0;
	
	/*���ַ���������г�ʼ��*/
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


/*-------------------------------------------------------
 ͨ����Կ���Ȼ�ȡ���ܳ���
-------------------------------------------------------*/
int getEncryptLengthByPubKey(int pubKeyLen)
{
	int cryLen = 0;								/*���ܳ���*/
	switch (pubKeyLen)
	{
		case 134:	/*256*/
			cryLen = 256;
			break;
		case 178:	/*512*/
			cryLen = 512;
			break;
		case 272:	/*1024*/
			cryLen = 1024;
			break;
		case 451:	/*2048*/
			cryLen = 2048;
			break;
		case 796:	/*4096*/
			cryLen = 4096;
			break;
		default:
			break;
	}
	return cryLen;
}


/*-------------------------------------------------------
 ����˽Կ�����ж϶�Ӧ�ļ��ܳ��ȣ��ó�ʵ�����ķֶγ���
-------------------------------------------------------*/
int getCipherRealLenByPriKey(int priKeyLen)
{
	/*��Ӧ���ܳ��ȶ�Ӧ��ÿ�����ĳ���*/
	int SignleRealLen = 0;
	if(priKeyLen == 319 || priKeyLen == 323)			/*256*/
		SignleRealLen = 32;								
	else if(priKeyLen == 518 || priKeyLen == 522)		/*512*/
		SignleRealLen = 64;								
	else if(priKeyLen == 912 || priKeyLen == 916)		/*1024*/
		SignleRealLen = 128;								
	else if(priKeyLen == 1700 || priKeyLen == 1704)		/*2048*/
		SignleRealLen = 256;									
	else if(priKeyLen == 3268 || priKeyLen == 3272)		/*4096*/
		SignleRealLen = 512;									
	return SignleRealLen;
}


/*-------------------------------------------------------
 ����˽Կ�����ж϶�Ӧ�ļ��ܳ��ȣ��ó�Base64��������ķֶγ���
-------------------------------------------------------*/
int getCipherLengthByPriKey(int priKeyLen)
{
	/*��Ӧ���ܳ��ȶ�Ӧ��ÿ��Base64���ĳ���*/
	int b64CipherLen = 0;
	if(priKeyLen == 319 || priKeyLen == 323)			/*256*/
		b64CipherLen = 44;					/*32*/
	else if(priKeyLen == 518 || priKeyLen == 522)		/*512*/
		b64CipherLen = 88;					/*64*/
	else if(priKeyLen == 912 || priKeyLen == 916)		/*1024*/
		b64CipherLen = 172;					/*128*/
	else if(priKeyLen == 1700 || priKeyLen == 1704)		/*2048*/
		b64CipherLen = 344;					/*256*/
	else if(priKeyLen == 3268 || priKeyLen == 3272)		/*4096*/
		b64CipherLen = 684;					/*512*/
	return b64CipherLen;
}


/*-------------------------------------------------------
 ͨ�����ܳ��Ȼ�ȡ���Ľ���Base64�����ĳ���
-------------------------------------------------------*/
int getBase64LenByEncryptLen(int cryLen)
{
	int Base64Len = 0;
	switch (cryLen)
	{
	case 256:
		Base64Len = 44;		/*32*/
		break;
	case 512:
		Base64Len = 88;		/*64*/
		break;
	case 1024:
		Base64Len = 172;		/*128*/
		break;
	case 2048:
		Base64Len = 344;		/*256*/
		break;
	case 4096:
		Base64Len = 684;		/*512*/
		break;
	default:
		break;
	}
	return Base64Len;
}