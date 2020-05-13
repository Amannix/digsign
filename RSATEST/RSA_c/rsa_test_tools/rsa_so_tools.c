#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>


int main()
{
	/*-------------------------------------------------------
	 调用动态库
	-------------------------------------------------------*/
	void * libm_handle = NULL;
	typedef int (*Gen)(const int g_nBits,char *privkey,char *pubkey);
	typedef int (*En)(char *pubkey,char *in_plain,char *cipher);
	typedef int (*De)(char *privkey,char *cipher,char *out_plain);
	char *errorInfo;
	int result;
	libm_handle = dlopen("./libs_hsrsa.so", RTLD_LAZY);
	if (!libm_handle)
	{
		printf("Open Error:%s.\n",dlerror());
		return 0;
	}	
	Gen Genkey = (Gen)dlsym(libm_handle,"Generate_RSA_Keys");
	En Encrypt = (En)dlsym(libm_handle,"PublicEncrypt");
	De Decrypt = (De)dlsym(libm_handle,"PrivateDecrypt");
	errorInfo = dlerror();
	if (errorInfo != NULL)
	{
		printf("Dlsym Error:%s.\n",errorInfo);
		return 0;
	}
	
	
	/*-------------------------------------------------------
	 生成密钥对部分
	-------------------------------------------------------*/
	void GenerateKeys()
	{
		char pubkey[4096] = {0};
		char privkey[4096] = {0};
		
		/*选择加密长度*/
		printf("-----------------------------\n");
		printf("Chose the KeySize:\n");
		int cmd,g_nBits;
 		printf("1 - 256\n");
		printf("2 - 512\n");
		printf("3 - 1024\n");
		printf("4 - 2048\n");
		printf("5 - 4096\n");
		printf("-----------------------------\n");
		printf("Enter choice: ");
		scanf("%d",&cmd);
		switch(cmd) 
		{ 
			case 1:
				g_nBits = 256;
				break; 
			case 2:
				g_nBits = 512;
				break;
			case 3:
				g_nBits = 1024;
				break;
			case 4:
				g_nBits = 2048;
				break;
			case 5:
				g_nBits = 4096;
				break;
 			default:
				printf("ERROR: Unrecognized command.\n");
				break;
		}
		/*调用密钥生成函数*/
		Genkey(g_nBits,pubkey,privkey);
		
		printf("-----------------------------\n");
		printf("\n%s",pubkey);
		printf("PublicKey Length is:%d\n",strlen(pubkey));
		printf("\n%s",privkey);
		printf("PrivateKey Length is:%d\n",strlen(privkey));
		
		/*选择退出方式*/
		while(1)
		{
			printf("\n-----------------------------\n");
			printf("Press 1 to continue...\nPress 0 to exit...\n");
			int command;
			scanf("%d",&command);
			switch (command)
			{
				case 1:
					return;
				case 0:
					exit(0);
				default:
					printf("ERROR: Unrecognized command.\n");
					break;
			}
		}
	}
	
	
	/*-------------------------------------------------------
	 使用公钥进行RSA加密部分
	-------------------------------------------------------*/
	void RSA_Encrypt()
	{
		char pubkey[4096] = {0};
		char privkey[4096] = {0};
		char in_plain[4096] = {0};
		char cipher[4096] = {0};
		
		printf("-----------------------------\n");
		printf("\nPlease input the PublicKey:\n");
		printf("-----------------------------\n");
		scanf("%s",pubkey);
		printf("-----------------------------\n");
		printf("The input PublicKey length is:%d\n",strlen(pubkey));
		printf("\nInput the plain:\n");
		printf("-----------------------------\n");
		scanf("%s",in_plain);
		printf("-----------------------------\n");
		printf("The input plain Length is:%d\n",strlen(in_plain));
		Encrypt(pubkey,in_plain,cipher);
		printf("\n%s",pubkey);
		printf("PublicKey Length is:%d\n\n",strlen(pubkey));
		printf("The cipher text is:\n");
		printf("-----------------------------\n");
		printf("%s\n",cipher);
		printf("-----------------------------\n");
		printf("The cipher Length is:%d\n",strlen(cipher));
		
		/*选择退出方式*/
		while(1)
		{
			printf("\n-----------------------------\n");
			printf("Press 1 to continue...\nPress 0 to exit...\n");
			int command;
			scanf("%d",&command);
			switch (command)
			{
				case 1:
					return;
				case 0:
					exit(0);
				default:
					printf("ERROR: Unrecognized command.\n");
					break;
			}
		}
	}
	
	
	/*-------------------------------------------------------
	 使用私钥进行RSA解密部分
	-------------------------------------------------------*/
	void RSA_Decrypt()
	{
		char pubkey[4096] = {0};
		char privkey[4096] = {0};
		char cipher[4096] = {0};
		char out_plain[4096] = {0};
		
		printf("-----------------------------\n");
		printf("\nPlease input the PrivateKey:\n");
		printf("-----------------------------\n");
		scanf("%s",privkey);
		printf("-----------------------------\n");
		printf("The input PrivateKey length is:%d\n\n",strlen(privkey));
		printf("Input the cipher:\n");
		printf("-----------------------------\n");
		scanf("%s",cipher);
		printf("-----------------------------\n");
		printf("The input Cipher length is:%d\n",strlen(cipher));
		Decrypt(privkey,cipher,out_plain);
		printf("\n%s",privkey);
		printf("PrivateKey Length is:%d\n\n",strlen(privkey));
		printf("The decrypted text is: \n");
		printf("-----------------------------\n");
		printf("%s\n",out_plain);
		printf("-----------------------------\n");
		printf("The decrypted text length is:%d\n",strlen(out_plain));
		
		/*选择退出方式*/
		while(1)
		{
			printf("\n-----------------------------\n");
			printf("Press 1 to continue...\nPress 0 to exit...\n");
			int command;
			scanf("%d",&command);
			switch (command)
			{
				case 1:
					return;
				case 0:
					exit(0);
				default:
					printf("ERROR: Unrecognized command.\n");
					break;
			}
		}
	}

	
	/*-------------------------------------------------------
	 选择工作方式菜单
	-------------------------------------------------------*/
	while(1)
	{
		int cmd;
		printf("\n*****************************\n");
		printf("* ------RSA加解密工具------ *\n");
		printf("*****************************\n");
		printf("-----------------------------\n");
		printf("Chose the Mode:\n");
		printf(" 1 - Generate RSA Keys\n");
 		printf(" 2 - Publickey for Encrypt\n");
		printf(" 3 - Privatekey for Decrypt\n");
		printf(" 0 - Exit\n");
		printf("-----------------------------\n");
		printf("Enter choice: ");
		scanf("%d",&cmd);
		switch(cmd) 
		{ 
			case 1:
				GenerateKeys();
				break; 
			case 2:
				RSA_Encrypt();
				break;
			case 3:
				RSA_Decrypt();
				break;
			case 0:
				return 0;
 			default:
				printf("ERROR: Unrecognized command.\n");
				break;
		}
	}	
	dlclose(libm_handle);
	
	return 0;
}