
#ifndef __HS_RSA_H__
#define __HS_RSA_H__	

#ifdef __cplusplus
extern "C" {
#endif
	
	/*Base64����*/
	int Base64Encode_rsa(const char *encoded, int encodedLength, char *decoded)
	{
		return EVP_EncodeBlock((unsigned char*)decoded, (const unsigned char*)encoded, encodedLength);
	}


	/*Base64����*/
	int Base64Decode_rsa(const char *encoded, int encodedLength, char *decoded)   
	{      
		return EVP_DecodeBlock((unsigned char*)decoded, (const unsigned char*)encoded, encodedLength); 
	}   


	/*����RSA��Կ��*/
	int Generate_RSA_Keys(const int g_nBits,char *privkey,char *pubkey);


	/*��Կ����*/
	int PublicEncrypt(char *pubkey,char *in_plain,char *cipher);


	/*˽Կ����*/
	int PrivateDecrypt(char *privkey,char *cipher,char *out_plain);

#ifdef __cplusplus
}
#endif

#endif /*__HS_RSA_H__*/
