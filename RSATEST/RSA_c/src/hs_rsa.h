
#ifndef __HS_RSA_H__
#define __HS_RSA_H__	

#ifdef __cplusplus
extern "C" {
#endif
	
	/*Base64编码*/
	int Base64Encode_rsa(const char *encoded, int encodedLength, char *decoded)
	{
		return EVP_EncodeBlock((unsigned char*)decoded, (const unsigned char*)encoded, encodedLength);
	}


	/*Base64解码*/
	int Base64Decode_rsa(const char *encoded, int encodedLength, char *decoded)   
	{      
		return EVP_DecodeBlock((unsigned char*)decoded, (const unsigned char*)encoded, encodedLength); 
	}   


	/*生成RSA密钥对*/
	int Generate_RSA_Keys(const int g_nBits,char *privkey,char *pubkey);


	/*公钥加密*/
	int PublicEncrypt(char *pubkey,char *in_plain,char *cipher);


	/*私钥解密*/
	int PrivateDecrypt(char *privkey,char *cipher,char *out_plain);

#ifdef __cplusplus
}
#endif

#endif /*__HS_RSA_H__*/
