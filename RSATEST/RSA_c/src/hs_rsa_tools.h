#ifndef _HS_RSA_TOOLS_H
#define _HS_RSA_TOOLS_H

#ifdef __cplusplus
extern "C" {
#endif

	/*对公钥进行PEM格式化*/
	void PubKeyPEMFormat(char *pubkey);


	/*对私钥进行PEM格式化*/
	void PrivKeyPEMFormat(char *privkey);


	/*根据输入的公钥长度返回相应的加密长度*/
	int getEncryptLengthByPubKey(int pubKeyLen);
	
	
	/*根据传入私钥的长度返回相应密文的真实长度*/
	int getCipherRealLenByPriKey(int priKeyLen);
	
	
	/*根据传入私钥的长度返回相应密文进行Base64编码的长度*/
	int getCipherLengthByPriKey(int priKeyLen);


	/*通过加密长度获取密文进行Base64编码后的长度*/
	int getBase64LenByEncryptLen(int cryLen);

#ifdef __cplusplus
}
#endif

#endif