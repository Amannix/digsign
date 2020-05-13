#ifndef _HS_RSA_TOOLS_H
#define _HS_RSA_TOOLS_H

#ifdef __cplusplus
extern "C" {
#endif

	/*�Թ�Կ����PEM��ʽ��*/
	void PubKeyPEMFormat(char *pubkey);


	/*��˽Կ����PEM��ʽ��*/
	void PrivKeyPEMFormat(char *privkey);


	/*��������Ĺ�Կ���ȷ�����Ӧ�ļ��ܳ���*/
	int getEncryptLengthByPubKey(int pubKeyLen);
	
	
	/*���ݴ���˽Կ�ĳ��ȷ�����Ӧ���ĵ���ʵ����*/
	int getCipherRealLenByPriKey(int priKeyLen);
	
	
	/*���ݴ���˽Կ�ĳ��ȷ�����Ӧ���Ľ���Base64����ĳ���*/
	int getCipherLengthByPriKey(int priKeyLen);


	/*ͨ�����ܳ��Ȼ�ȡ���Ľ���Base64�����ĳ���*/
	int getBase64LenByEncryptLen(int cryLen);

#ifdef __cplusplus
}
#endif

#endif