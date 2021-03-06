#ifndef _RSA_GENKEY_H
#define _RSA_GENKEY_H

int pubkey_pemtoder(char *pem, unsigned char **der);
int privkey_pemtoder(char *pem, unsigned char **der);
int Generate_RSA_Keys(const int g_nBits, char *pubkey , char *privkey);
void PubKeyPEMFormat(char *pubkey,int nPublicKeyLen);
void PrivKeyPEMFormat(char *privkey);
#endif