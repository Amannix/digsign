#ifndef _RSA_GENKEY_H
#define _RSA_GENKEY_H

int pubkey_pemtoder(unsigned char *pem, unsigned char **der);
int privkey_pemtoder(unsigned char *pem, unsigned char **der);
int Generate_RSA_Keys(const int g_nBits,unsigned char *pubkey ,unsigned char *privkey);
#endif