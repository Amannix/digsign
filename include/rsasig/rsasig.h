
#ifndef _RSASIG_H
#define _RSASIG_H

//#include <../openssl/rsa.h>
int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public);
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
void printLastError(char *msg);

#endif