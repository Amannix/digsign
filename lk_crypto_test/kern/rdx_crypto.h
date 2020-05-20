/*
 * rdx_crypto.h
 *
 *  Created on: 30 may 2018.
 *      Author: alekseym
 */

#ifndef RDX_CRYPTO_H_
#define RDX_CRYPTO_H_

#define RDX_ENCRYPT 1
#define RDX_DECRYPT 0

#define RDX_RSA_SIGN 1
#define RDX_RSA_VERIFY 0

int rdx_akcrypto_sign_ver(void *input, int len, void *output, int phase);
int rdx_sign_test(void);
int rdx_crypto_test(void);
int rdx_aes_test(void);

#endif /* RDX_CRYPTO_H_ */
