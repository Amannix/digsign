
#ifndef _CRTVER_H
#define _CRTVER_H

#include <linux/string.h>
int x509_crt_get_id_pubkey(const unsigned char *buf, size_t buflen, 
	unsigned char *pkey, unsigned int *pkeylen, unsigned char *id, unsigned int *idlen);

#endif