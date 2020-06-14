#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "../../include/kcrt/base64.h"
#include "../../include/kstd/hexdump.h"
#include "../../include/kcrt/x509_crt.h"

/**
 * \brief          Get certificate's public key
 *
 * \param buffer   points to the certificate buffer
 * \param len      size of the certificate buffer
 * \param pkey     save the public key
 * \param pkeylen  sae the size of the public key
 */
int x509_crt_get_id_pubkey(const unsigned char *buf, size_t buflen, 
	unsigned char *pkey, unsigned int *pkeylen, unsigned char *id, unsigned int *idlen)
{
	mbedtls_x509_crt cert;
	int ret;

	mbedtls_x509_crt_init(&cert);

	/* parse certificate derectly */
	ret = mbedtls_x509_crt_parse(&cert, buf, buflen);
    if(ret != 0) {
        goto exit;
    }

	if (pkey && pkeylen) {
		*pkeylen = cert.pk.pk_len - 1;
		memcpy(pkey, (unsigned char *)(cert.pk.pk_ctx + 1), cert.pk.pk_len);
	}

	if (id && idlen) {
		*idlen = cert.serial.len;
		memcpy(id, cert.serial.p, cert.serial.len);
	}

exit:
	mbedtls_x509_crt_free(&cert);
	return ret;
}