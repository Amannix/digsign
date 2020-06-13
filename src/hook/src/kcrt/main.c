#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"
#include "hexdump.h"

#include "x509_crt.h"

const static unsigned char asciiArray[] = 
"MIIDajCCAw+gAwIBAgIFQFOTAVIwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJD\r\n"
"TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y\r\n"
"aXR5MRswGQYDVQQDDBJDRkNBIEFDUyBTTTIgT0NBMzEwHhcNMTcwOTI2MDMwMjQ5\r\n"
"WhcNMjIwOTI2MDMwMjQ5WjCBnjELMAkGA1UEBhMCQ04xGzAZBgNVBAoMEkNGQ0Eg\r\n"
"QUNTIFNNMiBPQ0EzMTETMBEGA1UECwwKQ0ZDQSBPQ0EzMTEZMBcGA1UECwwQT3Jn\r\n"
"YW5pemF0aW9uYWwtMTFCMEAGA1UEAww5Q0ZDQUDkuK3lm73pk7bogZTogqHku73m\r\n"
"nInpmZDlhazlj7hATjkxMzEwMDAwNzM2MjM5ODkwVEAyMFkwEwYHKoZIzj0CAQYI\r\n"
"KoEcz1UBgi0DQgAEtAxvCszUS7/qsr2Kit7mYuu+VCTYYrKzkm+tRhvEbcdC3tfb\r\n"
"p8F3ORoSvFo3UcJkcXX2FOLK0OOFd/Kg473IbKOCAXcwggFzMGwGCCsGAQUFBwEB\r\n"
"BGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL29jc3AuY2ZjYS5jb20uY24vb2NzcDAy\r\n"
"BggrBgEFBQcwAoYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9vY2EzMS9vY2EzMS5j\r\n"
"ZXIwHwYDVR0jBBgwFoAUCNjRJsRIfZzsrJjp8X9iuYDOqUUwSAYDVR0gBEEwPzA9\r\n"
"BghggRyG7yoBBDAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNu\r\n"
"L3VzL3VzLTE0Lmh0bTAMBgNVHRMBAf8EAjAAMDwGA1UdHwQ1MDMwMaAvoC2GK2h0\r\n"
"dHA6Ly9jcmwuY2ZjYS5jb20uY24vb2NhMzEvU00yL2NybDE5NS5jcmwwDgYDVR0P\r\n"
"AQH/BAQDAgbAMB0GA1UdDgQWBBSYvL1Xk7Fs3XC8leIoDzWdHc+AkjAdBgNVHSUE\r\n"
"FjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANHADBEAiBaOf+a\r\n"
"XPThEE/FQJVbFOXEUyIWhTum52OyCUOLbre9PAIgPyn5gVI/7KfFXDriIhoLqGCL\r\n"
"KL9hsAmybSLGS80/TQE=\r\n";


const static unsigned char pemArray[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDajCCAw+gAwIBAgIFQFOTAVIwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJD\r\n"
"TjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9y\r\n"
"aXR5MRswGQYDVQQDDBJDRkNBIEFDUyBTTTIgT0NBMzEwHhcNMTcwOTI2MDMwMjQ5\r\n"
"WhcNMjIwOTI2MDMwMjQ5WjCBnjELMAkGA1UEBhMCQ04xGzAZBgNVBAoMEkNGQ0Eg\r\n"
"QUNTIFNNMiBPQ0EzMTETMBEGA1UECwwKQ0ZDQSBPQ0EzMTEZMBcGA1UECwwQT3Jn\r\n"
"YW5pemF0aW9uYWwtMTFCMEAGA1UEAww5Q0ZDQUDkuK3lm73pk7bogZTogqHku73m\r\n"
"nInpmZDlhazlj7hATjkxMzEwMDAwNzM2MjM5ODkwVEAyMFkwEwYHKoZIzj0CAQYI\r\n"
"KoEcz1UBgi0DQgAEtAxvCszUS7/qsr2Kit7mYuu+VCTYYrKzkm+tRhvEbcdC3tfb\r\n"
"p8F3ORoSvFo3UcJkcXX2FOLK0OOFd/Kg473IbKOCAXcwggFzMGwGCCsGAQUFBwEB\r\n"
"BGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL29jc3AuY2ZjYS5jb20uY24vb2NzcDAy\r\n"
"BggrBgEFBQcwAoYmaHR0cDovL2NybC5jZmNhLmNvbS5jbi9vY2EzMS9vY2EzMS5j\r\n"
"ZXIwHwYDVR0jBBgwFoAUCNjRJsRIfZzsrJjp8X9iuYDOqUUwSAYDVR0gBEEwPzA9\r\n"
"BghggRyG7yoBBDAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNu\r\n"
"L3VzL3VzLTE0Lmh0bTAMBgNVHRMBAf8EAjAAMDwGA1UdHwQ1MDMwMaAvoC2GK2h0\r\n"
"dHA6Ly9jcmwuY2ZjYS5jb20uY24vb2NhMzEvU00yL2NybDE5NS5jcmwwDgYDVR0P\r\n"
"AQH/BAQDAgbAMB0GA1UdDgQWBBSYvL1Xk7Fs3XC8leIoDzWdHc+AkjAdBgNVHSUE\r\n"
"FjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANHADBEAiBaOf+a\r\n"
"XPThEE/FQJVbFOXEUyIWhTum52OyCUOLbre9PAIgPyn5gVI/7KfFXDriIhoLqGCL\r\n"
"KL9hsAmybSLGS80/TQE=\r\n"
"-----END CERTIFICATE-----\r\n";

/**
 * \brief          Get certificate's public key
 *
 * \param buffer   points to the certificate buffer
 * \param len      size of the certificate buffer
 * \param pkey     save the public key
 * \param pkeylen  sae the size of the public key
 */
static int x509_crt_get_id_pubkey(const unsigned char *buf, size_t buflen, 
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

int main(int arc, char *argv[])
{
	
    	const unsigned char *src;
	unsigned char buffer[2048] = {0};
	unsigned char key[128] = {0};
	unsigned int keylen = 0;

	unsigned char id[32] = {0};
	unsigned int idlen;
	
	size_t len;
	int ret;

	/* SM2 with SM3 certificate */
	src = asciiArray;
	len = 0;
	memset(buffer, 0x00, sizeof(buffer));
   	mbedtls_base64_decode(buffer, sizeof(buffer), &len, src, sizeof(asciiArray) - 1);
	printf("len = %lu\n", len);
	hexdump(buffer, len);
	printf("\n");

	ret = x509_crt_get_id_pubkey((const unsigned char *)buffer, len, key, &keylen, id, &idlen);
	if (!ret) {
		/* success */
		printf("[DER]Pubkey: %u\n", keylen);
		hexdump(key, keylen);
		printf("\n");

		printf("[DER]Serial: %u\n", idlen);
		hexdump(id, idlen);
		printf("\n");
	}

	idlen = 0;
	keylen = 0;
	memset(key, 0x00, sizeof(key));
	memset(id, 0x00, sizeof(id));
	ret = x509_crt_get_id_pubkey(pemArray, sizeof(pemArray), key, &keylen, id, &idlen);
	if (!ret) {
		/* success */
		printf("[PEM]Pubkey: %u\n", keylen);
		hexdump(key, keylen);
		printf("\n");

		printf("[PEM]Serial: %u\n", idlen);
		hexdump(id, idlen);
		printf("\n");
	}

	return ret;
}
