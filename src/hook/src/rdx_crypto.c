/*
 * rdx_crypto.c
 *
 *  Created on: 30 may 2018.
 *      Author: alekseym
 */
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <crypto/akcipher.h>
#include <crypto/skcipher.h>
#include <linux/random.h>

#include "../include/rdx_crypto.h"

#define  KEY_LEN 256
unsigned  char *priv_key = "\x30\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xd8\x0b\x41\xf9\x7a\x3a\xfc\xa8\x25\x0c\xa0\x41\x0d\x49\x9b\x96\xa8\x80\xa6\x75\x74\x85\xd0\x6c\x1d\x80\x8f\x24\x06\x54\x9a\xc8\x68\x18\x94\x54\x5c\xa2\x5e\x68\x47\x61\x69\x10\x06\x4e\x08\x36\x12\xc1\x6b\x72\x71\x53\xdc\xf4\x7c\x08\xee\x2c\x1c\x37\x79\xfa\xf3\xb5\x1a\xdc\x02\x83\xff\x90\xf8\x73\x02\x43\xec\xc8\xb0\x5f\x6e\xd0\xd1\xc8\x7a\x4c\x6f\x21\x51\x04\x7a\x8e\xc1\x6a\xb7\xfd\x4c\x45\x3b\xcf\xca\xb8\xa6\xb6\x84\x3f\xa4\x5e\xa1\xc2\x80\xc8\xba\x8b\x8c\x17\x82\xfc\x75\xb9\xcd\x4a\x11\x74\xac\xfb\x75\x96\x68\x12\x38\xcf\x15\xe7\x6c\xbf\x2b\x4a\x7f\x20\xce\x5a\x41\xe3\xd1\x0d\x37\x59\x4a\xed\xbc\x9f\xc2\xb1\x4d\x9e\x84\x0d\x50\xaf\xa6\x79\x74\x79\x34\x3e\xd9\x10\xf2\x80\x5b\x3d\x48\x65\x01\x75\xbe\xc4\x62\x6c\xf0\xdd\x62\x47\xbc\xd0\x3a\x1e\x6b\x64\x6b\x77\x26\xf5\x18\x8d\x43\x57\x30\x4c\x73\x46\xdd\xa2\x79\xd2\xbe\xd9\xec\x36\xa5\x59\x12\x3c\x59\x87\x55\x31\x51\x27\x46\x46\x2c\x64\x5d\xe2\xb4\xf4\x84\xcd\x50\x84\x49\xa4\x25\x57\x48\xd8\xf5\x50\xa3\x85\xec\x0d\x97\xdb\xaf\x3f\x64\xef\xef\xbf\x33\x24\xc7\x05\x02\x03\x01\x00\x01\x02\x82\x01\x00\x18\xaf\x30\x9a\x90\x9c\xac\xc1\x89\x7a\x27\xd5\x46\xef\x62\x17\x94\xa9\x1e\x5b\xcd\x34\x7c\xdb\xdd\x83\x12\xd7\xca\xe1\x5f\xce\x06\x16\xc8\xdb\xda\xb9\xb2\x8f\xb7\x98\x29\xa8\xeb\x0f\x7f\x60\xae\x43\xeb\x42\xe8\x2f\xec\xcf\x02\x5d\x02\xd9\x87\x5f\xcf\x50\x1d\x08\x54\x49\x4f\x00\x45\xf3\x0a\x70\x19\x92\x29\x3b\xc4\xeb\x22\x7e\x39\x79\xee\x7f\x4d\x33\x41\x4e\x81\xb2\x4d\xe7\x23\x9e\x8d\x58\x5b\xbd\x22\x2c\x76\xdf\xe3\xbc\x61\xcb\x6e\x30\x0b\x06\xe4\x49\x8d\x78\x22\x3f\x36\x34\x44\x80\x71\xfe\x22\xc5\x98\x69\xa1\x2d\x4f\xb9\x7b\x17\x52\x12\x03\x5f\x0a\xfa\xd3\xce\x9a\x65\x48\x8b\x5b\xba\x93\x1d\xd6\xd9\x91\xee\x3b\x9a\xd7\x68\x06\x06\x85\x8d\x00\xf6\x4d\x67\xb6\xfc\xb9\xcf\x7f\x1d\x1b\x59\x58\xdc\xa2\x88\x7f\xee\xbe\x86\x2b\x08\x67\xc2\x3f\x8f\xed\x5e\x59\x07\xbb\xc8\xac\x76\xda\x26\x09\x36\x7f\x00\x57\xf3\x5a\x91\xc2\xba\x59\xf6\x9e\x8a\x0b\xf0\xff\xf6\xbc\xc9\x38\xc3\x47\x24\x4d\xf9\x8b\xd6\xa5\x8c\xac\x95\x81\x58\x3d\x6e\x05\x3f\x1b\x65\x36\xf3\x7a\xe5\x13\x37\x9e\x1f\x63\x72\x8a\x01\x9f\x88\x5b\xa9\xb7\x01\x02\x81\x81\x00\xf6\x92\x32\xd2\x0a\x26\xe8\x71\x9a\x2f\x05\x55\xba\xd5\x58\xcb\x3f\x88\x04\xa6\x8a\xda\xc5\x43\xb9\xba\xef\xea\x8a\x4d\x76\x9d\x3d\x9a\xc9\x4b\xd3\xd8\x3c\x1f\x79\x5c\x8f\x5e\x24\x10\x0f\x2a\x11\xa8\x14\x3f\x2b\x89\xaf\xc0\x03\x7d\xfc\x55\xaa\xbc\xc1\xa7\x8a\x00\x05\x0e\x5c\x1c\x50\x84\x21\xaa\x48\xf9\xe0\xec\xf7\x3b\xf1\x6b\x39\x17\x90\xe0\x16\xd3\xab\x6c\x21\xeb\xe0\xe4\x4c\x18\x30\x1a\x50\x0d\x4d\xfa\xf8\x82\x98\x0a\x37\x7f\x76\x8c\xd0\xa4\xa8\x08\x3f\xea\x13\x9f\x92\xbd\x63\xbb\xbf\x36\x3a\x8f\x03\xf3\x02\x81\x81\x00\xe0\x4e\x36\xfc\xad\x17\x96\x95\x09\xf5\xc9\xdd\xb7\x4c\xa1\x4e\x13\x23\xaf\x36\x9e\x6b\x3d\xab\x99\x1b\x19\x90\x51\x2c\x3f\x51\x77\x84\xbc\x91\x88\xf2\x7f\x40\xc3\x1d\x79\x63\xb5\x11\x85\x3c\x84\x74\xd6\x22\xe2\x26\x84\x15\x4d\xbe\x4c\x7a\xa2\xa0\xe1\x65\xe0\x39\xb7\x9d\x4f\x44\x9a\xfa\x5c\xdd\x6f\xe1\xf2\x6e\x9f\xd1\x82\xf7\x70\x9b\xf3\x4e\xb9\xaf\x65\xf1\x4d\x6f\xe9\x7f\xc9\x65\x8d\x80\xb0\x46\xde\x21\xbb\x17\x9d\xb1\xe7\xec\x95\xfa\x8f\x0a\x8d\x3f\xec\xcc\x7f\x12\x7c\x2b\x1e\x0d\x92\xa7\xc4\x8c\x5f\x27\x02\x81\x80\x11\x95\xc7\xae\x17\x2f\x43\x30\xa6\xf0\x67\x8e\xff\xae\x2b\x91\x03\x4c\xee\x17\xfa\x9b\x33\xaa\x6a\xda\x9c\x35\xbb\xfb\x5e\x54\x44\x8a\x7f\x84\xba\xed\x17\x0c\x9f\x99\x2c\x58\x68\x76\x04\xbe\xd9\x57\x85\x6a\x23\xee\xc3\xec\x0b\xd3\xb6\x65\x5d\xb1\xec\x95\xc8\x4f\xcc\x0c\x84\x21\x38\xd4\xd3\x99\xd3\x6e\x8e\xce\x17\xab\xdc\xc1\xea\xe6\x75\x5c\xa6\x04\x1e\x9b\xad\xa7\xa6\xf8\x61\x3c\xf0\x61\x50\x08\x42\xe1\x7d\x4b\xc3\x10\x27\x79\x1d\xb9\x59\x40\x05\x03\xe1\x9b\x0e\x1f\x39\x55\xec\x80\xfd\x58\x1e\xc1\x08\x65\x02\x81\x80\x72\x98\x43\x0b\x70\x3b\x1e\xd9\x61\xcf\x4a\xa4\x95\x62\xf6\xfd\xf6\x55\x42\xcc\xba\xbe\xbb\x31\x11\xf5\x80\x67\xf4\xb0\x90\x60\xc4\x98\xf1\xe5\xc0\x7b\x73\x7b\xd8\xb3\x14\x33\x56\x6c\x6f\x0f\x6d\xf4\x6a\xfa\x43\x63\xbe\x13\x4c\x36\xae\xc7\xf0\x92\x14\xd5\x81\x6a\xbb\x5e\x09\x03\x59\xd2\x12\xe3\xa6\xa7\x5e\xbe\x19\xb4\x66\x1e\x98\x4f\x74\x4c\x82\x1d\x14\x0d\xe5\xac\x09\x35\x19\xe5\x62\x17\x9e\xf7\x75\xc0\xf1\xde\xac\xd8\x19\x4f\x0b\x88\x88\xcf\xb1\x3e\x39\x72\x78\x71\x2f\x32\xb0\x15\xeb\x18\xff\x17\x5f\xfd\x02\x81\x81\x00\xb9\xc3\xf7\x80\x90\x23\x68\xf2\x5b\x7f\xae\xc2\x98\x94\x6e\x16\xef\x18\x1d\x33\x88\xa0\xcc\x5d\x64\x6f\xc7\xaf\xe2\xa0\x2f\xa9\x82\x6a\xbb\xa6\xd3\x05\xe9\x09\xfb\xae\x5d\xfe\xbb\xc6\xb4\x89\xca\xef\xd9\x5b\xcd\x60\xb3\x40\xc3\x3e\xd0\x5e\xf9\xb8\x6e\x49\x7d\x35\x66\xaa\x48\x69\x59\xf2\x4c\xba\x14\xf5\x87\xc5\x96\xd6\xed\x90\x7b\x20\x10\xe3\x39\x3a\x6e\xc7\x51\xfe\x09\xd9\x63\x42\x68\x23\x1c\x20\x59\xba\x04\xfd\xb8\x86\x70\xc6\xa2\x61\x05\xe2\xcf\x5d\x4f\xfe\x08\xb3\x40\xec\x64\xf0\xb7\x0b\x5d\x29\x36\x7a";

int priv_key_len = 1191;

unsigned char *pub_key =   "\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xd8\x0b\x41\xf9\x7a\x3a\xfc\xa8\x25\x0c\xa0\x41\x0d\x49\x9b\x96\xa8\x80\xa6\x75\x74\x85\xd0\x6c\x1d\x80\x8f\x24\x06\x54\x9a\xc8\x68\x18\x94\x54\x5c\xa2\x5e\x68\x47\x61\x69\x10\x06\x4e\x08\x36\x12\xc1\x6b\x72\x71\x53\xdc\xf4\x7c\x08\xee\x2c\x1c\x37\x79\xfa\xf3\xb5\x1a\xdc\x02\x83\xff\x90\xf8\x73\x02\x43\xec\xc8\xb0\x5f\x6e\xd0\xd1\xc8\x7a\x4c\x6f\x21\x51\x04\x7a\x8e\xc1\x6a\xb7\xfd\x4c\x45\x3b\xcf\xca\xb8\xa6\xb6\x84\x3f\xa4\x5e\xa1\xc2\x80\xc8\xba\x8b\x8c\x17\x82\xfc\x75\xb9\xcd\x4a\x11\x74\xac\xfb\x75\x96\x68\x12\x38\xcf\x15\xe7\x6c\xbf\x2b\x4a\x7f\x20\xce\x5a\x41\xe3\xd1\x0d\x37\x59\x4a\xed\xbc\x9f\xc2\xb1\x4d\x9e\x84\x0d\x50\xaf\xa6\x79\x74\x79\x34\x3e\xd9\x10\xf2\x80\x5b\x3d\x48\x65\x01\x75\xbe\xc4\x62\x6c\xf0\xdd\x62\x47\xbc\xd0\x3a\x1e\x6b\x64\x6b\x77\x26\xf5\x18\x8d\x43\x57\x30\x4c\x73\x46\xdd\xa2\x79\xd2\xbe\xd9\xec\x36\xa5\x59\x12\x3c\x59\x87\x55\x31\x51\x27\x46\x46\x2c\x64\x5d\xe2\xb4\xf4\x84\xcd\x50\x84\x49\xa4\x25\x57\x48\xd8\xf5\x50\xa3\x85\xec\x0d\x97\xdb\xaf\x3f\x64\xef\xef\xbf\x33\x24\xc7\x05\x02\x03\x01\x00\x01";

int pub_key_len = 270;

static void hexdump(unsigned char *buf,unsigned int len)
{
	int i;

	for (i = 0; i < len; i++) {
		pr_warn(KERN_CONT "%02X", buf[i]);
	}
	pr_warn("\n");
}


static int __rdx_akcrypto_tfm(struct crypto_akcipher *tfm,
			void *input, int len, void *output, int phase)
{
	struct akcipher_request *req;
	void *out_buf = NULL;
//	struct tcrypt_result result;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;

	xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

//	init_completion(&result.completion);

	if (phase) {
		pr_warn("set pub key \n");
		err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
	} else {
		pr_warn("set priv key\n");
		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
		err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
	}

	if (err){
		printk("set key error! err: %d phase: %d\n", err,phase);
		goto free_req;
	}

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	pr_warn("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, len);
	sg_init_one(&dst, out_buf, out_len_max);
	akcipher_request_set_crypt(req, &src, &dst, len, out_len_max);
//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //encryption phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		err =  crypto_akcipher_encrypt(req);
		if (err) {
			pr_err("alg: akcipher: encrypt test failed. err %d\n",
					err);
			goto free_all;
		}
		pr_warn("after enc in out_buf:\n");
		hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
		//crypted_len = out_len_max;

	} else { //decryption phase
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err = crypto_akcipher_decrypt(req);
		if (err) {
			pr_err("alg: akcipher: decrypt test failed. err %d\n",err);
			goto free_all;
		}
		pr_warn("after decrypt in out_buf:\n");
		hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	}

free_all:
	kfree(out_buf);
free_req:
	akcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int rdx_akcrypto_enc_dec(void *input, int len, void *output, int phase)
{
     struct crypto_akcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm(tfm, input, len, output, phase);

     crypto_free_akcipher(tfm);
     return err;
}

static int __rdx_akcrypto_tfm_sv(struct crypto_akcipher *tfm,
			void *input, int len, void *output, int phase)
{
	struct akcipher_request *req;
	void *out_buf = NULL;
//	struct tcrypt_result result;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;

	xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

//	init_completion(&result.completion);

	if (!phase) {
		pr_debug("set pub key \n");
		err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
	} else {
		pr_debug("set priv key\n");
		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
		err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
	}

	if (err){
		pr_err("set key error! err: %d phase: %d\n", err, phase);
		goto free_req;
	}

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	pr_debug("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, len);
	sg_init_one(&dst, out_buf, out_len_max);
	akcipher_request_set_crypt(req, &src, &dst, len, out_len_max);
//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //sign phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		err =  crypto_akcipher_sign(req);
		if (err) {
			pr_err("alg: akcipher: sign failed. err %d\n", err);
			goto free_all;
		}
		pr_debug("after sign in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	} else { //verification phase
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err = crypto_akcipher_verify(req);
		if (err) {
			pr_err("alg: akcipher: verify failed. err %d\n",
					err);
			goto free_all;
		}
		pr_debug("after verify in out_buf:\n");
		hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	}

free_all:
	kfree(out_buf);
free_req:
	akcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int rdx_akcrypto_sign_ver(void *input, int len, void *output, int phase)
{
     struct crypto_akcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm_sv(tfm, input, len, output, phase);

     crypto_free_akcipher(tfm);
     return err;
}

#define AES_KEY_LEN 32
#define IV_LEN 16
unsigned char *aes_key =
		"\xF0\xC9\x3C\xEE\x09\x9E\xDE\x2E\xF7\x48\xB7\x62\xE3\xC6\x60\x4B"
		"\x24\x74\xAC\x0C\xEC\xF3\xAF\x95\x2E\x4D\x78\xDD\x45\xCC\x2D\xBF";
unsigned char *iv_data =
		"\x62\x06\xF3\x02\x20\xFE\x06\xED\xFD\x49\x08\x4D\x1C\x2C\x19\x38";

static int __rdx_akcrypto_tfm_aes(struct crypto_skcipher *tfm,
			void *input, int len, void *output, int phase)
{
	struct skcipher_request *req;
	void *out_buf = NULL;
//	struct tcrypt_result result;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;
	char *ivdata;

	xbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

//	init_completion(&result.completion);

//	if (!phase) {
//		pr_debug("set pub key \n");
//		err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
//	} else {
//		pr_debug("set priv key\n");
//		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
//		err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
//	}
	err = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_LEN);

	if (err){
		pr_err("set key error! err: %d phase: %d\n", err, phase);
		goto free_req;
	}

	/* IV will be random */
	ivdata = kzalloc(16, GFP_KERNEL);
	if (!ivdata) {
		pr_info("could not allocate ivdata\n");
		goto free_req;
	}
	memcpy(ivdata, iv_data, 16);//get_random_bytes(ivdata, 16);


	err = -ENOMEM;
	pr_debug("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, 16);
	sg_init_one(&dst, out_buf, 16);

	skcipher_request_set_crypt(req, &src, &dst, 16, ivdata);

//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //sign phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		pr_warn ("start enc\n");
		err =  crypto_skcipher_encrypt(req);
		if (err) {
			pr_err("skcipher: encrypt failed. err %d\n", err);
			goto free_all;
		}
		pr_debug("after encrypt in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, 16);
	} else { //verification phase
		pr_warn("dec start\n");
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err =  crypto_skcipher_decrypt(req);
		if (err) {
			pr_err("skcipher: decrypt failed. err %d\n",
					err);
			goto free_all;
		}
		pr_debug("after decrypt in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, 16);
	}

free_all:
	kfree(out_buf);
free_req:
	skcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int rdx_akcrypto_aes(void *input, int len, void *output, int phase)
{
     struct crypto_skcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: skcipher: Failed to load tfm for aes: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm_aes(tfm, input, len, output, phase);

     crypto_free_skcipher(tfm);
     return err;
}

char *msg = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
int msg_len = 8;

int rdx_crypto_test(void)
{
	int ret = 0;
	char *c, *m;
	c = kzalloc(KEY_LEN, GFP_KERNEL);
	m = kzalloc(KEY_LEN, GFP_KERNEL);

	pr_warn("initial msg :\n");
	hexdump(msg, msg_len);

	ret = rdx_akcrypto_enc_dec(msg, msg_len, c, RDX_ENCRYPT);
	if (ret) {
		pr_err ("Encryption error\n");
		goto err;
	}
	pr_warn("encrypted msg :\n");
	hexdump(c, KEY_LEN);
	ret = rdx_akcrypto_enc_dec(c, KEY_LEN, m, RDX_DECRYPT);
	if (ret) {
		pr_err ("Decryption error\n");
		goto err;
	}
	pr_warn("decrypted msg :\n");
	hexdump(m, KEY_LEN);
err:
	kfree(c);
	kfree(m);
	return ret;
}

int rdx_sign_test(void)
{
	int ret = 0;
	char *c, *m;
	c = kzalloc(KEY_LEN, GFP_KERNEL);
	m = kzalloc(KEY_LEN, GFP_KERNEL);

	pr_warn("initial msg :\n");
	hexdump(msg, msg_len);

	ret = rdx_akcrypto_sign_ver(msg, msg_len, c, RDX_RSA_SIGN);
	if (ret) {
		pr_err ("RSA sign error\n");
		goto err;
	}
	pr_warn("signed msg :\n");
	hexdump(c, KEY_LEN);
    memset(m, 0, KEY_LEN);
    ret = rdx_akcrypto_sign_ver(c, KEY_LEN, m, RDX_RSA_VERIFY);
	if (ret) {
		pr_err ("RSA verify error\n");
		goto err;
	}
	pr_warn("verified msg :\n");
	hexdump(m, KEY_LEN);
err:
	kfree(c);
	kfree(m);
	return ret;
}

int rdx_aes_test(void)
{
	int ret = 0;
	char *c, *m;
	c = kzalloc(IV_LEN, GFP_KERNEL);
	m = kzalloc(IV_LEN, GFP_KERNEL);

	pr_warn("initial msg :\n");
	hexdump(msg, msg_len);

	ret = rdx_akcrypto_aes(msg, msg_len, c, RDX_ENCRYPT);
	if (ret) {
		pr_err ("AES encrypt error\n");
		goto err;
	}
	pr_warn("encrypted msg :\n");
	hexdump(c, KEY_LEN);

	ret = rdx_akcrypto_aes(c, 16, m, RDX_DECRYPT);
	if (ret) {
		pr_err ("Decryption error \n");
		goto err;
	}
	pr_warn("decrypted msg :\n");
	hexdump(m, 16);
err:
	kfree(c);
	kfree(m);
	return ret;
}

