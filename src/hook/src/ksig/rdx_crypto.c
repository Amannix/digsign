
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <crypto/akcipher.h>
#include <crypto/skcipher.h>
#include <linux/random.h>

#include "../../include/ksig/rdx_crypto.h"
#include "../../include/kstd/hexdump.h"

#define  KEY_LEN 256
unsigned  char *priv_key;

int priv_key_len = 1191;

unsigned char *pub_key = "\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xef\x1f\x6a\x7e\x3c\xcb\x9e\x85\x0b\x3d\xbe\x94\xec\x73\xd1\x1d\x7a\xf8\xc1\x07\x91\x81\x4d\x4b\x78\x9e\x02\x2e\x8c\x7a\xa7\x1e\x19\x84\x31\xdf\x68\xa3\x90\xfb\x5b\x01\xb0\x76\xb5\x54\x4d\x2a\x25\xe5\xb7\x7a\xfe\x97\x5c\x7f\xda\x86\xac\xf6\x71\x59\x33\xcc\x87\x80\x07\x80\xe6\xd1\xfc\xfe\x69\x9d\xa8\x14\x7a\x29\xac\xc6\xf1\xb5\x07\x43\xa6\x28\x36\x61\xe2\x94\xa3\x9a\x27\xa8\x15\x47\x32\xfa\x11\xc5\x1c\x7e\xfb\xd6\x2b\xbf\x27\x72\x2f\x2f\x1c\x4c\x12\x17\x9f\x2f\x51\x46\x3a\xa9\x37\xe8\x5b\x97\xbf\xc1\xf1\x6a\xb6\xf8\x15\x8b\x1a\x4a\x43\x37\x24\xf1\x69\xbd\x78\x8f\x54\x4e\x0a\x89\x70\x5d\xa5\xbd\x0f\x38\x70\x23\x00\x8e\x12\xb8\x9f\x96\xd0\xca\x2b\xbc\x31\xe0\x2f\x09\xc8\x89\x9c\x03\x53\xa0\xa1\x97\x0a\x2d\x62\x94\xe8\x66\x93\xee\x58\x42\x1f\x51\x53\x41\xf5\x4c\x28\xba\x58\xd3\xe0\xc1\x0c\xb2\x0a\xad\x7f\xd2\xa2\x5d\x9c\x15\xf1\x05\x38\x67\xc2\x8d\x97\x54\xd0\x7d\x2e\x04\x4c\x8c\x04\xe9\xcb\xe6\x86\x54\xa5\xdc\x6e\xab\xf4\x5e\x4c\xbe\x9c\x0c\xeb\x88\xad\x2d\xcf\xaa\xe5\x65\x6b\x52\x6c\xe9\xc8\x31\x41\xc9\x19\x6f\x02\x03\x01\x00\x01";

int pub_key_len = 270;

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
			void *input, int len, void *output, int phase, unsigned char *key, int key_len)
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
		err = crypto_akcipher_set_pub_key(tfm, key, key_len);
	} else {
		pr_debug("set priv key\n");
		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
		err = crypto_akcipher_set_priv_key(tfm, key, key_len);
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
		//hexdump(out_buf, out_len_max);
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

int rdx_akcrypto_sign_ver(void *input, int len, void *output, int phase, unsigned char *key, int key_len)
{
     struct crypto_akcipher *tfm;
     int err = 0;
     //pr_warn("start ver");
     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm_sv(tfm, input, len, output, phase, key, key_len);

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

/*
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
*/
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

