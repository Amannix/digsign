#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include "rdx_crypto.h"

static int __init rdx_init(void)
{
	pr_warn("Crypto test module init\n");
	pr_warn("Crypto test start...");
	rdx_crypto_test();
	pr_warn("Crypto test finish.");

	pr_warn("Sign test start...");
	rdx_sign_test();
	pr_warn("sign test finish.");

	/*pr_warn("AES test start...");
	rdx_aes_test();
	pr_warn("AES test finish.");*/

	return 0;
}

static void rdx_exit(void)
{
	pr_warn("crypto test module exit\n");
}

module_init(rdx_init);
module_exit(rdx_exit);

MODULE_AUTHOR("AM");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Test Linux Kernel crypto api. commit: " GIT_COMMIT);
