/*************************************************************************
	> File Name: sigtype.h
	> Author: xmb
	> Mail: 1785175681@qq.com 
	> Created Time: 2020年04月17日 星期五 00时58分56秒
 ************************************************************************/

#ifndef _SIGTYPE_H
#define _SIGTYPE_H

#define ELF_SIG_SH_NAME				".digsig"
#define ELF_SIG_SH_NAME_SIZE		(7)
#define ELF_SIG_SH_SIZE				(152)
#define ELF_SIG_SH_MD5_LEN          32
#define ELF_SIG_USER_ID				"1234567812345678"
#define ELF_SIG_USER_ID_LEN			16

#define ELF_SIG_SM2_G_COOR_LEN		64
#define ELF_SIG_SM2_PUBKEY_LEN		65

#define ELF_SIG_RSA_KEY_LEN         256
#define ELF_SIG_RSA_PUB_LEN_MAX     300
#define ELF_SIG_RSA_PRI_LEN_MAX     1300

#define ELF_SIG_SH_TAB_ADD_OFF (ELF_SIG_SH_NAME_SIZE+1)
#define ELF_SIG_SH_BUFF_SIZE (ELF_SIG_RSA_PUB_LEN_MAX + ELF_SIG_RSA_KEY_LEN)

#endif
