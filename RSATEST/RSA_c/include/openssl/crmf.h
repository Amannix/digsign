/*-
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CRMF (RFC 4211) implementation by M. Peylo, M. Viljanen, and D. von Oheimb.
 */

#ifndef OPENSSL_CRMF_H
# define OPENSSL_CRMF_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CRMF
#  include <openssl/opensslv.h>
#  include <openssl/safestack.h>
#  include <openssl/crmferr.h>
#  include <openssl/x509v3.h> /* for GENERAL_NAME etc. */

/* explicit #includes not strictly needed since implied by the above: */
#  include <openssl/types.h>
#  include <openssl/x509.h>

#  ifdef __cplusplus
extern "C" {
#  endif

#  define OSSL_CRMF_POPOPRIVKEY_THISMESSAGE          0
#  define OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE    1
#  define OSSL_CRMF_POPOPRIVKEY_DHMAC                2
#  define OSSL_CRMF_POPOPRIVKEY_AGREEMAC             3
#  define OSSL_CRMF_POPOPRIVKEY_ENCRYPTEDKEY         4

#  define OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT       0
#  define OSSL_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP  1

typedef struct ossl_crmf_encryptedvalue_st OSSL_CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_ENCRYPTEDVALUE)
typedef struct ossl_crmf_msg_st OSSL_CRMF_MSG;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_MSG)
DEFINE_STACK_OF(OSSL_CRMF_MSG)
typedef struct ossl_crmf_attributetypeandvalue_st OSSL_CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct ossl_crmf_pbmparameter_st OSSL_CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PBMPARAMETER)
typedef struct ossl_crmf_poposigningkey_st OSSL_CRMF_POPOSIGNINGKEY;
typedef struct ossl_crmf_certrequest_st OSSL_CRMF_CERTREQUEST;
typedef struct ossl_crmf_certid_st OSSL_CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTID)
DEFINE_STACK_OF(OSSL_CRMF_CERTID)

typedef struct ossl_crmf_pkipublicationinfo_st OSSL_CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PKIPUBLICATIONINFO)
typedef struct ossl_crmf_singlepubinfo_st OSSL_CRMF_SINGLEPUBINFO;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_SINGLEPUBINFO)
typedef struct ossl_crmf_certtemplate_st OSSL_CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTTEMPLATE)
typedef STACK_OF(OSSL_CRMF_MSG) OSSL_CRMF_MSGS;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_MSGS)

typedef struct ossl_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;

/* crmf_pbm.c */
OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(size_t slen, int owfnid,
                                           int itercnt, int macnid);
int OSSL_CRMF_pbm_new(const OSSL_CRMF_PBMPARAMETER *pbmp,
                      const unsigned char *msg, size_t msglen,
                      const unsigned char *sec, size_t seclen,
                      unsigned char **mac, size_t *maclen);

/* crmf_lib.c */
int OSSL_CRMF_MSG_set1_regCtrl_regToken(OSSL_CRMF_MSG *msg,
                                        const ASN1_UTF8STRING *tok);
int OSSL_CRMF_MSG_set1_regCtrl_authenticator(OSSL_CRMF_MSG *msg,
                                             const ASN1_UTF8STRING *auth);
int
OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(OSSL_CRMF_PKIPUBLICATIONINFO *pi,
                                                     OSSL_CRMF_SINGLEPUBINFO *spi);
#  define OSSL_CRMF_PUB_METHOD_DONTCARE 0
#  define OSSL_CRMF_PUB_METHOD_X500     1
#  define OSSL_CRMF_PUB_METHOD_WEB      2
#  define OSSL_CRMF_PUB_METHOD_LDAP     3
int OSSL_CRMF_MSG_set0_SinglePubInfo(OSSL_CRMF_SINGLEPUBINFO *spi,
                                     int method, GENERAL_NAME *nm);
#  define OSSL_CRMF_PUB_ACTION_DONTPUBLISH   0
#  define OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH 1
int OSSL_CRMF_MSG_set_PKIPublicationInfo_action(OSSL_CRMF_PKIPUBLICATIONINFO *pi,
                                                int action);
int OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(OSSL_CRMF_MSG *msg,
                                                  const OSSL_CRMF_PKIPUBLICATIONINFO *pi);
int OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(OSSL_CRMF_MSG *msg,
                                               const X509_PUBKEY *pubkey);
int OSSL_CRMF_MSG_set1_regCtrl_oldCertID(OSSL_CRMF_MSG *msg,
                                         const OSSL_CRMF_CERTID *cid);
OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial);

int OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(OSSL_CRMF_MSG *msg,
                                         const ASN1_UTF8STRING *utf8pairs);
int OSSL_CRMF_MSG_set1_regInfo_certReq(OSSL_CRMF_MSG *msg,
                                       const OSSL_CRMF_CERTREQUEST *cr);

int OSSL_CRMF_MSG_set_validity(OSSL_CRMF_MSG *crm, time_t from, time_t to);
int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid);
int OSSL_CRMF_MSG_get_certReqId(const OSSL_CRMF_MSG *crm);
int OSSL_CRMF_MSG_set0_extensions(OSSL_CRMF_MSG *crm, X509_EXTENSIONS *exts);

int OSSL_CRMF_MSG_push0_extension(OSSL_CRMF_MSG *crm, X509_EXTENSION *ext);
#  define OSSL_CRMF_POPO_NONE       -1
#  define OSSL_CRMF_POPO_RAVERIFIED 0
#  define OSSL_CRMF_POPO_SIGNATURE  1
#  define OSSL_CRMF_POPO_KEYENC     2
#  define OSSL_CRMF_POPO_KEYAGREE   3
int OSSL_CRMF_MSG_create_popo(OSSL_CRMF_MSG *crm, EVP_PKEY *pkey,
                              int dgst, int ppmtd);
int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs,
                               int rid, int acceptRAVerified);
OSSL_CRMF_CERTTEMPLATE *OSSL_CRMF_MSG_get0_tmpl(const OSSL_CRMF_MSG *crm);
ASN1_INTEGER
*OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(const OSSL_CRMF_CERTTEMPLATE *tmpl);
const X509_NAME
*OSSL_CRMF_CERTTEMPLATE_get0_issuer(const OSSL_CRMF_CERTTEMPLATE *tmpl);
const X509_NAME
*OSSL_CRMF_CERTID_get0_issuer(const OSSL_CRMF_CERTID *cid);
ASN1_INTEGER *OSSL_CRMF_CERTID_get0_serialNumber(const OSSL_CRMF_CERTID *cid);
int OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_CERTTEMPLATE *tmpl,
                                EVP_PKEY *pubkey,
                                const X509_NAME *subject,
                                const X509_NAME *issuer,
                                const ASN1_INTEGER *serial);
X509
*OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(const OSSL_CRMF_ENCRYPTEDVALUE *ecert,
                                       EVP_PKEY *pkey);

#  ifdef __cplusplus
}
#  endif
# endif /* !defined(OPENSSL_NO_CRMF) */
#endif /* !defined(OPENSSL_CRMF_H) */
