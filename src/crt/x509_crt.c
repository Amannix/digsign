/*
 *  X.509 certificate parsing and verification
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "../../include/crt/x509_crt.h"
#include "../../include/crt/pem.h"

#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( ret );
    }

    end = *p + len;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_VERSION +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates( unsigned char **p,
                           const unsigned char *end,
                           mbedtls_x509_time *from,
                           mbedtls_x509_time *to )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    end = *p + len;

    if( ( ret = mbedtls_x509_get_time( p, end, from ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_x509_get_time( p, end, to ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
//static int x509_get_uid( unsigned char **p,
//                         const unsigned char *end,
//                         mbedtls_x509_buf *uid, int n )
//{
//    int ret;
//
//    if( *p == end )
//        return( 0 );
//
//    uid->tag = **p;
//
//    if( ( ret = mbedtls_asn1_get_tag( p, end, &uid->len,
//            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | n ) ) != 0 )
//    {
//        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
//            return( 0 );
//
//        return( ret );
//    }
//
//    uid->p = *p;
//    *p += uid->len;
//
//    return( 0 );
//}

//static int x509_get_basic_constraints( unsigned char **p,
//                                       const unsigned char *end,
//                                       int *ca_istrue,
//                                       int *max_pathlen )
//{
//    int ret;
//    size_t len;
//
//    /*
//     * BasicConstraints ::= SEQUENCE {
//     *      cA                      BOOLEAN DEFAULT FALSE,
//     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
//     */
//    *ca_istrue = 0; /* DEFAULT FALSE */
//    *max_pathlen = 0; /* endless */
//
//    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
//            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    if( *p == end )
//        return( 0 );
//
//    if( ( ret = mbedtls_asn1_get_bool( p, end, ca_istrue ) ) != 0 )
//    {
//        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
//            ret = mbedtls_asn1_get_int( p, end, ca_istrue );
//
//        if( ret != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//       if( *ca_istrue != 0 )
//            *ca_istrue = 1;
//    }
//
//    if( *p == end )
//        return( 0 );
//
//    if( ( ret = mbedtls_asn1_get_int( p, end, max_pathlen ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    if( *p != end )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//
//    (*max_pathlen)++;
//
//    return( 0 );
//}

//static int x509_get_ns_cert_type( unsigned char **p,
//                                       const unsigned char *end,
//                                       unsigned char *ns_cert_type)
//{
//    int ret;
//    mbedtls_x509_bitstring bs = { 0, 0, NULL };
//
//    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    if( bs.len != 1 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_INVALID_LENGTH );
//
//    /* Get actual bitstring */
//    *ns_cert_type = *bs.p;
//    return( 0 );
//}

//static int x509_get_key_usage( unsigned char **p,
//                               const unsigned char *end,
//                               unsigned int *key_usage)
//{
//    int ret;
//    size_t i;
//    mbedtls_x509_bitstring bs = { 0, 0, NULL };
//
//    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    if( bs.len < 1 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_INVALID_LENGTH );
//
//    /* Get actual bitstring */
//    *key_usage = 0;
//    for( i = 0; i < bs.len && i < sizeof( unsigned int ); i++ )
//    {
//        *key_usage |= (unsigned int) bs.p[i] << (8*i);
//    }
//
//    return( 0 );
//}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
//static int x509_get_ext_key_usage( unsigned char **p,
//                               const unsigned char *end,
//                               mbedtls_x509_sequence *ext_key_usage)
//{
//    int ret;
//
//    if( ( ret = mbedtls_asn1_get_sequence_of( p, end, ext_key_usage, MBEDTLS_ASN1_OID ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    /* Sequence length must be >= 1 */
//    if( ext_key_usage->buf.p == NULL )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_INVALID_LENGTH );
//
//    return( 0 );
//}

/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 *
 * NOTE: we only parse and use dNSName at this point.
 */
//static int x509_get_subject_alt_name( unsigned char **p,
//                                      const unsigned char *end,
//                                      mbedtls_x509_sequence *subject_alt_name )
//{
//    int ret;
//    size_t len, tag_len;
//    mbedtls_asn1_buf *buf;
//    unsigned char tag;
//    mbedtls_asn1_sequence *cur = subject_alt_name;
//
//    /* Get main sequence tag */
//    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
//            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//    if( *p + len != end )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//
//    while( *p < end )
//    {
//        if( ( end - *p ) < 1 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                    MBEDTLS_ERR_ASN1_OUT_OF_DATA );
//
//        tag = **p;
//        (*p)++;
//        if( ( ret = mbedtls_asn1_get_len( p, end, &tag_len ) ) != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//        if( ( tag & MBEDTLS_ASN1_TAG_CLASS_MASK ) !=
//                MBEDTLS_ASN1_CONTEXT_SPECIFIC )
//        {
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
//        }
//
//        /* Skip everything but DNS name */
//        if( tag != ( MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2 ) )
//        {
//            *p += tag_len;
//            continue;
//        }
//
//        /* Allocate and assign next pointer */
//        if( cur->buf.p != NULL )
//        {
//            if( cur->next != NULL )
//                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );
//
//            cur->next = mbedtls_calloc( 1, sizeof( mbedtls_asn1_sequence ) );
//
//            if( cur->next == NULL )
//                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                        MBEDTLS_ERR_ASN1_ALLOC_FAILED );
//
//            cur = cur->next;
//        }
//
//        buf = &(cur->buf);
//        buf->tag = tag;
//        buf->p = *p;
//        buf->len = tag_len;
//        *p += buf->len;
//    }
//
//    /* Set final sequence entry's next pointer to NULL */
//    cur->next = NULL;
//
//    if( *p != end )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//
//    return( 0 );
//}

/*
 * X.509 v3 extensions
 *
 */
//static int x509_get_crt_ext( unsigned char **p,
//                             const unsigned char *end,
//                             mbedtls_x509_crt *crt )
//{
//    int ret;
//    size_t len;
//    unsigned char *end_ext_data, *end_ext_octet;
//
//    if( ( ret = mbedtls_x509_get_ext( p, end, &crt->v3_ext, 3 ) ) != 0 )
//    {
//        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
//            return( 0 );
//
//        return( ret );
//    }
//
//    while( *p < end )
//    {
//        /*
//         * Extension  ::=  SEQUENCE  {
//         *      extnID      OBJECT IDENTIFIER,
//         *      critical    BOOLEAN DEFAULT FALSE,
//         *      extnValue   OCTET STRING  }
//         */
//        mbedtls_x509_buf extn_oid = {0, 0, NULL};
//        int is_critical = 0; /* DEFAULT FALSE */
//        int ext_type = 0;
//
//        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
//                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//        end_ext_data = *p + len;
//
//        /* Get extension ID */
//        extn_oid.tag = **p;
//
//        if( ( ret = mbedtls_asn1_get_tag( p, end, &extn_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//        extn_oid.p = *p;
//        *p += extn_oid.len;
//
//        if( ( end - *p ) < 1 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                    MBEDTLS_ERR_ASN1_OUT_OF_DATA );
//
//        /* Get optional critical */
//        if( ( ret = mbedtls_asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
//            ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//        /* Data should be octet string type */
//        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
//                MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );
//
//        end_ext_octet = *p + len;
//
//        if( end_ext_octet != end_ext_data )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//
//        /*
//         * Detect supported extensions
//         */
//        ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type );
//
//        if( ret != 0 )
//        {
//            /* No parser found, skip extension */
//            *p = end_ext_octet;
//
//#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
//            if( is_critical )
//            {
//                /* Data is marked as critical: fail */
//                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                        MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
//            }
//#endif
//            continue;
//        }
//
//        /* Forbid repeated extensions */
//        if( ( crt->ext_types & ext_type ) != 0 )
//            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );
//
//        crt->ext_types |= ext_type;
//
//        switch( ext_type )
//        {
//        case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
//            /* Parse basic constraints */
//            if( ( ret = x509_get_basic_constraints( p, end_ext_octet,
//                    &crt->ca_istrue, &crt->max_pathlen ) ) != 0 )
//                return( ret );
//            break;
//
//        case MBEDTLS_X509_EXT_KEY_USAGE:
//            /* Parse key usage */
//            if( ( ret = x509_get_key_usage( p, end_ext_octet,
//                    &crt->key_usage ) ) != 0 )
//                return( ret );
//            break;
//
//        case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
//            /* Parse extended key usage */
//            if( ( ret = x509_get_ext_key_usage( p, end_ext_octet,
//                    &crt->ext_key_usage ) ) != 0 )
//                return( ret );
//            break;
//
//        case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
//            /* Parse subject alt name */
//            if( ( ret = x509_get_subject_alt_name( p, end_ext_octet,
//                    &crt->subject_alt_names ) ) != 0 )
//                return( ret );
//            break;
//
//        case MBEDTLS_X509_EXT_NS_CERT_TYPE:
//            /* Parse netscape certificate type */
//            if( ( ret = x509_get_ns_cert_type( p, end_ext_octet,
//                    &crt->ns_cert_type ) ) != 0 )
//                return( ret );
//            break;
//
//        default:
//            return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );
//        }
//    }
//
//    if( *p != end )
//        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//
//    return( 0 );
//}

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params )
{
    int ret;
    mbedtls_asn1_buf alg_oid;

    memset( params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_ALG + ret );

//    if( mbedtls_oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
//        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    /*
     * No parameters with RSA (only for EC)
     */
//    if( *pk_alg == MBEDTLS_PK_RSA &&
//            ( ( params->tag != MBEDTLS_ASN1_NULL && params->tag != 0 ) ||
//                params->len != 0 ) )
//    {
//        return( MBEDTLS_ERR_PK_INVALID_ALG );
//    }

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int mbedtls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedtls_pk_context *pk )
{
    int ret;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
//    const mbedtls_pk_info_t *pk_info;
	mbedtls_asn1_bitstring bs;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

//    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
//        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( ( ret = mbedtls_asn1_get_bitstring( p, end, &bs) ) != 0 ){
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );
    }

	/* here, we get the public key */
	pk->pk_len = bs.len;
	pk->pk_ctx = bs.p;

//    if( *p + len != end )
//        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

//    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
//        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

//    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
//        return( ret );

//#if defined(MBEDTLS_RSA_C)
//    if( pk_alg == MBEDTLS_PK_RSA )
//    {
//        ret = pk_get_rsapubkey( p, end, mbedtls_pk_rsa( *pk ) );
//    } else
//#endif /* MBEDTLS_RSA_C */

//#if defined(MBEDTLS_ECP_C)
//    if( pk_alg == MBEDTLS_PK_ECKEY_DH || pk_alg == MBEDTLS_PK_ECKEY )
//    {
//        ret = pk_use_ecparams( &alg_params, &mbedtls_pk_ec( *pk )->grp );
//        if( ret == 0 )
//            ret = pk_get_ecpubkey( p, end, mbedtls_pk_ec( *pk ) );
//    } else
//#endif /* MBEDTLS_ECP_C */

//        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

//    if( ret == 0 && *p != end )
//        ret = MBEDTLS_ERR_PK_INVALID_PUBKEY
//              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

//    if( ret != 0 )
//        mbedtls_pk_free( pk );

    return( ret );
}


/*
 * Parse and fill a single X.509 certificate in DER format
 */
static int x509_crt_parse_der_core( mbedtls_x509_crt *crt, const unsigned char *buf,
                                    size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end, *crt_end;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;

    memset( &sig_params1, 0, sizeof( mbedtls_x509_buf ) );
    memset( &sig_params2, 0, sizeof( mbedtls_x509_buf ) );
    memset( &sig_oid2, 0, sizeof( mbedtls_x509_buf ) );

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    // Use the original buffer until we figure out actual length
    p = (unsigned char*) buf;
    len = buflen;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len > (size_t) ( end - p ) )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }
    crt_end = p + len;

    // Create and populate a new buffer for the raw field
    crt->raw.len = crt_end - buf;
    crt->raw.p = p = mbedtls_calloc( 1, crt->raw.len );
    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    memcpy( p, buf, crt->raw.len );

    // Direct pointers to the new buffer 
    p += crt->raw.len - len;
    end = crt_end = p + len;

    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_get_version(  &p, end, &crt->version  ) ) != 0 ||
        ( ret = mbedtls_x509_get_serial(   &p, end, &crt->serial   ) ) != 0 ||
        ( ret = mbedtls_x509_get_alg(      &p, end, &crt->sig_oid,
                                            &sig_params1 ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( ret );
    }

    if( crt->version < 0 || crt->version > 2 )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    crt->version++;

//    if( ( ret = mbedtls_x509_get_sig_alg( &crt->sig_oid, &sig_params1,
//                                  &crt->sig_md, &crt->sig_pk,
//                                  &crt->sig_opts ) ) != 0 )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( ret );
//    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &crt->issuer ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( ret );
    }

    crt->issuer_raw.len = p - crt->issuer_raw.p;

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if( ( ret = x509_get_dates( &p, end, &crt->valid_from,
                                         &crt->valid_to ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( ret );
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( len && ( ret = mbedtls_x509_get_name( &p, p + len, &crt->subject ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( ret );
    }

    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo
     */
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &crt->pk ) ) != 0 )
    {
        mbedtls_x509_crt_free( crt );
        return( ret );
    }

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
//    if( crt->version == 2 || crt->version == 3 )
//    {
//        ret = x509_get_uid( &p, end, &crt->issuer_id,  1 );
//        if( ret != 0 )
//        {
//            mbedtls_x509_crt_free( crt );
//            return( ret );
//        }
//    }

//    if( crt->version == 2 || crt->version == 3 )
//    {
//        ret = x509_get_uid( &p, end, &crt->subject_id,  2 );
//        if( ret != 0 )
//        {
//            mbedtls_x509_crt_free( crt );
//            return( ret );
//        }
//    }

//#if !defined(MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3)
//    if( crt->version == 3 )
//#endif
//    {
//        ret = x509_get_crt_ext( &p, end, crt );
//        if( ret != 0 )
//        {
//            mbedtls_x509_crt_free( crt );
//            return( ret );
//        }
//    }
//
//    if( p != end )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//    }
//
//    end = crt_end;
//
//    /*
//     *  }
//     *  -- end of TBSCertificate
//     *
//     *  signatureAlgorithm   AlgorithmIdentifier,
//     *  signatureValue       BIT STRING
//     */
//    if( ( ret = mbedtls_x509_get_alg( &p, end, &sig_oid2, &sig_params2 ) ) != 0 )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( ret );
//    }
//
//    if( crt->sig_oid.len != sig_oid2.len ||
//        memcmp( crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len ) != 0 ||
//        sig_params1.len != sig_params2.len ||
//        ( sig_params1.len != 0 &&
//          memcmp( sig_params1.p, sig_params2.p, sig_params1.len ) != 0 ) )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( MBEDTLS_ERR_X509_SIG_MISMATCH );
//    }
//
//    if( ( ret = mbedtls_x509_get_sig( &p, end, &crt->sig ) ) != 0 )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( ret );
//    }
//
//    if( p != end )
//    {
//        mbedtls_x509_crt_free( crt );
//        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
//                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
//    }

    return( 0 );
}

/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
int mbedtls_x509_crt_parse_der( mbedtls_x509_crt *chain, const unsigned char *buf,
                        size_t buflen )
{
    int ret;
    mbedtls_x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    while( crt->version != 0 && crt->next != NULL )
    {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if( crt->version != 0 && crt->next == NULL )
    {
        crt->next = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) );

        if( crt->next == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );

        prev = crt;
        mbedtls_x509_crt_init( crt->next );
        crt = crt->next;
    }

    if( ( ret = x509_crt_parse_der_core( crt, buf, buflen ) ) != 0 )
    {
        if( prev )
            prev->next = NULL;

        if( crt != chain )
            mbedtls_free( crt );

        return( ret );
    }

    return( 0 );
}

/*
 * Parse one or more PEM certificates from a buffer and add them to the chained
 * list
 */
int mbedtls_x509_crt_parse( mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen )
{
    int success = 0, first_error = 0, total_failed = 0;
    int buf_format = MBEDTLS_X509_FORMAT_DER;

    /*
     * Check for valid input
     */
    if( chain == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    /*
     * Determine buffer content. Buffer contains either one DER certificate or
     * one or more PEM certificates.
     */
    if( buflen != 0 && buf[buflen - 1] == '\0' &&
        strstr( (const char *) buf, "-----BEGIN CERTIFICATE-----" ) != NULL ) {
        buf_format = MBEDTLS_X509_FORMAT_PEM;
    }

    if( buf_format == MBEDTLS_X509_FORMAT_DER )
        return mbedtls_x509_crt_parse_der( chain, buf, buflen );

    if( buf_format == MBEDTLS_X509_FORMAT_PEM ) {
        int ret;
        mbedtls_pem_context pem;

        /* 1 rather than 0 since the terminating NULL byte is counted in */
        while( buflen > 1 ) {
            size_t use_len;
            mbedtls_pem_init( &pem );

            /* If we get there, we know the string is null-terminated */
            ret = mbedtls_pem_read_buffer( &pem,
                           "-----BEGIN CERTIFICATE-----",
                           "-----END CERTIFICATE-----",
                           buf, NULL, 0, &use_len );

            if( ret == 0 ) {
                /*
                 * Was PEM encoded
                 */
                buflen -= use_len;
                buf += use_len;
            } else if( ret == MBEDTLS_ERR_PEM_BAD_INPUT_DATA ) {
                return( ret );
            } else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT ) {
                mbedtls_pem_free( &pem );

                /*
                 * PEM header and footer were found
                 */
                buflen -= use_len;
                buf += use_len;

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            } else
                break;

            ret = mbedtls_x509_crt_parse_der( chain, pem.buf, pem.buflen );

            mbedtls_pem_free( &pem );

            if( ret != 0 ) {
                /*
                 * Quit parsing on a memory error
                 */
                if( ret == MBEDTLS_ERR_X509_ALLOC_FAILED ) {
                    return( ret );
				}

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }

            success = 1;
        }
    }

    if( success ) 
        return( total_failed );
    else if( first_error ) 
        return( first_error );
    else 
        return( MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT );
}

/*
 * Initialize a certificate chain
 */
void mbedtls_x509_crt_init( mbedtls_x509_crt *crt )
{
    memset( crt, 0, sizeof(mbedtls_x509_crt) );
}

/*
 * Unallocate all certificate data
 */
void mbedtls_x509_crt_free( mbedtls_x509_crt *crt )
{
    mbedtls_x509_crt *cert_cur = crt;
    mbedtls_x509_crt *cert_prv;
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;
    mbedtls_x509_sequence *seq_cur;
    mbedtls_x509_sequence *seq_prv;

    if( crt == NULL )
        return;

    do
    {
        //mbedtls_pk_free( &cert_cur->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free( cert_cur->sig_opts );
#endif

        name_cur = cert_cur->issuer.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            mbedtls_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
            mbedtls_free( name_prv );
        }

        name_cur = cert_cur->subject.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            mbedtls_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
            mbedtls_free( name_prv );
        }

        seq_cur = cert_cur->ext_key_usage.next;
        while( seq_cur != NULL )
        {
            seq_prv = seq_cur;
            seq_cur = seq_cur->next;
            mbedtls_zeroize( seq_prv, sizeof( mbedtls_x509_sequence ) );
            mbedtls_free( seq_prv );
        }

        seq_cur = cert_cur->subject_alt_names.next;
        while( seq_cur != NULL )
        {
            seq_prv = seq_cur;
            seq_cur = seq_cur->next;
            mbedtls_zeroize( seq_prv, sizeof( mbedtls_x509_sequence ) );
            mbedtls_free( seq_prv );
        }

        if( cert_cur->raw.p != NULL )
        {
            mbedtls_zeroize( cert_cur->raw.p, cert_cur->raw.len );
            mbedtls_free( cert_cur->raw.p );
        }

        cert_cur = cert_cur->next;
    }
    while( cert_cur != NULL );

    cert_cur = crt;
    do
    {
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        mbedtls_zeroize( cert_prv, sizeof( mbedtls_x509_crt ) );
        if( cert_prv != crt )
            mbedtls_free( cert_prv );
    }
    while( cert_cur != NULL );
}