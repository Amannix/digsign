/*
 *  X.509 common functions for parsing and verification
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


#include <linux/string.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/stat.h>
#include <linux/dirent.h>

#include "../../include/kcrt/x509.h"
#include "../../include/kcrt/asn1.h"

#define mbedtls_free      kfree
#define mbedtls_calloc    kmalloc
#define mbedtls_printf    printk
#define mbedtls_snprintf  printk
#define mbedtls_time_t    time_t

#define CHECK(code) if( ( ret = code ) != 0 ){ return( ret ); }
#define CHECK_RANGE(min, max, val) if( val < min || val > max ){ return( ret ); }

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
int mbedtls_x509_get_serial( unsigned char **p, const unsigned char *end,
                     mbedtls_x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != ( MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_PRIMITIVE | 2 ) &&
        **p !=   MBEDTLS_ASN1_INTEGER )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_SERIAL + ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

/*
 * Parse an algorithm identifier with (optional) paramaters
 */
int mbedtls_x509_get_alg( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *alg, mbedtls_x509_buf *params )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_alg( p, end, alg, params ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_ALG + ret );

    return( 0 );
}

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_attr_type_value( unsigned char **p,
                                     const unsigned char *end,
                                     mbedtls_x509_name *cur )
{
    int ret;
    size_t len;
    mbedtls_x509_buf *oid;
    mbedtls_x509_buf *val;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_NAME + ret );

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_NAME +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &oid->len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_NAME + ret );

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_NAME +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != MBEDTLS_ASN1_BMP_STRING && **p != MBEDTLS_ASN1_UTF8_STRING      &&
        **p != MBEDTLS_ASN1_T61_STRING && **p != MBEDTLS_ASN1_PRINTABLE_STRING &&
        **p != MBEDTLS_ASN1_IA5_STRING && **p != MBEDTLS_ASN1_UNIVERSAL_STRING &&
        **p != MBEDTLS_ASN1_BIT_STRING )
        return( MBEDTLS_ERR_X509_INVALID_NAME +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &val->len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_NAME + ret );

    val->p = *p;
    *p += val->len;

    cur->next = NULL;

    return( 0 );
}

/*
 *  Name ::= CHOICE { -- only one possibility for now --
 *       rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * The data structure is optimized for the common case where each RDN has only
 * one element, which is represented as a list of AttributeTypeAndValue.
 * For the general case we still use a flat list, but we mark elements of the
 * same set so that they are "merged" together in the functions that consume
 * this list, eg mbedtls_x509_dn_gets().
 */
int mbedtls_x509_get_name( unsigned char **p, const unsigned char *end,
                   mbedtls_x509_name *cur )
{
    int ret;
    size_t set_len;
    const unsigned char *end_set;

    /* don't use recursion, we'd risk stack overflow if not optimized */
    while( 1 )
    {
        /*
         * parse SET
         */
        if( ( ret = mbedtls_asn1_get_tag( p, end, &set_len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_NAME + ret );

        end_set  = *p + set_len;

        while( 1 )
        {
            if( ( ret = x509_get_attr_type_value( p, end_set, cur ) ) != 0 )
                return( ret );

            if( *p == end_set )
                break;

            /* Mark this item as being no the only one in a set */
            cur->next_merged = 1;

            cur->next = mbedtls_calloc( sizeof( mbedtls_x509_name ), GFP_ATOMIC );

            if( cur->next == NULL )
                return( MBEDTLS_ERR_X509_ALLOC_FAILED );

            cur = cur->next;
        }

        /*
         * continue until end of SEQUENCE is reached
         */
        if( *p == end )
            return( 0 );

        cur->next = mbedtls_calloc(  sizeof( mbedtls_x509_name ), GFP_ATOMIC );

        if( cur->next == NULL )
            return( MBEDTLS_ERR_X509_ALLOC_FAILED );

        cur = cur->next;
    }
}

static int x509_parse_int( unsigned char **p, size_t n, int *res )
{
    *res = 0;

    for( ; n > 0; --n )
    {
        if( ( **p < '0') || ( **p > '9' ) )
            return ( MBEDTLS_ERR_X509_INVALID_DATE );

        *res *= 10;
        *res += ( *(*p)++ - '0' );
    }

    return( 0 );
}

static int x509_date_is_valid(const mbedtls_x509_time *t )
{
    int ret = MBEDTLS_ERR_X509_INVALID_DATE;
    int month_len;

    CHECK_RANGE( 0, 9999, t->year );
    CHECK_RANGE( 0, 23,   t->hour );
    CHECK_RANGE( 0, 59,   t->min  );
    CHECK_RANGE( 0, 59,   t->sec  );

    switch( t->mon )
    {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            month_len = 31;
            break;
        case 4: case 6: case 9: case 11:
            month_len = 30;
            break;
        case 2:
            if( ( !( t->year % 4 ) && t->year % 100 ) ||
                !( t->year % 400 ) )
                month_len = 29;
            else
                month_len = 28;
            break;
        default:
            return( ret );
    }
    CHECK_RANGE( 1, month_len, t->day );

    return( 0 );
}

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
static int x509_parse_time( unsigned char **p, size_t len, size_t yearlen,
                            mbedtls_x509_time *tm )
{
    int ret;

    /*
     * Minimum length is 10 or 12 depending on yearlen
     */
    if ( len < yearlen + 8 )
        return ( MBEDTLS_ERR_X509_INVALID_DATE );
    len -= yearlen + 8;

    /*
     * Parse year, month, day, hour, minute
     */
    CHECK( x509_parse_int( p, yearlen, &tm->year ) );
    if ( 2 == yearlen )
    {
        if ( tm->year < 50 )
            tm->year += 100;

        tm->year += 1900;
    }

    CHECK( x509_parse_int( p, 2, &tm->mon ) );
    CHECK( x509_parse_int( p, 2, &tm->day ) );
    CHECK( x509_parse_int( p, 2, &tm->hour ) );
    CHECK( x509_parse_int( p, 2, &tm->min ) );

    /*
     * Parse seconds if present
     */
    if ( len >= 2 )
    {
        CHECK( x509_parse_int( p, 2, &tm->sec ) );
        len -= 2;
    }
    else
        return ( MBEDTLS_ERR_X509_INVALID_DATE );

    /*
     * Parse trailing 'Z' if present
     */
    if ( 1 == len && 'Z' == **p )
    {
        (*p)++;
        len--;
    }

    /*
     * We should have parsed all characters at this point
     */
    if ( 0 != len )
        return ( MBEDTLS_ERR_X509_INVALID_DATE );

    CHECK( x509_date_is_valid( tm ) );

    return ( 0 );
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
int mbedtls_x509_get_time( unsigned char **p, const unsigned char *end,
                           mbedtls_x509_time *tm )
{
    int ret;
    size_t len, year_len;
    unsigned char tag;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if( tag == MBEDTLS_ASN1_UTC_TIME )
        year_len = 2;
    else if( tag == MBEDTLS_ASN1_GENERALIZED_TIME )
        year_len = 4;
    else
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;
    ret = mbedtls_asn1_get_len( p, end, &len );

    if( ret != 0 )
        return( MBEDTLS_ERR_X509_INVALID_DATE + ret );

    return x509_parse_time( p, len, year_len, tm );
}

int mbedtls_x509_get_sig( unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig )
{
    int ret;
    size_t len;
    int tag_type;

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag_type = **p;

    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE + ret );

    sig->tag = tag_type;
    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!)
 */
int mbedtls_x509_get_ext( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *ext, int tag )
{
    int ret;
    size_t len;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &ext->len,
            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag ) ) != 0 )
        return( ret );

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

    if( end != *p + len )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
