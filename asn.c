/* asn.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 */


#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "settings.h"

#include "asn.h"
#include "error.h"
#include <stdbool.h>
#include "sha256.h"

#ifdef CYASSL_DEBUG_ENCODING
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#define NOINLINE  __attribute__((noinline))
#define STATIC static NOINLINE

#if defined(USER_TIME)
#define XTIME time
    /* user time, and gmtime compatible functions, there is a gmtime 
       implementation here that WINCE uses, so really just need some ticks
       since the EPOCH 
    */

    /* special compact version of this struct, not the standard one. */
    struct tm {
        int32_t tm_gmtoff;      /* offset from UTC in seconds */
        int16_t tm_yday;        /* days since January 1 [0-365] */
        int16_t tm_year;        /* years since 1900 */
        int8_t  tm_mon;         /* months since January [0-11] */
        int8_t  tm_mday;        /* day of the month [1-31] */
        int8_t  tm_hour;        /* hours since midnight [0-23] */
        int8_t  tm_min;         /* minutes after the hour [0-59] */
        int8_t  tm_sec;         /* seconds after the minute [0-60] */
        int8_t  tm_wday;        /* days since Sunday [0-6] */
//      int8_t  tm_isdst;       /* Daylight Savings Time flag */
//      char    *tm_zone;       /* timezone abbreviation */
    };
    typedef long time_t;

    /* forward declaration */
    //const struct tm* x509gmtime(const time_t* timer);
    extern const struct tm* gmtime(const time_t* timer);
    time_t timegm(const struct tm* tm);
    extern time_t XTIME(time_t * timer);

    #define XGMTIME(c) gmtime((c))

#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h> 
    #define XTIME(tl)  time((tl))
    #define XGMTIME(c) gmtime((c))
#endif

int CertDecodeToExtensions(DecodedCert* cert);

#if defined( _WIN32_WCE ) || defined( USER_TIME )

#define YEAR0          1900
#define EPOCH_YEAR     1970
#define SECS_DAY       (24L * 60L * 60L)
// #define LEAPYEAR(year) (!((year) % 4) && (((year) % 100) || !((year) %400)))
#define YEARSIZE(year) (LEAPYEAR(year) ? 366 : 365)
#define YEARSECS(year) (LEAPYEAR(year) ? 366 * SECS_DAY : 365 * SECS_DAY)

STATIC int
LEAPYEAR(int year)
{
    return (!((year) % 4) && (((year) % 100) || !((year) % 400)));
}

static const int _ytab[2][12] =
{
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
};

time_t timegm(const struct tm* tm)
{
    int year, month, month_days;
    time_t rv = 0;

    year = tm->tm_year + YEAR0;
    while (year < EPOCH_YEAR) {
        rv -= YEARSECS(year);
        ++year;
    }
    while (year-- > EPOCH_YEAR) {
        rv += YEARSECS(year);
    }
    year = tm->tm_year + YEAR0;
    year = LEAPYEAR(year);
    month = tm->tm_mon % 12; /* ignore out-of-range months */
    month_days = 0;
    while (--month >= 0) {
        month_days += _ytab[year][month];
    }
    rv += (month_days + tm->tm_mday - 1) * SECS_DAY;
    rv += (3600 * tm->tm_hour) + (60 * tm->tm_min) + tm->tm_sec;
    return rv;
}

#endif /* _WIN32_WCE  || USER_TIME */




static INLINE word16 btoi(byte b)
{
    return (b >= 0x30 ? b - 0x30 : 0);
}


/* two byte date/time, add to value */
static INLINE int GetTime(const byte* date, int* idx)
{
    int i = *idx;
    int value;

    value  = btoi(date[i++]) * 10;
    value += btoi(date[i++]);

    *idx = i;
    return value;
}


STATIC int GetLength(const byte* input, word16* inOutIdx, int* len,
                     word16 maxIdx)
{
    int     length = 0;
    word16  i = *inOutIdx;
    byte    b;

    if ( (i+1) > maxIdx) {   /* for first read */
        CYASSL_MSG("GetLength bad index on input");
        return BUFFER_E;
    }

    b = input[i++];
    if (b >= ASN_LONG_LENGTH) {        
        word16 bytes = b & 0x7F;

        if (bytes > 2 || (i+bytes) > maxIdx) {   /* for reading bytes */
            CYASSL_MSG("GetLength bad long length");
            return BUFFER_E;
        }

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if ( (i+length) > maxIdx) {   /* for user of length */
        CYASSL_MSG("GetLength value exceeds buffer length");
        return BUFFER_E;
    }

    *inOutIdx = i;
    *len      = length;

    return length;
}


STATIC int GetAny(const byte* input, word16* inOutIdx, int* len,
                       word16 maxIdx)
{
    int    length = -1;
    word16 idx    = *inOutIdx;

    idx++;  /* skip over element type */
    if (GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx + length;

    return length;
}

STATIC int GetSequence(const byte* input, word16* inOutIdx, int* len,
                       word16 maxIdx)
{
    int    length = -1;
    word16 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


STATIC int GetSet(const byte* input, word16* inOutIdx, int* len, word16 maxIdx)
{
    int    length = -1;
    word16 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


/* winodws header clash for WinCE using GetVersion */
STATIC int GetMyVersion(const byte* input, word16* inOutIdx, int* version)
{
    word16 idx = *inOutIdx;

    CYASSL_ENTER("GetMyVersion");

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


/* Get small count integer, 32 bits or less */
STATIC int GetSmallInt(const byte* input, word16* inOutIdx, int* number, int maxIdx)
{
    word16 idx = *inOutIdx;
    word16 len;

    *number = 0;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > sizeof *number || len + idx > maxIdx)
        return ASN_PARSE_E;

    while (len--) {
        *number  = *number << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *number;
}

/* May not have one, not an error */
STATIC int GetExplicitVersion(const byte* input, word16* inOutIdx, int* version)
{
    word16 idx = *inOutIdx;

    CYASSL_ENTER("GetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

    /* go back as is */
    *version = 0;

    return 0;
}


STATIC int GetCertInt(DecodedCert *cert, CertElement *ce)
{
    const byte *input = cert->source;
    word16 maxIdx = cert->maxIdx;
    word16 i = cert->srcIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

#if 0
    /* strip leading zero */
    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;
#endif

    ce->idx = i;
    ce->len = length;

    cert->srcIdx = i + length;
    return length;
}


STATIC int GetObjectId(const byte* input, word16* inOutIdx, word16* oid,
                     word16 maxIdx)
{
    int    length;
    word16 i = *inOutIdx;
    byte   b;
    *oid = 0;

    b = input[i++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    while(length--)
        *oid += input[i++];
    /* just sum it up for now */

    *inOutIdx = i;

    return 0;
}


STATIC int GetAlgoId(const byte* input, word16* inOutIdx, word16* oid,
                     word16 maxIdx)
{
    int    length;
    word16 i = *inOutIdx;
    byte   b;

    *oid = 0;

    CYASSL_ENTER("GetAlgoId");

    if (GetSequence(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    b = input[i++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    while(length--) {
        /* odd HC08 compiler behavior here when input[i++] */
        *oid += input[i];
        i++;
    }
    /* just sum it up for now */

    /* could have NULL tag and 0 terminator, but may not */
    b = input[i++];

    if (b == ASN_TAG_NULL) {
        b = input[i++];
        if (b != 0) 
            return ASN_EXPECT_0_E;
    }
    else
    /* go back, didn't have it */
        i--;

    *inOutIdx = i;

    return 0;
}

STATIC int GetCertSeqWithEncoding(DecodedCert* cert, CertElement *seq)
{
    int rv;
    int len;
    word32 startOff = cert->srcIdx;
    word16 inOutIdx = cert->srcIdx;

    rv = GetSequence(cert->source, &inOutIdx, &len, cert->maxIdx);
    if (rv < 0)
        return rv;
    cert->srcIdx = len + inOutIdx;
    seq->idx = startOff;
    seq->len = len + inOutIdx - startOff;
    return seq->len;
}

STATIC int GetCertSequence(DecodedCert* cert, CertElement *seq)
{
    int rv;
    int len;
    word16 inOutIdx = cert->srcIdx;

    rv = GetSequence(cert->source, &inOutIdx, &len, cert->maxIdx);
    if (rv < 0)
        return rv;
    cert->srcIdx = inOutIdx;
    seq->idx = inOutIdx;
    seq->len = len;
    return len;
}

#if 0
STATIC int GetCertSeqSkipContent(DecodedCert* cert, CertElement *seq)
{
    int rv;
    word32 startOff = cert->srcIdx;

    rv = GetCertSequence(cert, seq);
    if (rv < 0)
        return rv;
    cert->srcIdx += rv;
    return (cert->srcIdx - startOff);
}

STATIC int GetBitString(const byte* input, word16* inOutIdx, int *len,
                        word16 maxIdx)
{
    int length;
    int idx = *inOutIdx;
    byte b = input[idx++];

    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(input, inOutIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    b = input[idx++];
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    --length;
    *len = length;
    *inOutIdx = idx + length;
    return length;
}
#endif

STATIC int GetCertBitString(DecodedCert* cert, CertElement *ce)
{
    int    length;
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    b = cert->source[cert->srcIdx++];
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    ce->len = length - 1;
    ce->idx = cert->srcIdx;
    cert->srcIdx += ce->len;

    return length;
}

void mnicInitDecodedCert(DecodedCert* cert, const byte* source, word16 inSz, void* heap)
{
    memset(cert, 0, sizeof *cert);
    cert->source          = source;  /* don't own */
    cert->maxIdx          = inSz;    /* can't go over this index */
    (void)heap;
}

#if 0
void FreeAltNames(DNS_entry* altNames, void* heap)
{
    (void)heap;

    while (altNames) {
        DNS_entry* tmp = altNames->next;

        XFREE(altNames->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(altNames,       heap, DYNAMIC_TYPE_ALTNAME);
        altNames = tmp;
    }
}
#endif

/* return 0 on sucess if the ECC curve oid sum is supported */
STATIC int CheckCurve(word16 oid)
{
    if (oid != ECC_256R1 && oid != ECC_384R1 && oid != ECC_521R1 && 
        oid != ECC_160R1 && oid != ECC_192R1 && oid != ECC_224R1)
        return ALGO_ID_E; 

    return 0;
}

STATIC int GetCertSPKI(DecodedCert* cert)
{
    word16 saved_srcIdx = cert->srcIdx;
    word16 saved_maxIdx = cert->maxIdx;
    int rv = GetCertSeqWithEncoding(cert, &cert->subjectPublicKeyInfo);
    cert->srcIdx = saved_srcIdx;
    cert->maxIdx = saved_maxIdx;
    return rv;
}

STATIC int GetCertKey(DecodedCert* cert)
{
    int length;
    word16 keyEnd;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    keyEnd = cert->srcIdx + length;

    if (GetAlgoId(cert->source, &cert->srcIdx, &cert->keyOID, keyEnd) < 0)
        return ASN_PARSE_E;

    switch (cert->keyOID) {
        case ECDSAk:
        {
            word16 oid = 0;

            if (GetObjectId(cert->source, &cert->srcIdx, &oid, keyEnd) < 0)
                return ASN_PARSE_E;

            cert->keyOID = oid;
            if (CheckCurve(oid) < 0)
                return ECC_CURVE_OID_E;

            if (GetCertBitString(cert, &cert->subjectPublicKey) < 0)
                return ASN_PARSE_E;
        }
        break;
        default:
            return ASN_UNKNOWN_OID_E;
    }

    return 0;
}


/* process NAME, either issuer or subject */
STATIC int GetCertName(DecodedCert* cert, CertElement *ce)
{
    int    nameEnd;  /* nameEnd of all distinguished names */
    int    dummy;
    word16 idx;
    word16 oid;

    CYASSL_MSG("Getting Cert Name");

    idx = cert->srcIdx;
    if (GetSequence(cert->source, &cert->srcIdx, &nameEnd, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    ce->idx = idx;
    ce->len = nameEnd + (cert->srcIdx - idx);

    nameEnd += cert->srcIdx;
    idx = 0;

    while (cert->srcIdx < (word16)nameEnd) {
        if (GetSet(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0) {
            CYASSL_MSG("Cert name lacks set header");
            return ASN_PARSE_E;
        }

        while (cert->srcIdx < (word16)nameEnd) {
            if (cert->source[cert->srcIdx] != (ASN_SEQUENCE | ASN_CONSTRUCTED))
                break;
            if (GetSequence(cert->source, &cert->srcIdx, &dummy, (word16)nameEnd) < 0)
                return ASN_PARSE_E;

            if (GetObjectId(cert->source, &cert->srcIdx, &oid, (word16)nameEnd) < 0)
                return ASN_PARSE_E;

            if (GetAny(cert->source, &cert->srcIdx, &dummy, (word16)nameEnd) < 0)
                return ASN_PARSE_E;
        }
    }

    return ce->len;
}


#ifndef NO_TIME_H

/* to the second */
STATIC int DateGreaterThan(const struct tm* a, const struct tm* b)
{
    if (a->tm_year > b->tm_year)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
           a->tm_mday > b->tm_mday)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min > b->tm_min)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min  == b->tm_min  && a->tm_sec > b->tm_sec)
        return 1;

    return 0; /* false */
}


static INLINE int DateLessThan(const struct tm* a, const struct tm* b)
{
    return !DateGreaterThan(a,b);
}
#endif /* NO_TIME_H */

STATIC int ParseDate(const byte* date, byte format, unsigned long *ptime)
{
    struct tm  certTime;
    int    i = 0;

    memset(&certTime, 0, sizeof(certTime));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    } else  { /* format == GENERALIZED_TIME */
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    certTime.tm_year += GetTime(date, &i); certTime.tm_year -= 1900; /* adjust */
    certTime.tm_mon   = GetTime(date, &i) - 1;                       /* adjust */
    certTime.tm_mday  = GetTime(date, &i);
    certTime.tm_hour  = GetTime(date, &i); 
    certTime.tm_min   = GetTime(date, &i); 
    if (date[i] && date[i] != 'Z') {     /* only Zulu supported for this profile */
        certTime.tm_sec   = GetTime(date, &i); 
    }

    if (date[i] && date[i] != 'Z') {     /* only Zulu supported for this profile */
        CYASSL_MSG("Only Zulu time supported for this profile"); 
        return 0;
    }

    *ptime = timegm(&certTime);
    return 1;  /* success */
}

#if defined(HAVE_CRL)
int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime = XTIME(0);
    time_t certTime;
    int rv;

    /* SSN change */
    if (!ltime) {
        /* if we don't know the date, we won't say 
         * any cert is outside of its validity period.
         */
        return 1;
    }

    rv = ParseDate(date, format, &certTime);
    if (rv)
        return rv;
    
    if (dateType == BEFORE) {
        if (ltime < certTime)
            return 0;
    } else if (ltime > certTime) {
            return 0;
    }
    return 1;
}
#endif


STATIC int GetCertDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b;

    b = cert->source[cert->srcIdx++];
    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    memset(date, 0, sizeof date);
    memcpy(date, &cert->source[cert->srcIdx], length);
    cert->srcIdx += length;

    if (!ParseDate(date, b,
         ((dateType == BEFORE) ? &cert->notBefore : &cert->notAfter)))
         return ASN_TIME_E;

    return 0;
}


STATIC int GetCertValidity(DecodedCert* cert)
{
    int length;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetCertDate(cert, BEFORE) < 0)
        return ASN_PARSE_E;

    if (GetCertDate(cert, AFTER) < 0)
        return ASN_PARSE_E;

    return 0;
}


/* Decode tbsCertificate up to (not including) extensions. */
int CertDecodeToExtensions(DecodedCert* cert)
{
    int ret = 0, version, len;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &version) < 0)
        return ASN_PARSE_E;
    cert->certVersion = version;

    if (GetCertInt(cert, &cert->serialNumber) < 0) 
        return ASN_PARSE_E;

    if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID,
                          cert->maxIdx)) < 0)
        return ret;

    if ( (ret = GetCertName(cert, &cert->issuer)) < 0)
        return ret;

    if ( (ret = GetCertValidity(cert)) < 0)
        return ret;

    if ( (ret = GetCertName(cert, &cert->subject)) < 0)
        return ret;

    if ( (ret = GetCertSPKI(cert)) < 0)
        return ret;

    if ( (ret = GetCertKey(cert)) < 0)
        return ret;

    return ret;
}



STATIC word16 SetDigest(const byte* digest, word16 digSz, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)digSz;
    memcpy(&output[2], digest, digSz);

    return digSz + 2;
} 


STATIC word16 BytePrecision(word16 value)
{
    word16 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * CYASSL_BIT_SIZE))
            break;

    return i;
}


STATIC word16 SetLength(word16 length, byte* output)
{
    word16 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * CYASSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}


STATIC word16 SetSequence(word16 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}


STATIC word16 SetAlgoID(int algoOID, byte* output, int type)
{
    /* adding TAG_NULL and 0 to end */

    /* hashTypes */
    static const byte sha256AlgoID[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                         0x04, 0x02, 0x01, 0x05, 0x00 };

    int    algoSz = 0;
    word16 idSz, seqSz;
    const  byte* algoName = 0;
    byte ID_Length[MAX_LENGTH_SZ];
    byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    if (type == hashType) {
        switch (algoOID) {

        case SHA256h:
            algoSz = sizeof(sha256AlgoID);
            algoName = sha256AlgoID;
            break;

        default:
            CYASSL_MSG("Unknown Hash Algo");
            return 0;  /* UNKOWN_HASH_E; */
        }
    }
    else if (type == sigType) {    /* sigType */
        switch (algoOID) {
        default:
            CYASSL_MSG("Unknown Signature Algo");
            return 0;
        }
    }
    else if (type == keyType) {    /* keyType */
        switch (algoOID) {
        default:
            CYASSL_MSG("Unknown Key Algo");
            return 0;
        }
    }
    else {
        CYASSL_MSG("Unknown Algo type");
        return 0;
    }

    idSz  = SetLength(algoSz - 2, ID_Length); /* don't include TAG_NULL/0 */
    seqSz = SetSequence(idSz + algoSz + 1, seqArray);
    seqArray[seqSz++] = ASN_OBJECT_ID;

    memcpy(output, seqArray, seqSz);
    memcpy(output + seqSz, ID_Length, idSz);
    memcpy(output + seqSz + idSz, algoName, algoSz);

    return seqSz + idSz + algoSz;

}


word16 mnicEncodeSignature(byte* out, const byte* digest, word16 digSz, int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word16 encDigSz, algoSz, seqSz; 

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, hashType);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    memcpy(out, seqArray, seqSz);
    memcpy(out + seqSz, algoArray, algoSz);
    memcpy(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}

#if 0
/* return true (1) for Confirmation */
STATIC int ConfirmSignature(const byte* buf, word16 bufSz,
    const byte* key, word16 keySz, word16 keyOID,
    const byte* sig, word16 sigSz, word16 sigOID,
    void* heap)
{
    byte digest[SHA256_DIGEST_SIZE]; /* max size */
    int  typeH, digestSz, ret = 0;

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;
    (void)heap;
    (void)ret;

    switch (sigOID) {
    case CTC_SHA256wRSA:
    case CTC_SHA256wECDSA:
        {
            Sha256 sha256;
            Sha256Init(&sha256);
            Sha256Update(&sha256, buf, bufSz);
            Sha256Final(&sha256, digest);
            typeH    = SHA256h;
            digestSz = SHA256_DIGEST_SIZE;
        }
        break;
    default:
            CYASSL_MSG("Verify Signautre has unsupported type");
            return 0;
    }

    switch (keyOID) {
        case ECDSAk:
        {
            ecc_key pubKey;
            int     verify = 0;

            if (ecc_import_x963(key, keySz, &pubKey) < 0) {
                CYASSL_MSG("ASN Key import error ECC");
                return 0;
            }

            ret = ecc_verify_hash(sig,sigSz,digest,digestSz,&verify,&pubKey);
            ecc_free(&pubKey);
            if (ret == 0 && verify == 1)
                return 1;  /* match */

            CYASSL_MSG("ECC Verify didn't match");
            return 0;
        }

        default:
            CYASSL_MSG("Verify Key type unknown");
            return 0;
    }
}
#endif


STATIC void CertDecodeAltNames(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;
    word16 oid;

    CYASSL_ENTER("CertDecodeAltNames");

    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) {
        CYASSL_MSG("\tBad Sequence");
        return;
    }

    while (length > 0) {
        int        strLen;
        byte       b = cert->source[idx++];

        length--;

        if (GetLength(cert->source, &idx, &strLen, maxIdx) < 0) {
            CYASSL_MSG("\tfail: str length");
            break;
        }
        if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_NAME_TYPE)) {
            oid = 0;
            if (GetObjectId(cert->source, &idx, &oid, maxIdx) < 0) 
                break;
            if (oid == SSN_SAN_OID) {
                b = cert->source[idx++];
                if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
                    int mac_strLen;
                    if (GetLength(cert->source, &idx, &mac_strLen, maxIdx) < 0) {
                        CYASSL_MSG("\tfail: mac str length");
                        break;
                    }
                    if (cert->source[idx++] == ASN_OCTET_STRING) {
                        if (GetLength(cert->source, &idx, &mac_strLen, maxIdx) < 0) {
                            CYASSL_MSG("\tfail: mac str length");
                            break;
                        }
                    }
                    cert->AltNames.idx = idx;
                    cert->AltNames.len = mac_strLen;
                    break;
                }
            }
        }
        length -= strLen;
        idx    += strLen;
    }   
}


STATIC void CertDecodeBasicCaConstraint(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;

    CYASSL_ENTER("CertDecodeBasicCaConstraint");
    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return;

    if (length == 0) return;
    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    if (cert->source[idx++] != ASN_BOOLEAN)
    {
        CYASSL_MSG("\tfail: constraint not BOOLEAN");
        return;
    }

    if (GetLength(cert->source, &idx, &length, maxIdx) < 0)
    {
        CYASSL_MSG("\tfail: length");
        return;
    }

    if (cert->source[idx])
        cert->flags |= CERT_F_IS_CA;
}


#define CRLDP_FULL_NAME 0
    /* From RFC3280 SS4.2.1.14, Distribution Point Name*/
#define GENERALNAME_URI 6
    /* From RFC3280 SS4.2.1.7, GeneralName */

#if 0 /* not supported */
STATIC void CertDecodeAuthInfo(word16 idx, int maxIdx, DecodedCert* cert)
/*
 *  Read the first of the Authority Information Access records. If there are
 *  any issues, return without saving the record.
 */
{
    int length = 0;
    word16 oid;

    /* Unwrap the list of AIAs */
    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return;

    /* Unwrap a single AIA */
    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return;

    oid = 0;
    if (GetObjectId(cert->source, &idx, &oid, maxIdx) < 0) 
        return;

    /* Only supporting URIs right now. */
    if (cert->source[idx] == (ASN_CONTEXT_SPECIFIC | GENERALNAME_URI))
    {
        idx++;
        if (GetLength(cert->source, &idx, &length, maxIdx) < 0) 
            return;

//      cert->extAuthInfoSz = length;
//      cert->extAuthInfo = cert->source + idx;
        idx += length;
    }
    else
    {
        /* Skip anything else. */
        idx++;
        if (GetLength(cert->source, &idx, &length, maxIdx) < 0) 
            return;
        idx += length;
    }

    if (idx < (word16)maxIdx)
    {
        CYASSL_MSG("\tThere are more Authority Information Access records, "
                   "but we only use first one.");
    }

    return;
}
#endif


STATIC void CertDecodeAuthKeyId(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;

    CYASSL_ENTER("CertDecodeAuthKeyId");

    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) {
        CYASSL_MSG("\tfail: should be a SEQUENCE\n");
        return;
    }

    if (cert->source[idx++] != (ASN_CONTEXT_SPECIFIC | 0)) {
        CYASSL_MSG("\tfail: wanted OPTIONAL item 0, not available\n");
        return;
    }

    if (GetLength(cert->source, &idx, &length, maxIdx) < 0) {
        CYASSL_MSG("\tfail: extension data length");
        return;
    }

    cert->AuthKeyID.idx = idx;
    cert->AuthKeyID.len = length;

    return;
}


STATIC void CertDecodeSubjKeyId(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;

    CYASSL_ENTER("CertDecodeSubjKeyId");

    if (cert->source[idx++] != ASN_OCTET_STRING) {
        CYASSL_MSG("\tfail: should be an OCTET STRING");
        return;
    }

    if (GetLength(cert->source, &idx, &length, maxIdx) < 0) {
        CYASSL_MSG("\tfail: extension data length");
        return;
    }

    cert->SubjKeyID.idx = idx;
    cert->SubjKeyID.len = length;

    return;
}

STATIC void CertDecodePolicies(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;
    int policy_length = 0;
    word16 oid;
    word16 policy_idx;

    CYASSL_ENTER("CertDecodePolicies");

    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return;

    while (length > 0) {
        policy_idx = idx;
        if (GetSequence(cert->source, &idx, &policy_length, maxIdx) < 0) 
            break;
        policy_length += idx - policy_idx;
        oid = 0;
        if (GetObjectId(cert->source, &idx, &oid, maxIdx) < 0) {
            break;
        }
        if (oid == ANY_POLICY_OID) {
            cert->flags |= CERT_F_HAS_ANY_POLICY;
            break;
        }
#if defined CERT_F_DLCA
        if (oid == SSN_DLCA_OID) {
            cert->flags |= CERT_F_DLCA;
        }
#endif
        idx = policy_idx + policy_length;
        length -= policy_length;
    }
}


STATIC void CertAddRole(int role, DecodedCert* cert)
{
    if (role < 0 || role > 255)
        return;
    if (cert->num_roles >= MAX_CERT_ROLES)
        return;
    cert->roles[cert->num_roles++] = (byte)role;
}

STATIC void CertDecodeSSNRole(word16 idx, int maxIdx, DecodedCert* cert)
{
    int length = 0;
    int number;

    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return;
    if (GetSmallInt(cert->source, &idx, &number, maxIdx) < 0)
        return;
    CertAddRole(number, cert);
}

STATIC void CertDecodeSSNMultiRole(word16 idx, int maxIdx, DecodedCert* cert)
{
    int len = 0;
    int number;

    if (GetSet(cert->source, &idx, &len, maxIdx) < 0)
        return;
    while (idx < maxIdx) {
        if (GetSmallInt(cert->source, &idx, &number, maxIdx) < 0)
            return;
        CertAddRole(number, cert);
    }
}

STATIC int CertDecodeExtensions(DecodedCert* cert)
/*
 *  Processing the Certificate Extensions. This does not modify the current
 *  index. It is works starting with the recorded extensions pointer.
 */
{
    word16 idx    = cert->srcIdx;
    word16 maxIdx = cert->extensions.idx + cert->extensions.len;
    int length;
    word16 oid;
    word16 isCritical;

    CYASSL_ENTER("CertDecodeExtensions");

    if (cert->extensions.idx == 0 || cert->extensions.len == 0) 
        return 0;  /* permit empty extensions */

    if (cert->source[idx++] != ASN_EXTENSIONS) 
        return EXTENSIONS_E;

    if (GetLength(cert->source, &idx, &length, maxIdx) < 0) 
        return EXTENSIONS_E;

    if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) 
        return EXTENSIONS_E;

    while (idx < (word16)maxIdx) {
        isCritical = 0;
        if (GetSequence(cert->source, &idx, &length, maxIdx) < 0) {
            CYASSL_MSG("\tfail: should be a SEQUENCE");
            return EXTENSIONS_E;
        }

        oid = 0;
        if (GetObjectId(cert->source, &idx, &oid, maxIdx) < 0) {
            CYASSL_MSG("\tfail: OBJECT ID");
            return EXTENSIONS_E;
        }

        /* check for critical flag */
        if (cert->source[idx] == ASN_BOOLEAN) {
            CYASSL_MSG("\tfound optional critical flag, moving past");
            isCritical = cert->source[idx + ASN_BOOL_SIZE];
            idx += (ASN_BOOL_SIZE + 1);
        }

        /* process the extension based on the OID */
        if (cert->source[idx++] != ASN_OCTET_STRING) {
            CYASSL_MSG("\tfail: should be an OCTET STRING");
            return EXTENSIONS_E;
        }

        if (GetLength(cert->source, &idx, &length, maxIdx) < 0) {
            CYASSL_MSG("\tfail: extension data length");
            return EXTENSIONS_E;
        }

        switch (oid) {
        case BASIC_CA_OID:
            CertDecodeBasicCaConstraint(idx, idx + length, cert);
            break;

#if 0 /* Not supported */
        case AUTH_INFO_OID:
            CertDecodeAuthInfo(idx, idx + length, cert);
            break;
#endif

        case ALT_NAMES_OID:
            CertDecodeAltNames(idx, idx + length, cert);
            break;

        case AUTH_KEY_OID:
            CertDecodeAuthKeyId(idx, idx + length, cert);
            break;

        case SUBJ_KEY_OID:
            CertDecodeSubjKeyId(idx, idx + length, cert);
            break;

        case CERT_POLICIES_OID:
            CertDecodePolicies(idx, idx + length, cert);
            break;

        case SSN_ROLE_OID:
            CertDecodeSSNRole(idx, idx + length, cert);
            break;

        case SSN_MULTI_ROLE_OID:
            CertDecodeSSNMultiRole(idx, idx + length, cert);
            break;

        default:
            CYASSL_MSG("\tExtension type not handled, skipping");
            if (isCritical) {
                return EXTENSIONS_E;
            }
            break;
        }
        idx += length;
    }

    return 0;
}

int CheckCertValidity(DecodedCert* cert)
{
    time_t ltime = XTIME(0);
    if (ltime) {
        if ((unsigned long)ltime < cert->notBefore)
            return ASN_BEFORE_DATE_E;
        if ((unsigned long)ltime > cert->notAfter)
            return ASN_AFTER_DATE_E;
    }
    return 0;
}

/* Call InitDecodedCert, then call this */
int mnicParseCert(DecodedCert* cert, bool validate)
{
    int   ret;

    ret = mnicParseCertRelative(cert);
    if (ret < 0)
        return ret;

    if (validate) {
        ret = CheckCertValidity(cert);
    }

#if 0
    if (verify && type != CA_TYPE) {
        Signer* ca = NULL;
        #ifndef NO_SKID
            if (cert->extAuthKeyIdSet)
                ca = GetCA(cm, cert->extAuthKeyId);
            if (ca == NULL)
                ca = GetCAByName(cm, cert->issuerHash);
        #else /* NO_SKID */
            ca = GetCA(cm, cert->issuerHash);
        #endif /* NO SKID */
        CYASSL_MSG("About to verify certificate signature");

        if (ca) {
            /* try to confirm/verify signature */
            if (!ConfirmSignature(cert->source + cert->Certificate.idx,
                        cert->sigIndex - cert->Certificate.idx,
                    ca->publicKey, ca->pubKeySize, ca->keyOID,
                    cert->signature, cert->sigLength, cert->signatureOID,
                    NULL)) {
                CYASSL_MSG("Confirm signature failed");
                return ASN_SIG_CONFIRM_E;
            }
        }
        else {
            /* no signer */
            CYASSL_MSG("No CA signer to verify with");
            return ASN_NO_SIGNER_E;
        }
    }

    if (badDate != 0)
        return badDate;
#endif

    return ret;
}


/* from SSL proper, for locking can't do find here anymore */
#ifdef __cplusplus
    extern "C" {
#endif
    CYASSL_LOCAL Signer* GetCA(void* signers, byte* hash);
    #ifndef NO_SKID
        CYASSL_LOCAL Signer* GetCAByName(void* signers, byte* hash);
    #endif
#ifdef __cplusplus
    } 
#endif

static int GetCertTBSHash(DecodedCert* cert, CertElement *ce)
{
    Sha256 sha256;
    unsigned hlen = 32;
    Sha256Init(&sha256);
    Sha256Update(&sha256, cert->source + ce->idx, ce->len);
    Sha256Final(&sha256, cert->certHash, &hlen);
    return 0;
}


int mnicParseCertRelative(DecodedCert* cert)
{
//  word16 confirmOID;
    int    ret;
//  int    badDate = 0;
    int    dummy;
    CertElement ce;

    if ((ret = GetCertSeqWithEncoding(cert, &cert->Certificate)) < 0)
        return ret;
    if (cert->maxIdx > cert->Certificate.len)
        cert->maxIdx = cert->Certificate.len;

    /* Now parse the 3 main components of the Certificate */
    cert->srcIdx = cert->Certificate.idx;
    if ((ret = GetCertSequence(cert, &ce)) < 0)
        return ret;
    if ((ret = GetCertSeqWithEncoding(cert, &cert->tbsCertificate)) < 0)
        return ret;
    if ((ret = GetCertTBSHash(cert, &cert->tbsCertificate)) < 0)
        return ret;
    if ((ret = GetCertSeqWithEncoding(cert, &cert->signatureAlgorithm)) < 0)
        return ret;
    if ((ret = GetCertBitString(cert, &cert->signatureValue)) < 0)
        return ret;
    if (cert->srcIdx != cert->maxIdx)
        return ASN_PARSE_E;

    /* Now decode the tbsCertificate, up to extensions. */
    cert->srcIdx = cert->tbsCertificate.idx;
    cert->maxIdx = cert->srcIdx + cert->tbsCertificate.len;
    if ((ret = CertDecodeToExtensions(cert)) < 0) {
        return ret;
    }

    if (cert->source[cert->srcIdx] == ASN_ISSUER_UNIQUE_ID && 
        GetAny(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0)
        return ASN_PARSE_E;
    if (cert->source[cert->srcIdx] == ASN_SUBJECT_UNIQUE_ID && 
        GetAny(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (cert->srcIdx < cert->signatureAlgorithm.idx) {
        cert->extensions.idx = cert->srcIdx;
        cert->extensions.len = cert->signatureAlgorithm.idx - cert->srcIdx;
        CertDecodeExtensions(cert);
    }

    /* advance past extensions */
    cert->srcIdx =  cert->signatureValue.idx;

#if 0
    if ((ret = GetAlgoId(cert->source, &cert->srcIdx, &confirmOID,
                         cert->maxIdx)) < 0)
        return ret;

    if ((ret = GetCertBitString(cert)) < 0)
        return ret;

    if (confirmOID != cert->signatureOID)
        return ASN_SIG_OID_E;
#endif

    return 0;
}

#if 0
/* Create and init an new signer */
Signer* MakeSigner(void* heap)
{
    Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap,
                                       DYNAMIC_TYPE_SIGNER);
    if (signer) {
        signer->name      = 0;
        signer->publicKey = 0;
        signer->next      = 0;
    }
    (void)heap;

    return signer;
}


/* Free an individual signer */
void FreeSigner(Signer* signer, void* heap)
{
    XFREE(signer->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(signer->publicKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(signer, heap, DYNAMIC_TYPE_SIGNER);

    (void)heap;
}


/* Free the whole singer table with number of rows */
void FreeSignerTable(Signer** table, int rows, void* heap)
{
    int i;

    for (i = 0; i < rows; i++) {
        Signer* signer = table[i];
        while (signer) {
            Signer* next = signer->next;
            FreeSigner(signer, heap);
            signer = next;
        }
        table[i] = NULL;
    }
}
#endif

#if defined(CYASSL_KEY_GEN) || defined(CYASSL_CERT_GEN)

STATIC int SetMyVersion(word16 version, byte* output, int header)
{
    int i = 0;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = ASN_BIT_STRING;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}

#endif /* CYASSL_KEY_GEN || CYASSL_CERT_GEN */

#if 0
/* Der Decode ECC-DSA Signautre, r & s stored as big ints */
int DecodeECC_DSA_Sig(const byte* sig, word16 sigLen, mp_int* r, mp_int* s)
{
    word16 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if ((word16)len > (sigLen - idx))
        return ASN_ECC_KEY_E;

    if (GetInt(r, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if (GetInt(s, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    return 0;
}
#endif

#if 0
int EccPrivateKeyDecode(const byte* input, word16* inOutIdx, ecc_key* key,
                        word16 inSz)
{
    word16 oid = 0;
    int    version, length;
    int    privSz, pubSz;
    byte   b;
    byte   priv[ECC_MAXSIZE];
    byte   pub[ECC_MAXSIZE * 2 + 1]; /* public key has two parts plus header */

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7) 
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    /* priv key */
    privSz = length;
    memcpy(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    /* prefix 0, may have */
    b = input[*inOutIdx];
    if (b == ECC_PREFIX_0) {
        *inOutIdx += 1;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        /* object id */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        while(length--) {
            oid += input[*inOutIdx];
            *inOutIdx += 1;
        }
        if (CheckCurve(oid) < 0)
            return ECC_CURVE_OID_E;
    }

    /* prefix 1 */
    b = input[*inOutIdx];
    *inOutIdx += 1;
    if (b != ECC_PREFIX_1)
        return ASN_ECC_KEY_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    /* key header */
    if (GetBitString(input, inOutIdx, &length, inSZ) < 0)
        return ASN_PARSE_E;

    pubSz = length;
    memcpy(pub, &input[*inOutIdx], pubSz);

    *inOutIdx += length;

    return ecc_import_private_key(priv, privSz, pub, pubSz, key);
}
#endif


#if defined(HAVE_CRL)

/* Get raw Date only, no processing, 0 on success */
STATIC int GetBasicDate(const byte* source, word16* idx, byte* date,
                        byte* format, int maxIdx)
{
    int    length;

    CYASSL_ENTER("GetBasicDate");

    *format = source[*idx];
    *idx += 1;
    if (*format != ASN_UTC_TIME && *format != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    memcpy(date, &source[*idx], length);
    *idx += length;

    return 0;
}


/* initialize decoded CRL */
void InitDecodedCRL(DecodedCRL* dcrl)
{
    CYASSL_MSG("InitDecodedCRL");

    memset(dcrl, 0, sizeof *dcrl);
}


/* free decoded CRL resources */
void FreeDecodedCRL(DecodedCRL* dcrl)
{
    RevokedCert* tmp = dcrl->certs;

    CYASSL_MSG("FreeDecodedCRL");

    while(tmp) {
        RevokedCert* next = tmp->next;
        XFREE(tmp, NULL, DYNAMIC_TYPE_REVOKED);
        tmp = next;
    }
}


/* store SHA1 hash of NAME */
STATIC int GetNameHash(const byte* source, word16* idx, byte* hash, int maxIdx)
{
    Sha    sha;
    int    length;  /* length of all distinguished names */
    word16 dummy;

    CYASSL_ENTER("GetNameHash");

    if (source[*idx] == ASN_OBJECT_ID) {
        CYASSL_MSG("Trying optional prefix...");

        if (GetLength(source, idx, &length, maxIdx) < 0)
            return ASN_PARSE_E;

        *idx += length;
        CYASSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    dummy = *idx;
    if (GetSequence(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    InitSha(&sha);
    ShaUpdate(&sha, source + dummy, length + *idx - dummy);
    ShaFinal(&sha, hash);

    *idx += length;

    return 0;
}


/* Get Revoked Cert list, 0 on success */
STATIC int GetRevoked(const byte* buff, word16* idx, DecodedCRL* dcrl,
                      int maxIdx)
{
    int    len;
    word16 end;
    byte   b;
    RevokedCert* rc;

    CYASSL_ENTER("GetRevoked");

    if (GetSequence(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    end = *idx + len;

    /* get serial number */
    b = buff[*idx];
    *idx += 1;

    if (b != ASN_INTEGER) {
        CYASSL_MSG("Expecting Integer");
        return ASN_PARSE_E;
    }

    if (GetLength(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    if (len > EXTERNAL_SERIAL_SIZE) {
        CYASSL_MSG("Serial Size too big");
        return ASN_PARSE_E;
    }

    rc = (RevokedCert*)XMALLOC(sizeof(RevokedCert), NULL, DYNAMIC_TYPE_CRL);
    if (rc == NULL) {
        CYASSL_MSG("Alloc Revoked Cert failed");
        return MEMORY_E;
    }

    memcpy(rc->serialNumber, &buff[*idx], len);
    rc->serialSz = len;

    /* add to list */
    rc->next = dcrl->certs;
    dcrl->certs = rc;
    dcrl->totalCerts++;

    *idx += len;

    /* get date */
    b = buff[*idx];
    *idx += 1;

    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME) {
        CYASSL_MSG("Expecting Date");
        return ASN_PARSE_E;
    }

    if (GetLength(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    /* skip for now */
    *idx += len;

    if (*idx != end)  /* skip extensions */
        *idx = end;

    return 0;
}


/* Get CRL Signature, 0 on success */
STATIC int GetCRL_Signature(const byte* source, word16* idx, DecodedCRL* dcrl,
                            int maxIdx)
{
    int    length;
    byte   b;

    CYASSL_ENTER("GetCRL_Signature");

    b = source[*idx];
    *idx += 1;
    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    dcrl->sigLength = length;

    b = source[*idx];
    *idx += 1;
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    dcrl->sigLength--;
    dcrl->signature = (byte*)&source[*idx];

    *idx += dcrl->sigLength;

    return 0;
}


/* prase crl buffer into decoded state, 0 on success */
int ParseCRL(DecodedCRL* dcrl, const byte* buff, word16 sz, void* cm)
{
    int     version, len;
    word16  oid, idx = 0;
    Signer* ca = NULL;

    CYASSL_MSG("ParseCRL");

    /* raw crl hash */
    /* hash here if needed for optimized comparisons
     * Sha     sha;
     * InitSha(&sha);
     * ShaUpdate(&sha, buff, sz);
     * ShaFinal(&sha, dcrl->crlHash); */

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;

    dcrl->Certificate.idx = idx;

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;
    dcrl->sigIndex = len + idx;

    /* may have version */
    if (buff[idx] == ASN_INTEGER) {
        if (GetMyVersion(buff, &idx, &version) < 0)
            return ASN_PARSE_E;
    }

    if (GetAlgoId(buff, &idx, &oid, sz) < 0)
        return ASN_PARSE_E;

    if (GetNameHash(buff, &idx, dcrl->issuerHash, sz) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buff, &idx, dcrl->lastDate, &dcrl->lastDateFormat, sz) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buff, &idx, dcrl->nextDate, &dcrl->nextDateFormat, sz) < 0)
        return ASN_PARSE_E;

    if (!ValidateDate(dcrl->nextDate, dcrl->nextDateFormat, AFTER)) {
        CYASSL_MSG("CRL after date is no longer valid");
        return ASN_AFTER_DATE_E;
    }

    if (idx != dcrl->sigIndex && buff[idx] != CRL_EXTENSIONS) {
        if (GetSequence(buff, &idx, &len, sz) < 0)
            return ASN_PARSE_E;

        len += idx;

        while (idx < (word16)len) {
            if (GetRevoked(buff, &idx, dcrl, sz) < 0)
                return ASN_PARSE_E;
        }
    }

    if (idx != dcrl->sigIndex)
        idx = dcrl->sigIndex;   /* skip extensions */

    if (GetAlgoId(buff, &idx, &dcrl->signatureOID, sz) < 0)
        return ASN_PARSE_E;

    if (GetCRL_Signature(buff, &idx, dcrl, sz) < 0)
        return ASN_PARSE_E;

    #ifndef NO_SKID
        if (dcrl->extAuthKeyIdSet)
            ca = GetCA(cm, dcrl->extAuthKeyId);
        if (ca == NULL)
            ca = GetCAByName(cm, dcrl->issuerHash);
    #else /* NO_SKID */
        ca = GetCA(cm, dcrl->issuerHash);
    #endif /* NO_SKID */
    CYASSL_MSG("About to verify CRL signature");

    if (ca) {
        CYASSL_MSG("Found CRL issuer CA");
        /* try to confirm/verify signature */
        if (!ConfirmSignature(buff + dcrl->Certificate.idx,
                dcrl->sigIndex - dcrl->Certificate.idx,
                ca->publicKey, ca->pubKeySize, ca->keyOID,
                dcrl->signature, dcrl->sigLength, dcrl->signatureOID, NULL)) {
            CYASSL_MSG("CRL Confirm signature failed");
            return ASN_CRL_CONFIRM_E;
        }
    }
    else {
        CYASSL_MSG("Did NOT find CRL issuer CA");
        return ASN_CRL_NO_SIGNER_E;
    }

    return 0;
}

#endif /* HAVE_CRL */
