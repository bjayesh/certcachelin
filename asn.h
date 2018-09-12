/* asn.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 */


#ifndef NO_ASN

#ifndef CTAO_CRYPT_ASN_H
#define CTAO_CRYPT_ASN_H

#include "types.h"
#include "asn_public.h"   /* public interface */
#include <stdbool.h>

#ifdef HAVE_ECC
    #include "ecc.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

enum {
    ISSUER  = 0,
    SUBJECT = 1,

    EXTERNAL_SERIAL_SIZE = 32,

    BEFORE  = 0,
    AFTER   = 1
};

/* ASN Tags   */
enum ASN_Tags {        
    ASN_BOOLEAN           = 0x01,
    ASN_INTEGER           = 0x02,
    ASN_BIT_STRING        = 0x03,
    ASN_OCTET_STRING      = 0x04,
    ASN_TAG_NULL          = 0x05,
    ASN_OBJECT_ID         = 0x06,
    ASN_ENUMERATED        = 0x0a,
    ASN_SEQUENCE          = 0x10,
    ASN_SET               = 0x11,
    ASN_UTC_TIME          = 0x17,
    ASN_DNS_TYPE          = 0x02,
    ASN_OTHER_NAME_TYPE   = 0x00,
    ASN_GENERALIZED_TIME  = 0x18,
    CRL_EXTENSIONS        = 0xa0,
    ASN_ISSUER_UNIQUE_ID  = 0xa1,
    ASN_SUBJECT_UNIQUE_ID = 0xa2,
    ASN_EXTENSIONS        = 0xa3,
    ASN_LONG_LENGTH       = 0x80
};

enum  ASN_Flags{
    ASN_CONSTRUCTED       = 0x20,
    ASN_CONTEXT_SPECIFIC  = 0x80
};

enum DN_Tags {
    ASN_COMMON_NAME   = 0x03,   /* CN */
    ASN_SUR_NAME      = 0x04,   /* SN */
    ASN_COUNTRY_NAME  = 0x06,   /* C  */
    ASN_LOCALITY_NAME = 0x07,   /* L  */
    ASN_STATE_NAME    = 0x08,   /* ST */
    ASN_ORG_NAME      = 0x0a,   /* O  */
    ASN_ORGUNIT_NAME  = 0x0b    /* OU */
};

enum PBES {
    PBE_MD5_DES      = 0,
    PBE_SHA1_DES     = 1,
    PBE_SHA1_DES3    = 2,
    PBE_SHA1_RC4_128 = 3,
    PBES2            = 13       /* algo ID */
};

enum ENCRYPTION_TYPES {
    DES_TYPE  = 0,
    DES3_TYPE = 1,
    RC4_TYPE  = 2
};

enum ECC_TYPES {
    ECC_PREFIX_0 = 160,
    ECC_PREFIX_1 = 161
};

enum Misc_ASN { 
    ASN_NAME_MAX        = 256,
    MAX_SALT_SIZE       =  64,     /* MAX PKCS Salt length */
    MAX_IV_SIZE         =  64,     /* MAX PKCS Iv length */
    MAX_KEY_SIZE        =  64,     /* MAX PKCS Key  length */
    PKCS5               =   5,     /* PKCS oid tag */
    PKCS5v2             =   6,     /* PKCS #5 v2.0 */
    PKCS12              =  12,     /* PKCS #12 */
    MAX_UNICODE_SZ      = 256,
    ASN_BOOL_SIZE       =   2,     /* including type */
    SHA_SIZE            =  20,
    RSA_INTS            =   8,     /* RSA ints in private key */
    MIN_DATE_SIZE       =  13,
    MAX_DATE_SIZE       =  32,
    ASN_GEN_TIME_SZ     =  15,     /* 7 numbers * 2 + Zulu tag */
    MAX_ENCODED_SIG_SZ  = 512,
    MAX_SIG_SZ          = 256,
    MAX_ALGO_SZ         =  20,
    MAX_SEQ_SZ          =   5,     /* enum(seq | con) + length(4) */  
    MAX_SET_SZ          =   5,     /* enum(set | con) + length(4) */  
    MAX_VERSION_SZ      =   5,     /* enum + id + version(byte) + (header(2))*/
    MAX_ENCODED_DIG_SZ  =  73,     /* sha512 + enum(bit or octet) + legnth(4) */
    MAX_RSA_INT_SZ      = 517,     /* RSA raw sz 4096 for bits + tag + len(4) */
    MAX_NTRU_KEY_SZ     = 610,     /* NTRU 112 bit public key */
    MAX_NTRU_ENC_SZ     = 628,     /* NTRU 112 bit DER public encoding */
    MAX_LENGTH_SZ       =   4,     /* Max length size for DER encoding */
    MAX_RSA_E_SZ        =  16,     /* Max RSA public e size */
    MAX_CA_SZ           =  32,     /* Max encoded CA basic constraint length */
    MAX_SN_SZ           =  35,     /* Max encoded serial number (INT) length */
    MAX_CERT_ROLES      =  11,
#ifdef CYASSL_CERT_GEN
    #ifdef CYASSL_ALT_NAMES
        MAX_EXTENSIONS_SZ   = 1 + MAX_LENGTH_SZ + CTC_MAX_ALT_SIZE,
    #else
        MAX_EXTENSIONS_SZ   = 1 + MAX_LENGTH_SZ + MAX_CA_SZ,
    #endif
                                   /* Max total extensions, id + len + others */
#endif
    MAX_OCSP_EXT_SZ     = 58,      /* Max OCSP Extension length */
    MAX_OCSP_NONCE_SZ   = 18,      /* OCSP Nonce size           */
    EIGHTK_BUF          = 8192,    /* Tmp buffer size           */
    MAX_PUBLIC_KEY_SZ   = MAX_NTRU_ENC_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ * 2
                                   /* use bigger NTRU size */
};


enum Oid_Types {
    hashType = 0,
    sigType  = 1,
    keyType  = 2
};


enum Hash_Sum  {
    MD2h    = 646,
    MD5h    = 649,
    SHAh    =  88,
    SHA256h = 414,
    SHA384h = 415,
    SHA512h = 416
};


enum Key_Sum {
    DSAk   = 515,
    RSAk   = 645,
    NTRUk  = 364,
    ECDSAk = 518
};


enum Ecc_Sum {
    ECC_256R1 = 526,
    ECC_384R1 = 210,
    ECC_521R1 = 211,
    ECC_160R1 = 184,
    ECC_192R1 = 520,
    ECC_224R1 = 209
};


enum KDF_Sum {
    PBKDF2_OID = 660
};


enum Extensions_Sum {
    AUTH_INFO_OID = 69,
    CA_ISSUER_OID = 117,
    SUBJ_KEY_OID  = 128,
    ALT_NAMES_OID = 131,
    BASIC_CA_OID  = 133,
    CRL_DIST_OID  = 145,
    CERT_POLICIES_OID = 146,
    ANY_POLICY_OID = 146,       /* Note collision */
    AUTH_KEY_OID  = 149,
    SSN_SAN_OID   = 465, /* SSN Subject Alt Name OID */
    SSN_ROLE_OID  = 466,
    SSN_MULTI_ROLE_OID = 469,
    SSN_DLCA_OID  = 473
};


enum VerifyType {
    NO_VERIFY = 0,
    VERIFY    = 1
};


typedef struct DNS_entry   DNS_entry;

struct DNS_entry {
    DNS_entry* next;   /* next on DNS list */
    char*      name;   /* actual DNS name */
};

typedef struct Signer      Signer;

struct CertElement {
    word16      idx;    /* offset from cert->source */
    word16      len;
};

typedef struct CertElement CertElement;

struct DecodedCert {
    const byte*   source;            /* byte buffer holder cert, NOT owner */
    word16  srcIdx;                  /* current offset into buffer         */
    word16  maxIdx;                  /* offset one past end of buffer      */
/* specific bytes values */
    byte    structVersion;
    byte    certVersion;
    word16  flags;
    uint8_t issuer_slot;
    byte    slot;
    CertElement   Certificate;       /* With DER encoding                  */
/* Certificate contents */
    CertElement   tbsCertificate;    /* With DER encoding                  */
    CertElement   signatureAlgorithm;/* With DER encoding                  */
    CertElement   signatureValue;    /* decoded value of bit string        */
/* tbsCertificate contents */
    /* version stored above. */
    CertElement   serialNumber;
//  CertElement   signature;         /* Alg id, see signatureOID below */
    CertElement   issuer;
    /* validity stored below CertElements. */
    CertElement   subject;
    CertElement   subjectPublicKeyInfo;
    CertElement   extensions;
/* parts of subjectPublicKeyInfo */
//  CertElement   algorithm;         /* see keyOID below */
    CertElement   subjectPublicKey;
/* Specific extensions */
//  CertElement   BasicCaConstraint; /* see flags */
    CertElement   AltNames;
    CertElement   AuthKeyID;
    CertElement   SubjKeyID;
/* Specific word16 values */
    word16  signatureOID;            /* sum of algorithm object id       */
    word16  keyOID;                  /* sum of key algo  object id       */

    unsigned long    notBefore;          /* should be time_t */
    unsigned long    notAfter;           /* should be time_t */
    byte    certHash[32];
    byte    num_roles;
    byte    roles[MAX_CERT_ROLES];
};  // 108 bytes

typedef struct DecodedCert DecodedCert;

/* bits for DecodedCert.flags */
#define CERT_F_READ_ONLY        0x01
#define CERT_F_VISITED          0x02
#define CERT_F_IS_CA            0x04
#define CERT_F_HAS_ANY_POLICY   0x08
#define CERT_F_OPERATOR         0x10
#define CERT_F_TO_DELETE        0x20
#define CERT_F_ROOT             0x40
#define CERT_F_USED             0x80
#define CERT_F_DLCA             0x100
#define CERT_F_MFG              0x200
#define CERT_F_DL               0x400
#define CERT_F_BC               0x800

struct CertBuffer {
    struct DecodedCert  dc;     // 108 bytes
    byte   buffer[1024 - sizeof(struct DecodedCert)];  // 892 bytes
};  // 1024 bytes

typedef struct CertBuffer CertBuffer;

#ifdef SHA_DIGEST_SIZE
#define SIGNER_DIGEST_SIZE SHA_DIGEST_SIZE
#else
#define SIGNER_DIGEST_SIZE 20 
#endif

/* CA Signers */
struct Signer {
    byte*   publicKey;
    word16  pubKeySize;
    word16  keyOID;                  /* key type */
    char*   name;                    /* common name */
    byte    subjectNameHash[SIGNER_DIGEST_SIZE];
                                     /* sha hash of names in certificate */
    #ifndef NO_SKID
        byte    subjectKeyIdHash[SIGNER_DIGEST_SIZE];
                                     /* sha hash of names in certificate */
    #endif
    Signer* next;
};


#define CYASSL_API
#define CYASSL_LOCAL

/* not for public consumption but may use for testing sometimes */
#ifdef CYASSL_TEST_CERT
    #define CYASSL_TEST_API CYASSL_API
#else
    #define CYASSL_TEST_API CYASSL_LOCAL
#endif

CYASSL_TEST_API void FreeAltNames(DNS_entry*, void*);
CYASSL_API      void mnicInitDecodedCert(DecodedCert*, const byte*, word16, void*);
CYASSL_TEST_API void FreeDecodedCert(DecodedCert*);
CYASSL_API      int  mnicParseCert(DecodedCert*, bool validate);

CYASSL_LOCAL int mnicParseCertRelative(DecodedCert*);

CYASSL_API      int CheckCertValidity(DecodedCert* cert);

CYASSL_LOCAL word16 mnicEncodeSignature(byte* out, const byte* digest, word16 digSz,
                                    int hashOID);

CYASSL_LOCAL Signer* MakeSigner(void*);
CYASSL_LOCAL void    FreeSigner(Signer*, void*);
CYASSL_LOCAL void    FreeSignerTable(Signer**, int, void*);


CYASSL_LOCAL int ToTraditional(byte* buffer, word16 length);
CYASSL_LOCAL int ToTraditionalEnc(byte* buffer, word16 length,const char*, int);

CYASSL_LOCAL int ValidateDate(const byte* date, byte format, int dateType);

#ifdef HAVE_ECC
    /* ASN sig helpers */
    CYASSL_LOCAL int StoreECC_DSA_Sig(byte* out, word16* outLen, mp_int* r,
                                      mp_int* s);
    CYASSL_LOCAL int DecodeECC_DSA_Sig(const byte* sig, word16 sigLen,
                                       mp_int* r, mp_int* s);
    /* private key helpers */
    CYASSL_LOCAL int EccPrivateKeyDecode(const byte* input,word16* inOutIdx,
                                         ecc_key*,word16);
#endif


/* for pointer use */
typedef struct CertStatus CertStatus;

/* for pointer use */
typedef struct RevokedCert RevokedCert;

#ifdef HAVE_CRL

struct RevokedCert {
    byte         serialNumber[EXTERNAL_SERIAL_SIZE];
    int          serialSz;
    RevokedCert* next;
};

typedef struct DecodedCRL DecodedCRL;

struct DecodedCRL {
    word16  certBegin;               /* offset to start of cert          */
    word16  sigIndex;                /* offset to start of signature     */
    word16  sigLength;               /* length of signature              */
    word16  signatureOID;            /* sum of algorithm object id       */
    byte*   signature;               /* pointer into raw source, not owned */
    byte    issuerHash[SHA_DIGEST_SIZE];  /* issuer hash                 */ 
    byte    crlHash[SHA_DIGEST_SIZE];     /* raw crl data hash           */ 
    byte    lastDate[MAX_DATE_SIZE]; /* last date updated  */
    byte    nextDate[MAX_DATE_SIZE]; /* next update date   */
    byte    lastDateFormat;          /* format of last date */
    byte    nextDateFormat;          /* format of next date */
    RevokedCert* certs;              /* revoked cert list  */
    int          totalCerts;         /* number on list     */
};

CYASSL_LOCAL void InitDecodedCRL(DecodedCRL*);
CYASSL_LOCAL int  ParseCRL(DecodedCRL*, const byte* buff, word16 sz, void* cm);
CYASSL_LOCAL void FreeDecodedCRL(DecodedCRL*);


#endif /* HAVE_CRL */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ASN_H */

#endif /* !NO_ASN */
