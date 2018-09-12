/*
 * Copyright (c) 2017 Itron Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <includes.h>

#include <x509_cache.h>
#include <x509_cache_flash.h>
#include <asn.h>
#include <sfl.h>
#include <x509_cache_flash.h>

#define TASK_PRIO       TEST_TASK_PRIORITY
#define TASK_STK_SIZE   4096

static OS_STK task_stk[TASK_STK_SIZE];


#define ELLIPTIC

#ifdef ELLIPTIC
#include <elpsoft.h>
#include <assert.h>
extern const elpprng_plugin sys_prng;
#endif

#define RESULT_PASS 0
#define RESULT_FAIL 1
#define VALID       1
#define INVALID     0
#define FOUND       1
#define NOT_FOUND   0

//tokens
#define TOKEN_EXPECT            1
#define TOKEN_PASS              2
#define TOKEN_FAIL              3
#define TOKEN_EDITBUF           5
#define TOKEN_INSERT            6
#define TOKEN_DELETE            9
#define TOKEN_FIND              10
#define TOKEN_BYID              11
#define TOKEN_BYSLOT            12
#define TOKEN_BYPUBKEY          13
#define TOKEN_BYSUBIDTYPE       14
#define TOKEN_BCBYMAC           15
#define TOKEN_DLBYMAC           16
#define TOKEN_PRINT_INDEX       17
#define TOKEN_PRINT_CACHE       18
#define TOKEN_PRINT_MSG         19
#define TOKEN_PROMPT            20
#define TOKEN_EXIT              21
#define TOKEN_PRINT_CERT        22
#define TOKEN_ISSUER            23
#define TOKEN_CREATE            24
#define TOKEN_SIGN              25
#define TOKEN_USING             26
#define TOKEN_SELF              27
#define TOKEN_CHECK_SANITY      28
#define TOKEN_NEWPAIR           29
#define TOKEN_OPER              30
#define TOKEN_BYSUBJ            31
#define TOKEN_SUBJECT           32
#define TOKEN_SKID              33
#define TOKEN_SERIAL            34
#define TOKEN_GETNEXT_MRU       35
#define TOKEN_STORE_INDEX       36
#define TOKEN_PRINT_KEYSTORE    37
#define TOKEN_ADDMANY           38
#define TOKEN_WALKCHAIN         39
#define TOKEN_ERASEALL          40

#define CERT_ELEMENT_MAXLEN_SERIALNO        9
#define CERT_ELEMENT_MAXLEN_SUBJECT         102
#define CERT_ELEMENT_MAXLEN_ISSUER          102
#define CERT_ELEMENT_MAXLEN_ALTNAMES        8
#define CERT_ELEMENT_MAXLEN_POLICIES        16
#define CERT_ELEMENT_MAXLEN_AUTHKEYID       20
#define CERT_ELEMENT_MAXLEN_SUBJKEYID       20
#define CERT_ELEMENT_MAXLEN_PUBKEY          65
#define CERT_ELEMENT_MAXLEN_NOTAFTER        8
#define CERT_ELEMENT_MAXLEN_SIGNATURE       72
#define CERT_ELEMENT_MAXLEN_ROLE            1

static void hexdump(uint8_t *p, uint32_t size);


int8_t g_strtok_current[512];
char *g_strtok_strptr;
static CertBuffer ram_cert;
static CertBuffer certbuf;

uint8_t der_cert[] = {  
    0x30,0x82,0x02,0x66,0x30,0x82,0x02,0x0d,0xa0,0x03,0x02,0x01,0x02,0x02,0x09,0x00,
    0xfc,0xb8,0xb3,0x15,0x22,0x15,0x91,0x96,0x30,0x09,0x06,0x07,0x2a,0x86,0x48,0xce,
    0x3d,0x04,0x01,0x30,0x64,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
    0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x08,0x0c,0x02,0x6e,0x65,0x31,
    0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x07,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,
    0x06,0x03,0x55,0x04,0x0a,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,
    0x04,0x0b,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x0c,
    0x02,0x6e,0x65,0x31,0x14,0x30,0x12,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
    0x09,0x01,0x16,0x05,0x6e,0x65,0x40,0x6e,0x65,0x30,0x1e,0x17,0x0d,0x31,0x38,0x30,
    0x34,0x30,0x36,0x31,0x34,0x34,0x31,0x31,0x32,0x5a,0x17,0x0d,0x32,0x38,0x30,0x34,
    0x30,0x33,0x31,0x34,0x34,0x31,0x31,0x32,0x5a,0x30,0x64,0x31,0x0b,0x30,0x09,0x06,
    0x03,0x55,0x04,0x06,0x13,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,
    0x08,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x07,0x0c,0x02,
    0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0a,0x0c,0x02,0x6e,0x65,0x31,
    0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0b,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,
    0x06,0x03,0x55,0x04,0x03,0x0c,0x02,0x6e,0x65,0x31,0x14,0x30,0x12,0x06,0x09,0x2a,
    0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01,0x16,0x05,0x6e,0x65,0x40,0x6e,0x65,0x30,
    0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,
    0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xb8,0x4c,0xf9,0x6b,0x9d,0x2d,
    0x8c,0x39,0x38,0xa4,0x8d,0x65,0x67,0x60,0x87,0x6b,0xd4,0x1b,0x39,0x9c,0x02,0x40,
    0x0e,0xa7,0x93,0xba,0x69,0x57,0x9a,0xaf,0xe0,0x13,0x07,0xe8,0x41,0xf0,0xc2,0xdd,
    0x94,0x92,0xff,0xf2,0x62,0xa5,0x79,0x1f,0xaa,0xfc,0x87,0x6d,0xfe,0x9a,0x6b,0xc0,
    0x22,0x50,0xc0,0x6a,0x41,0xc9,0xa7,0x09,0x2c,0xc5,0xa3,0x81,0xa8,0x30,0x81,0xa5,
    0x30,0x1d,0x06,0x03,0x55,0x1d,0x0e,0x04,0x16,0x04,0x14,0x62,0xb0,0x97,0x40,0x79,
    0x26,0x8a,0x40,0x20,0x74,0x72,0xe8,0xd9,0x07,0xd2,0x86,0x6b,0xb7,0x71,0x6e,0x30,
    0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,0x30,0x16,0x80,0x14,0x62,0xb0,0x97,0x40,
    0x79,0x26,0x8a,0x40,0x20,0x74,0x72,0xe8,0xd9,0x07,0xd2,0x86,0x6b,0xb7,0x71,0x6e,
    0x30,0x0f,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x05,0x30,0x03,0x01,0x01,
    0xff,0x30,0x11,0x06,0x03,0x55,0x1d,0x20,0x04,0x0a,0x30,0x08,0x30,0x06,0x06,0x04,
    0x2a,0x03,0x04,0x05,0x30,0x2c,0x06,0x03,0x55,0x1d,0x11,0x04,0x25,0x30,0x23,0xa0,
    0x21,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x81,0xae,0x60,0x0a,0x01,0xa0,0x13,0x04,
    0x11,0x30,0x30,0x2d,0x31,0x34,0x2d,0x32,0x32,0x2d,0x30,0x31,0x2d,0x32,0x33,0x2d,
    0x34,0x35,0x30,0x11,0x06,0x08,0x2d,0x0a,0x32,0x64,0x64,0x32,0x3d,0x32,0x04,0x05,
    0x30,0x03,0x02,0x01,0x0a,0x30,0x09,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x04,0x01,
    0x03,0x48,0x00,0x30,0x45,0x02,0x20,0x59,0x09,0x7a,0xac,0x44,0x71,0x3d,0x24,0x41,
    0x1a,0x5f,0xa5,0xbb,0xd6,0x38,0x93,0x41,0x66,0x06,0x37,0xca,0x52,0xdd,0x4e,0xfc,
    0x8e,0xb9,0x54,0xaa,0x94,0xbb,0xf8,0x02,0x21,0x00,0xf9,0xb6,0xc6,0x13,0x18,0x32,
    0xa6,0x5a,0x72,0x5b,0xdd,0x71,0xc6,0x17,0x0c,0x69,0xa8,0xc0,0xa2,0xd7,0xc4,0x18,
    0x1d,0x82,0xee,0xe4,0xa1,0x91,0xc2,0x79,0x3b,0x06 
};

int8_t *line;

char *commands[] = {
	"editbuf role 2",
	"#root1",
	"editbuf serial *a1",
	"editbuf subject *a1",
	"editbuf flags 0x40",
	"create",
	"sign self",
	"expect pass insert",
	"#root2",
	"editbuf serial *b1",
	"editbuf subject *b1",
	"editbuf flags 0x40",
	"create",
	"sign self",
	"expect pass insert",
	"editbuf serial *a2",
	"editbuf subject *a2",
	"editbuf subjkeyid *a2",
	"editbuf flags 0x80",
	"create",
	"sign using serial *a1",
	"expect pass insert",
	"editbuf serial *a3",
	"editbuf subject *a3",
	"editbuf subjkeyid *a3",
	"create",
	"sign using serial *a2",
	"expect pass insert",
	"expect fail insert",
	"editbuf serial *b2",
	"editbuf subject *b2",
	"editbuf subjkeyid *b2",
	"create",
	"sign using serial *b1",
	"expect pass insert",
	"expect pass find",
	"editbuf serial *b3",
	"editbuf subject *b3",
	"editbuf subjkeyid *b3",
	"editbuf flags 0x280",
	"create",
	"sign using serial *b2",
	"expect pass insert",
    "print_index",
    "print_chain 4",
	"expect pass delete byid serial *b3",
	"editbuf serial *a5",
	"expect fail find",
	"expect fail delete byslot 0",
	"expect pass delete byslot 5",
	"expect pass check_sanity",
	"expect pass find byid serial *a3",
	"expect fail find byid serial *a9",
	"expect fail find byslot 5",
	"expect fail find bcbymac *ae",
	"expect fail find dlbymac *ae",
	"expect pass find byslot 3",
	"expect pass find bysubj subject *a2 skid *a2",
	"expect pass find bysubj subject *a2",
	"expect fail find bysubj subject *a9 skid *a2",
	"expect fail find bysubj subject *a2 skid *a9",

    "#a6 is MFG",
	"editbuf serial *a6",
	"editbuf subject *a6",
	"editbuf subjkeyid *a6",
    "editbuf flags 0x280",
	"create",
	"sign using serial *a1",
	"expect pass insert",

    "#a7 is BC",
    "editbuf serial *a7",
	"editbuf subject *a7",
	"editbuf subjkeyid *a7",
	"editbuf altnames *ae",
    "editbuf flags 0x880",
	"create",
	"sign using serial *a6",
	"expect pass insert",

	"expect pass find bcbymac *ae",

    "#a8 is DLCA",
	"editbuf serial *a8",
	"editbuf subject *a8",
	"editbuf subjkeyid *a8",
    "editbuf flags 0x180",
	"create",
	"sign using serial *a2",
	"expect pass insert",

    "#a9 is DL",
    "editbuf serial *a9",
	"editbuf subject *a9",
	"editbuf subjkeyid *a9",
	"editbuf altnames *ad",
    "editbuf flags 0x480",
	"create",
	"sign using serial *a8",
	"expect pass insert",
	"expect pass find dlbymac *ad",

    "print_index",
	"expect pass find issuer serial *a3",
	"expect pass check_sanity",
	"expect fail delete byslot 0",
	"expect fail delete byslot 9",
	"expect pass delete byid serial *a6",
	"expect fail find oper 0",
	"editbuf serial *a6",
	"editbuf subject *a6",
	"editbuf subjkeyid *a6",
	"editbuf flags 0x98",
	"create",
	"sign using serial *a1",
	"expect pass insert",
	"editbuf serial *aa",
	"editbuf subject *aa",
	"editbuf subjkeyid *aa",
	"editbuf flags 0x98",
	"create",
	"sign using serial *a1",
	"expect pass insert",
    "print_index",
	"expect pass find oper 0",
	"expect pass find oper 5",
	"getnext_mru 0",
	"getnext_mru 5",
	"getnext_mru 6",
	"getnext_mru 4",
	"getnext_mru 8",
	"getnext_mru 7",
	"getnext_mru 3",
	"getnext_mru 2",
	"getnext_mru 1",
	"getnext_mru 255",
	"getnext_mru 10",
	"editbuf serial *ab",
	"editbuf subject *ab",
	"editbuf subjkeyid *ab",
	"editbuf flags 0x80",
	"create",
	"sign using serial *a3",
	"expect pass insert",
	"editbuf serial *ac",
	"editbuf subject *ac",
	"editbuf subjkeyid *ac",
	"editbuf flags 0x80",
	"create",
	"sign using serial *aa",
	"expect pass insert",
    "print_index",
    "print_chain 9",
    "erase_all",
    "print_index",
    NULL
};

#ifdef ELLIPTIC
typedef elpecc_key ECKEY;
#endif

ECKEY *ram_cert_eckey;
ECKEY eckey1, eckey2; 

#define KEY_STORE_SIZE 128
uint8_t auto_serial = 1;
struct ec_key_store {
    uint8_t valid;
    uint8_t serialNumber[CERT_ELEMENT_MAXLEN_SERIALNO];
    uint8_t subject[CERT_ELEMENT_MAXLEN_SUBJECT];
    uint8_t issuer[CERT_ELEMENT_MAXLEN_SUBJECT];
    uint8_t subjkeyid[CERT_ELEMENT_MAXLEN_SUBJKEYID];
    uint8_t authkeyid[CERT_ELEMENT_MAXLEN_AUTHKEYID];
    uint8_t slot_no;
    ECKEY eckey;
    uint8_t pubkey[CERT_ELEMENT_MAXLEN_PUBKEY];
} key_store[KEY_STORE_SIZE];

static void hexdumpnl(uint8_t *p, uint32_t size)
{
    while (size--) printf("%02x",*p++);
}

#define X509_CERT_FLAGS (          \
    "\1CERT_F_READ_ONLY"           \
    "\2CERT_F_VERIFIED"            \
    "\3CERT_F_IS_CA"               \
    "\4CERT_F_HAS_ANY_POLICY"      \
    "\5CERT_F_OPERATOR"            \
    "\7CERT_F_ROOT"                \
    "\10CERT_F_USED"               \
    "\11CERT_F_DLCA"              \
    "\12CERT_F_MFG"              \
)

static void
print_bits(unsigned int v, char *bits)
{
    int i;
    char c;
    int first = 1;

    printf("0x%x", v);
    if (bits) {
        printf("<");
        while ((i = *bits++)) {
            if (v & (1 << (i - 1))) {
                if (!first) {
                    printf(",");
                }
                first = 0;
                while ((c = *bits) > 32) {
                    bits++;
                    printf("%c", c);
                }
            } else {
                while (*bits > 32) {
                    bits++;
                }
            }
        }
        printf(">");
    }
}


static char *cache_strtok(char *src, const char *dilimeter)
{
    static char *s;
    static int pos = 0; 
    int start,j = 0; 

    if( src) {
        pos = 0; 
        s = src; 
    }    
    start = pos; 
    while(s[pos] != '\0')
    {    
        j = 0; 
        while(dilimeter[j] != '\0')
        {    
                if(s[pos] == dilimeter[j])
                {    
                    s[pos] = '\0';
                    if(s[start] == '\0')
                    {    
                        start = pos + 1; 
                        break;
                    }             
                    else 
                    {    
                        pos++;
                        return s + start;
                    }    
                }    
            j++; 
        }    
        pos++;
    }    
    s[pos] = '\0';
    if(s[start] == '\0')
    return NULL;
    else 
    return s + start;
}


static void print_key_store(void)
{
    uint8_t i;

    printf("\n entry   slot      serial                 eckey            "
    "subject                  issuer                   pubkey \n");
    printf("------------------------------------------------------------"
    "------------------------------------------------------------\n");
    for (i = 0; i < KEY_STORE_SIZE; i++) {
        if (key_store[i].valid == VALID) {
            printf("%5d ", i);
            printf("%6d\t",key_store[i].slot_no);
            hexdumpnl(key_store[i].serialNumber,9);
            printf("\t%p\t",&(key_store[i].eckey));
            hexdumpnl(key_store[i].subject,8);printf("\t");
            hexdumpnl(key_store[i].issuer,8);printf("\t");
            hexdumpnl(key_store[i].pubkey,8);printf("\t");
            printf("\n");
        }
    }
}


static void sync_keypair_with_cache(void);

static void clear_ec_key_store(void)
{
}

#ifdef ELLIPTIC
static int8_t create_new_ec_key_pair(ECKEY *eckey, uint8_t *pubkey)
{
    int ret;
    unsigned long outlen = 65;

    /* only 32 byte EC key supported. */
    //ret = elpecc_make_key(NULL,&elpsprng_plugin, 256/8, eckey);
    ret = elpecc_make_key(NULL,&sys_prng, 256/8, eckey);
    if (ret != ELPEOK) {
        printf("EC_KEY_generate_key() failed (%d)\n",ret);
        return 1;
    }
    ram_cert_eckey = eckey;

    /* export key to populate pubkey */
    ret = elpecc_ansi_x963_export(pubkey, &outlen, eckey);
    if (ret != ELPEOK) {
        printf("elpecc_ansi_x963_export() failed (%d)\n",ret);
        return 1;
    }

    return 0;
}

static uint8_t sign_cert(CertBuffer *pcert, ECKEY *eckey,
                  uint8_t *pubkey,uint8_t *issuer,
                  uint8_t *authkeyid)
{
#define SHA256_DIGEST_LENGTH    (256/8) 
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t signature[256],i;
    long unsigned int siglen = 128, hashlen = 256/8;
    elphash_state hstate;
    int ret;

    /* update issuer  & AuthKeyID before hash */
    memcpy(pcert->buffer+pcert->dc.issuer.idx,
           issuer, CERT_ELEMENT_MAXLEN_SUBJECT);
    memcpy(pcert->buffer+pcert->dc.AuthKeyID.idx,
           authkeyid, CERT_ELEMENT_MAXLEN_AUTHKEYID);

    elpsha256_init(ELPHASH_NOBLOCK,&hstate);
    elpsha256_process(pcert->buffer + pcert->dc.tbsCertificate.idx,
                     pcert->dc.tbsCertificate.len, &hstate);
    elpsha256_done(hash, &hashlen, &hstate);

    //do sign
    ret = elpecc_sign_hash(hash, SHA256_DIGEST_LENGTH, signature,
                           &siglen, NULL, &sys_prng, eckey);
    if (ret != ELPEOK) {
        printf("Error elpecc_sign_hash(), ret = %d\n",ret);
        return 1;
    }
    //update issuer in keystore
    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(pcert->buffer + pcert->dc.serialNumber.idx, 
                        key_store[i].serialNumber, 
                        CERT_ELEMENT_MAXLEN_SERIALNO)) {
                memcpy(key_store[i].issuer, issuer, 
                        CERT_ELEMENT_MAXLEN_SUBJECT); 
            }
        }
    }

    //update signature in pcert
    /* assuming signature is already in DER format */
    if (siglen > 0 && siglen <= CERT_ELEMENT_MAXLEN_SIGNATURE ) {
        memcpy(pcert->buffer + pcert->dc.signatureValue.idx,
               signature, siglen);
        pcert->dc.signatureValue.len = siglen;
    }
    else{
        printf("Error signature too long (%lu).\n",siglen);
        return 1;
    }
    
    return 0;
}
#endif

static void add_keypair_to_store(uint8_t *serialNumber, uint8_t *subject,
                          ECKEY *eckey,uint8_t *pubkey, uint8_t *subjkeyid )
{
    uint8_t i,found=0;

    for(i = 0;i < KEY_STORE_SIZE;i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(key_store[i].serialNumber, serialNumber,
                        CERT_ELEMENT_MAXLEN_SERIALNO)){
                found = 1;
                break;  
            }
        }

    }
    //check for free entry
    if(!found){
        for(i = 0;i < KEY_STORE_SIZE;i++)
            if(key_store[i].valid == INVALID) break;
    }
    //add to the list
    memcpy(&(key_store[i].serialNumber), serialNumber,
             CERT_ELEMENT_MAXLEN_SERIALNO); 
    memcpy(&(key_store[i].subject), subject,
             CERT_ELEMENT_MAXLEN_SUBJECT); 
    memcpy(&(key_store[i].subjkeyid), subjkeyid,
             CERT_ELEMENT_MAXLEN_SUBJKEYID); 
    key_store[i].eckey = *eckey;
    memcpy(key_store[i].pubkey,pubkey,sizeof(key_store[i].pubkey));
    key_store[i].valid = VALID; 
}

extern struct cache_index cache_index;

static void sync_keypair_with_cache(void)
{
    uint8_t i,used_entry;
    for (i = 0; i< KEY_STORE_SIZE; i++)
        key_store[i].valid = INVALID;
    used_entry = 0;
    used_entry = cache_get_next_mru(used_entry);
    while (used_entry != LIST_END_MARKER) {
    for(i = 0;i < KEY_STORE_SIZE;i++){
            if (key_store[i].slot_no == used_entry){ 
                key_store[i].valid = VALID;
                break;
        }   
    }
        used_entry = cache_get_next_mru(used_entry);
}

}

static void update_issuer_to_store(uint8_t *serialNumber, 
                                    uint8_t *issuer,
                                    uint8_t *authkeyid)
{
    uint8_t i;

    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(key_store[i].serialNumber, 
                        serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
                memcpy(&(key_store[i].issuer), issuer, 
                        CERT_ELEMENT_MAXLEN_ISSUER); 
                memcpy(&(key_store[i].authkeyid), authkeyid,
                        CERT_ELEMENT_MAXLEN_AUTHKEYID); 
            }
        }
    }
}

static error_t get_subjkeyid_from_store(uint8_t *serialNumber, 
                                    uint8_t **issuer_subjkeyid)
{
    uint8_t i;

    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(key_store[i].serialNumber, serialNumber,
                        CERT_ELEMENT_MAXLEN_SERIALNO)) {
                *issuer_subjkeyid = key_store[i].subjkeyid;
                return 0;
            }
        }
    }
    return 1;
}

static void update_slotno_to_store(uint8_t *serialNumber, uint8_t slot_no)
{
    uint8_t i;
    uint8_t slot_match = 0,serial_match = 0,match_count = 0;

    /* if there exists an entry with given slot_no, then that entry shall be
     * updated with the entry matching given serialNumber
	 */
    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (key_store[i].slot_no == slot_no) { 
                slot_match = i;
                match_count |= 1<<0;
            }    
            if (!memcmp(key_store[i].serialNumber, serialNumber,
                        CERT_ELEMENT_MAXLEN_SERIALNO)) {
                serial_match = i;
                match_count |= 1<<1;
            }
            if (match_count == 3) break;
        }
    }
    if (!(match_count & 2)) return; 
    if (match_count & 1) {
        key_store[slot_match] = key_store[serial_match];
        key_store[slot_match].slot_no = slot_no;
    }
    else {
        key_store[serial_match].slot_no = slot_no;
    }
}

static uint8_t get_keypair_from_store(uint8_t *serialNumber, ECKEY *eckey,
                             uint8_t **pubkey, uint8_t *subject)
{
    uint8_t i;

    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(key_store[i].serialNumber, serialNumber,
                        CERT_ELEMENT_MAXLEN_SERIALNO)) {
                *eckey = key_store[i].eckey;
                *pubkey = key_store[i].pubkey;
                memcpy(subject, key_store[i].subject,
                        CERT_ELEMENT_MAXLEN_SUBJECT);
                return 0;
            }
        }
    }

    return 1;
}

static uint8_t get_issuer_from_store(uint8_t *serialNumber, uint8_t *issuer)
{
    uint8_t i;

    for (i = 0; i < KEY_STORE_SIZE; i++){
        if(key_store[i].valid == VALID){
            if (!memcmp(key_store[i].serialNumber, serialNumber,
                        CERT_ELEMENT_MAXLEN_SERIALNO)) {
                memcpy(issuer, key_store[i].issuer, 
                        CERT_ELEMENT_MAXLEN_ISSUER);
                return 0;
            }
        }
    }
    return 1;
}

static uint8_t get_token_id(char *string)
{
    if (!strcmp(string, "expect")) return TOKEN_EXPECT;
    if (!strcmp(string, "pass")) return TOKEN_PASS;
    if (!strcmp(string, "fail")) return TOKEN_FAIL;
    if (!strcmp(string, "editbuf")) return TOKEN_EDITBUF;
    if (!strcmp(string, "insert")) return TOKEN_INSERT;
    if (!strcmp(string, "delete")) return TOKEN_DELETE;
    if (!strcmp(string, "find")) return TOKEN_FIND;
    if (!strcmp(string, "byid")) return TOKEN_BYID;
    if (!strcmp(string, "byslot")) return TOKEN_BYSLOT;
    if (!strcmp(string, "bcbymac")) return TOKEN_BCBYMAC;
    if (!strcmp(string, "dlbymac")) return TOKEN_DLBYMAC;
    if (!strcmp(string, "issuer")) return TOKEN_ISSUER;
    if (!strcmp(string, "create")) return TOKEN_CREATE;
    if (!strcmp(string, "sign")) return TOKEN_SIGN;
    if (!strcmp(string, "using")) return TOKEN_USING;
    if (!strcmp(string, "self")) return TOKEN_SELF;
    if (!strcmp(string, "check_sanity")) return TOKEN_CHECK_SANITY;
    if (!strcmp(string, "addmany")) return TOKEN_ADDMANY;
    if (!strcmp(string, "print_chain")) return TOKEN_WALKCHAIN;
    if (!strcmp(string, "erase_all")) return TOKEN_ERASEALL;

    if (!strcmp(string, "oper")) return TOKEN_OPER;
    if (!strcmp(string, "bysubj")) return TOKEN_BYSUBJ;
    if (!strcmp(string, "subject")) return TOKEN_SUBJECT;
    if (!strcmp(string, "skid")) return TOKEN_SKID;
    if (!strcmp(string, "serial")) return TOKEN_SERIAL;
    if (!strcmp(string, "getnext_mru")) return TOKEN_GETNEXT_MRU;

    if (!strcmp(string, "store_index")) return TOKEN_STORE_INDEX;
    if (!strcmp(string, "print_index")) return TOKEN_PRINT_INDEX;
    if (!strcmp(string, "print_cache")) return TOKEN_PRINT_CACHE;
    if (!strcmp(string, "print_cert")) return TOKEN_PRINT_CERT;
    if (!strcmp(string, "print")) return TOKEN_PRINT_MSG;
    if (!strcmp(string, "print_keystore")) return TOKEN_PRINT_KEYSTORE;

    if (!strcmp(string, "prompt")) return TOKEN_PROMPT;
    if (!strcmp(string, "exit")) return TOKEN_EXIT;

    return 0;
}

static void strip_last_newline(char *string)
{
    if (!string) return;
    uint32_t j = strlen(string);
    for (; j; j--) {
        if (string[j] == '\n') {
            string[j] = '\0';
            return;
        }
    }
}

static int8_t hexdigit_to_dec(char c, uint8_t *dec){
    if (c == '\0') {
        *dec = 0;
        return 0;
    }
    if ( (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
        *dec = 10 + c - 'a';
        return 0;
    }
    if (c >= '0' && c <= '9') {
        *dec = c - '0';
        return 0;
    }
    return -1;
}

static void hexstr_to_byte(char *hstr, uint8_t *byte)
{
    uint8_t dec;
    int ret = 0, skip = 0;
    if (hstr[0] == '0' && hstr[1] == 'x') {
        skip = 2;
    }
    ret = hexdigit_to_dec(hstr[1 + skip], byte);
    assert(ret == 0);
    ret = hexdigit_to_dec(hstr[0 +skip], &dec);
    assert(ret == 0);
    *byte += dec*16;
}

static void hexstr_to_word(char *hstr, uint16_t *word)
{
    uint8_t part,l;
    char padded_str[4];
    uint8_t i, j;

    if (hstr[0] == '0' && hstr[1] == 'x') {
        hstr+=2;
    }
    l = strlen(hstr);
    for(i = 0; i < 4-l; i++)
        padded_str[i] = '0';
    for(j = 0; j < l; j++)
        padded_str[i++] = *hstr++;

    hexstr_to_byte(padded_str,&part);
    *word = 256 * part;
    hexstr_to_byte(padded_str+2,&part);
    *word += part;
}

static uint8_t powerbase10(int i)
{
    uint8_t ret = 1;
    while(i--)
        ret *=10;
    return ret;
}

static int str_to_byte(char *string, uint8_t *byte)
{
    uint8_t len;
    int i;

    if (!string) return -1;
    len = strlen(string);

    if (len > 3) return -1;
    i = len;
    *byte = 0;
    while(i) {
        *byte += (string[i-1] - '0')*(powerbase10((len-i)));
        i--;
    }
    return 0;
}

static char *get_first_token(char *string)
{
    char *retstr;

    memcpy(g_strtok_current, string, sizeof(g_strtok_current));
    g_strtok_strptr = string;
    retstr = cache_strtok((char *)g_strtok_current," ;");
    if (retstr && strstr(retstr,"\n"))
        strip_last_newline(retstr);

    return retstr;
}

static char *get_next_token(char *string)
{
    char *retstr;

    if (g_strtok_strptr != string) {
        printf("Incorrect current string.\n");
        return NULL;
    }
    retstr = cache_strtok(NULL," ");
    if (retstr && strstr(retstr,"\n"))
        strip_last_newline(retstr);

    return retstr;
}

static void hexdump(uint8_t *p, uint32_t size)
{
    while (size--) printf("%02x",*p++);
    printf("\n");
}

static void sscan_octets(void *string, void *dest, uint8_t no_of_octets)
{
    uint8_t i, *cursor;

    for (i=0; i < no_of_octets; i++) {
        cursor = ((uint8_t *)(dest)) + i;
        hexstr_to_byte((char *)string + i*2,cursor);
    }
}

static char *get_algoid_string(uint8_t *signalgo, uint16_t len)
{
    uint8_t oid_ecdsa_sha1[] = {42, 134, 72, 206, 61, 4, 1 };
    if (!memcmp(signalgo+4,oid_ecdsa_sha1, 7))
        return "ecdsa-with-sha1";
    return "unknown-algo";
}

static void print_pcert(CertBuffer *cb)
{
    printf("CertBuffer@%p  (fileds marked ^ are truncated)\n",cb);
    printf("CertBuff->certVersion: ");
    hexdump((uint8_t *)&(cb->dc.certVersion), 1);
    printf("Certbuff->flags: ");
    print_bits(cb->dc.flags, X509_CERT_FLAGS);
    printf("\n");
    printf("CertBuff->signAlgoID: %s\n",
            get_algoid_string(cb->buffer + cb->dc.signatureAlgorithm.idx,
                                 cb->dc.signatureAlgorithm.len));
    printf("CertBuff->serialNumber: ");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.serialNumber.idx]),
             cb->dc.serialNumber.len);
    printf("CertBuff->subject: ^");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.subject.idx]), 16);
    printf("CertBuff->issuer: ^");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.issuer.idx]), 16);
    printf("CertBuff->subjectPublicKey: ^");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.subjectPublicKey.idx]), 16);
    printf("CertBuff->AltNames: ");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.AltNames.idx]),
            cb->dc.AltNames.len);
    printf("CertBuff->AuthKeyID: ");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.AuthKeyID.idx]),
            cb->dc.AuthKeyID.len);
    printf("CertBuff->SubjKeyID: ");
    hexdump((uint8_t *)&(cb->buffer[cb->dc.SubjKeyID.idx]),
            cb->dc.SubjKeyID.len);
    printf("CertBuff->valid_notBefore: ");
    printf("%lu\n",cb->dc.notBefore);
    printf("CertBuff->valid_notAfter : ");
    printf("%lu\n",cb->dc.notAfter);
    printf("CertBuff->signatureOID : ");
    printf("%d\n",cb->dc.signatureOID);
    printf("CertBuff->signatureValue:(%d) ^",cb->dc.signatureValue.len);
    hexdump((uint8_t *)&(cb->buffer[cb->dc.signatureValue.idx]), 16);
    printf("\n");
}

const char help_string[] = \
               "x509cache\n"
               "\n"
               "General instructions for input command set:\n"
               "1. Sequence of command arguments MUST be same as in syntax.\n"
               "2. extra whitespace may cause undefined behavior\n"
               "3. command starting with '#' IN FIRST COLUMN only is comment.\n"
               "\n"
               "GENERAL commands\n"
               "expect pass|fail <INSERTcommand|FINDcommand"
               "|DELETEcommand|SIGNATUREcommand>\n"
               "print_index\n"
               "print_cache\n"
               "print_cert [index]\n"
               "print <string>\n"
               "prompt\n"
               "exit\n"
               "\n"
               "INSERT commands\n"
               "insert\n"
               "\n"
               "EDITBUF commands\n"
               "editbuf serial <8-octets>|*<octet>\n"
               "editbuf subject <102-octets>|*<octet>\n"
               "editbuf issuer <102-octets>|*<octet>\n"
               "editbuf altnames <8-octets>|*<octet>\n"
               "editbuf policies <8-octets>|*<octet>\n"
               "editbuf authkeyid <16-octets>|*<octet>\n"
               "editbuf subjkeyid <16-octets>|*<octet>\n"
               "editbuf pubkey <65-octets>|*<octet>\n"
               "editbuf notafter <8-octets>|*<octet>\n"
               "\n"
               "FIND commands\n"
               "find\n"
               "find byid serial <8-octets>|*<octet>\n"
               "find byslot <slot_no>\n"
               "find bysubj subject <102-octets>|*<octet>"
               " skid <16-octets>|*<octet>\n"
               "find oper <slot_no>\n"
               "find bcbymac <8-octets>|*<octet>\n"
               "find dlbymac <8-octets>|*<octet>\n"
               "find issuer serial <8-octets>|*<octet>\n"
               "\n"
               "DELETE commands\n"
               "delete byslot <slot_no>\n"
               "delete byid serial <8-octets>|*<octet>\n"
               "\n"
               "SIGNATURE commands\n"
               "create\n"
               "\tcreate key pair for ram_cert, store in"
               " keypair_store and set pubkey of ram_cert.\n"
               "sign self | (using serial <8-octets>|*<octet>)\n"
               "\tsign\n"
               "\t\tsign using keypair of root certificate\n"
               "\tsign using serial <8-ocetes>|*<octet>\n"
               "\t\tsign using keypair of specified certificate\n"
               "\tsign self\n"
               "\t\tsign using keypair of ram_cert.\n"
               ;

void help(void)
{
    printf("%s\n",help_string);
}

static void parse_hexstring(void *string, void *ptr, uint8_t len)
{
    uint8_t tval;
    char *token = (char *)string;

    if (token[0] == '*') {
        hexstr_to_byte(token+1,&tval);
        memset(ptr,tval,len);
    }
    else
        sscan_octets(token, ptr, len);
}


static void report_result(char *result, int8_t errcode,
                    int8_t *line, uint32_t lno)
{
    if (line){
        strip_last_newline((char *)line);
        if (errcode)
            printf("!Result %s (%d). [Line %d: %s]\n",result,
                    errcode, lno,line);
        else
            printf("!Result %s. [Line %d: %s]\n",result, lno,line);
    }
    else
        printf("%s.\n",result);
}

static void check_and_report_result(error_t libret,
                     uint8_t expected_result,
                     int8_t *line, uint32_t lc)
{
    if (    (libret == ERR_OK && expected_result == RESULT_PASS) ||
            (libret == ERR_CACHE_FIND_NO_MATCH &&
             expected_result == RESULT_FAIL) ||
            (libret == ERR_OK && expected_result == RESULT_PASS) ||
            (libret != ERR_OK && expected_result == RESULT_FAIL) )
        report_result("Ok",0,NULL,lc);
    else {
        report_result("FAIL",libret,line,lc);
    }
}

static void print_index(void)
{
    uint8_t curr;
    int nl = 1, count = 0;
    uint8_t *serial,issuer_slot;

    //traverse used_list;
    printf("Used list:\n");
    if (cache_index.used_list_head == LIST_END_MARKER) {
        printf("Empty.\n");
    }
    else {
        curr = cache_index.used_list_head;
        while (cache_index.cache_lists[curr].next != LIST_END_MARKER) {
            cert_cache_read_cert(&certbuf, curr);
            count++;
            serial = (unsigned char *)
                     (certbuf.buffer+certbuf.dc.serialNumber.idx);
            issuer_slot = cache_index.cache_lists[curr].issuer_slot;
            printf("[%03u(%02x%02x)(%03u)]->", curr, serial[0],
                     serial[1],issuer_slot);
            if (nl % 4 == 0 ) printf("\n");nl++;
            curr = cache_index.cache_lists[curr].next;
        }
        cert_cache_read_cert(&certbuf, curr);
        serial = (unsigned char *)
                 (certbuf.buffer+certbuf.dc.serialNumber.idx);
        issuer_slot = cache_index.cache_lists[curr].issuer_slot;
        printf("[%03u(%02x%02x)(%03u)]\n", curr, serial[0],
                 serial[1],issuer_slot);
        printf("%d items.\n",count + 1);
    } 
    //traverse free list;
    printf("Free list:\n");
    nl = 1;
    count = 0;
    if (cache_index.free_list_head == LIST_END_MARKER) {
        printf("Empty.\n");
    }
    else {
        curr = cache_index.free_list_head;
        while (cache_index.cache_lists[curr].next != LIST_END_MARKER) {
            printf("[%03u]->", curr);
            count++;
            if (nl % 10 == 0 ) printf("\n");nl++;
            curr = cache_index.cache_lists[curr].next;
        }
        printf("[%03u]\n", curr);
        printf("%d items.\n",count + 1);
    }

}

static error_t parse_der_cert(CertBuffer *ram_cert)
{
    error_t ret;
    memcpy(ram_cert->buffer, der_cert, sizeof(der_cert));
    mnicInitDecodedCert(&ram_cert->dc, ram_cert->buffer, sizeof(der_cert), NULL); 
    ret = mnicParseCert(&ram_cert->dc,0);

    if (ret != ERR_OK ) {
        printf("Error parsing DER form of certificate.\n");
        return ret;
    }
    return ERR_OK;      
}


static char *get_next_command(void)
{
    static uint16_t curr_cmd = 0;
    return commands[curr_cmd++];
}

#define CMD_FAILED  1
static CertBuffer find_result_pcert, find_result_issuer; 
static uint32_t lc = 0, cmdcount = 0;
static uint8_t expected_result = RESULT_PASS;
static error_t libret = ERR_OK;
static uint8_t done = 0, prompt = 0;

int test_init(int *exit_code)
{
    return 0;
}


static void process_token(char *token);

int x509cache_tests(int *exit_code)
{
    uint8_t i;

    printf("start x509cache test...\n");
    //nxp_init();
    elp_mp = elpmath_desc;
    //libret = nxp_power_control(1);
    prompt = 0;

    libret = parse_der_cert(&ram_cert);
    if (libret != ERR_OK) {
        printf("Error initializing ram_cert. error %d\n",libret);
        return CMD_FAILED;
    }

    //initialize the variable valid to INVALID in key_store
    for(i=0;i < KEY_STORE_SIZE;i++)
        key_store[i].valid = INVALID;

    while (!done){
        if (!prompt) {
            if ( (libret != ERR_OK && expected_result == RESULT_PASS) ||
                 (libret == ERR_OK && expected_result == RESULT_FAIL) ) {
                //a test failed.
                clear_ec_key_store();
                cache_uninit();
                return CMD_FAILED;
            }
            line = (int8_t *)get_next_command();
            if (!line || line[0] == '\0') {
                done = 1;
                continue;
            }
        }
        else {
            //show prompt
            printf("==> ");
            //TODO read command from stdin to line
        }
        if (line == NULL) continue;
        lc++;
        if (line[0] == '#' || line[0] == '\n') continue;

        if (!prompt) {
                printf("[cmd%03d] %s => ",++cmdcount,line);
        }

        //process this line
        char *token;
        libret = ERR_OK;
        expected_result = RESULT_PASS; //default is to assume PASS
        token = get_first_token((char *)line);
        process_token(token);
    }

    clear_ec_key_store();
    cache_uninit();

    printf("All done.\n");
    *exit_code = 0;
    return 1;
}


static void process_token_expect(char *token)
{
    token = get_next_token((char *)line);
    if (get_token_id(token) == TOKEN_FAIL) {
        expected_result = RESULT_FAIL;
        return;
    }
    if (get_token_id(token) == TOKEN_PASS) {
        expected_result = RESULT_PASS;
        return;
    }
    printf("Incorrect result keyword for expect command\n");
}

static void process_token_editbuf(char *token)
{
    //read param and value from next tokens and update cert buffer
    token = get_next_token((char *)line);

    if (!strcmp(token,"serial")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.serialNumber.idx,
                CERT_ELEMENT_MAXLEN_SERIALNO);
    }

    if (!strcmp(token,"subject")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.subject.idx,
                CERT_ELEMENT_MAXLEN_SUBJECT);
    }

    if (!strcmp(token,"issuer")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.issuer.idx,
                CERT_ELEMENT_MAXLEN_ISSUER);
    }

    if (!strcmp(token,"altnames")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.AltNames.idx,
                CERT_ELEMENT_MAXLEN_ALTNAMES);
        ram_cert.dc.AltNames.len = CERT_ELEMENT_MAXLEN_ALTNAMES;
    }

    if (!strcmp(token,"authkeyid")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.AuthKeyID.idx,
                CERT_ELEMENT_MAXLEN_AUTHKEYID);
    }
    if (!strcmp(token,"subjkeyid")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.SubjKeyID.idx,
                CERT_ELEMENT_MAXLEN_SUBJKEYID);
    }
    if (!strcmp(token,"pubkey")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx,
                CERT_ELEMENT_MAXLEN_PUBKEY);
    }
    if (!strcmp(token,"notafter")){
        token = get_next_token((char *)line);
        parse_hexstring(token, 
                &ram_cert.dc.notAfter, 
                CERT_ELEMENT_MAXLEN_NOTAFTER);
    }
    if (!strcmp(token,"role")){
        token = get_next_token((char *)line);
        uint8_t val;
        str_to_byte(token, &val);
        ram_cert.dc.num_roles = CERT_ELEMENT_MAXLEN_ROLE;
        ram_cert.dc.roles[0] = val;
    }
    if (!strcmp(token,"flags")){
        token = get_next_token((char *)line);
        uint16_t val;
        hexstr_to_word(token,&val);
        ram_cert.dc.flags = val;
    }
    report_result("Ok",0,NULL,lc);
}

static void process_token_insert(char *token)
{
    uint16_t slot = 0;
    libret = cache_insert_cert(&ram_cert, &slot);
    /* reset issuer_slot */
    ram_cert.dc.issuer_slot = 0; 
    if (libret == ERR_OK) 
        update_slotno_to_store(ram_cert.buffer + 
                    ram_cert.dc.serialNumber.idx,
                    slot);
    sync_keypair_with_cache();
    check_and_report_result(libret, expected_result, line, lc);
}

static void process_token_delete(char *token)
{
    uint16_t slot_to_delete = 0;
    uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
    uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];

    token = get_next_token((char *)line);
    if (!strcmp(token,"byslot")){
        token = get_next_token((char *)line);
        str_to_byte(token,(uint8_t *)&slot_to_delete);
        libret = cache_delete_entry(slot_to_delete);
    }
    if (!strcmp(token,"byid")){
        //find and delete
        token = get_next_token((char *)line);
        if (token == NULL) {
            printf("Line %d: Not enough parameters for delete byid."
                " [syntax: delete byid serial <val>]\n",lc);
            return;
        }

        if (!strcmp(token,"serial")){
            token = get_next_token((char *)line);
            if (token == NULL) 
            {
                printf("Line %d: Not enough parameters for delete byid."
                    " [syntax: delete byid serial <val>]\n",lc);
                return;
            }
            parse_hexstring(token, serial, CERT_ELEMENT_MAXLEN_SERIALNO);
        }
        //get issuer from key-store
        libret = get_issuer_from_store(serial, issuer);
        if (libret){
            check_and_report_result(libret, expected_result, line, lc);
            return;
        } 

        libret = cache_find_by_issuer_and_serial(issuer,
                        CERT_ELEMENT_MAXLEN_ISSUER, 
                        serial, CERT_ELEMENT_MAXLEN_SERIALNO,
                        &certbuf, &slot_to_delete);
        if (libret != ERR_OK) {
            check_and_report_result(libret, expected_result, line, lc);
            return;
        }

        libret = cache_delete_entry(slot_to_delete);
    }
    sync_keypair_with_cache();
    check_and_report_result(libret, expected_result, line, lc);
}

static void process_subtoken_find(char *token)
{
    uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
    uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];
    uint16_t slot = 0;

    switch(get_token_id(token)){
        case TOKEN_BYID:
            {
                token = get_next_token((char *)line);
                if (token == NULL){
                    printf("Line %d: Not enough parameters for find byid.\
                        [syntax: find byid serial <val>]\n",lc);
                    return;
                }
                if (!strcmp(token,"serial")){
                    token = get_next_token((char *)line);
                    parse_hexstring(token, &serial,
                        CERT_ELEMENT_MAXLEN_SERIALNO);
                }
                libret = get_issuer_from_store(serial, issuer);
                if (libret) {
                    //no valid entry in key store. test API with invalid input
                    memset(issuer, 0, CERT_ELEMENT_MAXLEN_ISSUER);
                }
                libret = cache_find_by_issuer_and_serial(issuer,
                        CERT_ELEMENT_MAXLEN_ISSUER, 
                        serial, CERT_ELEMENT_MAXLEN_SERIALNO,
                        &find_result_pcert, &slot);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_BYSLOT:
            {
                uint8_t slotno;
                token = get_next_token((char *)line);
                str_to_byte(token,&slotno);
                libret =  cache_find_by_slot_number(slotno, &find_result_pcert);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_BCBYMAC:
            {
                uint8_t mac_addr[8];
                token = get_next_token((char *)line);
                parse_hexstring(token, mac_addr, 8);
                libret = cache_find_BC_by_MAC_address(mac_addr,
                            &find_result_pcert, &slot);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_DLBYMAC:
            {
                uint8_t mac_addr[8];
                token = get_next_token((char *)line);
                parse_hexstring(token, mac_addr, 8);
                libret = cache_find_DL_by_MAC_address(mac_addr,
                            &find_result_pcert, &slot);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_ISSUER:
            {
                uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
                uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];

                token = get_next_token((char *)line);
                if (token == NULL){
                    printf("Line %d: Not enough or incorrect sequence of"
                        " parameters for find issuer."
                        " [syntax: find issuer certid <val> sysid <val>]\n",lc);
                    break;
                }
                if (!strcmp(token,"serial")){
                    token = get_next_token((char *)line);
                    parse_hexstring(token, &serial, 
                            CERT_ELEMENT_MAXLEN_SERIALNO);
                }
                libret = get_issuer_from_store(serial, issuer);
                if (libret){
                    check_and_report_result(libret, expected_result, line, lc);
                    break;
                }
                libret = cache_find_by_issuer_and_serial(issuer,
                                CERT_ELEMENT_MAXLEN_ISSUER, 
                                serial, CERT_ELEMENT_MAXLEN_SERIALNO,
                                &find_result_pcert, &slot);
                if (libret != ERR_OK) {
                    printf("cert not found.\n");
                    check_and_report_result(libret, expected_result, line, lc);
                    break;
                }
                libret = cache_find_issuer(&find_result_pcert, 
                                &find_result_issuer, &slot);
                if (libret == ERR_OK) {
                    printf("IssuerSerial:");
                    uint8_t *serial = (uint8_t *)(find_result_issuer.buffer + 
                            find_result_issuer.dc.serialNumber.idx);
                    hexdumpnl(serial, find_result_issuer.dc.serialNumber.len);
                    printf("  ");
                }
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_BYSUBJ:
            {
                uint8_t subject[CERT_ELEMENT_MAXLEN_SUBJECT];   
                uint8_t skid[CERT_ELEMENT_MAXLEN_SUBJKEYID];    

                token = get_next_token((char *)line);
                if (token == NULL){
                    printf("Line %d: Not enough or incorrect sequence of"
                        " parameters for find bysubj. "
                        "syntax: find bysubj subject <val> [skid <val>]n",lc);
                    break;
                }
                if (!strcmp(token,"subject")){
                    token = get_next_token((char *)line);
                    parse_hexstring(token, &subject, 
                            CERT_ELEMENT_MAXLEN_SUBJECT);
                }
                token = get_next_token((char *)line);
                if (token == NULL) {
                    //if no skid, search only by subject
                    libret = cache_find_by_subject_and_SKID(subject, 
                            CERT_ELEMENT_MAXLEN_SUBJECT,
                            NULL, 0,&find_result_pcert, &slot);
                    check_and_report_result(libret, expected_result, line, lc);
                    break;
                }
                if (!strcmp(token,"skid")){
                    token = get_next_token((char *)line);
                    parse_hexstring(token, &skid,
                            CERT_ELEMENT_MAXLEN_SUBJKEYID);
                }
                libret = cache_find_by_subject_and_SKID(subject,
                            CERT_ELEMENT_MAXLEN_SUBJECT, skid,
                            CERT_ELEMENT_MAXLEN_SUBJKEYID,
                            &find_result_pcert, &slot);
                check_and_report_result(libret, expected_result, line, lc);
                break;
            }
            break;
        case TOKEN_OPER:
            {
                uint16_t slotno = 0;
                token = get_next_token((char *)line);
                str_to_byte(token,(uint8_t *)&slotno);
                libret = cache_find_next_operator_cert(&find_result_pcert,
                                &slotno);
                if (libret == ERR_OK) printf("found@slot %d ", slotno);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        default:
            printf("Unsupported specifier %s for find.\n", token);
            break;
    }
}

static void process_token_find(char *token)
{
    uint16_t slot = 0;

    token = get_next_token((char *)line);
    if (token == NULL){
        //no arguments to find. Try find "ram_cert" in cache
        libret = cache_find_cert(&ram_cert, &slot);
        check_and_report_result(libret, expected_result, line, lc);
        return;
    }
    process_subtoken_find(token);
}

static void process_token_create(char *token)
{
    uint8_t pubkey[CERT_ELEMENT_MAXLEN_PUBKEY];
    //create key pair, store in keypair_store and set pubkey of ram_cert
    create_new_ec_key_pair(&eckey1, pubkey);
    add_keypair_to_store(
            (uint8_t *)ram_cert.buffer + ram_cert.dc.serialNumber.idx, 
            (uint8_t *)ram_cert.buffer + ram_cert.dc.subject.idx, &eckey1,
            pubkey, 
            (uint8_t *)ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
    memcpy(ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx, pubkey,
            CERT_ELEMENT_MAXLEN_PUBKEY);
    //TODO: update AuthKeyID and subjKeyID
    /*
       For CA certificates, subject key identifiers SHOULD be derived from
       the public key or a method that generates unique values.  Two common
       methods for generating key identifiers from the public key are:

       (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
       value of the BIT STRING subjectPublicKey (excluding the tag,
       length, and number of unused bits).

       (2) The keyIdentifier is composed of a four bit type field with
       the value 0100 followed by the least significant 60 bits of the
       SHA-1 hash of the value of the BIT STRING subjectPublicKey
       (excluding the tag, length, and number of unused bit string bits).

       One common method for generating unique values is a monotonically
       increasing sequence of integers.
     */
    check_and_report_result(ERR_OK, expected_result, line, lc);
}

inline static void print_sign_command_usage(void)
{
    printf("Line %d: Not enough or incorrect sequence"
            " of parameters for \"sign using\".\n",lc);
    printf("sign self | (using serial <8-octets>|*<octet>)\n");
}

static void process_token_sign(char *token)
{
    ECKEY signer_key;
    uint8_t *signer_pubkey = NULL,*issuer_subjkeyid;
    uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
    uint8_t subject[CERT_ELEMENT_MAXLEN_ISSUER];

    token = get_next_token((char *)line);
    if (token == NULL){
        //no arguments to sign command. display usage
        print_sign_command_usage();
        return;
    }
    switch(get_token_id(token)){
        case TOKEN_USING:
            {
                token = get_next_token((char *)line);
                if (token == NULL){
                    print_sign_command_usage();
                    break;
                }
                if (!strcmp(token,"serial")){
                    token = get_next_token((char *)line);
                    if (token == NULL){
                        print_sign_command_usage();
                        break;
                    }
                    parse_hexstring(token, &serial, 
                            CERT_ELEMENT_MAXLEN_SERIALNO);
                }
                get_keypair_from_store(serial,&signer_key,
                            &signer_pubkey,subject);
                get_subjkeyid_from_store(serial, &issuer_subjkeyid);
                libret = sign_cert(&ram_cert,&signer_key,signer_pubkey,
                                    subject,issuer_subjkeyid);
                if (libret != ERR_OK) {
                    printf("sign_cert returned Error\n");
                    break;
                }
                update_issuer_to_store(
                        ram_cert.buffer + ram_cert.dc.serialNumber.idx,
                        subject, issuer_subjkeyid);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        case TOKEN_SELF:
            {
                //sign using keypair of ram_cert
                libret = sign_cert(&ram_cert, ram_cert_eckey, 
                           ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx,
                           ram_cert.buffer + ram_cert.dc.subject.idx, 
                           ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
                memcpy(ram_cert.buffer + ram_cert.dc.issuer.idx, 
                        ram_cert.buffer + ram_cert.dc.subject.idx, 
                        CERT_ELEMENT_MAXLEN_ISSUER);
                memcpy(ram_cert.buffer + ram_cert.dc.AuthKeyID.idx, 
                        ram_cert.buffer + ram_cert.dc.SubjKeyID.idx, 
                        CERT_ELEMENT_MAXLEN_AUTHKEYID);
                check_and_report_result(libret, expected_result, line, lc);
            }
            break;
        default:
            print_sign_command_usage();
            break;
    }
}

static void process_token_addmany(char *token)
{
    uint16_t range;
    uint16_t slot = 0;
    uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
    uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];
    uint8_t subject[CERT_ELEMENT_MAXLEN_ISSUER];
    ECKEY signer_key;
    uint8_t *signer_pubkey = NULL,*issuer_subjkeyid;	
    uint8_t nl = 1,i; 

    token = get_next_token((char *)line);
    str_to_byte(token,(uint8_t *)&range);
    token = get_next_token((char *)line);
    if(token == NULL){
        printf("Syntax error addmany command\n");
        printf("Syntax addmany <decimal_number_n> at <serialoctet>"
            " serial auto| (<serialoctet1 serialoctet2 .. serialoctetn>)\n");
        return;
    }
    if(!strcmp(token,"at"))
    {
        token = get_next_token((char *)line);
        parse_hexstring(token, serial, CERT_ELEMENT_MAXLEN_SERIALNO);
        libret = get_issuer_from_store(serial, issuer);
        if (libret) {
            check_and_report_result(libret, expected_result, line, lc);
            return;
        }
        token = get_next_token((char *)line);
        if(!strcmp(token,"serial"))
        {
            ECKEY eckey;
            uint8_t pubkey[CERT_ELEMENT_MAXLEN_PUBKEY];
            token = get_next_token((char *)line);
            for(i=0;i<range;i++){
                if(strcmp(token,"auto")){
                    parse_hexstring(token, 
                               ram_cert.buffer + ram_cert.dc.serialNumber.idx, 
                               CERT_ELEMENT_MAXLEN_SERIALNO);
                    parse_hexstring(token, 
                               ram_cert.buffer + ram_cert.dc.subject.idx, 
                               CERT_ELEMENT_MAXLEN_SUBJECT);
                    parse_hexstring(token, 
                               ram_cert.buffer + ram_cert.dc.SubjKeyID.idx,
                               CERT_ELEMENT_MAXLEN_SUBJKEYID);
                    token = get_next_token((char *)line);
                }
                else
                {
                    memset(ram_cert.buffer + ram_cert.dc.serialNumber.idx,
                                auto_serial,CERT_ELEMENT_MAXLEN_SERIALNO);
                    memset(ram_cert.buffer + ram_cert.dc.subject.idx,
                                auto_serial, CERT_ELEMENT_MAXLEN_SUBJECT);
                    memset(ram_cert.buffer + ram_cert.dc.SubjKeyID.idx,
                                auto_serial, CERT_ELEMENT_MAXLEN_SUBJKEYID);
                    printf("*%02x ",auto_serial);
                    if (nl++ % 16 == 0 ) printf("\n");
                    auto_serial++;
                }	
                create_new_ec_key_pair(&eckey, pubkey);
                add_keypair_to_store(
                    (uint8_t *)ram_cert.buffer + ram_cert.dc.serialNumber.idx,
                    (uint8_t *)ram_cert.buffer + ram_cert.dc.subject.idx,
                    &eckey, pubkey,
                    (uint8_t *)ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
                memcpy(ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx,
                    pubkey, CERT_ELEMENT_MAXLEN_PUBKEY);
                get_keypair_from_store(serial,&signer_key,
                    &signer_pubkey,subject);
                get_subjkeyid_from_store(serial, &issuer_subjkeyid);
                libret = sign_cert(&ram_cert,&signer_key,signer_pubkey,
                    subject,issuer_subjkeyid);
                if (libret != ERR_OK) {
                    printf("sign_cert returned Error\n");
                    return;
                }
                update_issuer_to_store(
                    ram_cert.buffer + ram_cert.dc.serialNumber.idx,
                    subject, issuer_subjkeyid);
                libret = cache_insert_cert(&ram_cert, &slot);
                /* reset issuer_slot */
                ram_cert.dc.issuer_slot = 0; 
                if(libret == ERR_OK) {
                    update_slotno_to_store(
                        ram_cert.buffer + ram_cert.dc.serialNumber.idx, slot);
                }
                else{ 
                    printf("\n");
                    check_and_report_result(libret, expected_result, line, lc);
                    return;
                }
                sync_keypair_with_cache();
            }
        }
    }
    printf("\n");
    check_and_report_result(ERR_OK, expected_result, line, lc);
}

static void process_token_walkchain(char *token)
{
    uint8_t slotno, issuer;
    token = get_next_token((char *)line);
    str_to_byte(token,&slotno);
    printf("chain for cert@%d: ", slotno);
    cert_cache_read_cert((void *)&certbuf, slotno);
    issuer = certbuf.dc.issuer_slot;
    while (issuer != cache_index.cache_lists[issuer].issuer_slot){
        printf("%03u--",issuer);
        issuer = cache_index.cache_lists[issuer].issuer_slot;
    }
    printf("%03u ",issuer); /* last one, root */
    check_and_report_result(ERR_OK, expected_result, line, lc);
}

static void print_cache(void)
{
    uint8_t curr;

    printf("Cert_cache:\n");
    curr = cache_index.used_list_head;
    while ( curr != LIST_END_MARKER) {
        cert_cache_read_cert((void *)&certbuf, curr);
        printf("#%d:\n",curr);
        printf("SerialNumber    : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.serialNumber.idx),
                CERT_ELEMENT_MAXLEN_SERIALNO);
        printf("Subject     : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.subject.idx), 16);
        printf("Issuer      : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.issuer.idx), 16);
        printf("Public key  : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.subjectPublicKey.idx), 16);
        printf("AltNames    : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.AltNames.idx), 16);
        printf("SubjKeyID       : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.SubjKeyID.idx), 16);
        printf("AuthKeyID   : ");
        hexdump((uint8_t *)(certbuf.buffer + 
                certbuf.dc.AuthKeyID.idx), 16);

        curr = cache_index.cache_lists[curr].next;
    }
}

static void process_token(char *token)
{ 
    while (token){
        switch(get_token_id(token)){
            case TOKEN_EXPECT:
                process_token_expect(token);
                break;
            case TOKEN_EDITBUF:
                process_token_editbuf(token);
                break;
            case TOKEN_INSERT:
                process_token_insert(token);
                break;
            case TOKEN_DELETE:
                process_token_delete(token);
                break;
            case TOKEN_FIND:
                process_token_find(token);
                break;
            case TOKEN_CREATE:
                process_token_create(token);
                break;
            case TOKEN_SIGN:
                process_token_sign(token);
                break;
            case TOKEN_CHECK_SANITY:
                libret = cache_check_sanity();  
                check_and_report_result(libret, expected_result, line, lc);
                break;
            case TOKEN_ADDMANY:
                process_token_addmany(token);
                break;
            case TOKEN_WALKCHAIN:
                process_token_walkchain(token);
                break;
            case TOKEN_ERASEALL:
                libret = cache_erase_all();  
                check_and_report_result(libret, expected_result, line, lc);
                break;
            case TOKEN_PRINT_INDEX:
                print_index();
                break;
            case TOKEN_PRINT_KEYSTORE:
                print_key_store();
                break;
            case TOKEN_STORE_INDEX:
                libret = cache_store_index();
                check_and_report_result(libret, expected_result, line, lc);
                break;
            case TOKEN_GETNEXT_MRU:
                {
                    uint8_t slotno, ret_slot;
                    token = get_next_token((char *)line);
                    str_to_byte(token,&slotno);
                    ret_slot = cache_get_next_mru(slotno);
                    printf("%d  ", ret_slot);
                    check_and_report_result(ERR_OK, expected_result, line, lc);
                }
                break;
            case TOKEN_PRINT_CACHE:
                print_cache();
                break;
            case TOKEN_PRINT_CERT:
                {
                    uint16_t index;
                    token = get_next_token((char *)line);
                    if (token) {
                        str_to_byte(token,(uint8_t *)&index);
                        cert_cache_read_cert((void *)&certbuf, index);
                        print_pcert(&certbuf);
                    }
                    else
                        print_pcert(&ram_cert);
                }
                break;
            case TOKEN_PRINT_MSG:
                //print everything except "print "
                printf("%s\n",line+6);
                token = NULL;
                continue;

            case TOKEN_PROMPT:
                prompt = 1;
                break;

            case TOKEN_EXIT:
                done = 1;
                token = NULL;
                continue;

            default:
                printf("Unrecognized keyword %s\n", token);
                break;
        }
        token = get_next_token((char *)line);
    }
}

int test_loop(void)
{   
    int exit_val;
    int *exit_code=&exit_val;
 
    cert_buffer_init();
    libret = cache_init();
    if (libret != ERR_OK) {
        printf("Error initializing cert Cache. error %d\n", libret);
        return CMD_FAILED;
    }

    //elliptic lib
    elp_mp = elpmath_desc;

    x509cache_tests(exit_code);
    exit(exit_val);
    return 1;
}

int
test_task_create(void)
{ 
    OSTaskCreate(test_loop, NULL, &task_stk[TASK_STK_SIZE - 1],
                TASK_PRIO, TASK_STK_SIZE);
  
    return (0);
} 
