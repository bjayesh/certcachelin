/*
 * Copyright SilverSpring Networks 2015
 * All rights reserved.
 *
 * $Id: sha256.h 127833 2018-08-14 14:40:12Z jbabu $
 */
#ifndef __D_SHA256_H__
#define __D_SHA256_H__

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    SHA256              =  2,   /* hash type unique */
    SHA256_BLOCK_SIZE   = 64,
    SHA256_DIGEST_SIZE  = 32,
    SHA256_PAD_SIZE     = 56
};

/* Sha256 digest (length = 108 bytes) */
typedef struct Sha256_struct
{
    uint32_t  buffLen;   /* in bytes          */
    uint32_t  loLen;     /* length in bytes   */
    uint32_t  hiLen;     /* length in bytes   */
    uint32_t  digest[SHA256_DIGEST_SIZE / sizeof(uint32_t)];
    uint32_t  buffer[SHA256_BLOCK_SIZE  / sizeof(uint32_t)];
} Sha256;

/* For direct calls, use the d_*() type calls */
void d_Sha256Init(Sha256* sha256);
void d_Sha256Update(Sha256* sha256, const void* data, unsigned len);
void d_Sha256Final(Sha256* sha256, uint8_t* hash, unsigned* hlen);
void d_Sha256Hash_memory( const uint8_t *inbuf, unsigned buflen,
        uint8_t *digest, unsigned *outlen);

/* Vector access to the SHA256 functions: */
#define SHA_INT     (50)
#ifdef NUM_INTERRUPTS
    #if NUM_INTERRUPTS != SHA_INT
        #error ******* Interrupt vector table not compatable *********
    #endif
#endif
#define SHA_VEC(n)  (((unsigned*)0)[SHA_INT+(n)])

/*
 * Define the vectored version of the SHA256 procedures.
 * These vector through vectors 50 to 53.
 */
static inline void v_Sha256Init(Sha256* pCtx)
{
    (*(void(*)(Sha256* sha256))(SHA_VEC(0)))(pCtx);
}

static inline void
v_Sha256Update(Sha256* pCtx, const uint8_t* data, unsigned len)
{
    (*(void(*)(Sha256*,const void*,unsigned))(SHA_VEC(1)))(pCtx,data,len);
}

static inline void
v_Sha256Final(Sha256* pCtx, unsigned char* hash, unsigned* hlen)
{
    (*(void(*)(Sha256*,uint8_t*,unsigned*))(SHA_VEC(2)))(pCtx,hash,hlen);
}

static inline void v_Sha256Hash_memory(const unsigned char* inbuf,
        unsigned buflen, uint8_t* digest, unsigned* outlen)
{
    (*(void(*)(const uint8_t*,unsigned,uint8_t*,unsigned*))(SHA_VEC(3)))
        (inbuf, buflen, digest, outlen);
}

/*
 * The define for FORCE_VECTORED_SHA256 affects which version of the SHA256
 * procedures are called when using the base procedure names.
 * If set to zero, it will call them directly, so the functions will be
 * compiled in with the code image, using space.
 * If set to 1, the calls are made through the vector table, so as to call
 * the copy in the boot sector.  This saves the code space used by the
 * functions, but requires that we have a new enough version of the boot
 * sector that implements the vectors.
 */
#define FORCE_VECTORED_SHA256   (0)
#if FORCE_VECTORED_SHA256
    #define Sha256Init          v_Sha256Init
    #define Sha256Update        v_Sha256Update
    #define Sha256Final         v_Sha256Final
    #define Sha256Hash_memory   v_Sha256Hash_memory
#else
    #define Sha256Init          d_Sha256Init
    #define Sha256Update        d_Sha256Update
    #define Sha256Final         d_Sha256Final
    #define Sha256Hash_memory   d_Sha256Hash_memory
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* __D_SHA256_H__ */
