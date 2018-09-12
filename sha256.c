/* sha256.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 *
 * Heavily modified to make it smaller by David L Paulsen, April 2015
 * Also modified to not use odd typedefs, like word32.
 * This version is optimized for a Cortex M3.
 * Several mods were made to reduce RAM space in the context and stack.
 */
/* code submitted by raphael.huck@efixo.com */

#include <string.h>
#include "sha256.h"


#define LITTLE_ENDIAN_ORDER     (1)
/*
 * ----------------------------------------------------------------------------
 *  Timing tests:                       --- Times in microseconds ---
 *  ELIMINATE_W   size   len=4   len=56   len=100000
 *                         122,91   213,183   144927 -- original SHA256 code --
 *            0   5564     122      213       161224
 *            1   5584     122      213       177124  (Use this)
 *  Using the ELIMINATE_W define saves 256 bytes of RAM in the context
 *  structure, by eliminating the W[] array.
 * ----------------------------------------------------------------------------
 */
#define ELIMINATE_W             (1)

#if LITTLE_ENDIAN_ORDER
/*
 * Do a memcpy reversing bytes from the source.
 */
inline static void endianMemcpyOut(
        uint8_t* pDst,          /* Destination buffer */
        const uint32_t* pSrc,   /* Source buffer */
        unsigned len )          /* Number of bytes to transfer */
{
    unsigned i;
    for (i=0; i<len; i++) {
        pDst[i] = ((uint8_t*)pSrc)[i^3];
    }
}
#else
/*
 * Do a memcpy without reversing bytes.
 */
inline static void endianMemcpyOut(
        uint8_t* pDst,          /* Destination buffer */
        const uint32_t* pSrc,   /* Source buffer */
        unsigned len )          /* Number of bytes to transfer */
{
    unsigned i;
    for (i=0; i<len; i++) {
        pDst[i] = ((uint8_t*)pSrc)[i];
    }
}
#endif

/*---
 *--- DLP: Using the CMSIS equate below creates bigger and slower code,
 *---      since the optimizer can't combine the rotate with other operations
 *---      like xor, add, or, etc.
 *--- #define rotrFixed(x, n)     __ROR(x,n)
 */
#define rotrFixed(x,n)   ((x>>n) | (x<<(32-n)))


#if !ELIMINATE_W
static void wcopy( uint32_t*dst, uint32_t*src, unsigned len )
{
    unsigned i;

    for( i=0; i<len; i++ )
    {
        dst[i] = src[i];
    }
}
#endif

void d_Sha256Init(Sha256* sha256)
{
    sha256->digest[0] = 0x6A09E667L;
    sha256->digest[1] = 0xBB67AE85L;
    sha256->digest[2] = 0x3C6EF372L;
    sha256->digest[3] = 0xA54FF53AL;
    sha256->digest[4] = 0x510E527FL;
    sha256->digest[5] = 0x9B05688CL;
    sha256->digest[6] = 0x1F83D9ABL;
    sha256->digest[7] = 0x5BE0CD19L;

    sha256->buffLen = 0;
    sha256->loLen   = 0;
    sha256->hiLen   = 0;
}

static const uint32_t K[64] = {
    0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL,
    0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L, 0xD807AA98L, 0x12835B01L,
    0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L,
    0xC19BF174L, 0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL,
    0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL, 0x983E5152L,
    0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L,
    0x06CA6351L, 0x14292967L, 0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL,
    0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
    0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L,
    0xD6990624L, 0xF40E3585L, 0x106AA070L, 0x19A4C116L, 0x1E376C08L,
    0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL,
    0x682E6FF3L, 0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L,
    0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
};

#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         rotrFixed(x, n)
#define R(x, n)         ((x)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

#if !ELIMINATE_W
    #define WsubI   W[i]
#endif

#define RND(a,b,c,d,e,f,g,h,i) \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + WsubI; \
     t1 = Sigma0(a) + Maj(a, b, c); \
     d += t0; \
     h  = t0 + t1;

/*
 * ---------------------------------------------------------------------------
 * ---------------------------------------------------------------------------
 */
static void Transform(Sha256* sha256)
{
    int i;
    uint32_t S0, S1, S2, S3, S4, S5, S6, S7;
    /*
     * Adding this volatile pointer saves 32 bytes of stack, and 32 bytes of
     * code space.
     */
    volatile uint32_t *pdg = sha256->digest;

#if ELIMINATE_W
    uint32_t WsubI;
#else
    uint32_t W[64];

    /* Copy context->state[] to working vars */
    wcopy( W, sha256->buffer, 16 );

    for (i=16; i < 64; i++) {
        W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];
    }
#endif

    /* Copy context->state[] to working vars */
    S0 = pdg[0];
    S1 = pdg[1];
    S2 = pdg[2];
    S3 = pdg[3];
    S4 = pdg[4];
    S5 = pdg[5];
    S6 = pdg[6];
    S7 = pdg[7];

    for (i = 0; i < 64; i++)
    {
        uint32_t t0, t1;
#if ELIMINATE_W
        WsubI = sha256->buffer[i & 0xf];
        if (i>=16) {
            /* Separating the calc using t0 saves a bunch of code on the M3 */
            t0 = sha256->buffer[(i-2) & 0xf];
            WsubI += Gamma1(t0);
            WsubI += sha256->buffer[(i-7) & 0xf];
            t0 = sha256->buffer[(i-15) & 0xf];
            WsubI += Gamma0(t0);
            sha256->buffer[i & 0xf] = WsubI;
        }
#endif
        RND(S0,S1,S2,S3,S4,S5,S6,S7,i);
        t0 = S7;
        S7 = S6;
        S6 = S5;
        S5 = S4;
        S4 = S3;
        S3 = S2;
        S2 = S1;
        S1 = S0;
        S0 = t0;
    }

    /* Add the working vars back into digest state[] */
    pdg[0] += S0;
    pdg[1] += S1;
    pdg[2] += S2;
    pdg[3] += S3;
    pdg[4] += S4;
    pdg[5] += S5;
    pdg[6] += S6;
    pdg[7] += S7;
}

void d_Sha256Update(Sha256* sha256, const void *data, unsigned len)
{
    unsigned tmp;
    unsigned bLen;
    uint8_t *pSrc = (uint8_t*)data;
    uint8_t *pBuf = (uint8_t*)sha256->buffer;

    /* Update the length in bits */
    tmp = sha256->loLen;
    if ( (sha256->loLen += (len << 3)) < tmp)
        sha256->hiLen++;    /* carry low to high */

    bLen = sha256->buffLen;
    while (len--)
    {
        /* Add next byte in little endian mode */
#if LITTLE_ENDIAN_ORDER
        pBuf[bLen^3] = *pSrc++;
#else
        pBuf[bLen] = *pSrc++;
#endif
        if (++bLen >= SHA256_BLOCK_SIZE) {
            Transform(sha256);
            bLen = 0;
        }
    }
    sha256->buffLen = bLen;
}

void d_Sha256Final(Sha256* sha256, uint8_t* hash, unsigned* hlen)
{
    unsigned bLen;
    uint8_t *pBuf = (uint8_t*)sha256->buffer;
    unsigned fill;

    fill = 0x80;   /* Tag at end of buffer */
    bLen = sha256->buffLen;

    do
    {
        /* Add next byte in little endian mode */
#if LITTLE_ENDIAN_ORDER
        pBuf[bLen^3] = fill;
#else
        pBuf[bLen] = fill;
#endif
        fill = 0;
        if (++bLen >= SHA256_BLOCK_SIZE) {
            Transform(sha256);
            bLen = 0;
        }
    } while (bLen != SHA256_PAD_SIZE);

    /* Store the length at the end of the buffer, and process the last one */
    sha256->buffer[SHA256_PAD_SIZE/4+0] = sha256->hiLen;
    sha256->buffer[SHA256_PAD_SIZE/4+1] = sha256->loLen;

    Transform(sha256);

    if (*hlen > SHA256_DIGEST_SIZE) {
        *hlen = SHA256_DIGEST_SIZE;
    }
    endianMemcpyOut(hash, sha256->digest, *hlen);
}


void d_Sha256Hash_memory( const uint8_t *inbuf, unsigned buflen,
        uint8_t *digest, unsigned *outlen)
{
    Sha256 sha256;
    d_Sha256Init(&sha256);
    d_Sha256Update(&sha256, inbuf, buflen);
    d_Sha256Final(&sha256, digest, outlen);
}

