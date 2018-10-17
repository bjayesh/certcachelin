/*
 * Copyright 2018 itron, Inc.
 * All rights reserved.
 *
 * $Id: cert_setflags.c 127833 2018-08-14 14:40:12Z jbabu $
 */
//#include <libc/include/string.h>
//#include <mac_addr.h>
#include <x509_cache.h>
#include <sha256.h>
#include "assert.h"

#define NOINLINE  __attribute__((noinline))
#define MAC_ADDR_LEN 8
#ifdef REMOVE
#ifndef MAX_UINT
#define MAX_UINT 0x7fffffff
#endif
#endif

char *strncasestr(const char *s, const char *find, size_t slen);
char *strnstr(const char *s, const char *find, size_t slen);
error_t cert_set_flags_for_bc_or_dl(DecodedCert *dc);
static int cert_toupper(int c);


/* string functions */
static int cert_toupper(int c)
{
    return ((c)>'a'&&(c)<='z')?((c)-'a'+'A'):(c);
}

/*
 * Find the first occurrence of find in s, where the search is limited to the 
 * first slen characters of s.
 */
char *
strncasestr(const char *s, const char *find, size_t slen)
{
        char c, sc; 
        size_t len;

        if ((c = *find++) != '\0') {
                len = strlen(find);
                do {
                        do {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                        return (NULL);
                        } while (cert_toupper(sc) != cert_toupper(c));
                        if (len > slen)
                                return (NULL);
                } while (strncasecmp(s, find, len) != 0); 
                s--;
        }   
        return ((char *)s);
}

/*
 * Find the first occurrence of find in s, where the search is limited to the 
 * first slen characters of s.
 */
char *
strnstr(const char *s, const char *find, size_t slen)
{
        char c, sc; 
        size_t len;

        if ((c = *find++) != '\0') {
                len = strlen(find);
                do {
                        do {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                        return (NULL);
                        } while ((sc) != (c));
                        if (len > slen)
                                return (NULL);
                } while (strncasecmp(s, find, len) != 0); 
                s--;
        }   
        return ((char *)s);
}


static const uint8_t pubkey_subject_info_prefix[]  = {  
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};

static const uint8_t OUisSSN[] = {
    0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 
    0x0A, 0x0C, 0x03, 'S', 'S', 'N', 0 };

static const uint8_t OUisITRON[] = {
    0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 
    0x0A, 0x0C, 0x05, 'i', 't', 'r', 'o', 'n', 0};

static const uint8_t CN[] = {
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0 };

/*
 * cert_set_flags_for_bc_or_dl
 */ 
error_t
cert_set_flags_for_bc_or_dl(DecodedCert *dc)
{
    uint16_t parent_slot, parent_flags;
    error_t err;

    assert(dc);
    parent_slot = dc->issuer_slot;
    assert(parent_slot); // else is programming error
    if (parent_slot == 0) return ERR_NO_ENTRY;
    err =  cache_get_flags(&parent_flags, parent_slot);
    assert(!err);   // else programming error

#if !defined REGRESS && !defined MSIM
    /* Is it a mfg cert ? */
    /* source DN contains OU=SSN or OU=itron and CN begins with "mfg" (ignore case) */
    /* and is issued by root */
    if (strncasestr((char *)dc->source + dc->subject.idx, (char *)OUisSSN, dc->subject.len) ||
        strncasestr((char *)dc->source + dc->subject.idx, (char *)OUisITRON, dc->subject.len)) {
        char *cn = strnstr((char *)dc->source + dc->subject.idx, (char *)CN, dc->subject.len);
        if (cn != NULL && cn[6] >= 3 && (!strncasecmp(cn + 7, "mfg", 3) ||
                                         !strncasecmp(cn + 7, "xmfg", 4))) {
            if (parent_flags & CERT_F_ROOT) {
                dc->flags |= CERT_F_MFG;
            }
        }
    }
#endif

    /* Is it a BC ? */
    if (parent_flags & CERT_F_MFG &&
        dc->AltNames.len == MAC_ADDR_LEN &&
        dc->subject.len <= 2) {
        dc->flags |= CERT_F_BC;
    }

    /* Is it an operator cert? */
    if ((dc->flags & CERT_F_HAS_ANY_POLICY) &&
        (dc->flags & CERT_F_IS_CA) &&
        (parent_flags & CERT_F_ROOT)) {
        dc->flags |= CERT_F_OPERATOR;
    }

    /* Is it a DLCA? */
    if (dc->flags & CERT_F_DLCA &&
        (parent_flags & CERT_F_OPERATOR) == 0) {
        dc->flags &= ~CERT_F_DLCA;
    }

    /* Is it a DL? */
    if (parent_flags & CERT_F_DLCA) {
        dc->flags |= CERT_F_DL;
    }

    return ERR_OK;
}
