/* 
 * mc_cache_osutil.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * OS specific functions for cert cache
 * $Id: x509_cache_osutil.c 127833 2018-08-14 14:40:12Z jbabu $
 */

#include <stdio.h>
#include <string.h>
#include <x509_cache.h>
#include "includes.h"
#include "os_cpu.h"
#include "os_cfg.h"
#include <ucos_ii.h>
#include <sysvar.h>
#include "assert.h"
#include "sha256.h"
#include <include/errors.h>
#include <sys/types.h>
#include <time_sync/time_sync.h>
#include "util/local_time.h"
#include <mmesh/nxp.h>

OS_EVENT *x509_cache_lock;
#define SHA256_DIGESTLEN    (256/8)
#define ECDSA_P256_SIGNATURE_SIZE   64

uint8_t cache_mutex_init(void);
void cache_lock(void);
error_t cache_check_x509cert_validity(CertBuffer *cert);

void cache_unlock(void);

/**
 * perform mutex lock
 * @return standard error codes
 */
void cache_lock(void)
{
    return;
	uint8_t ret;
    OSSemPend(x509_cache_lock, 0, &ret);
    assert (ret == OS_NO_ERR);
}

/**
 * perform mutex unlock
 * @return standard error codes
 */
void cache_unlock(void)
{
    return;
	uint8_t ret;
	ret = OSSemPost(x509_cache_lock);
    assert (ret == OS_NO_ERR);
}

/**
 * initialize mutex init
 * @return standard error codes
 */
uint8_t cache_mutex_init(void)
{
    x509_cache_lock = OSSemCreate(1);
    assert(x509_cache_lock);
    if (!x509_cache_lock)
        return ERR_CACHE_GEN_ERROR;
    return ERR_OK;
}

/**
 * uninit cert cache
 * @return standard error codes
 */
error_t cache_uninit(void)
{
/* OSSemDel is not enabled in os_cfg.h currently.
 * so this function is only a placeholder for now.
 */
#ifdef OSSEMDEL_ENABLED
    uint8_t ret;
    OS_EVENT *ret_mutex;
    ret_mutex = OSSemDel(x509_cache_lock,OS_DEL_NO_PEND,&ret);
    if (ret_mutex != NULL)
    {
        return ERR_CACHE_GEN_ERROR;
    }
#endif
    return ERR_OK;
}

/**
 * verify x.509 certificate - Returns zero on good signature, non-zero otherwise.
 * @param subj is the cert to validate
 * @param issuer is the issuer of cert 
 * @return standard error codes
 */
error_t cache_x509_verify_signature(CertBuffer *subj, CertBuffer *issuer)
{
    error_t  rc;

#ifdef MNIC
    unsigned hash_len = SHA256_DIGESTLEN;
    uint8_t  hash_buf[SHA256_DIGESTLEN];
#endif

    assert(subj && issuer);
    if (memcmp(subj->dc.source + subj->dc.issuer.idx, 
               issuer->dc.source + issuer->dc.subject.idx,
               issuer->dc.subject.len)) {
        return ERR_AUTH_FAIL;
    }
    if (subj->dc.AuthKeyID.len && issuer->dc.SubjKeyID.len) {
        if (subj->dc.AuthKeyID.len != issuer->dc.SubjKeyID.len ||
            memcmp(subj->dc.source + subj->dc.AuthKeyID.idx,
                    issuer->dc.source + issuer->dc.SubjKeyID.idx,
                    issuer->dc.SubjKeyID.len)) {
            return ERR_AUTH_FAIL;
        }
    }
#ifdef MNIC
    Sha256Hash_memory(subj->dc.source + subj->dc.tbsCertificate.idx,
                      subj->dc.tbsCertificate.len,
                      hash_buf, &hash_len);
    assert(hash_len == sizeof hash_buf);

    if (issuer->dc.subjectPublicKey.len != (ECDSA_P256_SIGNATURE_SIZE+1)) {
        return ERR_AUTH_FAIL;
    }

    (void) nxp_select_applet(core_appletSel);
    rc = nxp_verify_signature(issuer->dc.source + issuer->dc.subjectPublicKey.idx,
                              hash_buf,
                              subj->dc.source   + subj->dc.signatureValue.idx);
    return rc;
#else
    rc = nxp_verify_signature2(issuer->dc.source + issuer->dc.subjectPublicKey.idx,
                                subj->dc.source + subj->dc.tbsCertificate.idx,
                                subj->dc.tbsCertificate.len,
                                subj->dc.source   + subj->dc.signatureValue.idx);
#endif
    return ERR_OK;
}

/**
 * check if x.509 certificate expired
 * @param cert is the cert to validate
 * @return standard error codes
 */
error_t cache_check_x509cert_validity(CertBuffer *cert)
{
    uint32_t cur_time;

    cur_time = os_ticks_to_utc(0);
	
    assert(cert);
    if (cur_time) {
        if ( cur_time > ntohl(cert->dc.notAfter) ||
                cur_time < ntohl(cert->dc.notBefore) )
            return ERR_INVAL;
    }
    return ERR_OK;
}
