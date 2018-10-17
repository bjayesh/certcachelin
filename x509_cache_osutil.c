/* 
 * mc_cache_osutil.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * OS specific functions for cert cache
 * $Id: x509_cache_osutil.c 127833 2018-08-14 14:40:12Z jbabu $
 */
#ifdef UCOSII
#include <stdio.h>
#include <string.h>
#include "x509_cache.h"
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
	if (ret)
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

	//  assert(subj && issuer);
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

#endif

#ifdef LINUX
#include<stdio.h>
#include<time.h>
#include<assert.h>
#include<pthread.h>
#include<stdint.h>
#include<x509_cache.h>
#define SHA256_DIGESTLEN    (256/8)
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/sha.h>

void cache_unlock(void);
uint8_t cache_mutex_init(void);
void cache_lock(void);
error_t cache_check_x509cert_validity(CertBuffer *cert);
uint8_t key_store_last;
pthread_mutex_t cach_lock;
uint8_t cache_mutex_init(void)
{
	uint8_t ret;
	ret=pthread_mutex_init(&cach_lock,NULL);
	if(ret!=0)
	{
		return ERR_CACHE_GEN_ERROR;
	}
	return ERR_OK;
}

void cache_lock(void)
{
	uint8_t ret;

	ret=pthread_mutex_lock(&cache_lock);
	if (ret) {

		return ERR_CACHE_GEN_ERROR;
	}

}

void cache_unlock(void)
{
	uint8_t ret;
	ret=pthread_mutex_unlock(&cache_lock);
	if(ret)
	{
		return ERR_CACHE_GEN_ERROR;
	}
}

error_t cache_uninit(void)
{
	int ret;
	ret=pthread_mutex_destroy(&cache_lock);
	if (ret)
	{
		return ERR_CACHE_GEN_ERROR;
	}
	return ERR_OK;
}
error_t cache_check_x509cert_validity(CertBuffer *cert)
{
	time_t cur_time;
char *c_time_string;
	cur_time = time(NULL);
if(cur_time)
{	
	if ( cur_time > cert->dc.notAfter ||
				cur_time < cert->dc.notBefore )
			return ERR_INVAL;
	}
	return ERR_OK;
}

error_t cache_x509_verify_signature(CertBuffer *subj, CertBuffer *issuer)
{
	uint8_t ret=0;
	unsigned hash_len = SHA256_DIGESTLEN;
	uint8_t  hash_buf[SHA256_DIGESTLEN];
	uint8_t errbuf[256];

	//  assert(subj && issuer);
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
	SHA256(subj->dc.source + subj->dc.tbsCertificate.idx,
			subj->dc.tbsCertificate.len,
			hash_buf);
	assert(hash_len == sizeof(hash_buf));

	BN_CTX *ecctx= BN_CTX_new();
	EC_KEY *eckey = EC_KEY_new();
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_POINT *pubkey_point = EC_POINT_new(ec_group) ;

	ret=EC_KEY_set_group(eckey,ec_group);
	if(ret==0)
	{ printf("error to set group\n");
	}
	
	//pubkey_point = EC_POINT_hex2point(ec_group,issuer->dc.source + issuer->dc.subjectPublicKey.idx,pubkey_point,ecctx);
	ret = EC_POINT_oct2point(	ec_group, pubkey_point,
								issuer->dc.source + issuer->dc.subjectPublicKey.idx,
								issuer->dc.subjectPublicKey.len,
								ecctx);
	if(ret==0)
	{
		printf("error to set ec_point\n");
		ERR_error_string(ERR_get_error(), errbuf);
		printf("Error string:: %s\n",errbuf);

	}


	ret = EC_KEY_set_public_key(eckey,pubkey_point);
	if(ret==0)
	{
		printf("error to set eckey\n");
	}

	uint8_t verify_result= ECDSA_verify(0,hash_buf,hash_len,subj->dc.source + subj->dc.signatureValue.idx,subj->dc.signatureValue.len,eckey);
	if (verify_result==0) 
	{
		printf("Invalid Signature\n");
	}    
	else if(verify_result==-1)
	{
		printf("error to verify signature\n");
	}
	else if(verify_result==1) 
		return ERR_OK;

}
/*if (issuer->dc.subjectPublicKey.len != (ECDSA_P256_SIGNATURE_SIZE+1)) {
        return ERR_AUTH_FAIL;
    }

    (void) nxp_select_applet(core_appletSel);
    rc = nxp_verify_signature(issuer->dc.source + issuer->dc.subjectPublicKey.idx,
            hash_buf,
            subj->dc.source   + subj->dc.signatureValue.idx);
    return rc;
    rc = nxp_verify_signature2(issuer->dc.source + issuer->dc.subjectPublicKey.idx,
subj->dc.source + subj->dc.tbsCertificate.idx,
            subj->dc.tbsCertificate.len,
            subj->dc.source   + subj->dc.signatureValue.idx);
    return ERR_OK;
}*/

#endif
