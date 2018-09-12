/*
 * $Id $
 * Copyright 2018 iTron Network Solutions, Inc.  
 */
#ifndef _X509_INTERNAL_H_
#define _X509_INTERNAL_H_

/* function prototypes */
static error_t cache_find_cert_no_lock(IN const CertBuffer *pCert, 
               INOUT uint16_t *slot, IN uint16_t cmp_flags, uint8_t setmru);
static error_t cache_delete_entry_no_lock(uint16_t slot_num);
static uint8_t cache_get_next_visited_cert(void);
static error_t cache_delete_pcert_one(uint16_t slot_num);
static enum cert_types cache_get_cert_type(CertBuffer *pCert);
static int cache_is_issuer_of(CertBuffer *pcert1, CertBuffer *pcert2); 
static error_t cache_find_lock(INOUT CertBuffer *pcert, INOUT uint16_t *slot,
               struct compare_cert_parms *cmp);
static error_t cache_find_issuer_no_lock(IN const CertBuffer *src,
               OUT CertBuffer *pcert, OUT uint16_t *slot);

#endif
