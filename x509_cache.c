/** 
 * x509_cache.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * $Id: x509_cache.c 127833 2018-08-14 14:40:12Z jbabu $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <x509_cache.h>
#include "assert.h"
#include "x509_cache_flash.h"
#include "cert_misc.h"
#include "os_cpu.h"
#include "x509cacheinternal.h"

/**
 *  Cache structure
 *  Number of items in the cache is fixed.
 *  Each cert can be upto 1k
 *  |----0-----|----1-----|----2-----|----3-----|  ... ...  |----127-----|
 *  |    index |    root  |   cert   |   cert   |  ... ...  |    cert    |
 *  |----------|----------|----------|----------|  ... ...  |------------|
 */

extern error_t cache_check_x509cert_validity(CertBuffer *cert);
extern void  cache_lock(void);
extern void  cache_unlock(void);
extern uint8_t cache_mutex_init(void);

struct cache_index cache_index;


extern error_t cert_set_flags_for_bc_or_dl(DecodedCert *dc);

/**
 * delete item from used list
 * @param - slotno to delete
 * @return standard error codes
 */
static error_t cache_delete_from_used_list(uint8_t slotno)
{
    uint8_t prev, curr;

    prev = curr = cache_index.used_list_head;
    while (curr != LIST_END_MARKER) {
        if (curr == slotno) {
            if (cache_index.cache_lists[curr].flags & CERT_F_READ_ONLY)
                return ERR_CACHE_READ_ONLY;            
            if (curr == cache_index.used_list_head) 
                cache_index.used_list_head = cache_index.cache_lists[curr].next;
            else
                cache_index.cache_lists[prev].next = cache_index.cache_lists[curr].next;
            cache_index.cache_lists[curr].flags &= ~CERT_F_USED;
            return ERR_OK;
        }
        prev = curr;
        curr = cache_index.cache_lists[curr].next;
    }
    return ERR_CACHE_NOTHING_TO_DELETE;
}

/**
 * add to first available entry in used_list
 * @param - slotno to add
 * @param - flags of cert to add
 * @return standard error codes
 */
static error_t cache_add_to_used_list(uint8_t slotno, uint8_t flags)
{
    cache_index.cache_lists[slotno].flags = flags | CERT_F_USED;
    //make sure CERT_F_VISITED is set to 0
    cache_index.cache_lists[slotno].flags &= ~CERT_F_VISITED;
    
    cache_index.cache_lists[slotno].next = cache_index.used_list_head;
    cache_index.used_list_head = slotno;

    return ERR_OK;
}

/**
 * get available cache_slot (first in free_list)
 * @param - slotno is returned cache slot
 * @return standard error codes
 */
static error_t cache_get_available_cache_slot(uint8_t *slotno)
{
    if (cache_index.free_list_head == LIST_END_MARKER)
        return ERR_CACHE_FULL;

    *slotno = cache_index.free_list_head;
    cache_index.cache_lists[cache_index.free_list_head].flags &= ~CERT_F_USED;
    cache_index.free_list_head = cache_index.cache_lists[cache_index.free_list_head].next;
    return ERR_OK;
}

/**
 * add to free list
 * @param - slotno to add
 */
static void cache_add_to_free_list(uint8_t slotno, uint8_t flags)
{
    cache_index.cache_lists[slotno].next = cache_index.free_list_head;
    cache_index.cache_lists[slotno].flags = flags & ~CERT_F_USED;
    cache_index.free_list_head = slotno;
}

/**
 * delete LRU from cache to make space to insert new cert when cache is full
 * @return standard error codes
 */
static error_t cache_delete_lru_from_cache(void)
{
    uint8_t curr,lru_slot;

    /* assert list cannot be empty */
    assert(cache_index.used_list_head != LIST_END_MARKER);
    /* get first writable lru from used_list */
    curr = lru_slot = cache_index.used_list_head;
    while (curr != LIST_END_MARKER) {
        if (!(cache_index.cache_lists[curr].flags & CERT_F_READ_ONLY))
            lru_slot = curr;
        curr = cache_index.cache_lists[curr].next;
    }
    return cache_delete_entry_no_lock(lru_slot); 
}

static error_t cache_is_DL_cert(const CertBuffer *cert, uint8_t *res)
{
    /* output true if DL flag is set for cert. */
    error_t ret = ERR_OK;
    *res = (cert->dc.flags & CERT_F_DL)?1:0;

    return ret;
}

static error_t cache_is_BC_cert(const CertBuffer *cert,uint8_t *res)
{
    /* return true if BC flag is set */
    error_t ret = ERR_OK;
    *res = 0;
    *res = (cert->dc.flags & CERT_F_BC)?1:0;

    return ret;
}
/**
 * compare two certs
 * @param - pCert1 is cert with values to search for
 * @param - pCert2 is candidate for a match
 * @param - cmp specifies fields and values to compare
 * @return standard error codes
 */
static error_t cache_compare_certs(INOUT CertBuffer *pCert1, IN const CertBuffer *pCert2,
        IN struct compare_cert_parms *cmp)
{
    error_t ret = ERR_CACHE_FIND_NO_MATCH;
    uint8_t result = 0;

    switch(cmp->bitmap) {
        case CERT_CMP_PARAM_ALL:
            if (!memcmp(pCert1->buffer + pCert1->dc.Certificate.idx,
                        pCert2->buffer + pCert2->dc.Certificate.idx,
                        pCert1->dc.Certificate.len))
                ret = ERR_OK;
            break;
        case CERT_CMP_PARM_MACADDR_BC:
            if (    pCert2->dc.AltNames.len == ALTNAME_LEN_MACADDR   &&
                    pCert1->dc.AltNames.len == ALTNAME_LEN_MACADDR   && 
                    !memcmp(pCert1->buffer + pCert1->dc.AltNames.idx, 
                        pCert2->buffer + pCert2->dc.AltNames.idx,
                        pCert1->dc.AltNames.len)                     &&
                    (ERR_OK == cache_is_BC_cert(pCert2, &result))    &&
                    result
                )
                ret = ERR_OK;
            break;
        case CERT_CMP_PARM_MACADDR_DL:
            if (    pCert2->dc.AltNames.len == ALTNAME_LEN_MACADDR   &&
                    pCert1->dc.AltNames.len == ALTNAME_LEN_MACADDR   && 
                    !memcmp(pCert1->buffer + pCert1->dc.AltNames.idx,
                        pCert2->buffer + pCert2->dc.AltNames.idx,
                        pCert1->dc.AltNames.len)                     &&
                    (ERR_OK == cache_is_DL_cert(pCert2, &result))    &&
                    result
                )
                ret = ERR_OK;
            break;
        case CERT_CMP_PARAM_ISSUER_AND_SERIAL:
            if (cmp->serial_bytes == pCert2->dc.serialNumber.len &&
                    !memcmp(cmp->serial, pCert2->buffer + pCert2->dc.serialNumber.idx,
                        cmp->serial_bytes) &&
                    cmp->name_bytes == pCert2->dc.issuer.len &&
                    !memcmp(cmp->name, pCert2->buffer + pCert2->dc.issuer.idx,
                        cmp->name_bytes ) ) 
                ret = ERR_OK;
            break;
        case CERT_CMP_PARAM_SUBJECT_AND_SKID:
            /* If skid_bytes is zero, search only by subject. */
            if (cmp->skid_bytes == 0) {
                if (cmp->name_bytes == pCert2->dc.subject.len &&
                        !memcmp(cmp->name, pCert2->buffer + pCert2->dc.subject.idx, cmp->name_bytes ) )
                    ret = ERR_OK;
                break;
            }
            if ( cmp->name_bytes == pCert2->dc.subject.len &&
                    !memcmp(cmp->name, pCert2->buffer + pCert2->dc.subject.idx, cmp->name_bytes ) && 
                    cmp->skid_bytes == pCert2->dc.SubjKeyID.len &&
                    !memcmp(cmp->skid, pCert2->buffer + pCert2->dc.SubjKeyID.idx, cmp->skid_bytes) ) 
                ret = ERR_OK;
            break;
    }
    return ret;
}

/**
 * init cert cache
 * @return standard error codes
 */
API error_t cache_init()
{
    uint16_t i,out_len;
    uint8_t ret;

    ret = cache_mutex_init();
    if (ret != ERR_OK) {
        return ERR_CACHE_GEN_ERROR;
    }
    ret = cert_cache_read_index(&cache_index, sizeof(cache_index), &out_len);
    if (out_len == 0 || ret != ERR_OK) {
        /* Initialize used and free lists */
        cache_index.used_list_head = LIST_END_MARKER;
        /* add all except index slot to free_list */
        cache_index.free_list_head = 1;
        for (i = 1; i < TOTAL_CERT_SLOTS; i++) {
            cache_index.cache_lists[i].flags = 0;
            cache_index.cache_lists[i].next = i+1;
            cache_index.cache_lists[i].issuer_slot = 0;
        }
        cache_index.cache_lists[i-1].next = LIST_END_MARKER;
    }
    return ERR_OK;
}

/**
 * erase all of cert cache and recreate index
 * @return standard error codes
 */
API error_t cache_erase_all()
{
    error_t ret = ERR_OK;
    uint8_t curr,i;

    cache_lock();

    while (cache_index.used_list_head != LIST_END_MARKER) {
        curr = cache_index.used_list_head;
        while (curr != LIST_END_MARKER){
            if (cache_index.cache_lists[curr].flags & CERT_F_READ_ONLY)
                cache_index.cache_lists[curr].flags &= ~CERT_F_READ_ONLY;
            ret = cache_delete_pcert_one(curr);
            curr = cache_index.used_list_head;
        }
    }

    /* re-create index with all slots in free list */
    cache_index.used_list_head = LIST_END_MARKER;
    cache_index.free_list_head = 1;
    for (i = 1; i < TOTAL_CERT_SLOTS; i++) {
        cache_index.cache_lists[i].flags = 0;
        cache_index.cache_lists[i].next = i+1;
        cache_index.cache_lists[i].issuer_slot = 0;
    }
    cache_index.cache_lists[i-1].next = LIST_END_MARKER;

    ret = cache_store_index();

    cache_unlock();
    return ret;
}

/*
 * set given slotno as MRU (first in used_list)
 * @param - slotno is cache slot to become mru
 */
static error_t cache_set_slot_as_mru(uint8_t cache_slotno)
{
    error_t ret;
    uint8_t flags;

    flags = cache_index.cache_lists[cache_slotno].flags;
    ret = cache_delete_from_used_list(cache_slotno);
    if (ret == ERR_OK)
        ret = cache_add_to_used_list(cache_slotno, flags);
    return ret;
}


/**
 * find cert in cache
 * @param - pCert is the cert to find
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_cert(IN const CertBuffer *pCert, INOUT uint16_t *slot)
{
    error_t ret = ERR_OK;

    assert(pCert && slot);

    cache_lock();
    ret = cache_find_cert_no_lock(pCert,slot, CERT_CMP_PARAM_ALL, SETMRU);
    cache_unlock();
    return ret;
}

/**
 * find cert in cache when mutex lock is already held
 * @param - pCert is the cert to find
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @param - cmp_flags indicate which fields of pCert to compare
 * @return standard error codes
 */
static error_t cache_find_cert_no_lock(IN const CertBuffer *pCert, INOUT uint16_t *slot,
                                       IN uint16_t cmp_flags, uint8_t setmru)
{
    struct compare_cert_parms cmp;
    CertBuffer *certbuf1;
    uint8_t curr;
    error_t ret;

    if (cache_index.used_list_head == LIST_END_MARKER)
        return ERR_CACHE_FIND_NO_MATCH;

    certbuf1 = cert_buffer_get();
    if (!certbuf1)
        return ERR_NO_MEM;

    cmp.bitmap = cmp_flags;
    if (*slot == 0)
        curr = cache_index.used_list_head;
    else
        curr = cache_index.cache_lists[*slot].next;

    while (curr != LIST_END_MARKER) {
        ret = cert_cache_read_cert(certbuf1, curr);
        if (ret != ERR_OK) {
            cert_buffer_release(certbuf1);
            return ret;
        }
        if (ERR_OK == cache_compare_certs((CertBuffer *)pCert, certbuf1, &cmp)){
            *slot = curr;
            if (setmru) cache_set_slot_as_mru(*slot);
            cert_buffer_release(certbuf1);
            return ERR_OK;
        }
        curr = cache_index.cache_lists[curr].next;
    }
    cert_buffer_release(certbuf1);
    return ERR_CACHE_FIND_NO_MATCH;
}

/**
 * find cert in cache by issuer and serial
 * @param - issuer is the issuer bytestring to match
 * @param - issuer_bytes - length of issuer bytestring
 * @param - serial is the serial bytestring to match
 * @param - serial_bytes - length of serial bytestring
 * @param - pcert is the result cert if matched
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_by_issuer_and_serial(IN const uint8_t *issuer, IN unsigned issuer_bytes,
                                            IN const uint8_t *serial, IN unsigned serial_bytes,
                                            INOUT struct CertBuffer *pcert, INOUT uint16_t *slot) 
{
    struct compare_cert_parms cmp;
    assert(issuer && serial && pcert && slot);

    cmp.bitmap = CERT_CMP_PARAM_ISSUER_AND_SERIAL;
    cmp.serial_bytes = serial_bytes;
    cmp.serial = (uint8_t *)serial;
    cmp.name_bytes = issuer_bytes;
    cmp.name = (uint8_t *)issuer;
    return cache_find_lock(pcert, slot, &cmp);
}

/**
 * find cert in cache by issuer subject and SKID
 * @param - subject is the subject bytestring to match
 * @param - subject_bytes - length of subject_bytes bytestring
 * @param - skid is the skid bytestring to match
 * @param - skid_bytes - length of skid bytestring
 * @param - pcert is the result cert if matched
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_by_subject_and_SKID(const uint8_t *subject, unsigned subject_bytes, const uint8_t *skid,
        unsigned skid_bytes, CertBuffer *pcert, INOUT uint16_t *slot)
{
    /* SKID stands for Subject Key ID.  If skid_bytes is zero, search only by subject */
    struct compare_cert_parms cmp;
    assert(subject && pcert && slot);
    if (skid_bytes) assert(skid);

    cmp.bitmap = CERT_CMP_PARAM_SUBJECT_AND_SKID;
    cmp.name_bytes = subject_bytes;
    cmp.name = (uint8_t *)subject;
    cmp.skid_bytes = skid_bytes;
    cmp.skid = (uint8_t *)skid;
    return cache_find_lock(pcert, slot, &cmp);
}

/**
 * find next operator cert in cache
 * An Operator cert is issued by the root and has the “AnyPolicy” value in the Policies extension.  
 * Find the next one starting at MRU (if *slot is zero) or starting at *slot if not.
 * @param - pcert is the result cert if matched
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_next_operator_cert(OUT CertBuffer *pcert, INOUT uint16_t *slot)
{
    uint8_t curr;
    assert(pcert && slot && (*slot < TOTAL_CERT_SLOTS));

    /* walk through the list starting from given slot no. and 
     * return cert with operator and policy flags set.
     */  
    if (*slot == 0) 
        curr = cache_index.used_list_head;
    else
        curr = cache_index.cache_lists[*slot].next;

    while (curr != LIST_END_MARKER) {
        if (cache_index.cache_lists[curr].flags & (CERT_F_HAS_ANY_POLICY|CERT_F_OPERATOR)) {
            cert_cache_read_cert(pcert, curr);
            *slot = curr;
            return ERR_OK;
        }
        curr = cache_index.cache_lists[curr].next;
    }
    return ERR_CACHE_FIND_NO_MATCH;
}


/**
 * find a BC in cache by MAC address
 * @param - MAC_addr is MAC address to search for
 * @param - pcert is the result cert if matched
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_BC_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, uint16_t *slot)
{
    struct compare_cert_parms cmp;

    assert(MAC_addr && pcert && slot);

    cmp.bitmap = CERT_CMP_PARM_MACADDR_BC;
    memcpy(pcert->buffer + pcert->dc.AltNames.idx, MAC_addr, ALTNAME_LEN_MACADDR);
    pcert->dc.AltNames.len = ALTNAME_LEN_MACADDR;

    return cache_find_lock(pcert,slot,&cmp);
}

/**
 * find a DL in cache by MAC address
 * @param - MAC_addr is MAC address to search for
 * @param - pcert is the result cert if matched
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_DL_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, uint16_t *slot)
{
    struct compare_cert_parms cmp;

    assert(MAC_addr && pcert && slot);

    cmp.bitmap = CERT_CMP_PARM_MACADDR_DL;
    memcpy(pcert->buffer + pcert->dc.AltNames.idx, MAC_addr, ALTNAME_LEN_MACADDR);
    pcert->dc.AltNames.len = ALTNAME_LEN_MACADDR;

    return cache_find_lock(pcert,slot,&cmp);
}

/**
 * find cert in cache; caller shall not hold mutex lock 
 * @param - pcert is the cert to find
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @param - cmp is bitmap of fields to compare
 * @return standard error codes
 */
static error_t cache_find_lock(INOUT CertBuffer *pcert, INOUT uint16_t *slot, struct compare_cert_parms *cmp)
{
    uint8_t curr;
    error_t ret;
    CertBuffer *certbuf1;

    certbuf1 = cert_buffer_get();
    if (!certbuf1)
        return ERR_NO_MEM;
    cache_lock();
    if (*slot != 0) {
        /* when *slot is non-zero, caller is trying 'get next matching mru' */
        curr = cache_index.cache_lists[*slot].next;
    }
    else
        curr = cache_index.used_list_head;

    while (curr != LIST_END_MARKER) {
        ret = cert_cache_read_cert(certbuf1, curr);
        if (ret != ERR_OK){
            cache_unlock(); 
            cert_buffer_release(certbuf1);
            return ret;
        }
        if (ERR_OK == cache_compare_certs((CertBuffer *)pcert, certbuf1, cmp)){
            *slot = curr;
            *pcert = *certbuf1;
            cache_set_slot_as_mru(*slot);
            cache_unlock(); 
            cert_buffer_release(certbuf1);
            return ERR_OK;
        }
        curr = cache_index.cache_lists[curr].next;
    }
    cache_unlock();
    cert_buffer_release(certbuf1);
    return ERR_CACHE_FIND_NO_MATCH;
}

/**
 * find cert in cache by slot number
 * @param - slot_num is the slot number to find
 * @param - pcert is the cert to find
 * @param - slot is index of cert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_by_slot_number(uint16_t slot_num, CertBuffer *pcert)
{
    assert(pcert);

    /* verify that slot_num is a valid entry in used_list */
    if (!(cache_index.cache_lists[slot_num].flags & CERT_F_USED))
        return ERR_CACHE_INVALID_SLOT_TOFIND;
    return cert_cache_read_cert(pcert, slot_num);
}

/**
 * insert cert to cache
 * @param - pcert is the cert to include
 * @param - slot is index of cert cache to return
 * @return standard error codes
 */
API error_t cache_insert_cert(IN CertBuffer *pcert, OUT uint16_t *slot) 
{
    uint16_t fslot = 0, issuer_slot = 0;
    error_t ret;
    enum cert_types cert_type;
    CertBuffer *certbuf1;

    assert(pcert && slot);

    /* if cache is empty, this has to be a root cert */
    cert_type = cache_get_cert_type(pcert);
    if (cache_index.used_list_head == LIST_END_MARKER && cert_type != CERT_TYPE_ROOT)
        return ERR_CACHE_NO_ROOT_CERT;

    /* verify given certificate before insert */
    if (ERR_OK != cache_check_x509cert_validity(pcert)) {
        return ERR_CACHE_CERT_EXPIRED;
    }

    certbuf1 = cert_buffer_get();
    if (!certbuf1)
        return ERR_NO_MEM;
    cache_lock();
    if (cert_type == CERT_TYPE_ROOT) {
        ret = cache_x509_verify_signature(pcert,pcert);
        if (ret != ERR_OK) {
            cache_unlock();
            cert_buffer_release(certbuf1);
            return ERR_CACHE_CERT_SIGN_INVALID;
        }
        pcert->dc.flags |= CERT_F_READ_ONLY;
    }
    else {
        if ( cert_type != CERT_TYPE_ROOT && 
                (ERR_OK != cache_find_issuer_no_lock(pcert,certbuf1,&issuer_slot)) ) {
            cache_unlock();
            cert_buffer_release(certbuf1);
            return ERR_CACHE_CERT_NO_ISSUER;
        }
        ret = cache_x509_verify_signature(pcert,certbuf1);
        if (ret != ERR_OK) {
            cache_unlock();
            cert_buffer_release(certbuf1);
            return ERR_CACHE_CERT_SIGN_INVALID;
        }
    }

    if (cache_find_cert_no_lock(pcert,&fslot,CERT_CMP_PARAM_ALL, NO_SETMRU) == ERR_OK){
        cache_unlock();
        *slot = fslot;
        cert_buffer_release(certbuf1);
        return ERR_CACHE_ALREADY_EXIST;
    }

    /* insert as MRU */
    ret = cache_get_available_cache_slot((uint8_t *)slot); 
    if (ret == ERR_CACHE_FULL) {
        cache_delete_lru_from_cache();
        cache_get_available_cache_slot((uint8_t *)slot);
    }
    cache_add_to_used_list(*slot, pcert->dc.flags);
    pcert->dc.slot = *slot;

    /* update issuer_slot */
    if (cert_type != CERT_TYPE_ROOT) {
        cache_index.cache_lists[*slot].issuer_slot = issuer_slot;
        pcert->dc.issuer_slot = issuer_slot; 
    }
    else {
        cache_index.cache_lists[*slot].issuer_slot = *slot;
        pcert->dc.issuer_slot = *slot; 
    }
    ret = cert_set_flags_for_bc_or_dl(&pcert->dc);
    assert(!ret);
    pcert->dc.flags |= CERT_F_USED;
    cache_index.cache_lists[*slot].flags = pcert->dc.flags;
    ret = cert_cache_write_cert(pcert, *slot);

    cache_unlock();
    cert_buffer_release(certbuf1);
    return ret;
}

/**
 * delete cert from cache
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
API error_t cache_delete_entry(uint16_t slot_num) 
{
    error_t ret = ERR_OK;

    cache_lock();
    ret = cache_delete_entry_no_lock(slot_num);
    cache_unlock();
    return ret;
}

/**
 * explore cert to delete and all its children, then invoke actual delete
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
static error_t cache_delete_entry_no_lock(uint16_t slot_num) 
{
    error_t ret = ERR_OK;
    uint8_t tovisit,curr;
    uint8_t to_delete;
    CertBuffer *certbuf1, *certbuf2;

    if (slot_num == 0) return ERR_CACHE_NOTHING_TO_DELETE;
    if (cache_index.cache_lists[slot_num].flags & CERT_F_READ_ONLY ) 
        return ERR_CACHE_CANT_DELETE_ROOTCERT;
    /* make sure entry exists in used list */
    if (!(cache_index.cache_lists[slot_num].flags & CERT_F_USED))
        return ERR_CACHE_NOTHING_TO_DELETE;

    certbuf1 = cert_buffer_get();
    if (!certbuf1)
        return ERR_NO_MEM;
    certbuf2 = cert_buffer_get();
    if (!certbuf2) {
        cert_buffer_release(certbuf1);
        return ERR_NO_MEM;
    }
    //mark this node
    cache_index.cache_lists[slot_num].flags |= (CERT_F_TO_DELETE | CERT_F_VISITED);
    tovisit = slot_num;
    while (tovisit != LIST_END_MARKER) {
        ret = cert_cache_read_cert(certbuf1, tovisit);
        if (ret != ERR_OK) {
            goto err;
        }
        /* scan cache_list to find all certs issued by cert@tovisit */
        curr = cache_index.used_list_head;
        while (curr != LIST_END_MARKER) {
            /*skip if curr is same as tovisit */
            if (tovisit == curr) {
                curr = cache_index.cache_lists[curr].next;
                continue;
            }
            ret = cert_cache_read_cert(certbuf2, curr);
            if (ret != ERR_OK) {
                goto err;
            }
            if (cache_is_issuer_of(certbuf1, certbuf2)){
				cache_index.cache_lists[curr].flags |= (CERT_F_TO_DELETE | CERT_F_VISITED);
            }
            curr = cache_index.cache_lists[curr].next;
        }
        cache_index.cache_lists[tovisit].flags &= ~CERT_F_VISITED;
        tovisit = cache_get_next_visited_cert();
    }          

    /*perform actual delete */
    to_delete = slot_num;
    while (to_delete != LIST_END_MARKER){
        ret = cache_delete_pcert_one(to_delete);
        if (ret != ERR_OK){
            goto err;
        }
        cache_index.cache_lists[to_delete].flags &= ~(CERT_F_TO_DELETE|CERT_F_USED);
        //check for any other again
        curr = cache_index.used_list_head;
        while(curr != LIST_END_MARKER){
            if (cache_index.cache_lists[curr].flags & CERT_F_TO_DELETE){
                to_delete = curr;
                break;
            }
            curr = cache_index.cache_lists[curr].next;
        }
        if (curr == LIST_END_MARKER) 
            to_delete = LIST_END_MARKER;
    } 
err:
    cert_buffer_release(certbuf1);
    cert_buffer_release(certbuf2);
    return ret;
}

/**
 * walk through used list and return first entry marked VISITED
 * @return index of first VISITED entry
 */
static uint8_t cache_get_next_visited_cert(void)
{
    uint8_t curr;
    curr = cache_index.used_list_head;
    while (curr != LIST_END_MARKER) {
        if (cache_index.cache_lists[curr].flags & CERT_F_VISITED)
            return curr;
        curr = cache_index.cache_lists[curr].next;
    }
    return LIST_END_MARKER;
}

/**
 * delete one cert from cache
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
static error_t cache_delete_pcert_one(uint16_t slot_num)
{
    error_t ret;
    uint8_t flags;

    /* delete from used_list and add to free list */
    flags = cache_index.cache_lists[slot_num].flags;
    ret = cache_delete_from_used_list(slot_num);
    if (ret == ERR_OK) {
        cache_add_to_free_list(slot_num, flags);

        return cert_cache_delete_cert(slot_num);
    }
    return ret;
}

/**
 * delete all orphan nodes and their children if any 
 * @return standard error codes
 */
API error_t cache_check_sanity(void)
{
    int found = 0;
    error_t ret;
    uint8_t iter_i, iter_j;
    CertBuffer *certbuf1, *certbuf2;

    certbuf1 = cert_buffer_get();
    if (!certbuf1)
        return ERR_NO_MEM;
    certbuf2 = cert_buffer_get();
    if (!certbuf2) {
        cert_buffer_release(certbuf1);
        return ERR_NO_MEM;
    }
    cache_lock();

restart_loop:
    iter_i = cache_index.used_list_head;

    while(iter_i != LIST_END_MARKER) {
        ret = cert_cache_read_cert(certbuf1, iter_i);
        if (ret != ERR_OK) {
            goto err;
        }
        found = 0;

        iter_j = cache_index.used_list_head;
        while(iter_j != LIST_END_MARKER) {
            if (iter_i == iter_j) {
                if ( cache_is_issuer_of(certbuf1, certbuf1)) {
                    found = 1;
                    break;
                }
            }
            else {
                ret = cert_cache_read_cert(certbuf2, iter_j);
                if (ret != ERR_OK) {
                    goto err;
                }
                if ( cache_is_issuer_of(certbuf2, certbuf1)) {
                    found = 1;
                    break;
                }
            }
            iter_j = cache_index.cache_lists[iter_j].next;
        }
        if (!found) {
            ret = cache_delete_entry_no_lock(iter_i);
            if (ret != ERR_OK) {
                goto err;
            }
            goto restart_loop;
        }
        iter_i = cache_index.cache_lists[iter_i].next;
    }
err:
    cert_buffer_release(certbuf1);
    cert_buffer_release(certbuf2);
    cache_unlock();
    return ret;
}

/**
 * store cache index (used and free lists) to flash
 * @return standard error codes
 */
API error_t cache_store_index(void)
{
    return cert_cache_write_index(&cache_index,sizeof(struct cache_index));
}


/**
 * find issuer of given cert, does not acquire lock
 * @param - src is the cert to find issuer of
 * @param - pcert is the issuer to return
 * @param - slot is the slot no of issuer 
 * @return standard error codes
 */
static error_t cache_find_issuer_no_lock(IN const CertBuffer *src, OUT CertBuffer *pcert, INOUT uint16_t *slot)
{
    uint8_t curr;
    error_t ret;
    uint8_t issuer_slot;

    /* if src cert includes issuer_slot info, use it. 
     * if not, scan through used_list to find an issuer 
    */ 
    issuer_slot = src->dc.issuer_slot;
    if (issuer_slot) {
        ret = cert_cache_read_cert(pcert, issuer_slot); 
        if (ret != ERR_OK) {
            return ret;
        }
        *slot = issuer_slot;
        return ERR_OK;
    }
    curr = cache_index.used_list_head;
    while (curr != LIST_END_MARKER) {
        ret = cert_cache_read_cert(pcert, curr);
        if (ret != ERR_OK) {
            return ret;
        }
        if (cache_is_issuer_of(pcert,(CertBuffer *)src)) {
            *slot = curr;
            return ERR_OK;
        }
        curr = cache_index.cache_lists[curr].next;
    }

    return ERR_CACHE_FIND_NO_MATCH;
}

/**
 * find issuer of given cert
 * @param - src is the cert to find issuer of
 * @param - pcert is the issuer to return
 * @param - slot is the slot no of issuer 
 * @return standard error codes
 */
API error_t cache_find_issuer(IN const CertBuffer *psubject, OUT CertBuffer *pissuer, INOUT uint16_t *slot)
{
    error_t ret;

    assert(psubject && pissuer && slot);
    *slot = 0;
    cache_lock();
    ret = cache_find_issuer_no_lock(psubject,pissuer,slot);
    cache_unlock();

    return ret;
}

/**
 * check type of given cert
 * @param - pCert is the cert to be checked
 * @return - type of certificate
 */
static enum cert_types cache_get_cert_type(CertBuffer *pCert)
{
    if (pCert->dc.flags & CERT_F_ROOT) 
        return CERT_TYPE_ROOT;
    else
        return CERT_TYPE_NOTROOT;
}

/**
 * check if one cert is child of another
 * @param - maybe_issuer may be issuer
 * @param -  given - cert to check 
 * @return 1 if given was issued by maybe_issuer
 */
static int cache_is_issuer_of(CertBuffer *maybe_issuer, CertBuffer *given)
{
    if (maybe_issuer == given && given->dc.flags & CERT_F_ROOT) {
        return 1;
    }
    if (!maybe_issuer->dc.SubjKeyID.len){
        /* compare only subject and issuer */
        if ( given->dc.issuer.len == maybe_issuer->dc.subject.len && 
                !memcmp(maybe_issuer->buffer + maybe_issuer->dc.subject.idx,
                    given->buffer + given->dc.issuer.idx, given->dc.issuer.len)){
            return 1;
        }
    }
    else {
        /*compare subject/issuer and subjkeyid/authkeyid */
        if ( given->dc.issuer.len == maybe_issuer->dc.subject.len && 
                !memcmp(maybe_issuer->buffer + maybe_issuer->dc.subject.idx,
                    given->buffer + given->dc.issuer.idx, given->dc.issuer.len) &&
                given->dc.AuthKeyID.len &&
                maybe_issuer->dc.SubjKeyID.len == given->dc.AuthKeyID.len &&
                !memcmp(maybe_issuer->buffer + maybe_issuer->dc.SubjKeyID.idx,
                    given->buffer + given->dc.AuthKeyID.idx, given->dc.AuthKeyID.len) ) {
            return 1;
        }
    }
    return 0;
}

/*
 * return next or first mru
 * @param curr is next more recent than what is to be returned
 *        returns MRU is curr is 0
 * @return next mru in used_list
 */
API uint8_t cache_get_next_mru(IN uint8_t curr)
{
    uint8_t slot = cache_index.used_list_head;

    /* 0 is get first */
    if (curr == 0) return cache_index.used_list_head; 
    if (curr == LIST_END_MARKER) return LIST_END_MARKER;
    if (curr >= TOTAL_CERT_SLOTS || !(cache_index.cache_lists[curr].flags & CERT_F_USED)) 
        return LIST_END_MARKER;

    while (slot != curr) 
        slot = cache_index.cache_lists[slot].next;

    if (slot == LIST_END_MARKER) return slot;
    return cache_index.cache_lists[slot].next;
}

API error_t cache_get_flags(uint16_t *flags, uint16_t slot)
{
    uint16_t ret;

    assert(flags);
    if (slot == 0 || slot >= TOTAL_CERT_SLOTS || slot == LIST_END_MARKER) {
        return ERR_INVAL;
    }
    ret = cache_index.cache_lists[slot].flags;
    *flags = ret;
    return ERR_OK;

}

API error_t cache_get_issuer_slot(const uint16_t child_slot, uint16_t *parent_slot)
{
    uint16_t ret;

    assert(parent_slot);
    if (child_slot == 0 || child_slot == LIST_END_MARKER || 
        child_slot >= TOTAL_CERT_SLOTS) {
        return ERR_INVAL;
    }
    ret = cache_index.cache_lists[child_slot].issuer_slot;
    *parent_slot = ret;
    return ERR_OK;
}

static CertBuffer *cert_buffers;
OS_CPU_SR cpu_sr;
#define NOINLINE  __attribute__((noinline))
#define NUM_CERT_BUFFERS 6

void
cert_buffer_release(CertBuffer *cb)
{
    assert(cb);
    OS_ENTER_CRITICAL();
    cb->dc.source = (uint8_t *)cert_buffers;
    cert_buffers = cb; 
    OS_EXIT_CRITICAL();
}

CertBuffer *
cert_buffer_get(void)
{
    OS_ENTER_CRITICAL();
    CertBuffer *cb = cert_buffers;
    if (cb) {
        cert_buffers = (CertBuffer *)cb->dc.source;
    }   
    assert(cb);
    OS_EXIT_CRITICAL();
    return cb; 
}

NOINLINE void
cert_buffer_init(void)
{
    int i;
    CertBuffer *cb;

    for (i=0; i < NUM_CERT_BUFFERS; i++) {
        cb = malloc(sizeof *cb);
        assert(cb);
        memset(cb, 0, sizeof *cb);
        cert_buffer_release(cb);
    }   
}
