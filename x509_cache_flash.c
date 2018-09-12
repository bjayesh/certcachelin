/* 
 * mc_cache_flash.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * cert cache routines to read/write flash
 * $Id: x509_cache_flash.c 127833 2018-08-14 14:40:12Z jbabu $
 */

#include <stdio.h>
#include <string.h>
#include <x509_cache.h>
#include "includes.h"
#include "os_cpu.h"
#include "os_cfg.h"
#include <ucos_ii.h>
#include "assert.h"

#include "include/app_sysvar.h"
#include <flash_types.h>
#include <sfl_bsp.h>
#include "x509_cache_flash.h"

error_t cert_cache_add(uint16_t id, const void* val, size_t length);
error_t cert_cache_get(uint16_t id, void *val, size_t len, uint16_t *out_len);
error_t cert_cache_del(uint16_t id); 

/**
 * read cert from cache at given slot
 * @param slotno to read 
 * @param cert is the cert to return
 * @return standard error codes
 */
error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno)
{
    uint16_t out_len;
    error_t ret;

    assert(cert);

    ret =  cert_cache_get(slotno, (void *)cert, sizeof(CertBuffer), &out_len);
    if (ret == ERR_OK) {
        assert(cert->buffer[0] == 0x30);
    }
    cert->dc.source = cert->buffer;
    return ret;	
}

/**
 * write cert to cache at given slot
 * @param slotno to write 
 * @param cert is the cert to write
 * @return standard error codes
 */
error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno)
{
    assert(cert);

    return cert_cache_add(slotno,(const void *)cert, sizeof(CertBuffer));
}

/**
 * write index info to cache
 * @param index_table is data to write
 * @param table_size is size of data
 * @return standard error codes
 */
error_t cert_cache_write_index(const void *index_table, uint16_t table_size)
{
    assert(index_table);

    return cert_cache_add(CACHE_INDEX_SLOT,index_table,table_size);
}

/**
 * delete cert at given slot
 * @param slotno to delete 
 * @return standard error codes
 */
error_t cert_cache_delete_cert(uint8_t slotno)
{
    return cert_cache_del(slotno);
}

/**
 * read index data from cache
 * @param index_table is data to read
 * @param table_size is size of data
 * @param out_len is bytes read. 0 if this slot was never written to
 * @return standard error codes - error if never written
 */
error_t cert_cache_read_index(void *index_table, uint16_t table_size, uint16_t *out_len)
{
    assert(index_table && out_len);

    return cert_cache_get(CACHE_INDEX_SLOT,index_table, table_size, out_len);
}

error_t
cert_cache_add(uint16_t id, const void* val, size_t length)
{
    //validate id and length

    /* delete if length is 0 */
    if (length == 0)
        return app_sysvar_del(id);

    return app_sysvar_set(id, val, 0, length, length);
}

error_t
cert_cache_get(uint16_t id, void *val, size_t len, uint16_t *out_len)
{
    //validate id and len
    int rc;
    uint16_t length = len;
    uint16_t totlen = len;

    assert(len);

    rc =  app_sysvar_get(id, val, &length, 0, &totlen);
    *out_len = length;

    return rc;
}

/*
 * Delete a certificate
 */
error_t
cert_cache_del(uint16_t id) 
{
    return cert_cache_add(id, NULL, 0); 
}
