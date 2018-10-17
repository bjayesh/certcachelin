/* 
 * mc_cache_flash.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * cert cache routines to read/write flash
 * $Id: x509_cache_flash.c 127833 2018-08-14 14:40:12Z jbabu $
 */
#ifdef UCOSII
#include <stdio.h>
#include <string.h>
#include "x509_cache.h"
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
#endif
#ifdef LINUX
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <x509_cache.h>
#include "assert.h"
#include "asn.h"

//CertBuffer_cache_entry cert_cache[TOTAL_CERT_SLOTS];
CertBuffer cert_cache[TOTAL_CERT_SLOTS];

static void *get_cache_base_addr()
{
	return (void *)(cert_cache+1); //first one not used
}

error_t get_field_from_cert_cache(void *dest, uint16_t n, uint8_t index, uint16_t offset)
{
	// locate entry in cache and return content of mCert field starting at offset
	// caller should allocate dest
	void *base = get_cache_base_addr();
	memcpy(dest, (void *)(base + index*sizeof(cert_cache) + offset), n); 
	return ERR_OK;
}

error_t get_fullcert_from_cert_cache(CertBuffer *dest, uint8_t index )
{
	// locate entry and return full mCert
	// caller should allocate dest
	void *base = get_cache_base_addr();
	CertBuffer *pcert_flash = (CertBuffer *)(base + index*sizeof(CertBuffer));
	memcpy((void *)dest, (void *)(pcert_flash), sizeof(CertBuffer));
	return ERR_OK;
}


error_t write_cert_to_mcert_cache(IN CertBuffer *pcert, uint8_t index)
{
	void *base=get_cache_base_addr();
	*((CertBuffer *)(base + index*sizeof(CertBuffer)))=*pcert;

	return ERR_OK;
}

error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno)
{
	error_t ret;

	ret = get_fullcert_from_cert_cache(cert, slotno);
	cert->dc.source  = cert->buffer;

	return ret;
}

error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno)
{
	return write_cert_to_mcert_cache(cert, slotno);
}

error_t cert_cache_delete_cert(uint8_t slotno)
{
	void *base=get_cache_base_addr();
	memset((CertBuffer *)(base + slotno*sizeof(CertBuffer)),0,sizeof(CertBuffer));
return ERR_OK;
}

error_t cert_cache_read_index(void *index_table, uint16_t table_size, uint16_t *out_len)
{
static uint8_t first = 1;
assert(index_table && out_len);
void *base = get_cache_base_addr();
memcpy(index_table, base, table_size);
*out_len = table_size; 

//simulate out_len == 0 if index is not initialized
if (first) {
*out_len = 0;
first = 0;
} 
return ERR_OK;

}
//memcpy(index_table,&cert_cache[0],sizeof(CertBuffer));
//*out_len = (sizeof(index_table));
//out_len = (uint16_t)10;
//return ERR_OK;


error_t cert_cache_write_index(void *index_table, uint16_t table_size)
{
memcpy(&cert_cache[0],index_table,table_size);
return ERR_OK;
}
#endif
