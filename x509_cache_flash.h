/* 
 * x509_cache.h
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * $Id: x509_cache_flash.h 127833 2018-08-14 14:40:12Z jbabu $
 */
#ifndef _X509_CACHE_FLASH_H_
#define _X509_CACHE_FLASH_H_

error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno);
error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno);
error_t cert_cache_delete_cert(uint8_t slotno);
error_t cert_cache_write_index(const void *index_table, uint16_t table_size);
error_t cert_cache_read_index(void *index_table, uint16_t table_size, uint16_t *out_len);

#endif
