/*
 * $Id $
 * Copyright 2018 iTron Network Solutions, Inc.  
 */
#include "asn.h"
#include <errors.h>

error_t cert_is_signed_by(const DecodedCert *subj, const DecodedCert *issuer);

void cert_buffer_release(CertBuffer *cb);

CertBuffer * cert_buffer_get(void);
