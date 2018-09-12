/* visibility.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 */


/* Visibility control macros */


#ifndef CTAO_CRYPT_VISIBILITY_H
#define CTAO_CRYPT_VISIBILITY_H


/* CYASSL_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   CYASSL_LOCAL is used for non-API symbols (private).
*/

#define CYASSL_API
#define CYASSL_LOCAL

#endif /* CTAO_CRYPT_VISIBILITY_H */

