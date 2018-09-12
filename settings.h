/* settings.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of CyaSSL.
 *
 * Contact licensing@yassl.com with any questions or comments.
 *
 * http://www.yassl.com
 */


/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */


#ifndef CTAO_CRYPT_SETTINGS_H
#define CTAO_CRYPT_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

/* Uncomment next line if using IPHONE */
/* #define IPHONE */

/* Uncomment next line if using ThreadX */
/* #define THREADX */

/* Uncomment next line if using Micrium ucOS */
/* #define MICRIUM */

/* Uncomment next line if using Mbed */
/* #define MBED */

/* Uncomment next line if using Microchip PIC32 ethernet starter kit */
/* #define MICROCHIP_PIC32 */

/* Uncomment next line if using Microchip TCP/IP stack, for time features */
/* #define MICROCHIP_TCPIP */

/* Uncomment next line if using FreeRTOS */
/* #define FREERTOS */

/* Uncomment next line if using FreeRTOS Windows Simulator */
/* #define FREERTOS_WINSIM */

/* Uncomment next line if using RTIP */
/* #define EBSNET */

/* Uncomment next line if using lwip */
/* #define CYASSL_LWIP */

/* Uncomment next line if building CyaSSL for a game console */
/* #define CYASSL_GAME_BUILD */

/* Uncomment next line if building CyaSSL for LSR */
/* #define CYASSL_LSR */

/* Uncomment next line if building CyaSSL for Freescale MQX/RTCS/MFS */
/* #define FREESCALE_MQX */

/* Uncomment next line if using STM32F2 */
/* #define CYASSL_STM32F2 */

#define NO_CYASSL_MEMORY

#define USER_TIME

#include "visibility.h"

#ifdef IPHONE
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef THREADX 
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef MICROCHIP_PIC32
    #define SIZEOF_LONG_LONG 8
    #define SINGLE_THREADED
    #define CYASSL_USER_IO
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
#endif

#ifdef MICROCHIP_TCPIP
    /* includes timer functions */
    #include "TCPIP Stack/TCPIP.h"
#endif

#ifdef MBED
    #define SINGLE_THREADED
    #define CYASSL_USER_IO
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_SHA512
    #define NO_DH
    #define NO_DSA
    #define NO_HC128
#endif /* MBED */

#ifdef FREERTOS_WINSIM
    #define FREERTOS
    #define USE_WINDOWS_API
#endif


#if defined(CYASSL_LEANPSK) && !defined(XMALLOC_USER)
    #include <stdlib.h>
    #define XMALLOC(s, h, type)  malloc((s))
    #define XFREE(p, h, type)    free((p)) 
    #define XREALLOC(p, n, h, t) realloc((p), (n))
#endif

#if defined(XMALLOC_USER) && defined(SSN_BUILDING_LIBYASSL)
    #undef  XMALLOC
    #define XMALLOC     yaXMALLOC
    #undef  XFREE
    #define XFREE       yaXFREE
    #undef  XREALLOC
    #define XREALLOC    yaXREALLOC
#endif


#ifdef FREERTOS
    #ifndef NO_WRITEV
        #define NO_WRITEV
    #endif
    #ifndef NO_SHA512
        #define NO_SHA512
    #endif
    #ifndef NO_DH
        #define NO_DH
    #endif
    #ifndef NO_DSA
        #define NO_DSA
    #endif
    #ifndef NO_HC128
        #define NO_HC128
    #endif

    #ifndef SINGLE_THREADED
        #include "FreeRTOS.h"
        #include "semphr.h"
    #endif
#endif

#ifdef EBSNET
    #include "rtip.h"

    /* #define DEBUG_CYASSL */
    #define NO_CYASSL_DIR  /* tbd */

    #if (POLLOS)
        #define SINGLE_THREADED
    #endif

    #if (RTPLATFORM)
        #if (!RTP_LITTLE_ENDIAN)
            #define BIG_ENDIAN_ORDER
        #endif
    #else
        #if (!KS_LITTLE_ENDIAN)
            #define BIG_ENDIAN_ORDER
        #endif
    #endif

    #if (WINMSP3)
        #undef SIZEOF_LONG
        #define SIZEOF_LONG_LONG 8
    #else
        #sslpro: settings.h - please implement SIZEOF_LONG and SIZEOF_LONG_LONG
    #endif

    #define XMALLOC(s, h, type) ((void *)rtp_malloc((s), SSL_PRO_MALLOC))
    #define XFREE(p, h, type) (rtp_free(p))
    #define XREALLOC(p, n, h, t) realloc((p), (n))

#endif /* EBSNET */

#ifdef CYASSL_GAME_BUILD
    #define SIZEOF_LONG_LONG 8
    #if defined(__PPU) || defined(__XENON)
        #define BIG_ENDIAN_ORDER
    #endif
#endif

#ifdef CYASSL_LSR
    #define HAVE_WEBSERVER
    #define SIZEOF_LONG_LONG 8
    #define CYASSL_LOW_MEMORY
    #define NO_WRITEV
    #define NO_SHA512
    #define NO_DH
    #define NO_DSA
    #define NO_HC128
    #define NO_DEV_RANDOM
    #define NO_CYASSL_DIR
    #define NO_RABBIT
    #ifndef NO_FILESYSTEM
        #define LSR_FS
        #include "inc/hw_types.h"
        #include "fs.h"
    #endif
    #define CYASSL_LWIP
    #include <errno.h>  /* for tcp errno */
    #define CYASSL_SAFERTOS
    #if defined(__IAR_SYSTEMS_ICC__)
        /* enum uses enum */
        #pragma diag_suppress=Pa089
    #endif
#endif

#ifdef CYASSL_SAFERTOS
    #ifndef SINGLE_THREADED
        #include "SafeRTOS/semphr.h"
    #endif

    #include "SafeRTOS/heap.h"
    #define XMALLOC(s, h, type)  pvPortMalloc((s))
    #define XFREE(p, h, type)    vPortFree((p)) 
    #define XREALLOC(p, n, h, t) pvPortRealloc((p), (n))
#endif

#ifdef CYASSL_LOW_MEMORY
    #undef  RSA_LOW_MEM
    #define RSA_LOW_MEM
    #undef  CYASSL_SMALL_STACK
    #define CYASSL_SMALL_STACK
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT
#endif

#ifdef FREESCALE_MQX
    #define SIZEOF_LONG_LONG 8
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_RABBIT
    #define NO_CYASSL_DIR
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #define FREESCALE_K70_RNGA
    #ifndef NO_FILESYSTEM
        #include "mfs.h"
        #include "fio.h"
    #endif
    #ifndef SINGLE_THREADED
        #include "mutex.h"
    #endif

    #define XMALLOC(s, h, type) (void *)_mem_alloc_system((s))
    #define XFREE(p, h, type)   _mem_free(p)
    /* Note: MQX has no realloc, using fastmath above */
#endif

#ifdef CYASSL_STM32F2
    #define SIZEOF_LONG_LONG 8
    #define NO_DEV_RANDOM
    #define NO_CYASSL_DIR
    #define NO_RABBIT
    #define STM32F2_RNG
    #define STM32F2_CRYPTO
    #define KEIL_INTRINSICS
#endif


#if !defined(XMALLOC_USER) && !defined(MICRIUM_MALLOC) && \
    !defined(CYASSL_LEANPSK) && !defined(NO_CYASSL_MEMORY)
    #define USE_CYASSL_MEMORY
#endif


#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS)
    #undef  KEEP_PEER_CERT
    #define KEEP_PEER_CERT
#endif


/* stream ciphers except arc4 need 32bit alignment, intel ok without */
#ifndef XSTREAM_ALIGNMENT
    #if defined(__x86_64__) || defined(__ia64__) || defined(__i386__)
        #define NO_XSTREAM_ALIGNMENT
    #else
        #define XSTREAM_ALIGNMENT
    #endif
#endif


/* if using hardware crypto and have alignment requirements, specify the
   requirement here.  The record header of SSL/TLS will prvent easy alignment.
   This hint tries to help as much as possible.  */
#ifndef CYASSL_GENERAL_ALIGNMENT
    #ifdef CYASSL_AESNI
        #define CYASSL_GENERAL_ALIGNMENT 16
    #elif defined(XSTREAM_ALIGNMENT)
        #define CYASSL_GENERAL_ALIGNMENT  4
    #else 
        #define CYASSL_GENERAL_ALIGNMENT  0 
    #endif
#endif

/* Place any other flags or defines here */


#ifdef __cplusplus
    }   /* extern "C" */
#endif

#define CYASSL_MSG(x)
#define CYASSL_ENTER(x)

#endif /* CTAO_CRYPT_SETTINGS_H */

