#/*
#* Copyright SilverSpring Networks 2004-2007.
#* All rights reserved.
#*
#* $Id: Makefile 34413 2012-07-20 00:51:45Z cdo $ */

TARGET_LIB = x509cache

NO_WARNINGS_AS_ERRORS=0

C_LFLAGS += -I$(SSCERT_SRC)/include

vpath %.c

C_SRCS += x509_cache.c \
          x509_cache_osutil.c  \
          x509_cache_flash.c	\
          sha256.c	\
          cert_setflags.c	\
          asn.c

include $(BUILD_ROOT)/mk/rules.mk
