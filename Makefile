#/*
#* Copyright SilverSpring Networks 2004-2007.
#* All rights reserved.
#*
#* $Id: Makefile 34413 2012-07-20 00:51:45Z cdo $ */

 
TARGET_LIB = libx509cache.a
TARGET_APP = test/x509cache

CC=gcc

NO_WARNINGS_AS_ERRORS=0

CFLAGS = -g -I. -Wall -lpthread -DLINUX

vpath %.c

OBJECTS = x509_cache.o \
          x509_cache_osutil.o  \
          x509_cache_flash.o	\
          sha256.o	\
          cert_setflags.o	\
          asn.o

C_SRCS += x509_cache.c \
          x509_cache_osutil.c  \
          x509_cache_flash.c	\
          sha256.c	\
          cert_setflags.c	\
          asn.c


#x509_cache.o: x509_cache.c
#	$(CC) -c $(CFLAGS) x509_cache.c

all: $(TARGET_LIB) $(TARGET_APP)

$(TARGET_LIB): $(OBJECTS)
	ar rcs -o $(TARGET_LIB) $(OBJECTS) 

$(TARGET_APP): $(TARGET_LIB)
	make -C test

.c.o:
	#$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	-rm -f *.o
	-rm -f *.a    
	make -C test clean
