#
# Copyright (c) 2018 Itron, Inc.
# All rights reserved.
#
#
#TOPDIR = ../../..
CC=gcc
CFLAGS =  -g -I.. -I/usr/include/openssl  -static
LDFLAGS = -L.. -lx509cache -lcrypto -lpthread -ldl -lssl


TARGET = x509cache

C_SRCS =	x509cache.c

OBJS = x509cache.o

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@ 

$(OBJS):$(C_SRCS)
	$(CC) -c $< $(CFLAGS) -o $@ 

clean:
	-rm -f *.o
	-rm -f $(TARGET)
