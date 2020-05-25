# Makefile for librsasig.a

VPATH := ../../include/rsasig ../../lib

CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -I../../include/

LIBOBJS = base64.o rsa_genkey.o rsasig.o md5.o sha256.o

librsasig.a: clean $(LIBOBJS)
	ar crs $@ $(LIBOBJS)

#gcc *.c -I./ -L./ libssl.a libcrypto.a -lpthread -ldl

base64.o:base64.c base64.h

rsa_genkey.o:rsa_genkey.c rsa_genkey.h

rsasig.o:rsasig.c rsasig.h

md5.o:md5.c md5.h

sha256.o:sha256.c sha256.h

clean:
	rm -f librsasig.a $(LIBOBJS) a.out
