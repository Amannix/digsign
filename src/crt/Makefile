# Makefile for libcrt.a

VPATH := ../../include/crt ../../lib

CC = gcc
CFLAGS = -g -I../../include/

LIBOBJS = x509.o x509_crt.o pem.o base64.o asn1parse.o

libcrt.a: clean $(LIBOBJS)
	ar crs $@ $(LIBOBJS)

#gcc *.c -I./ -L./ libssl.a libcrypto.a -lpthread -ldl

x509.o:x509.c x509.h

x509_crt.o:x509_crt.c x509_crt.h

pem.o:pem.c pem.h

base64.o:base64.c base64.h

asn1parse.o:asn1parse.c asn1.h
clean:
	rm -f librsasig.a $(LIBOBJS) a.out
