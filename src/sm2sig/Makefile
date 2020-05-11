# Makefile for libsm2sig.a

VPATH := ../../include/sm2sig ../../lib

CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -I../../include/sm2sig

LIBOBJS = sm2_genkey.o sm2_sig.o sm3_prepro.o 
#test_sm2_sign_and_verify.o

libsm2sig.a: clean $(LIBOBJS)
	ar crs $@ $(LIBOBJS)

#gcc *.c -I./ -L./ libssl.a libcrypto.a -lpthread -ldl

sm2_genkey.o: sm2_genkey.c sm2_genkey.h

sm2_sig.o:sm2_sig.c sm2_sig.h

sm3_prepro.o:sm3_prepro.c sm3_prepro.h

test_sm2_sign_and_verify.o:test_sm2_sign_and_verify.c test_sm2_sign_and_verify.h

test:
	gcc test_demo.c -I../../include/sm2sig libsm2sig.a ../../lib/libssl.a ../../lib/libcrypto.a -lpthread -ldl

clean:
	rm -f libsm2sig.a $(LIBOBJS) a.out
