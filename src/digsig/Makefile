
CC = gcc
CFLAGS = -Wall -Wextra -O3 -Wno-unused-result -Wunused-parameter -g -I../../include -L../../lib

all: hexdump.o digsig

hexdump.o:
	$(CC) $(CFLAGS) -c hexdump.c

digver:elfrw/libelfrw.a sm2sig/libsm2sig.a
	$(CC) $(CFLAGS) -o digver digver.c -lelfrw -lsm2sig -lssl -lcrypto -lpthread -ldl

digsig:elfrw/libelfrw.a rsasig/librsasig.a crt/libcrt.a
	$(CC) $(CFLAGS) -o digsig digsig.c  hexdump.c -lelfrw -lrsasig -lcrt -lssl -lcrypto -lpthread -ldl 

elfrw/libelfrw.a:
	$(MAKE) -C ../elfrw libelfrw.a
	mv ../elfrw/libelfrw.a ../../lib

crt/libcrt.a:
	$(MAKE) -C ../crt libcrt.a
	mv ../crt/libcrt.a ../../lib

sm2sig/libsm2sig.a:
	$(MAKE) -C ../sm2sig libsm2sig.a
	mv ../sm2sig/libsm2sig.a ../../lib

rsasig/librsasig.a:
	$(MAKE) -C ../rsasig librsasig.a
	mv ../rsasig/librsasig.a ../../lib

clean:
	rm -f *.o digsig
allclean:
	rm -f *.o digsig
	$(MAKE) clean
