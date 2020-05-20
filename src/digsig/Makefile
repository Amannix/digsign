
CC = gcc
CFLAGS = -Wall -Wextra -O3 -Wno-unused-result -Ielfrw -g -I../../include -L../../lib

all: clean hello digsig

digver:elfrw/libelfrw.a sm2sig/libsm2sig.a
	$(CC) $(CFLAGS) -o digver digver.c -lelfrw -lsm2sig -lssl -lcrypto -lpthread -ldl

digsig:elfrw/libelfrw.a rsasig/librsasig.a
	$(CC) $(CFLAGS) -o digsig digsig.c -lelfrw -lrsasig -lssl -lcrypto -lpthread -ldl 
hello:
	$(CC) -o hello test.c

elfrw/libelfrw.a:
	$(MAKE) -C ../elfrw libelfrw.a
	mv ../elfrw/libelfrw.a ../../lib

sm2sig/libsm2sig.a:
	$(MAKE) -C ../sm2sig libsm2sig.a
	mv ../sm2sig/libsm2sig.a ../../lib

rsasig/librsasig.a:
	$(MAKE) -C ../rsasig librsasig.a
	mv ../rsasig/librsasig.a ../../lib

clean:
	rm -f digsig hello
allclean:
	rm -f digsig hello
	$(MAKE) clean
