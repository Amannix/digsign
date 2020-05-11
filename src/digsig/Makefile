
CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-result -Ielfrw -g -I../../include -L../../lib

all: clean hello digsig digver

digver:elfrw/libelfrw.a sm2sig/libsm2sig.a
	$(CC) $(CFLAGS) -o digver digver.c -lelfrw -lsm2sig -lssl -lcrypto -lpthread -ldl

digsig:elfrw/libelfrw.a sm2sig/libsm2sig.a
	$(CC) $(CFLAGS) -o digsig digsig.c -lelfrw -lsm2sig -lssl -lcrypto -lpthread -ldl
hello:
	$(CC) -o hello test.c

elfrw/libelfrw.a:
	$(MAKE) -C ../elfrw libelfrw.a
	mv ../elfrw/libelfrw.a ../../lib

sm2sig/libsm2sig.a:
	$(MAKE) -C ../sm2sig libsm2sig.a
	mv ../sm2sig/libsm2sig.a ../../lib

clean:
	rm -f digsig hello
allclean:
	rm -f digsig hello
	$(MAKE) clean
