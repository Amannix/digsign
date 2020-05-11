
CC = gcc
CFLAGS = -Wall -Wextra -Ielfrw -g

all: clean hello digsig

digsig:elfrw/libelfrw.a sm2sig/libsm2sig.a
	$(CC) $(CFLAGS) digsig.c elfrw/libelfrw.a sm2sig/libsm2sig.a 
hello:
	$(CC) -o hello test.c

elfrw/libelfrw.a:
	$(MAKE) -C elfrw libelfrw.a

sm2sig/libsm2sig.a:
	$(MAKE) -C sm2sig libsm2sig.a

clean:
	rm -f digsig hello
allclean:
	rm -f digsig hello
	$(MAKE) clean
