
CC = gcc
CFLAGS = -Wall -Wextra -Ielfrw -g

all: clean digsig

digsig:
	$(MAKE) -C ./src/digsig/

clean:
	rm -f digsig hello modelf hook.ko
allclean:
	rm -f digsig hello modelf hook.ko
	$(MAKE) -C ./src/digsig/ clean
