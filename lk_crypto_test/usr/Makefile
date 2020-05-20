
all: main.o
	gcc -o convert main.o -Wall
	
main.o: main.c
	gcc -o main.o -c main.c -Wall
	
clean :
	rm -rf convert
	rm -rf *.o

.PHONY: clean all
