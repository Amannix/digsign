#  Makefile for libelfrw.a

VPATH := ../../include/elfrw
CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -I../../include/elfrw

LIBOBJS = elfrw.o elfrw_dyn.o elfrw_ehdr.o elfrw_phdr.o elfrw_rel.o \
          elfrw_shdr.o elfrw_sym.o elfrw_ver.o

libelfrw.a: clean $(LIBOBJS)
	ar crs $@ $(LIBOBJS)
elfrw.o: elfrw.c elfrw.h elfrw_int.h
elfrw_dyn.o: elfrw_dyn.c elfrw_int.h
elfrw_ehdr.o: elfrw_ehdr.c elfrw_int.h
elfrw_phdr.o: elfrw_phdr.c elfrw_int.h
elfrw_rel.o: elfrw_rel.c elfrw_int.h
elfrw_shdr.o: elfrw_shdr.c elfrw_int.h
elfrw_sym.o: elfrw_sym.c elfrw_int.h
elfrw_ver.o: elfrw_ver.c elfrw_int.h

clean:
	rm -f libelfrw.a $(LIBOBJS)
