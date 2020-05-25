KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
VPATH := ./include ./src

obj-m += hook.o
hook-objs := src/rdx_crypto.o src/ftrace_hook.o src/sigver.o src/kstdio.o src/elfrw.o src/elfrw_ehdr.o src/elfrw_shdr.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
