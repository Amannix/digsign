KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += hook.o
hook-objs := src/ksig/sha256.o\
             src/ksig/rdx_crypto.o\
             src/kftrace/ftrace_hook.o\
             src/ksig/sigver.o\
             src/kstd/kstdio.o\
             src/kelf/elfrw.o\
             src/kelf/elfrw_ehdr.o\
             src/kelf/elfrw_shdr.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

test:
	sudo rmmod hook
	sudo insmod hook.ko

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean