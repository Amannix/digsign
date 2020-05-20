KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += hook.o
hook-objs := test.o ftrace_hook.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
