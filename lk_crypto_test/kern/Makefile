KERNELDIR ?= /lib/modules/$(shell uname -r)/build

KVER 		= $(shell uname -r)
KVER_MAJOR 	= $(shell uname -r | awk -F "." '{print $$1}')
KVER_MINOR 	= $(shell uname -r | awk -F "." '{print $$2}')
PWD       	:= $(shell pwd)
INSTALL_MOD_DIR += extra
GIT_COMMIT	= $(shell git rev-parse --verify HEAD)

ifeq (,$(ARCH))
ARCH = $(shell uname -m)
endif

ifeq ($(ARCH), e2k)
	CPU_ARCH := ARCH_E2K
else
	CPU_ARCH := ARCH_X86
endif

ifneq ("$(wildcard $(/etc/centos-release))","")
	DIST := RHEL7
else ifneq ("$(wildcard $(/etc/fedora-release))","")
	DIST := FEDORA
else ifeq ($(ARCH), e2k)
	DIST := DEB_E2K
else
	DIST := OS_GENERIC
endif

export CPU_ARCH DIST KVER_MAJOR KVER_MINOR GIT_COMMIT

all: build

build:
	@echo "Building for $(ARCH) architecture"
	@echo "Kernel version: $(KVER)"
	@echo "Distribution: $(DIST)"
	@echo "Build commit: $(GIT_COMMIT)"
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install: build
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: build clean install all
