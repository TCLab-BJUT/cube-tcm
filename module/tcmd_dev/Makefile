# Software-based Trusted Platform Module (TCM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id: Makefile 364 2010-02-11 10:24:45Z mast $

# kernel settings
KERNEL_RELEASE := $(shell uname -r)
KERNEL_BUILD   := /lib/modules/$(KERNEL_RELEASE)/build
#KERNEL_BUILD   := /usr/src/linux-$(KERNEL_RELEASE)
#KERNEL_BUILD   := /usr/src/linux-headers-$(KERNEL_RELEASE)
MOD_SUBDIR     := misc

# module settings
MODULE_NAME    := tcmd_dev
obj-m          := $(MODULE_NAME).o

# do not print "Entering directory ..."
MAKEFLAGS      += --no-print-directory
EXTRA_CFLAGS   += -Wall -Werror

all:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) modules

clean:
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) clean
	@rm -f Modules.symvers tcmd_dev.rules

TCM_GROUP ?= tss
INSTALL ?= install

tcmd_dev.rules: tcmd_dev.rules.in
	@sed -e "s/\$$TCM_GROUP/$(TCM_GROUP)/g" tcmd_dev.rules.in > tcmd_dev.rules

install: tcmd_dev.rules
	@$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR) INSTALL_MOD_PATH=$(DESTDIR) modules_install
	@$(INSTALL) -m 644 -D tcmd_dev.rules $(DESTDIR)/etc/udev/rules.d/80-tcmd_dev.rules

.PHONY: all clean install

