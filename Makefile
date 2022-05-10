# SPDX-License-Identifier: GPL-2.0-only

# make -C $KERNEL_SOURCE modules M=$PWD &&  make -C $KERNEL_SOURCE modules_install M=$PWD

obj-m += ostreefs.o

KBUILD_CFLAGS += 

ostreefs-objs += otfs.o
