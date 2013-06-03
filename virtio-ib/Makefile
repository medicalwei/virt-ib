# Makefile 2.6
obj-m += virtio_ib.o

KDIR:=/lib/modules/$(shell uname -r)/build
#KDIR=~/linux-2.6.32.60
# PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
