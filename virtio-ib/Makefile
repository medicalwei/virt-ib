# Makefile 2.6
obj-m += virtio_ib.o

KDIR:=/lib/modules/$(shell uname -r)/build
# PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
run: all
	-rm /dev/virtib
	-rmmod virtio_ib
	
	insmod virtio_ib.ko
	mknod /dev/virtib c `cat /proc/devices | grep virtib | cut -d' ' -f 1` 0
