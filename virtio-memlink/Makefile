# Makefile 2.6
obj-m += virtio_memlink.o

KDIR:=/lib/modules/$(shell uname -r)/build
# PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
run: all
	-rm /dev/memlink
	-rmmod virtio_memlink
	
	insmod virtio_memlink.ko
	mknod /dev/memlink c `cat /proc/devices | grep memlink | cut -d' ' -f 1` 0
