# Makefile 2.6
obj-m += virtio_ucma.o

KDIR:=/lib/modules/$(shell uname -r)/build
# PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
run: all
	-rm /dev/infiniband/rdma_cm
	-rmmod virtio_ucma
	
	insmod virtio_ucma.ko
	mknod /dev/infiniband/rdma_cm c 10 `cat /proc/misc | grep virt_rdma_cm | sed 's/^ *\([0-9]\+\).*$\/\1/g'`
