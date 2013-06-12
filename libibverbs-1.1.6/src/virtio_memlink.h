#ifndef _LINUX_VIRTIO_MEMLINK_H
#define _LINUX_VIRTIO_MEMLINK_H
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

/* The ID for virtio_memlink */
#define VIRTIO_ID_MEMLINK 65535

/* Size of a PFN in the memlink interface. */
#define VIRTIO_MEMLINK_PFN_SHIFT 12

struct virtio_memlink_ioctl_input
{
	int size;
	unsigned long long gva;
	unsigned long long hva; /* will be given by module */
};

#define MEMLINK_IOC_MAGIC 0xAF
#define MEMLINK_IOC_CREATE _IOW(MEMLINK_IOC_MAGIC, 1, struct virtio_memlink_ioctl_input *)
#define MEMLINK_IOC_REVOKE _IOW(MEMLINK_IOC_MAGIC, 2, int)
#define MEMLINK_IOC_MAXNR 2

#define MEMLINK_MAX_LINKS 32

#endif

