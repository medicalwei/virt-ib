#ifndef _LINUX_VIRTIO_UCMA_H
#define _LINUX_VIRTIO_UCMA_H
#define VIRTIO_ID_UCMA 98

enum {
	VIRTUCMA_OPEN_DEVICE,
	VIRTUCMA_POLL_DEVICE,
	VIRTUCMA_CLOSE_DEVICE,
};
typedef __u32 virtucma_cmd;

#endif

