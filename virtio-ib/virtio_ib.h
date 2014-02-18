#ifndef _LINUX_VIRTIO_IB_H
#define _LINUX_VIRTIO_IB_H
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/virtio.h>

#define VIRTIO_ID_IB 99
#define DBG 1

enum{
	IB_USER_VERBS_CMD_FIND_SYSFS = 1000,
	IB_USER_VERBS_CMD_OPEN_DEV,
	IB_USER_VERBS_CMD_MMAP,
	IB_USER_VERBS_CMD_UNMAP,
	IB_USER_VERBS_CMD_RING_DOORBELL,
	IB_USER_VERBS_CMD_BUF_COPY,
	IB_USER_VERBS_CMD_CLOSE_DEV_FD
};

struct vib_cmd_hdr{
	__u32 fd;
	__u32 cmd_size;
	__u32 resp_size;
	__u64 command;
	__u64 response;
};

struct vib_cmd{
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

enum{
	VIRTIO_IB_DEVICE_OPEN,
	VIRTIO_IB_DEVICE_CLOSE
};

enum{
	VIRTIO_IB_EVENT_READ,
	VIRTIO_IB_EVENT_POLL,
	VIRTIO_IB_EVENT_CLOSE
};

#endif

