#ifndef _LINUX_VIRTIO_IB_H
#define _LINUX_VIRTIO_IB_H
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/virtio.h>
#include <rdma/ib_user_verbs.h>

#define VIRTIO_ID_IB 99

enum{
        VIRTIB_DEVICE_FIND_SYSFS = 1000,
        VIRTIB_DEVICE_OPEN,
        VIRTIB_DEVICE_CLOSE,
        VIRTIB_DEVICE_MMAP,
        VIRTIB_DEVICE_MUNMAP
};

enum{
	VIRTIB_EVENT_READ,
	VIRTIB_EVENT_POLL,
	VIRTIB_EVENT_CLOSE
};

struct virtib_hdr_with_resp {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct virtib_create_cq {
	struct ib_uverbs_cmd_hdr	hdr;
	struct ib_uverbs_create_cq	cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct virtib_resize_cq {
	struct ib_uverbs_cmd_hdr	hdr;
	struct ib_uverbs_resize_cq	cmd;
	__u64				buf_addr;
};

struct virtib_create_srq {
	struct ib_uverbs_cmd_hdr	hdr;
	struct ib_uverbs_create_srq	cmd;
	__u64				buf_addr;
	__u64				db_addr;
};

struct virtib_create_qp {
	struct ib_uverbs_cmd_hdr	hdr;
	struct ib_uverbs_create_qp	cmd;
	__u64				buf_addr;
	__u64				db_addr;
	__u8				log_sq_bb_count;
	__u8				log_sq_stride;
	__u8				sq_no_prefetch;	/* was reserved in ABI 2 */
	__u8				reserved[5];
};
#endif

