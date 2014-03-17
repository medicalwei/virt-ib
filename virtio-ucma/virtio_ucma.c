/*
 * virtio RDMA UCMA passthrough driver
 * 2013 Yao Wei, SCOPE lab, NTHU
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <rdma/rdma_user_cm.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <linux/fdtable.h>

#include "virtio_ucma.h"

#define RDMA_CMD_MAX_SIZE 512

struct virtio_ucma *dev_vu = NULL;

struct virtio_ucma{
	struct virtio_device 		*vdev;

	struct virtqueue 		*write_vq;
	struct virtqueue 		*device_vq;
	struct virtqueue 		*poll_vq;
};

struct virtio_ucma_file{
	struct virtio_ucma 	*vu;
	__s32 			host_fd;

	struct completion 	acked;
	wait_queue_head_t 	poll_wait;
	unsigned int 		last_poll_status;
};

static void virtucma_poll_start(struct file *filp)
{
	struct virtio_ucma_file *file = filp->private_data;
	struct scatterlist sg[2];
	struct virtio_ucma *vu = file->vu;

	if(file->last_poll_status != 0)
		goto out;

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], &file->last_poll_status, sizeof file->last_poll_status);
	if(virtqueue_add_buf(vu->poll_vq, sg, 1, 1, file) < 0)
		goto out;

	virtqueue_kick(vu->poll_vq);

out:
	return;
}

static int virtucma_open(struct inode *inode, struct file *filp)
{
	struct virtio_ucma_file *file;
	struct scatterlist sg[2];
	virtucma_cmd cmd = VIRTUCMA_OPEN_DEVICE;
	__s32 host_fd = -1;
	struct virtio_ucma *vu = dev_vu;
	int err;

	file = kmalloc(sizeof *file, GFP_KERNEL);
	if(!file) {
		err = -ENOMEM;
		goto out;
	}

	init_completion(&file->acked);
	init_waitqueue_head(&file->poll_wait);
	file->last_poll_status = 0;

	sg_init_one(&sg[0], &cmd, sizeof cmd);
	sg_init_one(&sg[1], &host_fd, sizeof host_fd);
	if(virtqueue_add_buf(vu->device_vq, sg, 1, 1, file) < 0){
		err = -ENOMEM; /* FIXME: not NOMEM */
		goto out_free_file;
	}
	virtqueue_kick(vu->device_vq);
	wait_for_completion(&file->acked);

	if(host_fd < 0) {
		err = host_fd;
		goto out_free_file;
	}

	file->vu = vu;
	file->host_fd = host_fd;
	filp->private_data = file;

	return 0;

out_free_file:
	kfree(file);
out:
	return err;
}

static int virtucma_close(struct inode *inode, struct file *filp)
{
	struct virtio_ucma_file *file = filp->private_data;
	struct scatterlist sg[2];
	virtucma_cmd cmd = VIRTUCMA_CLOSE_DEVICE;
	struct virtio_ucma *vu = file->vu;
	int err;

	sg_init_one(&sg[0], &cmd, sizeof cmd);
	sg_init_one(&sg[1], &file->host_fd, sizeof file->host_fd);
	if(virtqueue_add_buf(vu->device_vq, sg, 2, 0, file) < 0){
		err = -ENOMEM; /* FIXME: not NOMEM */
		goto out;
	}
	virtqueue_kick(vu->device_vq);
	wait_for_completion(&file->acked);

	kfree(file);
	return 0;

out:
	return err;
}

void virtucma_change_fp_to_host_fd(struct rdma_ucm_cmd_hdr *hdr, char *in)
{
	if(hdr->cmd == RDMA_USER_CM_CMD_MIGRATE_ID) {
		struct rdma_ucm_migrate_id *s = (void *) in;
		struct file *filp; struct virtio_ucma_file *file;
		rcu_read_lock();
		filp = fcheck(s->fd);
		if(filp){
			file = filp->private_data;
			s->fd = file->host_fd;
		}
		rcu_read_unlock();
	}
}

unsigned long virtucma_copy_response_if_any(struct rdma_ucm_cmd_hdr *hdr,
		char *in, char *out)
{
#define VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(__cmd, __struct)\
	if(hdr->cmd == __cmd) {\
		struct __struct *s = (void *) in;\
		return copy_to_user((void __user*) s->response, out, hdr->out);\
	}\

	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_CREATE_ID,    rdma_ucm_create_id)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_DESTROY_ID,   rdma_ucm_destroy_id)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_BIND_ADDR,    rdma_ucm_bind_addr)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_QUERY_ROUTE,  rdma_ucm_query_route)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_INIT_QP_ATTR, rdma_ucm_init_qp_attr)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_JOIN_MCAST,   rdma_ucm_join_mcast)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_LEAVE_MCAST,  rdma_ucm_destroy_id)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_GET_EVENT,    rdma_ucm_get_event)
	VIRTUCMA_CHECK_CMD_AND_COPY_RESPONSE(RDMA_USER_CM_CMD_MIGRATE_ID,   rdma_ucm_migrate_id)
	return 0;
}

static ssize_t virtucma_write(struct file *filp, const char __user *buf,
			  size_t len, loff_t *pos)
{
	/* XXX: "in" in this place is the whole input including header */
	struct virtio_ucma_file *file = filp->private_data;
	struct scatterlist sg[4];
	struct virtio_ucma *vu = file->vu;
	char in[RDMA_CMD_MAX_SIZE], out[RDMA_CMD_MAX_SIZE];
	struct rdma_ucm_cmd_hdr *hdr=(void *)in;
	int ret;

	/* reset polling status */
	file->last_poll_status = 0;

	/* copy header */
	if(copy_from_user(in, buf, len)){
		ret = -EFAULT;
		goto out;
	}

	virtucma_change_fp_to_host_fd(hdr, in + sizeof(*hdr));

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], in, len);
	sg_init_one(&sg[2], &ret, sizeof ret);
	sg_init_one(&sg[3], out, sizeof out);
	if(virtqueue_add_buf(vu->write_vq, sg, 2, 2, file) < 0){
		ret = -ENOMEM; /* FIXME: not NOMEM */
		goto out;
	}
	virtqueue_kick(vu->write_vq);
	wait_for_completion(&file->acked);

	virtucma_copy_response_if_any(hdr, in + sizeof(*hdr), out);

out:
	return ret;
}

static unsigned int virtucma_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct virtio_ucma_file *file = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &file->poll_wait, wait);

	mask |= file->last_poll_status;
	if(mask == 0)
		virtucma_poll_start(filp);

	return mask;
}

static const struct file_operations virtucma_fops = {
	.owner 	 = THIS_MODULE,
	.open 	 = virtucma_open,
	.release = virtucma_close,
	.write	 = virtucma_write,
	.poll    = virtucma_poll,
};

static struct miscdevice virtucma_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "virt_rdma_cm",
	.fops	= &virtucma_fops,
};

static void virtucma_callback(struct virtqueue *vq)
{
	struct virtio_ucma_file *file;
	unsigned int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		complete(&file->acked);
	}
}

static void virtucma_poll_callback(struct virtqueue *vq)
{
	struct virtio_ucma_file *file;
	unsigned int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		wake_up_interruptible(&file->poll_wait);
	}
}

static int init_vq(struct virtio_ucma *vu)
{
	struct virtqueue *vqs[3];

	vq_callback_t *callbacks[] = {
		virtucma_callback,
		virtucma_callback,
		virtucma_poll_callback
	};

	const char *names[] = {
		"write",
		"device",
		"poll"
	};

	int err;
	err = vu->vdev->config->find_vqs(vu->vdev, 3, vqs, callbacks, names);
	if(err) {
		printk(KERN_ERR "virtio-ucma: virtqueue initialization failed\n");
		goto out;
	}

	vu->write_vq  = vqs[0];
	vu->device_vq = vqs[1];
	vu->poll_vq   = vqs[2];

	return 0;

out:
	return err;
}

static int virtucma_probe(struct virtio_device *vdev)
{
	struct virtio_ucma *vu;
	int err;

	vdev->priv = vu = kmalloc(sizeof(*vu), GFP_KERNEL);
	if(!vu) {
		err = -ENOMEM;
		goto out;
	}

	vu->vdev = vdev;
	dev_vu = vu;
	
	err = init_vq(vu);
	if(err)
		goto out_free_vu;

	err = misc_register(&virtucma_misc);
	if(err)
		goto out_free_vu;

	return 0;

out_free_vu:
	kfree(vu);
out:
	printk(KERN_ERR "virtib: probe failed\n");
	return err;
}

static void virtucma_remove(struct virtio_device *vdev)
{
	struct virtio_ucma *vu = vdev->priv;

	misc_deregister(&virtucma_misc);
	vu->vdev->config->reset(vu->vdev);
	vu->vdev->config->del_vqs(vu->vdev);
	kfree(vu);
}

static unsigned int features[] = {};

static struct virtio_device_id id_table[] = {
	{VIRTIO_ID_UCMA, VIRTIO_DEV_ANY_ID},
	{0},
};

static struct virtio_driver virtio_ucma_driver = {
	.feature_table 		= features,
	.feature_table_size 	= ARRAY_SIZE(features),
	.driver.name 		= KBUILD_MODNAME,
	.driver.owner 		= THIS_MODULE,
	.id_table 		= id_table,
	.probe 			= virtucma_probe,
	.remove 		= virtucma_remove,
};

static int __init init(void)
{
	int err;

	err = register_virtio_driver(&virtio_ucma_driver);	
	if(err != 0)
		goto out;

	return 0;
out:
	return err;
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_ucma_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio RDMA UCMA passthrough driver");
MODULE_LICENSE("GPL");
