#include "virtio_ib.h"

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <asm/pgtable.h>
#include <linux/unistd.h>
#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>
#include <linux/pagemap.h>
#include <linux/fdtable.h>
#include <rdma/ib_user_verbs.h>

#define IB_UVERBS_CMD_MAX_SIZE 16384

struct virtio_ib{
	struct virtio_device     *vdev;

	struct virtqueue         *write_vq;
	struct virtqueue         *read_vq;
	struct virtqueue         *device_vq;
	struct virtqueue         *event_vq;
};

struct virtio_ib_file{
	struct virtio_ib         *vib;
	__s32                     host_fd;

	struct completion         write_acked;
	struct completion         read_acked;
	struct completion         device_acked;

	char                      in_buf[IB_UVERBS_CMD_MAX_SIZE];
	char                      out_buf[IB_UVERBS_CMD_MAX_SIZE];
};

struct virtio_ib_event_file{
	struct virtio_ib         *vib;
	__s32                     host_fd;
	wait_queue_head_t         wait_queue;
	struct fasync_struct     *async_queue;
	struct completion         acked;

	unsigned int              last_poll_status;
	unsigned int              is_polling;
};

struct virtio_ib *vib_dev;

static void virtib_event_poll_start(struct virtio_ib_event_file *file)
{
	struct scatterlist sg[3];
	struct virtio_ib *vib = file->vib;
	__s32 cmd = VIRTIB_EVENT_POLL;

	if(file->last_poll_status != 0)
		goto out;

	if(file->is_polling != 0)
		goto out;

	file->is_polling = 1;

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], &cmd, sizeof cmd);
	sg_init_one(&sg[2], &file->last_poll_status,
			sizeof file->last_poll_status);
	if(virtqueue_add_buf(vib->event_vq, sg, 2, 1, file) < 0)
		goto out;

	virtqueue_kick(vib->event_vq);

out:
	return;
}

static ssize_t virtib_event_read(struct file *filp, char __user *buf,
				    size_t len, loff_t *pos)
{
	struct virtio_ib_event_file *file = filp->private_data;
	struct scatterlist sg[5];
	struct virtio_ib *vib = file->vib;
	__s32 cmd = VIRTIB_EVENT_READ;
	char out[16];
	int ret;

	virtib_event_poll_start(file);
	wait_for_completion(&file->acked);

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], &cmd, sizeof cmd);
	sg_init_one(&sg[2], &len, sizeof len);
	sg_init_one(&sg[3], &ret, sizeof ret);
	sg_init_one(&sg[4], out, sizeof out);

	BUG_ON(virtqueue_add_buf(vib->event_vq, sg, 3, 2, file) < 0);
	virtqueue_kick(vib->event_vq);
	wait_for_completion(&file->acked);

	/* clear read status */
	file->last_poll_status = 0;

	if (copy_to_user(buf, out, ret) > 0){
		return -EINVAL;
	}

	return ret;
}

static unsigned int virtib_event_poll(struct file *filp,
					 struct poll_table_struct *wait)
{
	struct virtio_ib_event_file *file = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &file->wait_queue, wait);

	mask |= file->last_poll_status;
	if(mask == 0 && file->is_polling == 0)
		virtib_event_poll_start(file);

	return mask;
}

static int virtib_event_fasync(int fd, struct file *filp, int on)
{
	struct virtio_ib_event_file *file = filp->private_data;

	virtib_event_poll_start(file);
	return fasync_helper(fd, filp, on, &file->async_queue);
}

static int virtib_event_close(struct inode *inode, struct file *filp)
{
	struct virtio_ib_event_file *file = filp->private_data;
	struct scatterlist sg[2];
	struct virtio_ib *vib = file->vib;
	__s32 cmd = VIRTIB_EVENT_CLOSE;

	/* prevent from triggering wakeup actions */
	file->last_poll_status = 0;

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], &cmd, sizeof cmd);

	BUG_ON(virtqueue_add_buf(vib->event_vq, sg, 2, 0, file) < 0);
	virtqueue_kick(vib->event_vq);
	wait_for_completion(&file->acked);

	kfree(file);
	return 0;
}

static const struct file_operations virtib_event_fops = {
	.owner	 = THIS_MODULE,
	.read 	 = virtib_event_read,
	.poll    = virtib_event_poll,
	.release = virtib_event_close,
	.fasync  = virtib_event_fasync
};

__s32 virtib_alloc_event_file(__s32 host_fd){
	struct virtio_ib_event_file *ev_file;
	struct file *filp;
	int ret;
	__s32 fd;

	ev_file = kmalloc(sizeof *ev_file, GFP_KERNEL);
	if (!ev_file)
		return -ENOMEM;

	fd = get_unused_fd();
	if (fd < 0) {
		ret = fd;
		goto err;
	}

	filp = anon_inode_getfile("[virtib-event]", &virtib_event_fops,
				  ev_file, O_RDONLY);
	if (!filp) {
		ret = -ENFILE;
		goto err_fd;
	}

	ev_file->host_fd = host_fd;
	init_completion(&ev_file->acked);
	init_waitqueue_head(&ev_file->wait_queue);
	ev_file->async_queue = NULL;
	ev_file->last_poll_status = 0;
	ev_file->is_polling = 1;
	ev_file->vib = vib_dev;

	fd_install(fd, filp);

	return fd;

err_fd:
	put_unused_fd(fd);

err:
	kfree(ev_file);
	return ret;
}

static int virtib_open(struct inode *inode, struct file *filp)
{
	struct virtio_ib_file *file;
	struct virtio_ib *vib;
	struct scatterlist sg[2];
	__s32 cmd = VIRTIB_DEVICE_OPEN;

	try_module_get(THIS_MODULE);

	file = kmalloc(sizeof(struct virtio_ib_file), GFP_KERNEL);
	filp->private_data = file;
	vib = file->vib = vib_dev;

	init_completion(&file->write_acked);
	init_completion(&file->read_acked);
	init_completion(&file->device_acked);

	sg_init_one(&sg[0], &cmd, sizeof(cmd));
	sg_init_one(&sg[1], &file->host_fd, sizeof(file->host_fd));

	if(virtqueue_add_buf(vib->device_vq, sg, 1, 1, file) < 0) {
		printk(KERN_ERR "virtio-ib: virtib_open add_buf error\n");
		return -EFAULT;
	}

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	if ((int) file->host_fd == -1){
		printk(KERN_ERR "virtio-ib: virtib_open close error\n");
	}

	return 0;
}

static int virtib_release(struct inode *inode, struct file *filp)
{
	struct virtio_ib_file *file = filp->private_data;
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];
	__s32 cmd = VIRTIB_DEVICE_CLOSE;
	__s32 ret;

	module_put(THIS_MODULE);

	sg_init_one(&sg[0], &cmd, sizeof(cmd));
	sg_init_one(&sg[1], &file->host_fd, sizeof(file->host_fd));
	sg_init_one(&sg[2], &ret, sizeof(ret));

	if (virtqueue_add_buf(vib->device_vq, sg, 2, 1, file) < 0) {
		printk(KERN_ERR "virtio-ib: virtib_release add_buf error\n");
		return -EFAULT;
	}

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	if ((int) ret == -1)
		printk(KERN_ERR "virtio-ib: virtib_release close error\n");

	kfree(file);
	module_put(THIS_MODULE);

	return 0;
}

/* virtib device functions */

static ssize_t virtib_device_find_sysfs(struct virtio_ib_file *file,
		struct virtib_hdr_with_resp *hdr){
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];
	int ret;

	sg_init_one(&sg[0], &hdr->command, sizeof(hdr->command));
	sg_init_one(&sg[1], &ret, sizeof(ret));
	sg_init_one(&sg[2], file->out_buf, sizeof(file->out_buf));

	if(virtqueue_add_buf(vib->device_vq, sg, 1, 2, file) < 0) {
		printk(KERN_ERR "virtio-ib: virtib_device_find_sysfs add_buf error\n");
		return -EFAULT;
	}

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	if (copy_to_user((void *) hdr->response, file->out_buf,
				hdr->out_words*4)){
		printk(KERN_ERR "virtio-ib: virtib_device_find_sysfs response error\n");
		return -EFAULT;
	}

	return ret;
}

static ssize_t virtib_device_mmap(struct virtio_ib_file *file,
		struct virtib_device_mmap *cmd)
{
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[4];
	__u64 ret;

	sg_init_one(&sg[0], &cmd->command, sizeof(cmd->command));
	sg_init_one(&sg[1], &file->host_fd, sizeof(file->host_fd));
	sg_init_one(&sg[2], &cmd->offset, sizeof(cmd->offset));
	sg_init_one(&sg[3], &ret, sizeof(ret));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 3, 1, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	if ((void *) ret == (void *) -1) {
		printk(KERN_ERR "virtio-ib: virtib_device_mmap error\n");
		return -EFAULT;
	}

	if (copy_to_user((void *) cmd->response, &ret, sizeof(ret))){
		printk(KERN_ERR "virtio-ib: virtib_device_mmap response error\n");
		return -EFAULT;
	}

	return sizeof(struct virtib_device_mmap);
}

static ssize_t virtib_device_munmap(struct virtio_ib_file *file,
		struct virtib_device_munmap *cmd)
{
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];
	__s32 ret;

	sg_init_one(&sg[0], &cmd->command, sizeof(cmd->command));
	sg_init_one(&sg[1], &cmd->hva, sizeof(cmd->hva));
	sg_init_one(&sg[2], &ret, sizeof(ret));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 2, 1, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	if ((int) ret == -1) {
		printk(KERN_ERR "virtio-ib: virtib_device_munmap error\n");
		return -EFAULT;
	}

	return sizeof(struct virtib_device_munmap);
}

static ssize_t virtib_device_mcopy(struct virtio_ib_file *file,
		struct virtib_device_mcopy *cmd)
{
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[4];

	/* borrowing second buffer */
	if (cmd->bytecnt > IB_UVERBS_CMD_MAX_SIZE)
		return -EFAULT;
	if (copy_from_user(file->out_buf, &cmd->src_addr, cmd->bytecnt))
		return -EFAULT;

	sg_init_one(&sg[0], &cmd->command, sizeof(cmd->command));
	sg_init_one(&sg[1], &cmd->dst_hva, sizeof(cmd->dst_hva));
	sg_init_one(&sg[2], &file->out_buf, cmd->bytecnt);
	sg_init_one(&sg[3], &cmd->bytecnt, sizeof(cmd->bytecnt));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 4, 0, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	return sizeof(struct virtib_device_mcopy);
}

static ssize_t virtib_device_massign(struct virtio_ib_file *file,
		struct virtib_device_massign *cmd)
{
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];

	sg_init_one(&sg[0], &cmd->command, sizeof(cmd->command));
	sg_init_one(&sg[1], &cmd->dst_hva, sizeof(cmd->dst_hva));
	sg_init_one(&sg[2], &cmd->data_long, sizeof(cmd->data_long));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 3, 0, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

	return sizeof(struct virtib_device_massign);
}

static void virtib_replace_guest_fd_to_host_fd(void *buf)
{
	struct ib_uverbs_cmd_hdr *hdr = buf;
	if (hdr->command == IB_USER_VERBS_CMD_CREATE_CQ) {
		struct virtib_create_cq *s = (void *) buf;
		struct file *filp; struct virtio_ib_event_file *file;
		if (s->cmd.comp_channel != -1) {
			rcu_read_lock();
			filp = fcheck(s->cmd.comp_channel);
			if (filp){
				file = filp->private_data;
				s->cmd.comp_channel = file->host_fd;
			}
			rcu_read_unlock();
		}
	}
}

static ssize_t virtib_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *f_pos)
{
	struct virtio_ib_file *file = filp->private_data;
	struct virtio_ib *vib = file->vib;
	struct virtib_hdr_with_resp *hdr = (void *) file->in_buf;
	struct scatterlist sg[4];
	int ret = 0;

	if (copy_from_user(file->in_buf, buf, len))
		return -EFAULT;

	if (hdr->command == VIRTIB_DEVICE_FIND_SYSFS)
		return virtib_device_find_sysfs(file, hdr);
	else if (hdr->command == VIRTIB_DEVICE_MMAP)
		return virtib_device_mmap(file, (void *) hdr);
	else if (hdr->command == VIRTIB_DEVICE_MUNMAP)
		return virtib_device_munmap(file, (void *) hdr);
	else if (hdr->command == VIRTIB_DEVICE_MCOPY)
		return virtib_device_mcopy(file, (void *) hdr);
	else if (hdr->command == VIRTIB_DEVICE_MASSIGN
			|| hdr->command == VIRTIB_DEVICE_MASSIGN_LONG)
		return virtib_device_massign(file, (void *) hdr);

	virtib_replace_guest_fd_to_host_fd((void *) file->in_buf);

	sg_init_one(&sg[0], &file->host_fd, sizeof(file->host_fd));
	sg_init_one(&sg[1], file->in_buf, len);
	sg_init_one(&sg[2], &ret, sizeof(int));
	sg_init_one(&sg[3], file->out_buf, sizeof(file->out_buf));

	if(virtqueue_add_buf(vib->write_vq, sg, 2, 2, file) < 0) {
		printk(KERN_ERR "virtio-ib: virtib_write add_buf error\n");
		return -EFAULT;
	}

	virtqueue_kick(vib->write_vq);
	wait_for_completion(&file->write_acked);

	if (hdr->command == IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL){
		struct ib_uverbs_create_comp_channel_resp *__resp =
			(void *) file->out_buf;
		__resp->fd = virtib_alloc_event_file(__resp->fd);
	} else if (hdr->command == IB_USER_VERBS_CMD_GET_CONTEXT){
		struct ib_uverbs_get_context_resp *__resp =
			(void *) file->out_buf;
		__resp->async_fd = virtib_alloc_event_file(__resp->async_fd);
	}

	if (hdr->out_words > 0 &&
			copy_to_user((void *) hdr->response,
				file->out_buf, hdr->out_words*4)){
		printk(KERN_ERR "virtio-ib: virtib_write response error\n");
		return -EFAULT;
	}

	return ret;
}

static ssize_t virtib_read(struct file *filp, char __user *ubuf,
		size_t count, loff_t *f_pos)
{
	/* TODO: cleanup? */
	struct virtio_ib_file *file = filp->private_data;
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];
	char *path_buffer = kmalloc(sizeof(char) * 1024, GFP_KERNEL);
	char *file_buffer = kmalloc(sizeof(char) * 1024, GFP_KERNEL);
	ssize_t retsize;

	if (copy_from_user(path_buffer, ubuf, sizeof(char)*1024)){
		printk(KERN_ERR "VIB: [virtib_read] copy from user failed\n");
		goto out;
	}

	sg_init_one(&sg[0], path_buffer, sizeof(char)*1024);
	sg_init_one(&sg[1], file_buffer, sizeof(char)*1024);
	sg_init_one(&sg[2], &retsize, sizeof(ssize_t));

	BUG_ON(virtqueue_add_buf(vib->read_vq, sg, 1, 2, file) < 0);

	virtqueue_kick(vib->read_vq);
	wait_for_completion(&file->read_acked);

	if (retsize < 0 || copy_to_user((void *) ubuf, file_buffer, retsize))
		printk(KERN_ERR "virtio-ib: virtio_read copy to user failed\n");

out:
	kfree(path_buffer);
	kfree(file_buffer);
	return retsize;
}

struct file_operations virtib_fops = {
	.owner   = THIS_MODULE,
	.open    = virtib_open,
	.release = virtib_release,
	.read    = virtib_read,
	.write   = virtib_write,
};

static struct miscdevice virtib_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "virtib",
	.fops  = &virtib_fops,
};


static void virtib_write_cb(struct virtqueue *vq)
{
	struct virtio_ib_file *file;
	int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		complete(&file->write_acked);
	}
}

static void virtib_read_cb(struct virtqueue *vq)
{
	struct virtio_ib_file *file;
	int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		complete(&file->read_acked);
	}
}

static void virtib_device_cb(struct virtqueue *vq)
{
	struct virtio_ib_file *file;
	int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		complete(&file->device_acked);
	}
}

static void virtib_event_cb(struct virtqueue *vq)
{
	struct virtio_ib_event_file *file;
	int len;

	while((file = virtqueue_get_buf(vq, &len)) != 0){
		complete(&file->acked);

		file->is_polling = 0;
		if (file->last_poll_status != 0){
			wake_up_interruptible(&file->wait_queue);
			kill_fasync(&file->async_queue, SIGIO, POLL_IN);
		}
	}
}

static int init_vq(struct virtio_ib *vib)
{
	struct virtqueue *vqs[4];
	vq_callback_t *callbacks[] = {virtib_write_cb, virtib_read_cb,
				      virtib_device_cb, virtib_event_cb};
	const char *names[] = { "write", "read", "device", "event"};
	int err = 0;

	err = vib->vdev->config->find_vqs(vib->vdev, 4, vqs, callbacks, names);
	if (err){
		printk(KERN_ERR "virtib: virtqueue initial failed\n");
		return err;
	}

	vib->write_vq      = vqs[0];
	vib->read_vq       = vqs[1];
	vib->device_vq     = vqs[2];
	vib->event_vq      = vqs[3];

	return 0;
}

static int virtib_probe(struct virtio_device *vdev)
{
	int err;
	struct virtio_ib *vib;

	vdev->priv = vib = kmalloc(sizeof(struct virtio_ib), GFP_KERNEL);
	if (!vib){
		err = -ENOMEM;
		goto out;
	}

	vib->vdev = vdev;
	vib_dev = vib;

	err = init_vq(vib);
	if (err) {
		printk(KERN_ERR "virtib: failed to initialize virtio.");
		goto err_init_vq;
	}

	err = misc_register(&virtib_misc);
	if (err) {
		printk(KERN_ERR "virtib: failed to register misc device.");
		goto err_init_vq;
	}

	return 0;

err_init_vq:
	kfree(vib);
out:
	printk(KERN_ERR "virtib: probe failed\n");
	return err;
}

static void virtib_remove(struct virtio_device *vdev)
{
	struct virtio_ib *vib = vdev->priv;
	int err;

	err = misc_deregister(&virtib_misc);
	if (err)
		printk(KERN_ERR "virtib: deregister misc device failed\n");
	vib_dev = NULL;

	vib->vdev->config->reset(vib->vdev);
	vib->vdev->config->del_vqs(vib->vdev);
	kfree(vib);
}

static unsigned int features[] = {};

static struct virtio_device_id id_table[] = {
	{VIRTIO_ID_IB, VIRTIO_DEV_ANY_ID},
	{0},
};

static struct virtio_driver virtio_ib_driver = {
	.feature_table      = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name        = KBUILD_MODNAME,
	.driver.owner       = THIS_MODULE,
	.id_table           = id_table,
	.probe              = virtib_probe,
	.remove             = virtib_remove,
};

static int __init init(void){
	return register_virtio_driver(&virtio_ib_driver);
}

static void __exit fini(void){
	unregister_virtio_driver(&virtio_ib_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio ib driver");
MODULE_LICENSE("GPL");
