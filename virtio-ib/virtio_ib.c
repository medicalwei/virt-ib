#include "virtio_ib.h"

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <asm/pgtable.h>
#include <linux/unistd.h>
#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/sched.h>

static int   dev_major;
static int   dev_minor;
struct cdev  *cdev;
static int   device_open = 0;

struct virtio_ib{
        int size;
        void* data;
        
	struct virtio_device 	*vdev;
	struct cdev 		cdev;
        
	struct virtqueue 	*write_vq;
        struct virtqueue 	*read_vq;
        struct virtqueue 	*device_vq;
	
	struct completion 	done;
};

struct virtio_ib *vib_cdev;

static struct virtio_device_id id_table[] = {
        {VIRTIO_ID_IB, VIRTIO_DEV_ANY_ID}, 
	{0},
};

static void virtib_cb(struct virtqueue *vq)
{
	int len;
	while(virtqueue_get_buf(vq, &len));
	complete_all(&vib_cdev->done);
}

static int init_vq(struct virtio_ib *vib)
{
	struct virtqueue *vqs[3];
	vq_callback_t *callbacks[] = {virtib_cb, virtib_cb, virtib_cb};
	const char *names[] = { "write", "read", "device"};
	int err = 0;

	err = vib->vdev->config->find_vqs(vib->vdev, 3, vqs, callbacks, names);
	if (err){
		printk(KERN_ERR "virtib: virtqueue initial failed\n");
		return err;
	}

	vib->write_vq  = vqs[0];
	vib->read_vq   = vqs[1];
	vib->device_vq = vqs[2];

	return 0; 
}

static int virtib_probe(struct virtio_device *vdev)
{
	int err;
	struct virtio_ib *vib = kmalloc(sizeof(struct virtio_ib), GFP_KERNEL);	

	if (!vib){
		err = -ENOMEM;
		goto out;
	}

	vdev->priv = vib;
	vib->vdev = vdev;
	
	err = init_vq(vib);

	memcpy(&vib->cdev, cdev, sizeof(struct cdev));

	if (err)
		goto err_init_vq;

	vib_cdev = vib;

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
	vib_cdev = NULL;

        vib->vdev->config->reset(vib->vdev);
        vib->vdev->config->del_vqs(vib->vdev);
        kfree(vib);
}

static unsigned int features[] = {};

static struct virtio_driver virtio_ib_driver = {
        .feature_table      = features,
        .feature_table_size = ARRAY_SIZE(features),
        .driver.name	    = KBUILD_MODNAME,
        .driver.owner 	    = THIS_MODULE,
        .id_table 	    = id_table,
        .probe 		    = virtib_probe,
        .remove 	    = virtib_remove,
};

static int virtib_open(struct inode *inode, struct file *file)
{
	device_open++;

	file->private_data = vib_cdev;
	
	try_module_get(THIS_MODULE);
	return 0;
}

static int virtib_release(struct inode *inode, struct file *file)
{
	device_open--;

	module_put(THIS_MODULE);

	return 0;	
}

static int virtib_device(struct vib_cmd *cmd, struct virtqueue *vq,
		struct virtio_ib *vib)
{
	struct scatterlist sg[3];
	char *buffer = kmalloc(cmd->out_words * 4, GFP_KERNEL);	
	int resp;

	init_completion(&vib->done);
	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], cmd, cmd->in_words * 4);	
	sg_set_buf(&sg[1], &resp, sizeof(int));
	sg_set_buf(&sg[2], buffer, cmd->out_words * 4);


	if(virtqueue_add_buf(vq, sg, 1, 2, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_device] add_buf failed\n");

	virtqueue_kick(vq);
	wait_for_completion(&vib->done);

	if (copy_to_user((void *) cmd->response, buffer, cmd->out_words*4)){
		printk(KERN_ERR "VIB: [virtio_device] copy to user failed\n");
		return -EFAULT;
	}
	kfree(buffer);	
	
	return resp;
}

static int virtib_mmap(struct vib_cmd_hdr hdr, struct virtqueue *vq,
	       	struct virtio_ib *vib)
{
	struct scatterlist sg[4];
	char *cmd  = kmalloc(hdr.cmd_size, GFP_KERNEL);
	__u64 resp;
	int ret = 0;

	if (copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 4);
	sg_set_buf(&sg[0], cmd, hdr.cmd_size);
	sg_set_buf(&sg[1], &hdr.fd, sizeof(int));
	sg_set_buf(&sg[2], &ret, sizeof(int));
	sg_set_buf(&sg[3], &resp, sizeof(resp));

	if(virtqueue_add_buf(vq, sg, 2, 2, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_mmap] add_buf failed\n");

	virtqueue_kick(vq);
	wait_for_completion(&vib->done);

	if (copy_to_user((void *) hdr.response, &resp, hdr.resp_size)){
		printk(KERN_ERR "VIB: [virtio_mmap] copy to user failed\n");
		return -EFAULT;
	}
	
	kfree(cmd);
	return ret;

}

static int virtib_unmap(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
	struct scatterlist sg[4];
	char *cmd  = kmalloc(hdr.cmd_size, GFP_KERNEL);
	int ret;

	if (copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 4);
	sg_set_buf(&sg[0], cmd, hdr.cmd_size);
        sg_set_buf(&sg[1], &hdr.response, sizeof(__u64));
        sg_set_buf(&sg[2], &hdr.resp_size, sizeof(int));
        sg_set_buf(&sg[3], &ret, sizeof(int));	

	if(virtqueue_add_buf(vq, sg, 3, 1, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_unmap] add_buf failed\n");

	virtqueue_kick(vq);

	kfree(cmd);
	return ret;
}

static int virtib_ring_doorbell(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
        struct scatterlist sg[5];
        char *cmd = kmalloc(hdr.cmd_size, GFP_KERNEL);
        int ret;

        if(copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 5);
        sg_set_buf(&sg[0], cmd, hdr.cmd_size);
        sg_set_buf(&sg[1], &hdr.response, sizeof(__u64));
        sg_set_buf(&sg[2], &hdr.resp_size, sizeof(__u32));
        sg_set_buf(&sg[3], &hdr.fd, sizeof(__u32));
        sg_set_buf(&sg[4], &ret, sizeof(int));

	if(virtqueue_add_buf(vq, sg, 4, 1, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_ring_doorbell] add_buf failed\n");

        virtqueue_kick(vq);

        kfree(cmd);
        return ret;
}

static int virtib_buf_copy(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
        struct scatterlist sg[4];
        char *cmd = kmalloc(hdr.cmd_size, GFP_KERNEL);
        char *ctrl = kmalloc(hdr.resp_size, GFP_KERNEL);
        int ret;

        if(copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	
        if(copy_from_user(ctrl, (void *) hdr.response, hdr.resp_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 4);
        sg_set_buf(&sg[0], cmd, hdr.cmd_size);
        sg_set_buf(&sg[1], ctrl, hdr.resp_size);
        sg_set_buf(&sg[2], &((struct vib_cmd*)cmd)->response, sizeof(__u64));
        sg_set_buf(&sg[3], &ret, sizeof(int));

	if(virtqueue_add_buf(vq, sg, 3, 1, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_buf_copy] add_buf failed\n");

        virtqueue_kick(vq);

        kfree(cmd);
        kfree(ctrl);
        return ret;
}

static int virtib_close_dev_fd(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
	struct scatterlist sg[3];
        char *cmd = kmalloc(hdr.cmd_size, GFP_KERNEL);
        int resp;

        if(copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 3);
        sg_set_buf(&sg[0], cmd, hdr.cmd_size);
        sg_set_buf(&sg[1], &hdr.fd, sizeof(int));
        sg_set_buf(&sg[2], &resp, sizeof(int));

	if(virtqueue_add_buf(vq, sg, 2, 1, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_close_dev_fd] add_buf failed\n");

        virtqueue_kick(vq);

        kfree(cmd);
        return resp;
}

static int virtib_cmd_with_resp(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
	struct scatterlist sg[4];
	char *cmd  = kmalloc(hdr.cmd_size, GFP_KERNEL);
	char *resp = kmalloc(hdr.resp_size, GFP_KERNEL);

	int ret;

	if (copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 4);
	sg_set_buf(&sg[0], cmd, hdr.cmd_size);
	sg_set_buf(&sg[1], &hdr.fd, sizeof(int));
	sg_set_buf(&sg[2], &ret, sizeof(int));
	sg_set_buf(&sg[3], resp, hdr.resp_size);

	if(virtqueue_add_buf(vq, sg, 2, 2, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_cmd_with_resp] add_buf failed\n");

	virtqueue_kick(vq);
	wait_for_completion(&vib->done);

	if (copy_to_user((void *) hdr.response, resp, hdr.resp_size)){
		printk(KERN_ERR "VIB: [virtio_cmd_with_resp] copy to user failed\n");
		return -EFAULT;
	}
	
	kfree(cmd);
	kfree(resp);
	return ret;
}

static int virtib_cmd(struct vib_cmd_hdr hdr, struct virtqueue *vq,
		struct virtio_ib *vib)
{
	struct scatterlist sg[3];
	char *cmd  = kmalloc(hdr.cmd_size, GFP_KERNEL);

	int ret;
	
	if (copy_from_user(cmd, (void *) hdr.command, hdr.cmd_size))
		return -EFAULT;	

	init_completion(&vib->done);
	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], cmd, hdr.cmd_size);
	sg_set_buf(&sg[1], &hdr.fd, sizeof(int));
	sg_set_buf(&sg[2], &ret, sizeof(int));

	if(virtqueue_add_buf(vq, sg, 2, 1, vib) < 0)
		printk(KERN_ERR "VIB: [virtib_cmd] add_buf failed\n");

	virtqueue_kick(vq);

	kfree(cmd);
	return ret;
}

static ssize_t virtib_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	struct virtio_ib *vib = filp->private_data;
	struct vib_cmd_hdr hdr;
	struct vib_cmd cmd;
	int ret = 0;

	/*Get command header*/
	if (copy_from_user(&hdr, buf, count))
		return -EFAULT;	

	/*Get ibverbs command content*/
	if (copy_from_user(&cmd, (void *) hdr.command, sizeof(cmd)))
		return -EFAULT;
	
	switch(cmd.command){
		case IB_USER_VERBS_CMD_GET_CONTEXT:
		case IB_USER_VERBS_CMD_QUERY_DEVICE:
		case IB_USER_VERBS_CMD_QUERY_PORT:
		case IB_USER_VERBS_CMD_ALLOC_PD:
		case IB_USER_VERBS_CMD_CREATE_AH:
		case IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL:
		case IB_USER_VERBS_CMD_CREATE_CQ:
		case IB_USER_VERBS_CMD_RESIZE_CQ:
		case IB_USER_VERBS_CMD_DESTROY_CQ:
		case IB_USER_VERBS_CMD_POLL_CQ:
		case IB_USER_VERBS_CMD_CREATE_QP:
		case IB_USER_VERBS_CMD_QUERY_QP:
		case IB_USER_VERBS_CMD_DESTROY_QP: 
		case IB_USER_VERBS_CMD_CREATE_SRQ:
		case IB_USER_VERBS_CMD_QUERY_SRQ:
		case IB_USER_VERBS_CMD_DESTROY_SRQ:
		case IB_USER_VERBS_CMD_GET_EVENT:
		case IB_USER_VERBS_CMD_REG_MR:
			return virtib_cmd_with_resp(hdr, vib->write_vq, vib);
		case IB_USER_VERBS_CMD_FIND_SYSFS:
			return virtib_device(&cmd, vib->device_vq, vib);
		case IB_USER_VERBS_CMD_DEALLOC_PD:
		case IB_USER_VERBS_CMD_DESTROY_AH:
		case IB_USER_VERBS_CMD_DEREG_MR:
		case IB_USER_VERBS_CMD_REQ_NOTIFY_CQ:
		case IB_USER_VERBS_CMD_MODIFY_QP:
		case IB_USER_VERBS_CMD_ATTACH_MCAST:
		case IB_USER_VERBS_CMD_DETACH_MCAST:
		case IB_USER_VERBS_CMD_MODIFY_SRQ:
			return virtib_cmd(hdr, vib->write_vq, vib);
		case IB_USER_VERBS_CMD_OPEN_DEV:
			return virtib_cmd(hdr, vib->device_vq, vib);
		case IB_USER_VERBS_CMD_MMAP:
			return virtib_mmap(hdr, vib->write_vq, vib);
		case IB_USER_VERBS_CMD_UNMAP:
			return virtib_unmap(hdr, vib->write_vq, vib);
		case IB_USER_VERBS_CMD_RING_DOORBELL:
			return virtib_ring_doorbell(hdr, vib->device_vq, vib); 
		case IB_USER_VERBS_CMD_BUF_COPY:
			return virtib_buf_copy(hdr, vib->device_vq, vib);
		case IB_USER_VERBS_CMD_CLOSE_DEV_FD:
			return virtib_close_dev_fd(hdr, vib->device_vq, vib);
		case 3000:
			return virtib_device(&cmd, vib->write_vq, vib);
		default:
			printk(KERN_ERR "VIB: no such command\n");
			return -1;
	}

	return ret;
	
}

static ssize_t virtib_read(struct file *filp, char __user *ubuf, size_t count, loff_t *f_pos)
{
	struct virtio_ib *vib = filp->private_data;
	struct scatterlist sg[3];
	char *path_buffer = kmalloc(sizeof(char) * 1024, GFP_KERNEL);
	char *file_buffer = kmalloc(sizeof(char) * 1024, GFP_KERNEL);
	ssize_t retsize;

	if (copy_from_user(path_buffer, ubuf, sizeof(char)*1024)){
		printk(KERN_ERR "VIB: [virtib_read] copy from user failed\n");
		goto out;
	}

	init_completion(&vib->done);
	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], path_buffer, sizeof(char)*1024);
	sg_set_buf(&sg[1], file_buffer, sizeof(char)*1024);
	sg_set_buf(&sg[2], &retsize, sizeof(ssize_t));

	if(virtqueue_add_buf(vib->read_vq, sg, 1, 2, vib) < 0){
		printk(KERN_ERR "VIB: [virtib_read] add_buf failed\n");
		retsize = -EFAULT;
		goto out;
	}

	virtqueue_kick(vib->read_vq);
	wait_for_completion(&vib->done);

	if (retsize < 0 || copy_to_user((void *) ubuf, file_buffer, retsize))
		printk(KERN_ERR "VIB: [virtio_read] copy to user failed\n");

out:
	kfree(path_buffer);
	kfree(file_buffer);
	return retsize;
}

struct file_operations dev_fops = {
        .owner 	 = THIS_MODULE,
        .open 	 = virtib_open,
        .release = virtib_release,
        .read 	 = virtib_read,
        .write 	 = virtib_write,
};

static int init_chr_dev(void){
	dev_t dev;
	int err;

	err = alloc_chrdev_region(&dev, 0, 1, "virtib");
	if (err < 0)
		return err;

	dev_major = MAJOR(dev);
	dev_minor = MINOR(dev);

	cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);	
	if (!cdev)
		return -1;

	cdev_init(cdev, &dev_fops);
	cdev->owner = THIS_MODULE;
	cdev->ops   = &dev_fops;

	err = cdev_add(cdev, MKDEV(dev_major, dev_minor), 1);
	if (err < 0){
		kfree(cdev);
		cdev = NULL;
		return -EFAULT;
	}
		
	return 0;
}

static int __init virtib_init(void){
	int err;

	err = init_chr_dev();

	if (err < 0)
		return err;

	return register_virtio_driver(&virtio_ib_driver);	
}

static void __exit virtib_fini(void){
	dev_t dev;

	dev = MKDEV(dev_major, dev_minor);
	if (cdev){
		cdev_del(cdev);
		kfree(cdev);
	}
	
	unregister_chrdev_region(dev, 1);
	unregister_virtio_driver(&virtio_ib_driver);
}

module_init(virtib_init);
module_exit(virtib_fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio ib driver");
MODULE_LICENSE("GPL");
