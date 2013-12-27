#include <linux/virtio.h>
#include "virtio_memlink.h"
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/pagemap.h>
#include <asm/uaccess.h>

#define DEBUG 1

static int dev_major;
static int dev_minor;
struct cdev *dev_cdevp = NULL;

struct memlink;
struct virtio_memlink;

struct memlink
{
	struct page **pages;
	unsigned int size;
	unsigned int offset;
	unsigned int num_pfns;
	uint32_t *pfns;
	uint64_t hva;
	struct memlink *next, *pprev;
};

struct virtio_memlink
{
	struct virtio_device *vdev;
	struct virtqueue *create_vq;
	struct virtqueue *revoke_vq;

	struct memlink *memlinks_head;

	struct completion create_acked;
	struct completion revoke_acked;
};

static struct virtio_memlink *vml_global;

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_MEMLINK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static void memlink_create_ack(struct virtqueue *vq)
{
	struct virtio_memlink *vml;
	unsigned int len;

	vml = virtqueue_get_buf(vq, &len);
	if (vml) {
		complete(&vml->create_acked);
	}
}

static void memlink_revoke_ack(struct virtqueue *vq)
{
	struct virtio_memlink *vml;
	unsigned int len;

	vml = virtqueue_get_buf(vq, &len);
	if (vml)
		complete(&vml->revoke_acked);
}

static void virtmemlink_changed(struct virtio_device *vdev)
{
}

void memlink_free(struct memlink *ml){
	/* release page cache */
	int i;
	for(i=0; i<ml->num_pfns; i++){
		set_page_dirty_lock(ml->pages[i]);
		page_cache_release(ml->pages[i]);
	}

	/* free memory */
	kfree(ml->pages);
	kfree(ml->pfns);
}

static int create(struct virtio_memlink *vml, struct virtio_memlink_ioctl_input *input)
{
	struct scatterlist sg[4];
	struct virtqueue *vq = vml->create_vq;
	int err, i;
	struct memlink *ml = kmalloc(sizeof(struct memlink), GFP_KERNEL);

	ml->size = input->size;
	ml->offset = input->gva & (PAGE_SIZE-1);
	ml->num_pfns = (ml->size + ml->offset)/PAGE_SIZE;

	if ((ml->size + ml->offset)%PAGE_SIZE > 0) {
		ml->num_pfns += 1;
	}

	if (!access_ok(VERIFY_WRITE, input->gva, ml->num_pfns)) {
		printk(KERN_ERR "virtmemlink: not a valid address\n");
		kfree(ml);
		return -EFAULT;
	}

	ml->pfns = kmalloc(sizeof(uint32_t)* ml->num_pfns, GFP_KERNEL);

	if (ml->pfns == NULL) {
		kfree(ml);
		return -ENOMEM;
	}

	ml->pages = kmalloc(sizeof(*ml->pages) * ml->num_pfns, GFP_KERNEL);

	if (ml->pages == NULL) {
		kfree(ml->pages);
		kfree(ml);
		return -ENOMEM;
	}

	down_write(&current->mm->mmap_sem);
	err = get_user_pages_fast(input->gva & ~(PAGE_SIZE-1) ,
			ml->num_pfns, 1, ml->pages);
	up_write(&current->mm->mmap_sem);

	if (err <= 0) {
		kfree(ml->pages);
		kfree(ml->pfns);
		kfree(ml);
		return -EFAULT;
	}

	for (i=0; i<ml->num_pfns; i++) {
		ml->pfns[i] = page_to_pfn(ml->pages[i]);
	}

	sg_init_one(&sg[0], &ml->size, sizeof(ml->size));
	sg_init_one(&sg[1], &ml->offset, sizeof(ml->offset));
	sg_init_one(&sg[2], ml->pfns,
			sizeof(ml->pfns[0]) * ml->num_pfns);
	sg_init_one(&sg[3], &ml->hva, sizeof(input->hva));

	init_completion(&vml->create_acked);

	BUG_ON(virtqueue_add_buf(vq, sg, 3, 1, vml) < 0);

	virtqueue_kick(vq);

	wait_for_completion(&vml->create_acked);

	if (input->hva == 0) {
		memlink_free(ml);
		return -ENOSPC;
	}

	input->hva = ml->hva;

	ml->next = vml->memlinks_head;
	ml->pprev = NULL;
	if (ml->next != NULL) {
		ml->next->pprev = ml->next;
	}

	vml->memlinks_head = ml;

	return 0;
}

static int revoke(struct virtio_memlink *vml, uint64_t hva)
{
	struct virtqueue *vq = vml->revoke_vq;
	struct scatterlist sg;
	struct memlink *ml;

	for (ml = vml->memlinks_head; ml != NULL; ml = ml->next){
		if (ml->hva == hva){
			break;
		}
	}
	if (ml == NULL) {
		return -EINVAL;
	}

	/* revoke remote link */
	sg_init_one(&sg, &ml->hva, sizeof(ml->hva));
	init_completion(&vml->revoke_acked);

	if (virtqueue_add_buf(vq, &sg, 1, 0, vml) < 0)
		BUG();

	virtqueue_kick(vq);
	wait_for_completion(&vml->revoke_acked);


	memlink_free(ml);
	if (ml->pprev != NULL){
		ml->pprev->next = ml->next;
	} else {
		vml->memlinks_head = ml->next;
	}
	if (ml->next != NULL){
		ml->next->pprev = ml->pprev;
	}

	kfree(ml);

	return 0;
}

static void reset(struct virtio_memlink *vml)
{
	int i;
	for(i=0; i<MEMLINK_MAX_LINKS; i++){
		revoke(vml, i);
	}
}

static int init_vq(struct virtio_memlink *vml)
{
	struct virtqueue *vqs[2];
	vq_callback_t *callbacks[] = { memlink_create_ack, memlink_revoke_ack };
	const char *names[] = { "memlink" };
	int err;

	err = vml->vdev->config->find_vqs(vml->vdev, 2, vqs, callbacks, names);
	if (err) {
		printk(KERN_ERR "virtmemlink: virtqueue init failed\n");
		return err;
	}

	vml->create_vq = vqs[0];
	vml->revoke_vq = vqs[1];

	return 0;
}

static int virtmemlink_probe(struct virtio_device *vdev)
{
	struct virtio_memlink *vml;
	int err;

	vdev->priv = vml = kmalloc(sizeof(*vml), GFP_KERNEL);
	if (!vml) {
		err = -ENOMEM;
		goto out;
	}

	vml->vdev = vdev;

	err = init_vq(vml);

	if (err)
		goto out_free_vml;

	vml_global = vml;

	vml->memlinks_head = NULL;

	return 0;

out_free_vml:
	kfree(vml);
out:
	printk(KERN_ERR "virtmemlink: probe failed\n");
	return err;
}

static void virtmemlink_remove(struct virtio_device *vdev)
{
	struct virtio_memlink *vml = vdev->priv;

	reset(vml);

	vml->vdev->config->reset(vml->vdev);
	vml->vdev->config->del_vqs(vml->vdev);
	kfree(vml);
#if DEBUG
	printk(KERN_INFO "virtmemlink: removed\n");
#endif
}

static unsigned int features[] = {};

static struct virtio_driver virtio_memlink_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtmemlink_probe,
	.remove =	virtmemlink_remove,
	.config_changed = virtmemlink_changed
};

static int dev_open(struct inode *inode, struct file *filp)
{
#if DEBUG
	printk(KERN_INFO "dev_open\n");
#endif
	return 0;
}

static int dev_release(struct inode *inode, struct file *filp)
{
#if DEBUG
	printk(KERN_INFO "dev_release\n");
#endif
	return 0;
}

static int dev_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long args)
{
	struct virtio_memlink_ioctl_input input;
	int revoke_id;
	int ret;

	if (_IOC_TYPE(cmd) != MEMLINK_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > MEMLINK_IOC_MAXNR)
		return -ENOTTY;

	switch (cmd) {
		case MEMLINK_IOC_CREATE:
			ret = copy_from_user(&input, (void *)args, sizeof(struct virtio_memlink_ioctl_input));
			if (ret != 0){
				printk(KERN_ERR "%s: copy_from_user failed. size seems not match.\n", __FUNCTION__);
				return -EFAULT;
			}

			ret = create(vml_global, &input);
			if (ret < 0){
				printk(KERN_ERR "%s: memlink failed to create.\n", __FUNCTION__);
			} else {
				printk(KERN_ERR "%s: memlink hva: %llx, size: %d\n", __FUNCTION__, input.hva, input.size);
			}

			ret = copy_to_user((void *)args, &input, sizeof(struct virtio_memlink_ioctl_input));
			break;

		case MEMLINK_IOC_REVOKE:
			// TODO: debug
			revoke_id = (int)args;
			printk(KERN_ERR "%s: revoking %d\n", __FUNCTION__, revoke_id);
			revoke(vml_global, revoke_id);
			break;

		default:
			return -ENOTTY;
	}
	return 0;
}

struct file_operations dev_fops = {
	.owner   = THIS_MODULE,
	.open    = dev_open,
	.release = dev_release,
	.ioctl   = dev_ioctl
};

static int init_ioctl(void)
{
	dev_t dev;
	int err;

#if DEBUG
	printk(KERN_INFO "virtmemlink: init_ioctl\n");
#endif

	err = alloc_chrdev_region(&dev, 0, 1, "memlink");
	if (err < 0)
		return err;

	dev_major = MAJOR(dev);
	dev_minor = MINOR(dev);

	dev_cdevp = kmalloc(sizeof(struct cdev), GFP_KERNEL);
	if (dev_cdevp == NULL)
		return -1;

	cdev_init(dev_cdevp, &dev_fops);
	dev_cdevp->owner = THIS_MODULE;
	if (err < 0) {
		kfree(dev_cdevp);
		dev_cdevp = NULL;
		return -EFAULT;
	}

	err = cdev_add(dev_cdevp, MKDEV(dev_major, dev_minor), 1);
	if (err < 0) {
		return -EFAULT;
	}

#if DEBUG
	printk(KERN_INFO "virtmemlink: register chrdev(%d, %d)\n", dev_major, dev_minor);
#endif
	return 0;
}

static void fini_ioctl(void)
{
	dev_t dev;

	dev = MKDEV(dev_major, dev_minor);
	if (dev_cdevp) {
		cdev_del(dev_cdevp);
		kfree(dev_cdevp);
	}
	unregister_chrdev_region(dev, 1);
	printk("virtmemlink: fini_ioctl\n");
}

static int __init init(void)
{
	int err;

#if DEBUG
	printk(KERN_INFO "virtmemlink: init\n");
#endif
	err = init_ioctl();
	if (err < 0){
		return err;
	}
	return register_virtio_driver(&virtio_memlink_driver);
}

static void __exit fini(void)
{
#if DEBUG
	printk(KERN_INFO "virtmemlink: fini\n");
#endif
	fini_ioctl();
	unregister_virtio_driver(&virtio_memlink_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio memlink driver");
MODULE_LICENSE("GPL");
