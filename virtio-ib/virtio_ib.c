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
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>

#define IB_UVERBS_CMD_MAX_SIZE 16384

struct virtio_ib{
	struct virtio_device     *vdev;

	struct virtqueue         *write_vq;
	struct virtqueue         *read_vq;
	struct virtqueue         *device_vq;
	struct virtqueue         *event_vq;

	spinlock_t	 	  write_lock;
};

struct virtio_ib_memlink{
	struct page             **pages;
	unsigned int              num_pfns;
	size_t                    sizeof_pfns;
	uint32_t                 *pfns;
};

struct virtio_ib_file{
	struct virtio_ib         *vib;
	__s32                     host_fd;

	struct completion         write_acked;
	struct completion         read_acked;
	struct completion         device_acked;

	char                      in_buf[IB_UVERBS_CMD_MAX_SIZE];
	char                      out_buf[IB_UVERBS_CMD_MAX_SIZE];

	struct radix_tree_root    cq_memlinks;
	struct radix_tree_root    qp_memlinks;
	struct radix_tree_root    srq_memlinks;
	struct radix_tree_root    mr_memlinks;
};

struct virtio_ib_event_file{
	struct virtio_ib         *vib;
	__s32                     host_fd;
	wait_queue_head_t         wait_queue;
	struct fasync_struct     *async_queue;
	struct completion         acked;

	int                       cmd;
	unsigned int              last_poll_status;
	unsigned int              is_polling;
};

struct virtio_ib_mmap_struct{
	struct virtio_ib_file    *file;
	unsigned long             page;
	unsigned long             size;
	__u32                     offset;
	__s32                     flags;
};

struct virtio_ib_queue_memlink{
	struct virtio_ib_memlink *buf_ml,
				 *db_ml;
};

struct virtio_ib_mr_memlink{
	struct virtio_ib_memlink *ml;
};

struct virtio_ib *vib_dev;

static void virtib_event_poll_start(struct virtio_ib_event_file *file)
{
	struct scatterlist sg[3];
	struct virtio_ib *vib = file->vib;
	file->cmd = VIRTIB_EVENT_POLL;

	if(file->last_poll_status != 0 || file->is_polling != 0)
		goto out;

	file->is_polling = 1;

	sg_init_one(&sg[0], &file->host_fd, sizeof file->host_fd);
	sg_init_one(&sg[1], &file->cmd, sizeof file->cmd);
	sg_init_one(&sg[2], &file->last_poll_status,
			sizeof file->last_poll_status);

	BUG_ON(virtqueue_add_buf(vib->event_vq, sg, 2, 1, file) < 0);
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

	module_put(THIS_MODULE);

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
	ev_file->is_polling = 0;
	ev_file->vib = vib_dev;

	fd_install(fd, filp);

	try_module_get(THIS_MODULE);

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

	INIT_RADIX_TREE(&file->cq_memlinks, GFP_ATOMIC);
	INIT_RADIX_TREE(&file->qp_memlinks, GFP_ATOMIC);
	INIT_RADIX_TREE(&file->srq_memlinks, GFP_ATOMIC);
	INIT_RADIX_TREE(&file->mr_memlinks, GFP_ATOMIC);

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

static void virtib_device_mmap(struct vm_area_struct *vma)
{
	struct virtio_ib_mmap_struct *priv = vma->vm_private_data;
	struct virtio_ib_file *file = priv->file;
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[6];
	__s32 cmd = VIRTIB_DEVICE_MMAP;

	if (priv->offset & 0x100000)
		return;

	sg_init_one(&sg[0], &cmd, sizeof(cmd));
	sg_init_one(&sg[1], &file->host_fd, sizeof(file->host_fd));
	sg_init_one(&sg[2], &priv->offset, sizeof(priv->offset));
	sg_init_one(&sg[3], &priv->page, sizeof(priv->page));
	sg_init_one(&sg[4], &priv->size, sizeof(priv->size));
	sg_init_one(&sg[5], &priv->flags, sizeof(priv->flags));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 6, 0, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);
}

static void virtib_device_munmap(struct vm_area_struct *vma)
{
	struct virtio_ib_mmap_struct *priv = vma->vm_private_data;
	struct virtio_ib_file *file = priv->file;
	struct virtio_ib *vib = file->vib;
	struct scatterlist sg[3];
	__s32 cmd = VIRTIB_DEVICE_MUNMAP;

	if (priv->offset & 0x100000)
		goto free_pages;

	sg_init_one(&sg[0], &cmd, sizeof(cmd));
	sg_init_one(&sg[1], &priv->page, sizeof(priv->page));
	sg_init_one(&sg[2], &priv->size, sizeof(priv->size));

	BUG_ON(virtqueue_add_buf(vib->device_vq, sg, 3, 0, file) < 0);

	virtqueue_kick(vib->device_vq);
	wait_for_completion(&file->device_acked);

free_pages:
	free_pages((unsigned long) __va(priv->page), get_order(priv->size));
	kfree(priv);
}

static struct vm_operations_struct virtib_mmap_vm_ops = {
	.open  = virtib_device_mmap,
	.close = virtib_device_munmap,
};

static int virtib_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct virtio_ib_mmap_struct *priv =
		kmalloc(sizeof(struct virtio_ib_mmap_struct), GFP_KERNEL);
	unsigned long page;
	unsigned int order;

	/* TODO: use dma-mappings.h */

	order = get_order(vma->vm_end - vma->vm_start);
	page = __get_free_pages(GFP_KERNEL, order);

	vma->vm_private_data = (void *) priv;

	priv->file = filp->private_data;
	priv->page = __pa(page);
	priv->size = PAGE_SIZE << order;
	priv->offset = vma->vm_pgoff << PAGE_SHIFT;
	priv->flags = vma->vm_flags;
	vma->vm_pgoff = __pa(page) >> PAGE_SHIFT;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot)) {
		free_pages(page, order);
		kfree(priv);
		return -EAGAIN;
	}

	vma->vm_ops = &virtib_mmap_vm_ops;
	virtib_device_mmap(vma);
	return 0;
}

static void virtib_replace_guest_fd_to_host_fd(
		struct virtib_hdr_with_resp *hdr)
{
	if (hdr->command == IB_USER_VERBS_CMD_CREATE_CQ) {
		struct virtib_create_cq *s = (void *) hdr;
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

static struct virtio_ib_memlink *virtib_get_pages(
		unsigned long addr,
		size_t size)
{
	int err, i;
	struct virtio_ib_memlink *ml;
	unsigned long start_addr, end_addr;
	unsigned int num_pfns;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long pfn64;

	start_addr = addr & PAGE_MASK;
	if (size == 0) {
		num_pfns = 1;
	} else {
		end_addr = PAGE_ALIGN(addr + size);
		num_pfns = (end_addr - start_addr) >> PAGE_SHIFT;
	}

	ml = kmalloc(sizeof(struct virtio_ib_memlink), GFP_KERNEL);
	if (ml == NULL) {
		err = -ENOMEM;
		goto reterr;
	}

	ml->num_pfns = num_pfns;
	ml->sizeof_pfns = sizeof(*ml->pfns)*num_pfns;

	if (!access_ok(VERIFY_WRITE, start_addr, num_pfns)) {
		goto try_follow_pfn;
	}

	ml->pages = kmalloc(sizeof(*ml->pages) * num_pfns, GFP_KERNEL);
	if (ml->pages == NULL) {
		err = -ENOMEM;
		goto free_ml;
	}

	err = get_user_pages_fast(start_addr, num_pfns, 1, ml->pages);

	if (err <= 0) {
		kfree(ml->pages);
		goto try_follow_pfn;
	}

	ml->pfns = (uint32_t *) kmalloc(ml->sizeof_pfns, GFP_KERNEL);
	if (ml->pfns == NULL) {
		err = -ENOMEM;
		goto free_pages;
	}

	for (i=0; i<num_pfns; i++)
		ml->pfns[i] = (uint32_t) page_to_pfn(ml->pages[i]);

	return ml;

try_follow_pfn:
	ml->pages = NULL;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start_addr);
	if (!vma) {
		err = -EFAULT;
		up_read(&mm->mmap_sem);
		goto free_ml;
	}

	ml->pfns = (uint32_t *) kmalloc(ml->sizeof_pfns, GFP_KERNEL);
	for (i=0; i<num_pfns; i++) {
		err = follow_pfn(vma, start_addr + PAGE_SIZE*i, &pfn64);
		ml->pfns[i] = (uint32_t) pfn64;
		if (err < 0) {
			kfree(ml->pfns);
			err = -EFAULT;
			up_read(&mm->mmap_sem);
			goto free_ml;
		}
	}
	up_read(&mm->mmap_sem);
	return ml;


free_pages:
	kfree(ml->pages);
free_ml:
	kfree(ml);
reterr:
	return 0;
}

static void virtib_put_pages(struct virtio_ib_memlink *ml)
{
	int i;

	if (ml == NULL)
		return;

	if (ml->pages != NULL) {
		for(i=0; i<ml->num_pfns; i++){
			put_page(ml->pages[i]);
		}
	}

	/* free memory */
	kfree(ml->pfns);
	kfree(ml);
}

static int virtib_memlink_before_send(
		struct virtib_hdr_with_resp *hdr, struct scatterlist *sg,
		void ** ml)
{
	const struct virtib_create_cq  *cmd_create_cq  = (void *) hdr;
	const struct virtib_resize_cq  *cmd_resize_cq  = (void *) hdr;
	const struct virtib_create_srq *cmd_create_srq = (void *) hdr;
	const struct virtib_create_qp  *cmd_create_qp  = (void *) hdr;
	const struct ib_uverbs_reg_mr  *cmd_reg_mr     = (void *) hdr->ctx;

	struct virtio_ib_queue_memlink *qml;
	struct virtio_ib_mr_memlink *mrml;
	int ret = 0;

	if (hdr->command == IB_USER_VERBS_CMD_CREATE_CQ){
		*ml = qml = (void *) kmalloc(
				sizeof(struct virtio_ib_queue_memlink),
				GFP_KERNEL);
		qml->buf_ml = virtib_get_pages(cmd_create_cq->buf_addr,
				 cmd_create_cq->buf_size);
		qml->db_ml  = virtib_get_pages(cmd_create_cq->db_addr, 0);
		sg_init_one(&sg[0], qml->buf_ml->pfns,
				qml->buf_ml->sizeof_pfns);
		sg_init_one(&sg[1], qml->db_ml->pfns,
				qml->db_ml->sizeof_pfns);

		ret = 2;
	} else if (hdr->command == IB_USER_VERBS_CMD_CREATE_QP){
		*ml = qml = (void *) kmalloc(
				sizeof(struct virtio_ib_queue_memlink),
				GFP_KERNEL);
		qml->buf_ml = virtib_get_pages(cmd_create_qp->buf_addr,
			         cmd_create_qp->buf_size);
		sg_init_one(&sg[0], qml->buf_ml->pfns,
				qml->buf_ml->sizeof_pfns);
		if (cmd_create_qp->db_addr != 0) {
			qml->db_ml = virtib_get_pages(cmd_create_qp->db_addr,
					0);
			sg_init_one(&sg[1], qml->db_ml->pfns,
					qml->db_ml->sizeof_pfns);
			ret = 2;
		} else {
			qml->db_ml = NULL;
			ret = 1;
		}
	} else if (hdr->command == IB_USER_VERBS_CMD_CREATE_SRQ){
		*ml = qml = (void *) kmalloc(
				sizeof(struct virtio_ib_queue_memlink),
				GFP_KERNEL);
		qml->buf_ml = virtib_get_pages(cmd_create_srq->buf_addr,
			         cmd_create_srq->buf_size);
		qml->db_ml  = virtib_get_pages(cmd_create_srq->db_addr, 0);
		sg_init_one(&sg[0], qml->buf_ml->pfns,
				qml->buf_ml->sizeof_pfns);
		sg_init_one(&sg[1], qml->db_ml->pfns,
				qml->db_ml->sizeof_pfns);
		ret = 2;
	} else if (hdr->command == IB_USER_VERBS_CMD_REG_MR){
		*ml = mrml = (void *) kmalloc(
				sizeof(struct virtio_ib_mr_memlink),
				GFP_KERNEL);
		mrml->ml = virtib_get_pages(cmd_reg_mr->start,
			         cmd_reg_mr->length);
		sg_init_one(&sg[0], mrml->ml->pfns,
				mrml->ml->sizeof_pfns);
		ret = 1;
	} else if (hdr->command == IB_USER_VERBS_CMD_RESIZE_CQ){
		*ml = qml = (void *) kmalloc(
				sizeof(struct virtio_ib_queue_memlink),
				GFP_KERNEL);
		qml->buf_ml = virtib_get_pages(cmd_resize_cq->buf_addr,
			         cmd_resize_cq->buf_size);
		sg_init_one(&sg[0], qml->buf_ml->pfns,
				qml->buf_ml->sizeof_pfns);
		ret = 1;
	}
	return ret;
}

static void virtib_memlink_after_send(struct virtio_ib_file *file,
		void *cmd, void *resp, void *ml)
{
	const struct virtib_hdr_with_resp *hdr = cmd;
	const struct ib_uverbs_destroy_cq *cmd_destroy_cq = (void *) hdr->ctx;
	const struct ib_uverbs_destroy_srq *cmd_destroy_srq = (void *) hdr->ctx;
	const struct ib_uverbs_destroy_qp *cmd_destroy_qp = (void *) hdr->ctx;
	const struct ib_uverbs_dereg_mr *cmd_dereg_mr = (void *) hdr->ctx;
	const struct ib_uverbs_resize_cq *cmd_resize_cq = (void *) hdr->ctx;
	const struct ib_uverbs_create_cq_resp *cmd_create_cq_resp = resp;
	const struct ib_uverbs_create_srq_resp *cmd_create_srq_resp = resp;
	const struct ib_uverbs_create_qp_resp *cmd_create_qp_resp = resp;
	const struct ib_uverbs_reg_mr_resp *cmd_reg_mr = resp;

	const struct virtio_ib_queue_memlink *qml_resize = ml;
	struct virtio_ib_queue_memlink *qml;
	struct virtio_ib_mr_memlink *mrml;

	if (hdr->command == IB_USER_VERBS_CMD_DESTROY_CQ){
		if ((qml = radix_tree_delete(&file->cq_memlinks,
				cmd_destroy_cq->cq_handle)) != NULL) {
			virtib_put_pages(qml->buf_ml);
			virtib_put_pages(qml->db_ml);
			kfree(qml);
		}
	} else if (hdr->command == IB_USER_VERBS_CMD_DESTROY_QP){
		if ((qml = radix_tree_delete(&file->qp_memlinks,
				cmd_destroy_qp->qp_handle)) != NULL) {
			virtib_put_pages(qml->buf_ml);
			virtib_put_pages(qml->db_ml);
			kfree(qml);
		}
	} else if (hdr->command == IB_USER_VERBS_CMD_DESTROY_SRQ){
		if ((qml = radix_tree_delete(&file->srq_memlinks,
				cmd_destroy_srq->srq_handle)) != NULL) {
			virtib_put_pages(qml->buf_ml);
			virtib_put_pages(qml->db_ml);
			kfree(qml);
		}
	} else if (hdr->command == IB_USER_VERBS_CMD_DEREG_MR){
		if ((mrml = radix_tree_delete(&file->mr_memlinks,
				cmd_dereg_mr->mr_handle)) != NULL) {
			virtib_put_pages(mrml->ml);
			kfree(mrml);
		}
	} else if (hdr->command == IB_USER_VERBS_CMD_CREATE_CQ){
		BUG_ON(radix_tree_insert(&file->cq_memlinks,
					cmd_create_cq_resp->cq_handle,
					ml) != 0);
	} else if (hdr->command == IB_USER_VERBS_CMD_CREATE_QP){
		BUG_ON(radix_tree_insert(&file->qp_memlinks,
					cmd_create_qp_resp->qp_handle,
					ml) != 0);
	} else if (hdr->command == IB_USER_VERBS_CMD_CREATE_SRQ){
		BUG_ON(radix_tree_insert(&file->srq_memlinks,
					cmd_create_srq_resp->srq_handle,
					ml) != 0);
	} else if (hdr->command == IB_USER_VERBS_CMD_REG_MR){
		BUG_ON(radix_tree_insert(&file->mr_memlinks,
					cmd_reg_mr->mr_handle,
					ml) != 0);
	} else if (hdr->command == IB_USER_VERBS_CMD_RESIZE_CQ){
		qml = radix_tree_lookup(&file->mr_memlinks,
				cmd_resize_cq->cq_handle);
		BUG_ON(qml == NULL);
		virtib_put_pages(qml->buf_ml);
		qml->buf_ml = qml_resize->buf_ml;
		kfree(qml_resize);
	}
}

static ssize_t virtib_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *f_pos)
{
	struct virtio_ib_file *file;
	struct virtio_ib *vib;
	struct virtib_hdr_with_resp *hdr;
	struct scatterlist sg[6];
	int ret = 0;
	void *ml = NULL;
	int memlink_sg_count;

	spin_lock(&vib_dev->write_lock);
	file = filp->private_data;
	vib = file->vib;
	hdr = (void *) file->in_buf;

	if (copy_from_user(file->in_buf, buf, len)) {
		ret = -EFAULT;
		goto unlock;
	}

	if (hdr->command == VIRTIB_DEVICE_FIND_SYSFS) {
		ret = virtib_device_find_sysfs(file, hdr);
		goto unlock;
	}

	virtib_replace_guest_fd_to_host_fd(hdr);

	if (hdr->command == IB_USER_VERBS_CMD_CREATE_CQ  ||
	    hdr->command == IB_USER_VERBS_CMD_RESIZE_CQ  ||
	    hdr->command == IB_USER_VERBS_CMD_CREATE_SRQ ||
	    hdr->command == IB_USER_VERBS_CMD_CREATE_QP){
		/* do not pass buf_size onto infiniband driver */
		len -= sizeof(__u64);
		hdr->in_words -= sizeof(__u64)/4;
	}

	memlink_sg_count = virtib_memlink_before_send(hdr, &sg[2], &ml);

	sg_init_one(&sg[0], &file->host_fd, sizeof(file->host_fd));
	sg_init_one(&sg[1], file->in_buf, len);
	sg_init_one(&sg[2 + memlink_sg_count + 0], &ret, sizeof(int));
	sg_init_one(&sg[2 + memlink_sg_count + 1], file->out_buf, sizeof(file->out_buf));

	if(virtqueue_add_buf(vib->write_vq, sg, 2 + memlink_sg_count,
				2, file) < 0) {
		printk(KERN_ERR "virtio-ib: virtib_write add_buf error\n");
		ret = -EFAULT;
		goto unlock;
	}

	virtqueue_kick(vib->write_vq);
	wait_for_completion(&file->write_acked);

	virtib_memlink_after_send(file, hdr, file->out_buf, ml);

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
		ret = -EFAULT;
	}

	if (ret > 0 &&
			(hdr->command == IB_USER_VERBS_CMD_CREATE_CQ  ||
	   		 hdr->command == IB_USER_VERBS_CMD_RESIZE_CQ  ||
	   		 hdr->command == IB_USER_VERBS_CMD_CREATE_SRQ ||
	   		 hdr->command == IB_USER_VERBS_CMD_CREATE_QP)){
		/* do not pass buf_size onto infiniband driver */
		ret += sizeof(__u64);
	}

unlock:
	spin_unlock(&vib_dev->write_lock);

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
		printk(KERN_ERR "virtio-ib: copy from user failed\n");
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
	.mmap    = virtib_mmap,
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
		file->is_polling = 0;
		if (file->last_poll_status != 0){
			wake_up_interruptible(&file->wait_queue);
			kill_fasync(&file->async_queue, SIGIO, POLL_IN);
		}

		complete(&file->acked);
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
		printk(KERN_ERR "virtib: virtqueue initialize failed\n");
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
		printk(KERN_ERR "virtib: initialize virtio failed.\n");
		goto err_init_vq;
	}

	err = misc_register(&virtib_misc);
	if (err) {
		printk(KERN_ERR "virtib: register misc device failed.\n");
		goto err_init_vq;
	}

	spin_lock_init(&vib->write_lock);

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
