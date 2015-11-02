#define pr_fmt(fmt) "afl: " fmt "\n"

#include <linux/compiler.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>

#include "afl.h"

//#define AFL_DEBUG
#ifdef AFL_DEBUG
#  define afl_func_entry() pr_info("[%s:%d] %s called.", current->comm, current->pid, __func__)
#  define err(msg, ...)	   pr_err( "[%s:%d] %s: " msg, current->comm, current->pid, __func__, ## __VA_ARGS__)
#  define info(msg, ...)   pr_info("[%s:%d] %s: " msg, current->comm, current->pid, __func__, ## __VA_ARGS__)
#  define debug(msg, ...)  pr_debug("[%s:%d] %s: " msg, current->comm, current->pid, __func__, ## __VA_ARGS__)
#else
#  define afl_func_entry()
#  define err(...)
#  define info(...)
#  define debug(...)
#endif


static void afl_get_area(struct afl_area* area)
{
	kref_get(&area->kref);
}

static void afl_free_area(struct afl_area* area)
{
	afl_func_entry();

	if (area) {
		vfree(area->area);
		kfree(area);
	}
}

static void _afl_free_area(struct kref* kref)
{
	afl_func_entry();

	afl_free_area(container_of(kref, struct afl_area, kref));
}

static void afl_put_area(struct afl_area* area)
{
	kref_put(&area->kref, _afl_free_area);
}

static void afl_maybe_log(unsigned short location)
{
	unsigned long flags;
	struct afl_area* area = NULL;

	spin_lock_irqsave(&current->afl_lock, flags);
	area = current->afl_area;
	if (area)
		afl_get_area(area);
	spin_unlock_irqrestore(&current->afl_lock, flags);

	if (!area) {
		debug("not logging due to missing area.");
		return;
	}

	read_lock_irqsave(&area->lock, flags);
	if (area->task != current) {
		info("not logging, the area has been re-associated.");
		goto out;
	}

	area->area[area->prev_location ^ location]++;
	area->prev_location = location >> 1;
 out:
	read_unlock_irqrestore(&area->lock, flags);
	afl_put_area(area);
}

void __fuzz_coverage(void)
{
	unsigned long caller_addr = _RET_IP_;
	unsigned short caller_hash = caller_addr & ((sizeof(unsigned short) - 1) << 8);

	afl_maybe_log(caller_hash);
}
EXPORT_SYMBOL(__afl_maybe_log);

static unsigned long offset;
static struct afl_area* afl_alloc_area(void)
{
	struct afl_area* area = NULL;

	afl_func_entry();

	/* The AFL_GET_OFFSET ioctl returns a long so make sure we're not
	 * overflowing
	 */
	if (offset + AFL_AREA_SIZE > LONG_MAX)
		goto nomem;

	if (!(area = kzalloc(sizeof(*area), GFP_KERNEL)))
		goto nomem;

	area->area = vmalloc_user(AFL_AREA_SIZE);
	if (!area->area)
		goto nomem;

	kref_init(&area->kref);
	rwlock_init(&area->lock);
	area->offset = offset;
	offset += AFL_AREA_SIZE;

	return area;

 nomem:
	err("could not not allocate afl_area.");
	afl_free_area(area);
	return NULL;
}

static struct page* afl_get_page_at_offset(struct afl_area* area, unsigned long offset)
{
	struct page* page = NULL;

	afl_func_entry();

	if (offset < area->offset || offset > area->offset + AFL_AREA_SIZE) {
		err("requested offset out of mapping: 0x%lx.", offset);
		return NULL;
	}

	page = vmalloc_to_page(area->area + offset - area->offset);
	get_page(page);

	return page;
}

static int afl_vm_fault(struct vm_area_struct* vma, struct vm_fault* vmf)
{
	afl_func_entry();

	if (!(vmf->page = afl_get_page_at_offset(vma->vm_file->private_data,
						 vmf->pgoff << PAGE_SHIFT)))
		return -1;
	return 0;
}

static void afl_unmap(struct vm_area_struct* vma)
{
	afl_func_entry();

	afl_put_area(vma->vm_file->private_data);
}

static void afl_map_copied(struct vm_area_struct* vma)
{
	afl_func_entry();

	afl_get_area(vma->vm_file->private_data);
}

static const struct vm_operations_struct afl_vm_ops = {
	.fault = afl_vm_fault,
	.close = afl_unmap,
	.open  = afl_map_copied, /* Called on fork()/clone() when the mapping is copied */
};

static int afl_mmap(struct file* filep, struct vm_area_struct* vma)
{
	struct afl_area* area = vma->vm_file->private_data;
	afl_func_entry();

	if (vma->vm_pgoff << PAGE_SHIFT != area->offset ||
	    vma->vm_end - vma->vm_start != AFL_AREA_SIZE)
		return -EFAULT;

	/* The /dev/afl device drops a reference on close, but the file
	   descriptor can be closed with the mmaping still alive so we keep
	   a reference for those.  This is put in afl_unmap(). */
	afl_get_area(area);
	vma->vm_ops = &afl_vm_ops;

	return 0;
}

static long afl_assoc_area(struct afl_area* area)
{
	unsigned long flags;
	afl_func_entry();

	write_lock_irqsave(&area->lock, flags);
	if (area->task == current) {
		write_unlock_irqrestore(&area->lock, flags);
		return 0;
	}
	area->task = current;
	write_unlock_irqrestore(&area->lock, flags);

	memset(area->area, 0, AFL_AREA_SIZE);

	spin_lock_irqsave(&current->afl_lock, flags);
	afl_get_area(area);
	current->afl_area = area;
	spin_unlock_irqrestore(&current->afl_lock, flags);

	info("area %p associated with %s.", area, current->comm);

	return 0;
}

void afl_task_release(struct task_struct* tsk)
{
	unsigned long flags;
	struct afl_area* area = NULL;

	spin_lock_irqsave(&tsk->afl_lock, flags);
	area = tsk->afl_area;
	if (area)
		tsk->afl_area = NULL;
	spin_unlock_irqrestore(&tsk->afl_lock, flags);

	/* The area was never associated with this task, nothing to do
	   here. */
	if (!area)
		return;

	write_lock_irqsave(&area->lock, flags);
	if (area->task == tsk) /* It might have been re-associated.. */
		area->task = NULL;
	write_unlock_irqrestore(&area->lock, flags);

	afl_put_area(area);
}
EXPORT_SYMBOL(afl_task_release);

static long afl_disassoc_area(struct afl_area* area)
{
	unsigned long flags;

	write_lock_irqsave(&area->lock, flags);
	/* The task might have been freed at this time, so we must not try
	   to reset its afl_area field to NULL and put the area.  

	   If the task_struct still exists, afl_maybe_log will notice that
	   the area->task field is different from 'current' and won't write
	   to the area.  The final afl_put_area() required is done in
	   afl_task_release(), where we know for sure that the task_struct
	   hasn't disappeared behind our back and is being torned down. */
	area->task = NULL;
	write_unlock_irqrestore(&area->lock, flags);

 	/* Make sure the afl-fuzz sees all previous modification made to
           our area so write pages to physical memory. */
	flush_cache_vmap((uunsigned long) area->area,
			 (unsigned long) area->area + AFL_AREA_SIZE);
	return 0;
}

static long afl_ioctl(struct file* filep, unsigned int cmd, unsigned long parm)
{
	afl_func_entry();

	switch (cmd) {
	case AFL_CTL_ASSOC_AREA: /* aflc */
		return afl_assoc_area(filep->private_data);
	case AFL_CTL_DISASSOC_AREA: /* aflc */
		return afl_disassoc_area(filep->private_data);
	case AFL_CTL_GET_MMAP_OFFSET:
		return ((struct afl_area*) filep->private_data)->offset;
	default:
		return -EINVAL;
	}
}
static int afl_open(struct inode* inode, struct file* filep)
{
	struct afl_area* area = NULL;

	afl_func_entry();

	if (!(area = afl_alloc_area()))
		return -ENOMEM;

	filep->private_data = area;

	return nonseekable_open(inode, filep);
}


static int afl_close(struct inode* inode, struct file* filep)
{
	afl_func_entry();

	afl_put_area(filep->private_data);
	return 0;
}

static const struct file_operations afl_file_ops = {
	.owner          = THIS_MODULE,
	.open           = afl_open,
	.mmap		= afl_mmap,
	.unlocked_ioctl = afl_ioctl,
	.llseek         = no_llseek,
	.release        = afl_close,
};

static struct miscdevice afl_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "afl",
	.fops  = &afl_file_ops,
};

static int __init afl_init(void)
{
	int error = 0;

	afl_func_entry();

	error = misc_register(&afl_device);
	if (error < 0)
		err("could not register misc device.");

	return error;
}

static void __exit afl_exit(void)
{
	afl_func_entry();

	misc_deregister(&afl_device);
}

module_init(afl_init);
module_exit(afl_exit);
