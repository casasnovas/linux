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
#include <linux/vmalloc.h>

#include "afl.h"

#define AFL_DEBUG
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

static DEFINE_HASHTABLE(areas, AFL_HLIST_BITS);
static DEFINE_RWLOCK(areas_lock);

static void afl_get_area(struct afl_area* area)
{
	kref_get(&area->kref);
}

static struct afl_area* afl_get_area_from_task(const struct task_struct* task)
{
	struct afl_area* area = NULL;
	unsigned long flags;

	read_lock_irqsave(&areas_lock, flags);
	hash_for_each_possible(areas, area, hlist, hash_ptr(task, AFL_HLIST_BITS)) {
		if (area->task == task) {
			afl_get_area(area);
			debug("found task");
			goto out;
		}
	}
	debug("task not found.");
	area = NULL;
 out:
	read_unlock_irqrestore(&areas_lock, flags);
	return area;
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
	struct afl_area* area = NULL;

	area = afl_get_area_from_task(current);
	if (!area) {
		debug("not logging due to missing area.");
		return;
	}

	area->area[area->prev_location ^ location]++;
	area->prev_location = location >> 1;

	afl_put_area(area);
}

/**
 * Entry point of instrumented branches, the hash is in register %rcx.
 */
void __afl_maybe_log(void)
{
	unsigned short cx;
	asm volatile("": "=c" (cx));

	afl_maybe_log(cx);
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

	INIT_HLIST_NODE(&area->hlist);
	kref_init(&area->kref);
	area->area = vmalloc_user(AFL_AREA_SIZE);
	if (!area->area)
		goto nomem;

	area->offset = offset;
	offset += AFL_AREA_SIZE;

	return area;

 nomem:
	err("could not not allocate afl_area.");
	afl_free_area(area);
	return NULL;
}

/**
 * Must be called with @areas_lock held.
 */
static bool afl_task_in_hlist(const struct task_struct* task)
{
	struct afl_area* area = NULL;

	afl_func_entry();

	hash_for_each_possible(areas, area, hlist, hash_ptr(task, AFL_HLIST_BITS)) {
		if (area->task == task)
			return true;
	}
	return false;
}

static struct page* afl_get_page_at_offset(struct afl_area* area, unsigned long offset)
{
	struct page* page = NULL;

	afl_func_entry();

	if (offset < area->offset || offset > area->offset + AFL_AREA_SIZE) {
		err("requested offset out of mapping: 0x%lx.", offset);
		return NULL;
	}

	afl_get_area(area);

	page = vmalloc_to_page(area->area + offset - area->offset);
	get_page(page);

	afl_put_area(area);

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

static const struct vm_operations_struct afl_vm_ops = {
	.fault = afl_vm_fault
};

static int afl_mmap(struct file* file, struct vm_area_struct* vma)
{
	afl_func_entry();

	vma->vm_ops = &afl_vm_ops;

	return 0;
}

static int afl_assoc_area(struct afl_area* area, const struct task_struct* task)
{
	unsigned long flags;
	afl_func_entry();

	write_lock_irqsave(&areas_lock, flags);
	if (afl_task_in_hlist(task)) {
		write_unlock_irqrestore(&areas_lock, flags);
		err("area already allocated for task \"%s\"", task->comm);
		return -EEXIST;
	}

	area->task = task;
	hash_add(areas, &area->hlist, hash_ptr(task, AFL_HLIST_BITS));

	write_unlock_irqrestore(&areas_lock, flags);

	info("area %p associated with %s.", area, task->comm);

	return 0;
}

static int afl_remove_area_from_hashmap(struct afl_area* needle)
{
	unsigned long flags;
	afl_func_entry();

	write_lock_irqsave(&areas_lock, flags);
	if (hash_hashed(&needle->hlist)) {
		info("removing area from hash_map: %p", needle);
		hash_del(&needle->hlist);
		write_unlock_irqrestore(&areas_lock, flags);
		return 0;
	}
	info("could not remove area from hash_map: %p", needle);
	write_unlock_irqrestore(&areas_lock, flags);
	return -ESRCH;
}

static int afl_disassoc_area(struct afl_area* area)
{
	int err = 0;
	afl_func_entry();

	if ((err = afl_remove_area_from_hashmap(area)))
		err("could not disassociat area.");
	area->task = NULL;

	return err;
}

static long afl_ioctl(struct file* filep, unsigned int cmd, unsigned long parm)
{
	afl_func_entry();

	switch (cmd) {
	case AFL_CTL_ASSOC_AREA: /* aflc */
		return afl_assoc_area(filep->private_data, current);
	case AFL_CTL_DISASSOC_AREA: /* afls */
		return afl_disassoc_area(filep->private_data);
	case AFL_CTL_GET_MMAP_OOFSET:
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

	afl_remove_area_from_hashmap(filep->private_data);
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

	hash_init(areas);

	error = misc_register(&afl_device);
	if (error < 0)
		err("could not register misc device.");

	return error;
}

static void afl_free_hashlist(void)
{
	struct afl_area *area;
	struct hlist_node* tmp;
	unsigned long flags;
	unsigned int i;

	afl_func_entry();

	write_lock_irqsave(&areas_lock, flags);
	hash_for_each_safe(areas, i, tmp, area, hlist) {
		hash_del(&area->hlist);
		afl_put_area(area);
	}
	write_unlock_irqrestore(&areas_lock, flags);
}

static void __exit afl_exit(void)
{
	afl_func_entry();

	misc_deregister(&afl_device);

	afl_free_hashlist();
}

module_init(afl_init);
module_exit(afl_exit);
