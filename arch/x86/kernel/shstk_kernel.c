// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel (supervisor) shadow stacks, FRED only.
 */
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include <asm/fred.h>
#include <asm/processor.h>
#include <asm/shstk_kernel.h>

void kernel_shstk_clear(struct task_struct *tsk)
{
	tsk->thread.kshstk = NULL;
}

int kernel_shstk_alloc(struct task_struct *tsk)
{
	void *shstk;

	kernel_shstk_clear(tsk);

	if (!kernel_shstk_enabled())
		return 0;

	shstk = __vmalloc_node_range(KERNEL_SHSTK_SIZE, PAGE_SIZE,
				     VMALLOC_START, VMALLOC_END,
				     GFP_KERNEL | __GFP_ZERO | __GFP_ACCOUNT,
				     PAGE_KERNEL_SHADOW_STACK, 0, NUMA_NO_NODE,
				     __builtin_return_address(0));
	if (!shstk)
		return -ENOMEM;

	tsk->thread.kshstk = shstk;
	return 0;
}

/*
 * arch_release_task_struct() runs from RCU, where vfree() stores its list
 * node in the freed memory, which faults on a shadow stack page.  Defer to
 * a workqueue with the node in the direct map alias of the first page.
 */
struct kshstk_free_node {
	struct llist_node ll;
	void *vaddr;
};

static LLIST_HEAD(kshstk_free_list);

static void kshstk_free_work_fn(struct work_struct *work)
{
	struct llist_node *list = llist_del_all(&kshstk_free_list);
	struct kshstk_free_node *node, *tmp;

	llist_for_each_entry_safe(node, tmp, list, ll)
		vfree(node->vaddr);
}
static DECLARE_WORK(kshstk_free_work, kshstk_free_work_fn);

void kernel_shstk_free(struct task_struct *tsk)
{
	void *shstk = tsk->thread.kshstk;
	struct kshstk_free_node *node;

	if (!shstk)
		return;

	tsk->thread.kshstk = NULL;
	node = page_address(vmalloc_to_page(shstk));
	node->vaddr = shstk;
	if (llist_add(&node->ll, &kshstk_free_list))
		schedule_work(&kshstk_free_work);
}

/*
 * Shadow stack frame of a ring 0 FRED event
 *
 *	frame[0]	interrupted SSP
 *	frame[1]	LIP (checked against regs->ip)
 *	frame[2]	augmented CS (checked against regs->csx)
 */
noinstr unsigned long *fred_shstk_frame(struct pt_regs *regs)
{
	if (!kernel_shstk_enabled() || user_mode(regs))
		return NULL;

	return (unsigned long *)fred_info(regs)->resv;
}

/* Mirror changes to regs->ip and regs->csx before ERETS */
noinstr void __fred_shstk_sync_frame(struct pt_regs *regs)
{
	unsigned long *frame = fred_shstk_frame(regs);

	if (!frame)
		return;

	if (unlikely(frame[1] != regs->ip))
		wrss64(regs->ip, &frame[1]);
	if (unlikely(frame[2] != regs->csx))
		wrss64(regs->csx, &frame[2]);
}
