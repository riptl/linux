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
#include <asm/switch_to.h>

static unsigned long kshstk_top(struct task_struct *tsk)
{
	return (unsigned long)tsk->thread.kshstk + KERNEL_SHSTK_SIZE;
}

/* Write shadow stack memory through the direct map */
static void kshstk_write_alias(unsigned long addr, unsigned long val)
{
	struct page *page = vmalloc_to_page((void *)addr);

	*(unsigned long *)(page_address(page) + offset_in_page(addr)) = val;
}

void kernel_shstk_clear(struct task_struct *tsk)
{
	tsk->thread.kshstk = NULL;
	tsk->thread.kssp = 0;
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
 * Seed a new task's shadow stack for its first switch-in:
 *
 *	top - 8		ret_from_fork_asm, popped by __switch_to()'s RET
 *	top - 16	restore token for RSTORSSP in __switch_to_asm()
 */
void kernel_shstk_setup_thread(struct task_struct *p)
{
	unsigned long top;

	if (!p->thread.kshstk)
		return;

	top = kshstk_top(p);
	kshstk_write_alias(top - 8, (unsigned long)ret_from_fork_asm);
	kshstk_write_alias(top - 16, SHSTK_RSTOR_TOKEN(top - 8));
	p->thread.kssp = top - 8;
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

/*
 * Running off the bottom of the shadow stack faults on the guard page, and
 * that #PF cannot push its frame either, so it ends in #DF.
 */
void kernel_shstk_report_overflow(struct pt_regs *regs)
{
	unsigned long *frame = fred_shstk_frame(regs);
	unsigned long base, ssp;

	if (!frame)
		return;

	base = (unsigned long)current->thread.kshstk;
	ssp = frame[0];
	if (!base || ssp < base - PAGE_SIZE || ssp >= base + 4 * sizeof(long))
		return;

	pr_emerg("BUG: kernel shadow stack overflow: SSP %016lx at the bottom of [%016lx, %016lx)\n",
		 ssp, base, base + KERNEL_SHSTK_SIZE);
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
