// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel (supervisor) shadow stacks, FRED only.
 */
#include <linux/irqflags.h>
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include <asm/fred.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/shstk_kernel.h>
#include <asm/switch_to.h>
#include <asm/text-patching.h>

/* Cache of IA32_PL0_SSP, see fred_update_ssp0() */
DEFINE_PER_CPU(unsigned long, fred_ssp0);
EXPORT_PER_CPU_SYMBOL_GPL(fred_ssp0);

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
 * Turn shadow stacks on for this CPU with SSP in the stack below @top.  Every
 * RET from here on must find a matching entry.  The callers never return, so
 * the only pending returns are the noinline caller's own and optionally its
 * caller's:
 *
 *	top - 8		outer_ret (if any)
 *	top - 16	own_ret
 *	top - 24	restore token
 */
static __always_inline void __kernel_shstk_enable(unsigned long top,
						  unsigned long outer_ret,
						  unsigned long own_ret)
{
	unsigned long ssp = top, flags;
	u64 msr;

	if (outer_ret) {
		ssp -= 8;
		kshstk_write_alias(ssp, outer_ret);
	}
	ssp -= 8;
	kshstk_write_alias(ssp, own_ret);
	kshstk_write_alias(ssp - 8, SHSTK_RSTOR_TOKEN(ssp));

	local_irq_save(flags);

	/* The boot CPU wrote FRED_CONFIG before the feature was known */
	rdmsrq(MSR_IA32_FRED_CONFIG, msr);
	wrmsrq(MSR_IA32_FRED_CONFIG, msr | FRED_CONFIG_SHSTK_REDZONE);

	rdmsrq(MSR_IA32_S_CET, msr);
	msr |= CET_SHSTK_EN | CET_WRSS_EN;

	/*
	 * One asm statement, so the compiler cannot place a CALL while SSP is
	 * 0.  INCSSP skips the previous-SSP token RSTORSSP leaves behind.
	 */
	asm volatile("wrmsr\n\t"
		     "rstorssp %[token]\n\t"
		     "incsspq %[one]"
		     : [token] "+m" (*(unsigned long *)(ssp - 8))
		     : "c" (MSR_IA32_S_CET), "a" ((u32)msr), "d" ((u32)(msr >> 32)),
		       [one] "r" (1UL)
		     : "memory");

	fred_invalidate_ssp0();

	local_irq_restore(flags);
}

/*
 * The caller must never return.  @outer_ret is its own return address if
 * its caller may return (arch_cpu_finalize_init()).
 */
noinline void kernel_shstk_enable_cpu(unsigned long outer_ret)
{
	if (!kernel_shstk_enabled())
		return;

	/* The init task never went through copy_thread() */
	if (!current->thread.kshstk && kernel_shstk_alloc(current))
		panic("Cannot allocate the kernel shadow stack for CPU %d\n",
		      smp_processor_id());

	__kernel_shstk_enable(kshstk_top(current), outer_ret,
			      (unsigned long)__builtin_return_address(0));
}

/*
 * Re-enable after suspend, hibernation or kexec jump.  @base is the slot for
 * the caller's return address, recorded on the way down.
 */
noinline void kernel_shstk_resume(unsigned long base, unsigned long outer_ret)
{
	/* Still on after a failed suspend or hibernation image creation */
	if (!kernel_shstk_enabled() || rdssp())
		return;

	if (!base)
		panic("kernel shadow stack: no resume base recorded for CPU %d\n",
		      smp_processor_id());

	__kernel_shstk_enable(base + 8, outer_ret,
			      (unsigned long)__builtin_return_address(0));
}

void kernel_shstk_disable_cpu(void)
{
	u64 msr;

	if (!kernel_shstk_enabled())
		return;

	rdmsrq(MSR_IA32_S_CET, msr);
	wrmsrq(MSR_IA32_S_CET, msr & ~(CET_SHSTK_EN | CET_WRSS_EN));
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

/*
 * Emulated CALL: FRED_CONFIG_SHSTK_REDZONE left a free slot below the
 * interrupted SSP.  Fill it and have ERETS restore SSP pointing at it.
 */
noinstr void fred_shstk_emulate_call(struct pt_regs *regs, unsigned long ret_ip)
{
	unsigned long *frame = fred_shstk_frame(regs);

	if (!frame)
		return;

	wrss64(ret_ip, (unsigned long *)(frame[0] - 8));
	wrss64(frame[0] - 8, &frame[0]);
}

/* Emulated RET: check the entry like RET would, have ERETS restore SSP + 8 */
noinstr void fred_shstk_emulate_ret(struct pt_regs *regs, unsigned long ret_ip)
{
	unsigned long *frame = fred_shstk_frame(regs);

	if (!frame)
		return;

	if (unlikely(*(unsigned long *)frame[0] != ret_ip)) {
		instrumentation_begin();
		BUG();
		instrumentation_end();
	}

	wrss64(frame[0] + 8, &frame[0]);
}

/* The live SSP and, for a kernel-mode event frame, the shadow stack frame */
void show_shstk_regs(struct pt_regs *regs, const char *log_lvl)
{
	unsigned long *frame, f[3], top = 0;

	if (!kernel_shstk_enabled())
		return;

	printk("%sSSP: %016lx", log_lvl, rdssp());

	frame = fred_shstk_frame(regs);
	if (!frame || copy_from_kernel_nofault(f, frame, sizeof(f))) {
		pr_cont("\n");
		return;
	}
	copy_from_kernel_nofault(&top, (void *)f[0], sizeof(top));
	pr_cont(" frame: %px SSP: %016lx *SSP: %016lx LIP: %016lx CS: %04lx\n",
		frame, f[0], top, f[1], f[2]);
}

/*
 * kretprobe: replace the return address on top of the interrupted shadow
 * stack.  A jump-optimized kprobe has no FRED frame; optimized_callback()
 * records the slot in kprobe_shstk_ret_slot instead.
 */
noinstr void fred_shstk_replace_ret(struct pt_regs *regs, unsigned long ret_ip)
{
	unsigned long *slot = (unsigned long *)__this_cpu_read(kprobe_shstk_ret_slot);
	unsigned long *frame;

	if (!kernel_shstk_enabled())
		return;

	if (!slot) {
		frame = fred_shstk_frame(regs);
		if (!frame)
			return;
		slot = (unsigned long *)frame[0];
	}

	wrss64(ret_ip, slot);
}

DEFINE_PER_CPU(unsigned long, kprobe_shstk_ret_slot);
