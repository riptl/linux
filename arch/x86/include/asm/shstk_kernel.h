/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel (supervisor) shadow stacks, FRED only.
 */
#ifndef _ASM_X86_SHSTK_KERNEL_H
#define _ASM_X86_SHSTK_KERNEL_H

#include <asm/cpufeatures.h>

/* Restore token for RSTORSSP: the SSP above the token slot, bit 0 = 64-bit */
#define SHSTK_RSTOR_TOKEN(ssp)		((ssp) | 1UL)

#ifndef __ASSEMBLER__

#include <linux/types.h>
#include <asm/cpufeature.h>

struct pt_regs;
struct task_struct;

#ifdef CONFIG_X86_KERNEL_SHADOW_STACK

static __always_inline bool kernel_shstk_enabled(void)
{
	return cpu_feature_enabled(X86_FEATURE_KERNEL_SHSTK);
}

/* RDSSP is a NOP while shadow stacks are off; the register stays 0 */
static __always_inline unsigned long rdssp(void)
{
	unsigned long ssp = 0;

	asm volatile("rdsspq %0" : "+r" (ssp));
	return ssp;
}

/* IA32_S_CET.WRSS_EN is set whenever the feature is on */
static __always_inline void wrss64(unsigned long val, unsigned long *addr)
{
	asm volatile("wrssq %[val], %[addr]"
		     : [addr] "+m" (*addr) : [val] "r" (val) : "memory");
}

/* Pop @nr (at most 255) entries */
static __always_inline void incssp(unsigned long nr)
{
	asm volatile("incsspq %0" :: "r" (nr) : "memory");
}

static __always_inline void rstorssp(unsigned long *token)
{
	asm volatile("rstorssp %0" : "+m" (*token) :: "memory");
}

static __always_inline void saveprevssp(void)
{
	asm volatile("saveprevssp" ::: "memory");
}

void kernel_shstk_clear(struct task_struct *tsk);
int kernel_shstk_alloc(struct task_struct *tsk);
void kernel_shstk_free(struct task_struct *tsk);
void kernel_shstk_setup_thread(struct task_struct *p);

unsigned long *fred_shstk_frame(struct pt_regs *regs);
void __fred_shstk_sync_frame(struct pt_regs *regs);

/* ERETS checks regs->ip and regs->csx against the shadow stack frame */
static __always_inline void fred_shstk_sync_frame(struct pt_regs *regs)
{
	if (kernel_shstk_enabled())
		__fred_shstk_sync_frame(regs);
}

#else /* !CONFIG_X86_KERNEL_SHADOW_STACK */

static __always_inline bool kernel_shstk_enabled(void) { return false; }
static inline unsigned long rdssp(void) { return 0; }
static inline void kernel_shstk_clear(struct task_struct *tsk) { }
static inline int kernel_shstk_alloc(struct task_struct *tsk) { return 0; }
static inline void kernel_shstk_free(struct task_struct *tsk) { }
static inline void kernel_shstk_setup_thread(struct task_struct *p) { }
static inline unsigned long *fred_shstk_frame(struct pt_regs *regs) { return NULL; }
static __always_inline void fred_shstk_sync_frame(struct pt_regs *regs) { }

#endif /* CONFIG_X86_KERNEL_SHADOW_STACK */

#endif /* !__ASSEMBLER__ */

#endif /* _ASM_X86_SHSTK_KERNEL_H */
