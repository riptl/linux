/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel (supervisor) shadow stacks, FRED only.
 */
#ifndef _ASM_X86_SHSTK_KERNEL_H
#define _ASM_X86_SHSTK_KERNEL_H

#include <asm/cpufeatures.h>

/* Restore token for RSTORSSP: the SSP above the token slot, bit 0 = 64-bit */
#define SHSTK_RSTOR_TOKEN(ssp)		((ssp) | 1UL)

#ifdef __ASSEMBLER__

#include <asm/alternative.h>

/*
 * For a RET to an address stored at (%rsp) over the slot of an RSB balancing
 * CALL (ftrace): write the address into the shadow stack slot that CALL
 * pushed.  Preserves all registers and flags.  A jump-over alternative, as
 * objtool needs the same stack layout in both variants.
 */
.macro SHSTK_WRITE_RET_TOP
#ifdef CONFIG_X86_KERNEL_SHADOW_STACK
	ALTERNATIVE "jmp .Lshstk_write_done_\@", "", X86_FEATURE_KERNEL_SHSTK
	pushq	%rax
	pushq	%rcx
	movq	16(%rsp), %rcx
	xorl	%eax, %eax
	rdsspq	%rax
	testq	%rax, %rax
	jz	.Lshstk_write_pop_\@
	wrssq	%rcx, (%rax)
.Lshstk_write_pop_\@:
	popq	%rcx
	popq	%rax
.Lshstk_write_done_\@:
#endif
.endm

#else /* !__ASSEMBLER__ */

#include <linux/objtool.h>
#include <linux/types.h>
#include <asm/alternative.h>
#include <asm/cpufeature.h>

/*
 * For rethook's top level asm(): push a shadow stack slot with a CALL, then
 * do SHSTK_WRITE_RET_TOP.  The INT3 keeps the CALL displacement nonzero; a
 * CALL to the next instruction pushes no shadow stack entry.
 */
#ifdef CONFIG_X86_KERNEL_SHADOW_STACK
#define SHSTK_SYNC_RET_TOP_STR						\
	ALTERNATIVE("jmp 8893f", "", X86_FEATURE_KERNEL_SHSTK) "\n\t"	\
	ANNOTATE_INTRA_FUNCTION_CALL "\n\t"				\
	"call 8891f\n\t"						\
	"int3\n\t"							\
	"8891: lea 8(%rsp), %rsp\n\t"					\
	"pushq %rax\n\t"						\
	"pushq %rcx\n\t"						\
	"movq 16(%rsp), %rcx\n\t"					\
	"xorl %eax, %eax\n\t"						\
	"rdsspq %rax\n\t"						\
	"testq %rax, %rax\n\t"						\
	"jz 8892f\n\t"							\
	"wrssq %rcx, (%rax)\n\t"					\
	"8892: popq %rcx\n\t"						\
	"popq %rax\n"							\
	"8893:\n"
#else
#define SHSTK_SYNC_RET_TOP_STR
#endif

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
void kernel_shstk_disable_cpu(void);
void kernel_shstk_report_overflow(struct pt_regs *regs);

unsigned long *fred_shstk_frame(struct pt_regs *regs);
void __fred_shstk_sync_frame(struct pt_regs *regs);
void fred_shstk_replace_ret(struct pt_regs *regs, unsigned long ret_ip);
DECLARE_PER_CPU(unsigned long, kprobe_shstk_ret_slot);

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
static inline void kernel_shstk_disable_cpu(void) { }
static inline void kernel_shstk_report_overflow(struct pt_regs *regs) { }
static inline unsigned long *fred_shstk_frame(struct pt_regs *regs) { return NULL; }
static __always_inline void fred_shstk_sync_frame(struct pt_regs *regs) { }
static inline void fred_shstk_replace_ret(struct pt_regs *regs, unsigned long ret_ip) { }

#endif /* CONFIG_X86_KERNEL_SHADOW_STACK */

#endif /* !__ASSEMBLER__ */

#endif /* _ASM_X86_SHSTK_KERNEL_H */
