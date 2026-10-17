// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for the x86 kernel (supervisor) shadow stack.  A RET or RSTORSSP
 * mismatch raises a fatal #CP, so those tests are marked "Crashes entire
 * system" in tools/testing/selftests/lkdtm/tests.txt; stores to shadow
 * stack memory and shadow stack accesses to ordinary memory are an Oops.
 */
#include "lkdtm.h"
#include <linux/annotate.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <linux/cpufeature.h>
#include <asm/asm.h>
#include <asm/extable_fixup_types.h>
#include <asm/page_64_types.h>
#include <linux/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/shstk_kernel.h>

/*
 * Every test needs shadow stacks to be live on this CPU, not just built in:
 * the feature can be vetoed at boot (no FRED, nokernelshstk, an incompatible
 * mitigation).  RDSSP is a NOP when they are off.
 */
static bool shstk_active(void)
{
	if (kernel_shstk_enabled() && rdssp())
		return true;

	pr_err("XFAIL: kernel shadow stack is not active on this CPU (feature %s)\n",
	       kernel_shstk_enabled() ? "enabled" : "disabled");
	pr_expected_config(CONFIG_X86_KERNEL_SHADOW_STACK);
	return false;
}

static volatile int shstk_redirected;

/*
 * The classic ROP primitive: overwrite the return address on the regular
 * stack and execute RET.  The shadow stack still holds the original return
 * address, so the RET must raise #CP (near ret) and the kernel must panic.
 *
 * Done in asm to be independent of frame layout and compiler version: the
 * CALL pushes the address of the JMP on both stacks, the "gadget" at 1:
 * replaces the regular stack copy with the address of 2: and returns.
 * Without shadow stacks the RET lands at 2:, with them it never returns.
 */
static noinline void lkdtm_SHSTK_RET_MISMATCH(void)
{
	if (!shstk_active())
		return;

	pr_info("Attempting RET with a corrupted return address (SSP %px) ...\n",
		(void *)rdssp());

	shstk_redirected = 0;
	asm volatile(ANNOTATE_INTRA_FUNCTION_CALL "\n\t"
		     "call 1f\n\t"
		     "jmp 3f\n\t"			/* the legitimate return target */
		     "1: lea 2f(%%rip), %%rax\n\t"
		     "mov %%rax, (%%rsp)\n\t"		/* ROP: redirect the return */
		     ANNOTATE_RETPOLINE_SAFE "\n\t"
		     "ret\n\t"			/* a plain RET: this is the fault site */
		     "int3\n\t"
		     "2: movl $1, %[redir]\n\t"	/* unchecked RET got here */
		     "3:\n\t"
		     : [redir] "=m" (shstk_redirected)
		     :
		     : "rax", "memory");

	if (shstk_redirected)
		pr_err("FAIL: RET followed the corrupted return address, no #CP!\n");
	else
		pr_err("FAIL: RET with mismatched shadow stack returned normally?!\n");
}
/* Intra-function CALL plus a RET in the middle of a C function: objtool, look away */
STACK_FRAME_NON_STANDARD(lkdtm_SHSTK_RET_MISMATCH);

/*
 * An ordinary store to a shadow stack page (Write=0, Dirty=1) must fault:
 * supervisor shadow stack memory can only be written with WRSS.  Writing
 * the value that is already there keeps the test harmless should it ever
 * "succeed".  Expected: Oops ("BUG: unable to handle page fault").
 *
 * This also covers the fault handler: pte_write() is true for shadow stack
 * PTEs, so a naive spurious fault check would retry the store forever.
 */
static void lkdtm_SHSTK_WRITE_SHSTK(void)
{
	volatile unsigned long *ssp;

	if (!shstk_active())
		return;

	ssp = (volatile unsigned long *)rdssp();
	pr_info("Attempting ordinary store to the shadow stack at %px ...\n", ssp);
	*ssp = *ssp;
	pr_err("FAIL: survived an ordinary store to the shadow stack!\n");
}

/*
 * Same store through the exception table: the fault must be fixed up (the
 * store is skipped) and nothing may change.  Reads of shadow stack memory are
 * ordinary reads.  An open coded extable entry rather than
 * copy_to_kernel_nofault(), which is not exported to modules.
 */
static noinline bool shstk_store_nofault(unsigned long *addr, unsigned long val)
{
	int faulted = 0;	/* int: the fixup needs a 32/64-bit register */

	asm volatile("1: mov %[val], %[addr]\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_ONE_REG, %[faulted])
		     : [addr] "=m" (*addr), [faulted] "+r" (faulted)
		     : [val] "r" (val));
	return !faulted;
}

static void lkdtm_SHSTK_WRITE_NOFAULT(void)
{
	unsigned long *ssp, val, poison;

	if (!shstk_active())
		return;

	ssp = (unsigned long *)rdssp();
	if (copy_from_kernel_nofault(&val, ssp, sizeof(val))) {
		pr_err("FAIL: cannot read the shadow stack at %px\n", ssp);
		return;
	}
	pr_info("Shadow stack top %px holds %pS\n", ssp, (void *)val);

	poison = val ^ 1;
	if (shstk_store_nofault(ssp, poison)) {
		pr_err("FAIL: fixup-protected store to the shadow stack did not fault\n");
		return;
	}
	if (READ_ONCE(*ssp) != val) {
		pr_err("FAIL: the rejected store changed the shadow stack!\n");
		return;
	}
	pr_info("ok: ordinary store to the shadow stack was rejected\n");
}

/*
 * WRSS is a shadow stack access: it may only target shadow stack pages.
 * Expected on .text and on .data: Oops with "kernel shadow stack access".
 * As above, the written value is the one already there.
 */
static int shstk_data_target = 0x5a5a;

static void lkdtm_SHSTK_WRSS_TEXT(void)
{
	unsigned long *target = (unsigned long *)lkdtm_SHSTK_WRSS_TEXT;

	if (!shstk_active())
		return;

	pr_info("Attempting WRSS to kernel text at %px ...\n", target);
	wrss64(*target, target);
	pr_err("FAIL: survived WRSS to kernel text!\n");
}

static void lkdtm_SHSTK_WRSS_DATA(void)
{
	unsigned long *target = (unsigned long *)&shstk_data_target;

	if (!shstk_active())
		return;

	pr_info("Attempting WRSS to kernel data at %px ...\n", target);
	wrss64(*target, target);
	pr_err("FAIL: survived WRSS to kernel data!\n");
}

/* Positive counterpart: WRSS to the task's own shadow stack works. */
static void lkdtm_SHSTK_WRSS_SELF(void)
{
	unsigned long *ssp, val;

	if (!shstk_active())
		return;

	ssp = (unsigned long *)rdssp();
	val = READ_ONCE(*ssp);
	pr_info("WRSS of %pS back onto the shadow stack at %px ...\n", (void *)val, ssp);
	wrss64(val, ssp);
	if (READ_ONCE(*ssp) != val) {
		pr_err("FAIL: shadow stack slot changed?!\n");
		return;
	}
	pr_info("ok: WRSS to the shadow stack succeeded\n");
}

/*
 * RSTORSSP consumes a restore token: bits 2:0 must be 001 and the encoded
 * address must be the slot's own address plus 8.  A return address slot on
 * the current shadow stack is not a token (bit 0 is clear for every kernel
 * return address this test accepts), so RSTORSSP on it raises #CP (rstorssp),
 * which is fatal.
 */
static void lkdtm_SHSTK_RSTORSSP_BAD_TOKEN(void)
{
	unsigned long *slot, val;

	if (!shstk_active())
		return;

	slot = (unsigned long *)rdssp();
	val = READ_ONCE(*slot);
	if ((val & 7) == 1) {
		/* Vanishingly unlikely; never risk a real pivot */
		pr_err("XFAIL: top of the shadow stack looks like a token (%lx)\n", val);
		return;
	}

	pr_info("Attempting RSTORSSP on %px holding %pS (not a token) ...\n",
		slot, (void *)val);
	rstorssp(slot);
	pr_err("FAIL: survived RSTORSSP with an invalid token!\n");
}

/*
 * A well-formed restore token in ordinary memory: the token load is a shadow
 * stack access to a non-shadow-stack page.  Expected: Oops with "kernel
 * shadow stack access".
 */
static unsigned long shstk_fake_token __aligned(8);

static void lkdtm_SHSTK_RSTORSSP_NOT_SHSTK(void)
{
	if (!shstk_active())
		return;

	shstk_fake_token = SHSTK_RSTOR_TOKEN((unsigned long)&shstk_fake_token + 8);
	pr_info("Attempting RSTORSSP on kernel data at %px ...\n", &shstk_fake_token);
	rstorssp(&shstk_fake_token);
	pr_err("FAIL: survived RSTORSSP on a non-shadow-stack page!\n");
}

/*
 * Report the task's kernel shadow stack and verify its mapping: SSP inside
 * the task's stack, PTE present with Write=0 and Dirty=1, and the stack
 * lives in vmalloc space with a guard page below it.  The reported addresses
 * are consumed by tools/testing/selftests/x86/kshstk/kshstk_user_access.c,
 * which verifies that user mode cannot touch them.
 */
static void lkdtm_SHSTK_REPORT(void)
{
	unsigned long base, top, ssp, flags;
	unsigned int level;
	pte_t *pte;

	if (!shstk_active())
		return;

	base = (unsigned long)current->thread.kshstk;
	top = base + KERNEL_SHSTK_SIZE;
	ssp = rdssp();

	pr_info("SSP: %px, shadow stack: [%px, %px) (%lu bytes), PL0_SSP top: %px\n",
		(void *)ssp, (void *)base, (void *)top, (unsigned long)KERNEL_SHSTK_SIZE,
		(void *)top);

	if (!base || ssp < base || ssp >= top) {
		pr_err("FAIL: SSP is not inside the task's kernel shadow stack!\n");
		return;
	}
	if (!is_vmalloc_addr((void *)base)) {
		pr_err("FAIL: kernel shadow stack is not in vmalloc space!\n");
		return;
	}

	pte = lookup_address(ssp, &level);
	if (!pte || level != PG_LEVEL_4K || !pte_present(*pte)) {
		pr_err("FAIL: no 4K PTE for the shadow stack at %px\n", (void *)ssp);
		return;
	}
	flags = pte_flags(*pte);
	pr_info("PTE: %016lx (Write=%d Dirty=%d User=%d NX=%d)\n", pte_val(*pte),
		!!(flags & _PAGE_RW), !!(flags & _PAGE_DIRTY),
		!!(flags & _PAGE_USER), !!(flags & _PAGE_NX));
	if ((flags & _PAGE_RW) || !(flags & _PAGE_DIRTY) || (flags & _PAGE_USER)) {
		pr_err("FAIL: shadow stack PTE is not supervisor Write=0 Dirty=1!\n");
		return;
	}

	pte = lookup_address(base - PAGE_SIZE, &level);
	if (pte && level == PG_LEVEL_4K && pte_present(*pte)) {
		pr_err("FAIL: no guard page below the kernel shadow stack!\n");
		return;
	}

	pr_info("ok: shadow stack mapping is Write=0 Dirty=1 with SSP inside it\n");
}

/*
 * Shadow stack depth.  Each CALL consumes 8 bytes of the KERNEL_SHSTK_SIZE
 * shadow stack regardless of the regular frame size.  The recursion is in
 * asm so that a frame costs exactly 8 bytes on both stacks and cannot be
 * turned into a loop; the bottom frame returns the SSP seen there.
 *
 * SHSTK_DEPTH_SAFE recurses well inside the stack and reports the depth.
 * SHSTK_DEPTH_OVERFLOW recurses past its end: the CALL into the guard page
 * faults, and since FRED delivers that #PF on the full shadow stack the
 * event frame push faults as well, ending in #DF.  The overflow depth is
 * kept small enough not to exhaust the regular stack first.
 */
#define SHSTK_DEPTH_SAFE_FRAMES		500
#define SHSTK_DEPTH_OVERFLOW_FRAMES	(KERNEL_SHSTK_SIZE / 8 + 256)

unsigned long lkdtm_shstk_recurse(unsigned long depth);
asm(
	".text\n"
	".type lkdtm_shstk_recurse, @function\n"
	".globl lkdtm_shstk_recurse\n"
	ASM_FUNC_ALIGN
	"lkdtm_shstk_recurse:\n"
		ANNOTATE_NOENDBR "\n"
		"testq %rdi, %rdi\n"
		"jz 1f\n"
		"decq %rdi\n"
		"call lkdtm_shstk_recurse\n"
		"jmp 2f\n"
	"1:	xorl %eax, %eax\n"
		"rdsspq %rax\n"
	"2:	" ASM_RET
	".size lkdtm_shstk_recurse, .-lkdtm_shstk_recurse\n"
);

static unsigned long shstk_max_used;

static void shstk_depth(unsigned long frames, bool expect_overflow)
{
	unsigned long base, top, before, bottom, after;

	if (!shstk_active())
		return;

	base = (unsigned long)current->thread.kshstk;
	top = base + KERNEL_SHSTK_SIZE;
	before = rdssp();
	if (!base || before < base || before >= top) {
		pr_err("FAIL: SSP %px outside the task's shadow stack [%px, %px)\n",
		       (void *)before, (void *)base, (void *)top);
		return;
	}

	pr_info("shadow stack %lu bytes, used %lu (free %lu, max seen so far %lu), recursing %lu frames%s ...\n",
		(unsigned long)KERNEL_SHSTK_SIZE, top - before, before - base,
		shstk_max_used, frames,
		expect_overflow ? " (expected to overflow)" : "");

	bottom = lkdtm_shstk_recurse(frames);
	after = rdssp();

	if (expect_overflow) {
		pr_err("FAIL: survived a %lu frame recursion on a %lu byte shadow stack (bottom SSP %px)!\n",
		       frames, (unsigned long)KERNEL_SHSTK_SIZE, (void *)bottom);
		return;
	}

	if (top - bottom > shstk_max_used)
		shstk_max_used = top - bottom;

	if (after != before) {
		pr_err("FAIL: SSP moved across a balanced recursion: %px -> %px\n",
		       (void *)before, (void *)after);
		return;
	}
	/* @frames recursive CALLs plus the CALL from here into the helper */
	if (before - bottom != (frames + 1) * 8) {
		pr_err("FAIL: %lu frames consumed %lu shadow stack bytes, expected %lu\n",
		       frames, before - bottom, (frames + 1) * 8);
		return;
	}
	pr_info("ok: shadow stack depth %lu bytes at the bottom (%lu before and after), %lu free at the bottom\n",
		top - bottom, top - before, bottom - base);
}

static void lkdtm_SHSTK_DEPTH_SAFE(void)
{
	shstk_depth(SHSTK_DEPTH_SAFE_FRAMES, false);
}

static void lkdtm_SHSTK_DEPTH_OVERFLOW(void)
{
	shstk_depth(SHSTK_DEPTH_OVERFLOW_FRAMES, true);
}

static struct crashtype crashtypes[] = {
	CRASHTYPE(SHSTK_RET_MISMATCH),
	CRASHTYPE(SHSTK_WRITE_SHSTK),
	CRASHTYPE(SHSTK_WRITE_NOFAULT),
	CRASHTYPE(SHSTK_WRSS_TEXT),
	CRASHTYPE(SHSTK_WRSS_DATA),
	CRASHTYPE(SHSTK_WRSS_SELF),
	CRASHTYPE(SHSTK_RSTORSSP_BAD_TOKEN),
	CRASHTYPE(SHSTK_RSTORSSP_NOT_SHSTK),
	CRASHTYPE(SHSTK_REPORT),
	CRASHTYPE(SHSTK_DEPTH_SAFE),
	CRASHTYPE(SHSTK_DEPTH_OVERFLOW),
};

struct crashtype_category shstk_crashtypes = {
	.crashtypes = crashtypes,
	.len	    = ARRAY_SIZE(crashtypes),
};
