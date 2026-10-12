// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel (supervisor) shadow stacks, FRED only.
 */
#include <asm/fred.h>
#include <asm/shstk_kernel.h>

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
