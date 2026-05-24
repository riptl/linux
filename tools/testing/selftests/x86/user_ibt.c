// SPDX-License-Identifier: GPL-2.0
/*
 * Test kernel support for userspace Indirect Branch Tracking (IBT).
 * Enables IBT manually via prctl(). Must be compiled with
 * -fcf-protection=branch to enable ENDBR64 instrumentation.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/const.h>
#include <linux/prctl.h>
#include <ucontext.h>
#include <unistd.h>
#include "../kselftest.h"

/*
 * Allow building this test with old kernel headers.
 */
#ifndef PR_SET_CFI
#define PR_GET_CFI			80
#define PR_SET_CFI			81
#endif
#ifndef PR_CFI_ENABLE
#define PR_CFI_ENABLE			(1UL << 0)
#define PR_CFI_DISABLE			(1UL << 1)
#endif
#ifndef PR_CFI_BRANCH_LANDING_PADS
#define PR_CFI_BRANCH_LANDING_PADS	0
#endif
#ifndef SEGV_CPERR
#define SEGV_CPERR			10
#endif

#if !defined(__CET__) || (__CET__ & 1) != 1
int main(int argc, char *argv[])
{
	ksft_print_header();
	ksft_exit_skip("Compiler does not support CET.\n");
	return 0;
}
#else
void __attribute__((naked, aligned(4096))) valid_target(void)
{
#ifdef __x86_64__
	asm volatile (
		"endbr64\n"
		"ret\n"
	);
#else
	asm volatile (
		"endbr32\n"
		"ret\n"
	);
#endif
}

void __attribute__((nocf_check, naked, aligned(4096))) invalid_target(void)
{
	asm volatile ("ret\n");
}

void __attribute__((naked)) user_ibt_basic_test(void)
{
#ifdef __x86_64__
	asm volatile (
		"leaq valid_target(%rip), %rax\n"
		"call *%rax\n"
		"ret\n"
	);
#else
	asm volatile (
		"movl $valid_target, %eax\n"
		"call *%eax\n"
		"ret\n"
	);
#endif
}

void __attribute__((naked)) user_ibt_notrack_test(void)
{
#ifdef __x86_64__
	asm volatile (
		"leaq invalid_target(%rip), %rax\n"
		"notrack call *%rax\n"
		"ret\n"
	);
#else
	asm volatile (
		"movl $invalid_target, %eax\n"
		"notrack call *%eax\n"
		"ret\n"
	);
#endif
}

static sigjmp_buf jmpbuf;
static sig_atomic_t num_segv;
static sig_atomic_t got_cperr;

static void segv_handler(int signum, siginfo_t *si, void *uc)
{
	num_segv++;
	got_cperr = si->si_code == SEGV_CPERR;
	siglongjmp(jmpbuf, 1);
}

int user_ibt_violation_test(void)
{
	struct sigaction sa = {};
	size_t volatile ptr;

	num_segv = 0;
	got_cperr = false;

	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL))
		return 0;

	if (!sigsetjmp(jmpbuf, 1)) {
		/*
		 * Force an indirect call and drop 'nocf_check' attribute.
		 * Obfuscate cast through a temp local to suppress
		 * -Wincompatible-pointer-types (which correctly detects
		 * the nocf_check attribute mismatch)
		 */
		ptr = (size_t)invalid_target;
		((void (* volatile)(void))ptr)();
		/* Fall through in case this didn't SIGSEGV */
	}

	signal(SIGSEGV, SIG_DFL);

	return num_segv == 1 && got_cperr;
}

static int user_ibt_signal_handler(void (* handler)(int, siginfo_t *, void *), bool expect_segv)
{
	struct sigaction sa = {};
	pid_t pid = getpid();

	if (pid < 0)
		return 0;
	num_segv = 0;
	got_cperr = false;

	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGPWR, &sa, NULL))
		return 0;

	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL))
		return 0;

	if (kill(getpid(), SIGPWR))
		return 0;

	signal(SIGSEGV, SIG_DFL);
	signal(SIGPWR, SIG_DFL);

	return 1;
}

int user_ibt_signal_handler_valid(void)
{
	user_ibt_signal_handler((void *)valid_target, false);
	return num_segv == 0;
}

int user_ibt_signal_handler_invalid(void)
{
	user_ibt_signal_handler((void *)invalid_target, true);
	return num_segv == 1 && got_cperr;
}

static void sigreturn_segv_handler(int signum, siginfo_t *si, void *uc)
{
        void * addr = si->si_addr;
	if (si->si_code != SEGV_ACCERR ||
            (addr != valid_target && addr != invalid_target))
		asm volatile("ud2");
	if (mprotect(addr, 4096, PROT_READ | PROT_EXEC))
		_exit(1);
	/* rt_sigreturn to test_page, triggering SIGTRAP */
}

static sig_atomic_t got_trap;

static void sigreturn_trap_handler(int signum, siginfo_t *si, void *uc)
{
	got_trap = 1;
	siglongjmp(jmpbuf, 1);
}

int user_ibt_sigreturn(void * target, bool valid)
{
	struct sigaction sa = {};

	/*
	 * Indirect call a non-executable page, triggering a segfault at
         * the call target. Handle the SIGSEGV by mapping the page
	 * (containing an int3 instruction). Resume using rt_sigreturn
	 * to continue at the indirect jump target. Possible outcomes:
	 *   SIGSEGV with SEGV_CPERR: IBT violation detected
	 *   SIGTRAP: IBT violation detection broken by signal handler
	 */

        if (mprotect(target, 4096, PROT_READ))
                return 0;

	num_segv = false;
	got_cperr = false;

	sa.sa_sigaction = sigreturn_trap_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGTRAP, &sa, NULL))
		return 0;

	sa.sa_sigaction = sigreturn_segv_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL))
		return 0;

	if (!sigsetjmp(jmpbuf, 1)) {
		/* Force an indirect call to test_page */
		size_t volatile ptr = (size_t)target;
		((void (* volatile)(void))ptr)();
		asm volatile("ud2"); /* unreachable */
	}

	signal(SIGTRAP, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
        if (mprotect(target, 4096, PROT_READ | PROT_EXEC))
                return 0;

	if (valid)
		return got_trap && !num_segv;
	else
		return !got_trap && num_segv && got_cperr;
}

static sig_atomic_t xsave_ok;

struct fpx_sw_bytes {
    uint32_t magic1;
    uint32_t extended_size;
    uint64_t xfeatures;
    uint32_t xstate_size;
    uint32_t padding[7];
};

struct xsave_hdr {
    uint64_t xstate_bv;
};

static void check_xsave_handler(int signum, siginfo_t *si, void *uc_)
{
        ucontext_t *uc = uc_;
        uint8_t * fp = (uint8_t *)uc->uc_mcontext.fpregs;
        if (!fp)
                return;
 struct fpx_sw_bytes *sw =
        (struct fpx_sw_bytes *)(fp + 464);

        if (sw->magic1 != 0x46505853u)
                return; /* expect extended XSAVE area when CET enabled */

        if (sw->extended_size < 520)
                return;

        uint32_t *magic2 = (uint32_t *)(fp + sw->extended_size - sizeof(uint32_t));

        if (*magic2 != 0x46505845u)
                return;

        uint64_t xstate_bv = *(uint64_t *)(fp + 512);

        xsave_ok = !( xstate_bv & 1UL<<11);
}

int user_ibt_xsave(void)
{
        pid_t pid = getpid();
        struct sigaction sa = {};

        if (pid < 0)
                return 0;

        sa.sa_sigaction = check_xsave_handler;
        sa.sa_flags = SA_SIGINFO;
        if (sigaction(SIGPWR, &sa, NULL))
                return 0;

        xsave_ok = false;
        if (kill(pid, SIGPWR))
                return 0;
        return xsave_ok;
}

int main(int argc, char *argv[])
{
	unsigned long lpad_status = PR_CFI_ENABLE;

	ksft_print_header();
	ksft_set_plan(3);

	if (syscall(__NR_prctl, PR_SET_CFI, PR_CFI_BRANCH_LANDING_PADS, lpad_status, 0, 0)) {
		if (errno == EINVAL || errno == EOPNOTSUPP)
			ksft_exit_skip("User IBT is not supported.\n");
		ksft_exit_fail_perror("Failed to enable user IBT");
	}

	user_ibt_basic_test();
	ksft_test_result_pass("valid indirect call with endbr64\n");

	user_ibt_notrack_test();
	ksft_test_result_pass("notrack indirect call to non-endbr target\n");

	ksft_test_result(user_ibt_violation_test(),
			 "indirect call to non-endbr target raises SIGSEGV\n");

	ksft_test_result(user_ibt_signal_handler_valid(),
			 "Signal handler sanity check\n");

	ksft_test_result(user_ibt_signal_handler_invalid(),
			 "Signal handler without ENDBR raises SIGSEGV\n");

	ksft_test_result(user_ibt_sigreturn(valid_target, true),
			 "IBT state preserved across signal handler (valid case)\n");

	ksft_test_result(user_ibt_sigreturn(invalid_target, false),
			 "IBT state preserved across signal handler (missing ENDBR case)\n");

	ksft_test_result(user_ibt_xsave(),
			 "CET state not visible in sigframe XSAVE\n");

	ksft_finished();
}
#endif
