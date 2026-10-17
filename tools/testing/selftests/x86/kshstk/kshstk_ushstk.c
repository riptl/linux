// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: interplay with user shadow stacks.
 *
 * A task with a user shadow stack has two shadow stacks that the kernel
 * must keep straight: IA32_PL3_SSP (XSAVE managed, part of the user FPU
 * state) and the kernel shadow stack with IA32_PL0_SSP.  Paths where both
 * are touched in one go:
 *
 *  - signal delivery and sigreturn: the kernel pushes a restore token on
 *    the user shadow stack and rewrites PL3_SSP, then returns through
 *    ERETU, which checks SSP against PL0_SSP; sigreturn restores PL3_SSP
 *    from the token
 *  - nested signals and sigaltstack
 *  - fork and exec (a new user shadow stack, the old one freed, with the
 *    kernel shadow stack of the task unchanged)
 *  - thread creation (kernel allocates the user shadow stack in clone)
 *  - a user-mode #CP: must be SIGSEGV with si_code SEGV_CPERR, and must not
 *    be confused with a kernel shadow stack violation (which panics)
 *  - ptrace NT_X86_SHSTK get/set on a stopped child
 *  - clone3() with a shadow_stack_size (if the kernel knows the field) and
 *    the kernel sized clone3() thread shadow stack
 *  - mprotect() of a shadow stack and a shadow stack access to the
 *    resulting read-only page (a #PF with the SHSTK bit from user mode)
 *
 * Every case runs in a forked child that enables the user shadow stack
 * itself (arch_prctl must be a raw syscall: no return may be pending
 * between enabling and the end of the enabling function).  The parent
 * checks that the child exited the way it should and that the kernel log
 * stays clean (when dmesg is readable).  Build with -fcf-protection=full.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "../../kselftest.h"

#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE	0x5001
#define ARCH_SHSTK_DISABLE	0x5002
#define ARCH_SHSTK_STATUS	0x5005
#define ARCH_SHSTK_SHSTK	(1ULL << 0)
#define ARCH_SHSTK_WRSS		(1ULL << 1)
#endif
#ifndef __NR_map_shadow_stack
#define __NR_map_shadow_stack	453
#endif
#ifndef SHADOW_STACK_SET_TOKEN
#define SHADOW_STACK_SET_TOKEN	(1ULL << 0)
#endif
#ifndef SEGV_CPERR
#define SEGV_CPERR		10
#endif
#ifndef NT_X86_SHSTK
#define NT_X86_SHSTK		0x204
#endif

#define SS_SIZE			0x200000
#define PAGE_SZ			4096

static int iterations = 2000;
static const char *self_path;

/* Raw, inlined: a function call between enabling and here would #CP on return */
#define ARCH_PRCTL(op, arg) ({						\
	long _ret;							\
	asm volatile("syscall" : "=a" (_ret)				\
		     : "0" (SYS_arch_prctl), "D" (op), "S" (arg)	\
		     : "rcx", "r11", "memory");				\
	_ret;								\
})

static inline __attribute__((always_inline)) unsigned long get_ssp(void)
{
	unsigned long ssp = 0;

	asm volatile("rdsspq %0" : "+r" (ssp));
	return ssp;
}

static void wrss(unsigned long *addr, unsigned long val)
{
	asm volatile("wrssq %[val], (%[addr])" :: [addr] "r" (addr), [val] "r" (val) : "memory");
}

/* ---- kernel log ---------------------------------------------------------- */

static long kmsg_bad(void)
{
	FILE *f = popen("dmesg 2>/dev/null | grep -Eic 'kernel shadow stack|#CP|BUG:|Oops|WARNING'", "r");
	char buf[64];
	long n = -1;

	if (!f)
		return -1;
	if (fgets(buf, sizeof(buf), f))
		n = atol(buf);
	pclose(f);
	return n;
}

static bool dmesg_ok;

static void check_dmesg(void)
{
	static int probed;

	if (!probed) {
		FILE *f = popen("dmesg > /dev/null 2>&1 && echo ok", "r");
		char buf[8] = "";

		if (f) {
			if (!fgets(buf, sizeof(buf), f))
				buf[0] = 0;
			pclose(f);
		}
		dmesg_ok = !strncmp(buf, "ok", 2);
		probed = 1;
		if (!dmesg_ok)
			ksft_print_msg("dmesg not readable, kernel log checks skipped\n");
	}
}

/* ---- case runner --------------------------------------------------------- */

/*
 * Run @fn in a child with the user shadow stack enabled.  Exit codes:
 * 0 ok, 77 user shadow stack could not be enabled, anything else or a
 * signal is a failure unless @expect_sig says the child must die of it.
 */
static int run_case(const char *name, void (*fn)(void), int expect_sig)
{
	long before = dmesg_ok ? kmsg_bad() : 0, after;
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		ksft_test_result_fail("%s: fork: %s\n", name, strerror(errno));
		return -1;
	}
	if (pid == 0) {
		if (ARCH_PRCTL(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK))
			_exit(77);
		if (!get_ssp())
			_exit(78);
		fn();
		_exit(0);
	}
	if (waitpid(pid, &status, 0) < 0) {
		ksft_test_result_fail("%s: waitpid: %s\n", name, strerror(errno));
		return -1;
	}
	after = dmesg_ok ? kmsg_bad() : 0;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
		ksft_test_result_skip("%s: user shadow stack cannot be enabled\n", name);
		return 1;
	}
	if (after != before) {
		ksft_test_result_fail("%s: %ld new kernel messages (shadow stack/BUG/WARNING)\n",
				      name, after - before);
		return -1;
	}
	if (expect_sig) {
		if (WIFSIGNALED(status) && WTERMSIG(status) == expect_sig) {
			ksft_test_result_pass("%s\n", name);
			return 0;
		}
		ksft_test_result_fail("%s: expected signal %d, status 0x%x\n",
				      name, expect_sig, status);
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		ksft_test_result_pass("%s\n", name);
		return 0;
	}
	if (WIFEXITED(status))
		ksft_test_result_fail("%s: child exit code %d\n", name, WEXITSTATUS(status));
	else
		ksft_test_result_fail("%s: child killed by signal %d\n", name, WTERMSIG(status));
	return -1;
}

/* ---- signals ------------------------------------------------------------- */

static volatile int sig_count, nested_count;

static void usr1_handler(int sig, siginfo_t *si, void *ctx)
{
	sig_count++;
	/* Nested: a second signal delivered while this handler runs */
	if ((sig_count & 7) == 0)
		raise(SIGUSR2);
}

static void usr2_handler(int sig, siginfo_t *si, void *ctx)
{
	nested_count++;
}

static void case_signals(void)
{
	struct sigaction sa = { .sa_sigaction = usr1_handler,
				.sa_flags = SA_SIGINFO | SA_NODEFER };
	struct sigaction sa2 = { .sa_sigaction = usr2_handler,
				 .sa_flags = SA_SIGINFO | SA_ONSTACK };
	stack_t ss = { .ss_size = 64 * 1024 };
	sigset_t set;
	int i;

	ss.ss_sp = malloc(ss.ss_size);
	if (!ss.ss_sp || sigaltstack(&ss, NULL))
		_exit(2);
	if (sigaction(SIGUSR1, &sa, NULL) || sigaction(SIGUSR2, &sa2, NULL))
		_exit(3);

	for (i = 0; i < iterations; i++) {
		raise(SIGUSR1);
		/* Delivered on the way out of a blocking syscall */
		if ((i & 63) == 0) {
			sigemptyset(&set);
			kill(getpid(), SIGUSR2);
			sched_yield();
		}
	}
	/* Signal to a task that is sleeping in the kernel: sigsuspend */
	if (fork() == 0) {
		usleep(10000);
		kill(getppid(), SIGUSR1);
		_exit(0);
	}
	sigfillset(&set);
	sigdelset(&set, SIGUSR1);
	sigsuspend(&set);
	wait(NULL);

	if (sig_count < iterations || nested_count == 0)
		_exit(4);
}

/* ---- fork + exec --------------------------------------------------------- */

static void case_fork_exec(void)
{
	int i, status;

	for (i = 0; i < 50; i++) {
		pid_t pid = fork();

		if (pid == 0) {
			raise(SIGCONT);	/* a signal frame on the forked copy */
			execl(self_path, self_path, "--exec-child", NULL);
			_exit(9);
		}
		if (pid < 0 || waitpid(pid, &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(5);
	}
}

/* The exec'ed image: enable the shadow stack again, use it, leave */
static int exec_child(void)
{
	if (ARCH_PRCTL(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK))
		_exit(0);	/* no user shadow stack: nothing to test */
	raise(SIGCONT);
	getppid();
	_exit(0);
}

/* ---- threads ------------------------------------------------------------- */

static void *thread_fn(void *arg)
{
	raise(SIGCONT);
	sched_yield();
	if ((uintptr_t)arg & 1)
		pthread_exit(NULL);
	return NULL;
}

static void case_threads(void)
{
	int i, j;

	signal(SIGCONT, SIG_DFL);
	for (i = 0; i < iterations / 20; i++) {
		pthread_t t[8];

		for (j = 0; j < 8; j++)
			if (pthread_create(&t[j], NULL, thread_fn, (void *)(uintptr_t)j))
				_exit(6);
		for (j = 0; j < 8; j++)
			pthread_join(t[j], NULL);
	}
}

/* ---- user-mode #CP ------------------------------------------------------- */

static void cp_handler(int sig, siginfo_t *si, void *ctx)
{
	/* No return from here: the shadow stack is out of sync by design */
	_exit(si->si_code == SEGV_CPERR ? 0 : 10);
}

static void case_user_cp(void)
{
	struct sigaction sa = { .sa_sigaction = cp_handler, .sa_flags = SA_SIGINFO };

	if (sigaction(SIGSEGV, &sa, NULL))
		_exit(3);

	/* ROP: replace the regular stack return address, keep the shadow one */
	asm volatile("call 1f\n\t"
		     "jmp 3f\n\t"
		     "1: lea 2f(%%rip), %%rax\n\t"
		     "mov %%rax, (%%rsp)\n\t"
		     "ret\n\t"
		     "2: int3\n\t"		/* an unchecked RET got here */
		     "3:\n\t"
		     ::: "rax", "memory");
	_exit(11);	/* the RET returned normally?! */
}

/* ---- ptrace -------------------------------------------------------------- */

static void case_ptrace(void)
{
	unsigned long ssp = 0, ssp2 = 0;
	struct iovec iov = { .iov_base = &ssp, .iov_len = sizeof(ssp) };
	int status;
	pid_t pid;

	/* The traced child: user shadow stack on, stops, continues, exits */
	pid = fork();
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			_exit(12);
		raise(SIGSTOP);
		raise(SIGCONT);
		getppid();
		_exit(0);
	}
	if (pid < 0)
		_exit(13);
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status))
		_exit(14);

	if (ptrace(PTRACE_GETREGSET, pid, NT_X86_SHSTK, &iov) || !ssp)
		goto fail;
	/* Write the same value back, then read it again */
	if (ptrace(PTRACE_SETREGSET, pid, NT_X86_SHSTK, &iov))
		goto fail;
	iov.iov_base = &ssp2;
	if (ptrace(PTRACE_GETREGSET, pid, NT_X86_SHSTK, &iov) || ssp2 != ssp)
		goto fail;
	/* Invalid values must be rejected */
	ssp2 = ssp + 1;
	if (!ptrace(PTRACE_SETREGSET, pid, NT_X86_SHSTK, &iov))
		goto fail;
	ssp2 = 0xffffffffffff0000UL;
	if (!ptrace(PTRACE_SETREGSET, pid, NT_X86_SHSTK, &iov))
		goto fail;
	/* Single-step a few instructions of a shadow stack task */
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	waitpid(pid, &status, 0);
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	waitpid(pid, &status, 0);
	if (ptrace(PTRACE_CONT, pid, NULL, NULL))
		goto fail;
	if (waitpid(pid, &status, 0) < 0)
		goto fail;
	/* SIGCONT stop under ptrace */
	if (WIFSTOPPED(status) && ptrace(PTRACE_CONT, pid, NULL, NULL) == 0)
		waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		_exit(15);
	return;
fail:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	_exit(16);
}

/* ---- clone3 -------------------------------------------------------------- */

struct clone_args_ext {
	struct clone_args args;
	__u64 shadow_stack_size;	/* not in every kernel's uapi */
};

static int clone3_child_ret;

void clone3_child_work(void);
void __attribute__((used)) clone3_child_work(void)
{
	raise(SIGCONT);
	getppid();
	clone3_child_ret = 1;
}

/*
 * clone3(CLONE_VM) with a raw syscall: the child runs on the new stack and
 * must not return into this frame, so the child side is asm that calls a
 * function and exits.
 */
static long do_clone3(struct clone_args_ext *ca, size_t size)
{
	long ret;

	asm volatile("syscall\n\t"
		     "test %%rax, %%rax\n\t"
		     "jnz 1f\n\t"
		     "call clone3_child_work\n\t"
		     "mov $60, %%eax\n\t"	/* SYS_exit */
		     "xor %%edi, %%edi\n\t"
		     "syscall\n\t"
		     "1:"
		     : "=a" (ret)
		     : "0" (__NR_clone3), "D" (ca), "S" (size)
		     : "rcx", "r11", "memory");
	return ret;
}

static void case_clone3(void)
{
	struct clone_args_ext ca;
	char *stack;
	int i, status;
	long ret;
	bool with_size = true;

	signal(SIGCONT, SIG_DFL);
	stack = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED)
		_exit(17);

	for (i = 0; i < 200; i++) {
		memset(&ca, 0, sizeof(ca));
		ca.args.flags = CLONE_VM | CLONE_VFORK;
		ca.args.exit_signal = SIGCHLD;
		ca.args.stack = (uintptr_t)stack;
		ca.args.stack_size = 64 * 1024;
		ca.shadow_stack_size = 2 * PAGE_SZ;
		clone3_child_ret = 0;

		ret = -1;
		if (with_size) {
			ret = do_clone3(&ca, sizeof(ca));
			/* Older uapi: the kernel sizes the shadow stack itself */
			if (ret == -E2BIG)
				with_size = false;
		}
		if (!with_size)
			ret = do_clone3(&ca, sizeof(ca.args));
		if (ret < 0)
			_exit(18);
		if (waitpid(ret, &status, __WALL) < 0 || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0 || !clone3_child_ret)
			_exit(19);
	}
	/* A regular clone3 fork as well */
	memset(&ca, 0, sizeof(ca));
	ca.args.exit_signal = SIGCHLD;
	ret = syscall(__NR_clone3, &ca, sizeof(ca.args));
	if (ret == 0) {
		raise(SIGCONT);
		_exit(0);
	}
	if (ret < 0 || waitpid(ret, &status, 0) < 0 || !WIFEXITED(status))
		_exit(20);
	_exit(0);
}

/* ---- mprotect of shadow stacks ------------------------------------------- */

/*
 * mprotect() on a shadow stack VMA only changes pages that are populated
 * afterwards: pte_modify() leaves existing Write=0,Dirty=1 PTEs alone (as
 * upstream's test_shadow_stack.c also relies on), so the accesses below go
 * to pages that have not been touched yet.
 */
static void *new_shstk;
static volatile int shstk_faults;

static void shstk_segv_handler(int sig, siginfo_t *si, void *ctx)
{
	shstk_faults++;
	if (si->si_code != SEGV_ACCERR)
		_exit(21);
	/* Make the region writable again so that the faulting WRSS can retry */
	if (mprotect(new_shstk, SS_SIZE, PROT_READ | PROT_WRITE))
		_exit(22);
}

static void case_mprotect(void)
{
	struct sigaction sa = { .sa_sigaction = shstk_segv_handler, .sa_flags = SA_SIGINFO };
	unsigned long *p, *q;

	if (ARCH_PRCTL(ARCH_SHSTK_ENABLE, ARCH_SHSTK_WRSS))
		_exit(23);
	if (sigaction(SIGSEGV, &sa, NULL))
		_exit(3);

	new_shstk = (void *)syscall(__NR_map_shadow_stack, 0, SS_SIZE, SHADOW_STACK_SET_TOKEN);
	if (new_shstk == MAP_FAILED)
		_exit(24);
	p = (unsigned long *)((char *)new_shstk + SS_SIZE - 64);	/* token page */
	q = (unsigned long *)((char *)new_shstk + SS_SIZE / 2);		/* untouched */

	/* Writable shadow stack: WRSS works, the token is there */
	wrss(p, 0x1234);
	if (*p != 0x1234 || (p[7] & 1) != 1)
		_exit(25);

	/* Read-only: a WRSS to a fresh page is a SHSTK #PF, the handler reopens it */
	if (mprotect(new_shstk, SS_SIZE, PROT_READ))
		_exit(26);
	wrss(q, 0x5678);
	if (shstk_faults != 1 || *q != 0x5678)
		_exit(27);

	/* PROT_NONE and back, with an ordinary read in between */
	if (mprotect(new_shstk, SS_SIZE, PROT_NONE))
		_exit(28);
	if (mprotect(new_shstk, SS_SIZE, PROT_READ | PROT_WRITE))
		_exit(29);
	if (*q != 0x5678 || *p != 0x1234)
		_exit(30);

	/* Dropped pages come back as shadow stack pages: WRSS still works */
	if (madvise(new_shstk, SS_SIZE, MADV_DONTNEED))
		_exit(31);
	wrss(q, 0x9abc);
	if (*q != 0x9abc || shstk_faults != 1)
		_exit(32);
	munmap(new_shstk, SS_SIZE);
}

/*
 * The task's own shadow stack: the pages below the current one are still
 * untouched (the stack was enabled at the top of this child).  Make them
 * read-only, then CALL deep enough to reach them: the push is a shadow
 * stack write to a read-only page, SIGSEGV.
 */
static unsigned long __attribute__((noinline)) recurse(int n)
{
	unsigned long r;

	if (n <= 0)
		return get_ssp();
	r = recurse(n - 1);
	asm volatile("" : "+r" (r) :: "memory");	/* no tail-recursion elimination */
	return r;
}

static void case_mprotect_own(void)
{
	unsigned long ssp = get_ssp(), page = (ssp - 8) & ~(PAGE_SZ - 1UL), bottom;
	int frames = 4 * PAGE_SZ / 8;

	signal(SIGSEGV, SIG_DFL);
	/* Sanity: the recursion really consumes shadow stack */
	bottom = recurse(16);
	if (ssp - bottom < 16 * 8 || ssp - bottom > 32 * 8)
		_exit(33);
	/* The 4 pages below the one in use */
	if (mprotect((void *)(page - 4 * PAGE_SZ), 4 * PAGE_SZ, PROT_READ))
		_exit(34);
	recurse(frames);	/* more frames than fit in the writable page */
	_exit(35);
}

/* ---- main ---------------------------------------------------------------- */

static bool cpuinfo_has(const char *flag)
{
	char line[8192];
	bool found = false;
	FILE *f = fopen("/proc/cpuinfo", "r");

	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		size_t n = strlen(flag);

		if (strncmp(line, "flags", 5))
			continue;
		while ((p = strstr(p, flag))) {
			if ((p == line || p[-1] == ' ') && (p[n] == ' ' || p[n] == '\n')) {
				found = true;
				break;
			}
			p++;
		}
		break;
	}
	fclose(f);
	return found;
}

int main(int argc, char **argv)
{
	int opt;

	self_path = argv[0];
	if (argc > 1 && !strcmp(argv[1], "--exec-child"))
		return exec_child();

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		if (opt == 'n')
			iterations = atoi(optarg);
	}

	ksft_print_header();
	if (!cpuinfo_has("user_shstk")) {
		ksft_exit_skip("user_shstk not in /proc/cpuinfo\n");
	}
	ksft_set_plan(8);
	ksft_print_msg("kernel_shstk %s, user_shstk present, %d iterations\n",
		       cpuinfo_has("kernel_shstk") ? "active" : "NOT active (running anyway)",
		       iterations);
	check_dmesg();
	signal(SIGCHLD, SIG_DFL);

	run_case("signals, nested signals and sigaltstack", case_signals, 0);
	run_case("fork + exec of self", case_fork_exec, 0);
	run_case("pthread_create/exit storm", case_threads, 0);
	run_case("user-mode #CP is SIGSEGV/SEGV_CPERR", case_user_cp, 0);
	run_case("ptrace NT_X86_SHSTK get/set and single-step", case_ptrace, 0);
	run_case("clone3 threads with a shadow stack", case_clone3, 0);
	run_case("mprotect of a map_shadow_stack() region", case_mprotect, 0);
	run_case("CALL on a read-only own shadow stack is SIGSEGV", case_mprotect_own, SIGSEGV);

	ksft_finished();
}
