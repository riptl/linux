// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: a 32-bit compat process.
 *
 * Compat tasks enter the kernel through int $0x80 (FRED clears SYSCALL32
 * and SYSENTER32) and leave through ERETU to a 32-bit code segment; signal
 * delivery builds a compat frame and compat sigreturn / rt_sigreturn
 * restore from it.  This program does nothing but exercise those paths:
 *
 *  - int $0x80 syscalls (write, getpid, getppid, sched_yield)
 *  - the same through the 32-bit vDSO's __kernel_vsyscall (AT_SYSINFO)
 *  - rt_sigaction with SA_SIGINFO + SA_RESTORER and kill(self) in a loop,
 *    returning through an rt_sigreturn trampoline
 *  - a non-RT handler (plain sigreturn frame) with a sigaltstack
 *  - #BP (int3 -> SIGTRAP) and #PF (fresh mmap page) from compat mode
 *  - fork, clone(CLONE_VM | CLONE_VFORK), waitpid, exit
 *
 * Freestanding so that no 32-bit libc is needed: own _start, raw syscalls,
 * built with -m32 -nostdlib -static -ffreestanding (see the Makefile).
 * Exit code 0 means every check passed; kshstk_compat.sh runs many
 * instances in parallel and watches dmesg.
 */
typedef unsigned int u32;
typedef unsigned long ulong;

#define NR_exit		1
#define NR_fork		2
#define NR_write	4
#define NR_waitpid	7
#define NR_getpid	20
#define NR_kill		37
#define NR_getppid	64
#define NR_munmap	91
#define NR_sigreturn	119
#define NR_clone	120
#define NR_sched_yield	158
#define NR_rt_sigreturn	173
#define NR_rt_sigaction	174
#define NR_sigaltstack	186
#define NR_mmap2	192
#define NR_exit_group	252

#define SIGTRAP		5
#define SIGUSR1		10
#define SIGUSR2		12
#define SIGCHLD		17
#define SA_SIGINFO	0x00000004
#define SA_ONSTACK	0x08000000
#define SA_RESTORER	0x04000000
#define SA_NODEFER	0x40000000
#define CLONE_VM	0x00000100
#define CLONE_VFORK	0x00004000
#define AT_NULL		0
#define AT_SYSINFO	32

#define ITER		2000

static long sys5(long nr, long a, long b, long c, long d, long e)
{
	long ret;

	asm volatile("int $0x80"
		     : "=a" (ret)
		     : "0" (nr), "b" (a), "c" (b), "d" (c), "S" (d), "D" (e)
		     : "memory");
	return ret;
}
#define sys0(nr)		sys5(nr, 0, 0, 0, 0, 0)
#define sys1(nr, a)		sys5(nr, (long)(a), 0, 0, 0, 0)
#define sys2(nr, a, b)		sys5(nr, (long)(a), (long)(b), 0, 0, 0)
#define sys3(nr, a, b, c)	sys5(nr, (long)(a), (long)(b), (long)(c), 0, 0)
#define sys4(nr, a, b, c, d)	sys5(nr, (long)(a), (long)(b), (long)(c), (long)(d), 0)

static void (*vsyscall)(void);

/* The vDSO entry: args in registers as for int $0x80, ebp is clobbered */
static long vsys3(long nr, long a, long b, long c)
{
	long ret;

	if (!vsyscall)
		return sys3(nr, a, b, c);
	asm volatile("call *%[fn]"
		     : "=a" (ret)
		     : "0" (nr), "b" (a), "c" (b), "d" (c), [fn] "m" (vsyscall)
		     : "memory");
	return ret;
}

static void __attribute__((noreturn)) die(int code)
{
	sys1(NR_exit_group, code);
	for (;;)
		;
}

static void out(const char *s)
{
	int n = 0;

	while (s[n])
		n++;
	sys3(NR_write, 1, s, n);
}

struct kernel_sigaction {
	void *handler;
	ulong flags;
	void *restorer;
	ulong mask[2];
};

struct stack_t32 {
	void *ss_sp;
	int ss_flags;
	u32 ss_size;
};

/* Signal return trampolines, as glibc provides them for the kernel */
extern void rt_restorer(void);
extern void nonrt_restorer(void);
asm(".text\n"
    ".type rt_restorer, @function\n"
    "rt_restorer:\n\t"
    "movl $173, %eax\n\t"	/* rt_sigreturn */
    "int $0x80\n\t"
    "hlt\n"
    ".type nonrt_restorer, @function\n"
    "nonrt_restorer:\n\t"
    "popl %eax\n\t"		/* the signal number */
    "movl $119, %eax\n\t"	/* sigreturn */
    "int $0x80\n\t"
    "hlt\n");

static volatile int rt_count, nonrt_count, trap_count;

static void rt_handler(int sig, void *info, void *ctx)
{
	rt_count++;
	if (sig != SIGUSR1 || !info || !ctx)
		die(3);
}

static void nonrt_handler(int sig)
{
	nonrt_count++;
	if (sig != SIGUSR2)
		die(4);
}

static void trap_handler(int sig)
{
	trap_count++;
}

static int install(int sig, void *handler, ulong flags, void *restorer)
{
	struct kernel_sigaction sa = {
		.handler = handler,
		.flags = flags | SA_RESTORER,
		.restorer = restorer,
	};
	return sys4(NR_rt_sigaction, sig, &sa, 0, 8);
}

static char altstack[16384] __attribute__((aligned(16)));
static char thread_stack[16384] __attribute__((aligned(16)));
static volatile int thread_ran;

void thread_fn(void);
void __attribute__((used)) thread_fn(void)
{
	int pid = sys0(NR_getpid);

	sys2(NR_kill, pid, SIGUSR1);
	sys0(NR_sched_yield);
	thread_ran = 1;
}

/* clone(CLONE_VM | CLONE_VFORK): the child runs thread_fn on its own stack and exits */
static long clone_vm(void *stack)
{
	long ret;

	asm volatile("int $0x80\n\t"
		     "testl %%eax, %%eax\n\t"
		     "jnz 1f\n\t"
		     "call thread_fn\n\t"
		     "movl $1, %%eax\n\t"	/* exit */
		     "xorl %%ebx, %%ebx\n\t"
		     "int $0x80\n\t"
		     "hlt\n\t"
		     "1:"
		     : "=a" (ret)
		     : "0" (NR_clone), "b" (CLONE_VM | CLONE_VFORK | SIGCHLD), "c" (stack)
		     : "memory");
	return ret;
}

static void run(void)
{
	struct stack_t32 ss = { .ss_sp = altstack, .ss_flags = 0, .ss_size = sizeof(altstack) };
	volatile char *page;
	int pid, i, status, child;

	pid = sys0(NR_getpid);
	if (pid <= 0 || vsys3(NR_getpid, 0, 0, 0) != pid)
		die(5);

	if (sys2(NR_sigaltstack, &ss, 0))
		die(6);
	if (install(SIGUSR1, rt_handler, SA_SIGINFO | SA_NODEFER, rt_restorer) ||
	    install(SIGUSR2, nonrt_handler, SA_ONSTACK, nonrt_restorer) ||
	    install(SIGTRAP, trap_handler, 0, nonrt_restorer))
		die(7);

	/* Signals: rt frame, non-rt frame on the alternate stack, #BP */
	for (i = 0; i < ITER; i++) {
		if (sys2(NR_kill, pid, SIGUSR1))
			die(8);
		if ((i & 3) == 0 && vsys3(NR_kill, pid, SIGUSR2, 0))
			die(9);
		if ((i & 15) == 0)
			asm volatile("int3" ::: "memory");
		if ((i & 63) == 0)
			sys0(NR_sched_yield);
	}
	if (rt_count != ITER || nonrt_count != ITER / 4 || trap_count != ITER / 16)
		die(10);

	/* #PF from compat mode, and the mmap2/munmap syscalls */
	for (i = 0; i < 64; i++) {
		page = (volatile char *)sys5(NR_mmap2, 0, 4096, 3 /* RW */, 0x22 /* PRIVATE|ANON */, -1);
		if ((ulong)page >= (ulong)-4096)
			die(11);
		page[100] = 1;
		if (page[100] != 1)
			die(12);
		sys2(NR_munmap, page, 4096);
	}

	/* fork: the child takes a signal and exits */
	for (i = 0; i < 20; i++) {
		child = sys0(NR_fork);
		if (child < 0)
			die(13);
		if (child == 0) {
			int me = sys0(NR_getpid);

			sys2(NR_kill, me, SIGUSR1);
			sys0(NR_getppid);
			sys1(NR_exit, 0);
		}
		if (sys3(NR_waitpid, child, &status, 0) != child || status != 0)
			die(14);
	}

	/* clone(CLONE_VM): a "thread" sharing the address space */
	for (i = 0; i < 20; i++) {
		thread_ran = 0;
		child = clone_vm(thread_stack + sizeof(thread_stack) - 16);
		if (child < 0)
			die(15);
		if (sys3(NR_waitpid, child, &status, 0) != child || status != 0 || !thread_ran)
			die(16);
	}
}

void __attribute__((noreturn, used)) start_c(ulong *sp)
{
	int argc = sp[0];
	ulong *p = sp + 1 + argc + 1;	/* skip argv and its NULL */

	while (*p)			/* envp */
		p++;
	p++;
	for (; p[0] != AT_NULL; p += 2) {
		if (p[0] == AT_SYSINFO)
			vsyscall = (void (*)(void))p[1];
	}

	run();
	out("ok\n");
	die(0);
}

asm(".text\n"
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n\t"
    "xorl %ebp, %ebp\n\t"
    "movl %esp, %eax\n\t"
    "andl $-16, %esp\n\t"
    "subl $12, %esp\n\t"
    "pushl %eax\n\t"
    "call start_c\n\t"
    "hlt\n");
