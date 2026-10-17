// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: kernel-mode FRED events that modify regs->ip.
 *
 * ERETS verifies the LIP and CS in the shadow stack event frame against the
 * regular stack frame, so every handler that changes regs->ip must be
 * mirrored by fred_shstk_sync_frame().  From user space the reachable
 * cases are:
 *
 *  - exception table fixups: kernel #PF on a user address inside
 *    copy_from_user()/copy_to_user()/get_user()/put_user(), string copies,
 *    futex atomics and the uaccess paths of many syscalls.  The fixup
 *    moves regs->ip to the recovery label.
 *
 *  - kernel-mode #PF with a normal retry (regs->ip unchanged, but a full
 *    FRED event frame round trip from kernel mode, with a nested event
 *    frame when the fault handler itself is interrupted).
 *
 *  - NMIs in kernel mode: perf sampling at high frequency on a task that
 *    spends its time in the kernel (FRED stack level 2 shadow stack,
 *    nested inside other kernel events).
 *
 *  - kernel-mode #DB: a hardware data breakpoint on a kernel variable
 *    (FRED stack level 1 shadow stack; root only).
 *
 * WARN_ON_ONCE continuation, INT3 emulation and kprobe single-stepping are
 * covered by kshstk_lkdtm.sh and kshstk_tracing.sh, which need root and
 * tracefs/LKDTM.
 *
 * The test passes if every syscall returns the expected error and the
 * machine survives; the failure mode is a #CP at ERETS, which is fatal.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../kselftest.h"

static int iterations = 20000;
static int ncpus;

static void *unmapped_page(void)
{
	void *p = mmap(NULL, 4096 * 3, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		ksft_exit_fail_msg("mmap: %s\n", strerror(errno));
	/* Middle page unmapped: accesses that straddle fault mid-copy */
	munmap((char *)p + 4096, 4096);
	return p;
}

static unsigned long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

/* ---- Exception table fixups ---------------------------------------------- */

static int test_uaccess_fixups(void)
{
	char *buf = unmapped_page();
	char *bad = buf + 4096;		/* unmapped */
	char *edge = buf + 4096 - 64;	/* 64 good bytes, then a fault */
	int fd, pfd[2], sv[2], fails = 0, i;
	struct iovec iov[2];
	struct stat st;
	char tmp[256];

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0 || pipe2(pfd, O_NONBLOCK) ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv))
		ksft_exit_fail_msg("setup: %s\n", strerror(errno));

	for (i = 0; i < iterations; i++) {
		/* copy_to_user() fully bad and partially bad */
		if (pread(fd, bad, 4096, 0) != -1 || errno != EFAULT)
			fails++;
		if (pread(fd, edge, 4096, 0) != 64)
			fails++;

		/*
		 * copy_from_user() through a pipe and a socket.  A fault in
		 * the middle of the copy yields either a short count or
		 * -EFAULT depending on the path; both are fixups.  Drain
		 * whatever arrived (non-blocking).
		 */
		if (write(pfd[1], bad, 64) != -1 || errno != EFAULT)
			fails++;
		if (write(pfd[1], edge, 4096) > 64)
			fails++;
		while (read(pfd[0], tmp, sizeof(tmp)) > 0)
			;
		if (send(sv[0], edge, 4096, MSG_DONTWAIT) > 64)
			fails++;
		while (recv(sv[1], tmp, sizeof(tmp), MSG_DONTWAIT) > 0)
			;

		/* iovec import and partial iov copies */
		iov[0].iov_base = buf;
		iov[0].iov_len = 32;
		iov[1].iov_base = bad;
		iov[1].iov_len = 32;
		if (preadv(fd, iov, 2, 0) != 32)
			fails++;
		if (readv(pfd[1], (void *)bad, 1) != -1 ||
		    (errno != EFAULT && errno != EBADF))
			fails++;

		/* put_user()/get_user() style small accesses */
		if (stat("/proc/self/exe", (void *)bad) != -1 || errno != EFAULT)
			fails++;
		/* Raw syscall: the vDSO version would fault in user mode */
		if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, bad) != -1 || errno != EFAULT)
			fails++;
		if (syscall(SYS_futex, bad, FUTEX_WAKE, 1, NULL, NULL, 0) != -1 ||
		    errno != EFAULT)
			fails++;
		if (syscall(SYS_futex, bad, FUTEX_WAIT, 0, NULL, NULL, 0) != -1 ||
		    errno != EFAULT)
			fails++;
		if (pipe((void *)bad) != -1 || errno != EFAULT)
			fails++;

		/* strncpy_from_user() */
		if (open(bad, O_RDONLY) != -1 || errno != EFAULT)
			fails++;
		if (access(edge, F_OK) != -1 || (errno != EFAULT && errno != ENOENT))
			fails++;

		/* Kernel-mode #PF with retry (not a fixup): touch via the kernel */
		if (fstat(fd, &st))
			fails++;
		madvise(buf, 4096, MADV_DONTNEED);
		if (pread(fd, buf, 4096, 0) != 4096)	/* kernel faults the page in */
			fails++;
	}

	close(fd);
	close(pfd[0]);
	close(pfd[1]);
	close(sv[0]);
	close(sv[1]);
	return fails;
}

/* ---- Signal frames on bad stacks ----------------------------------------- */

static volatile int got_signal;

static void sig_handler(int sig)
{
	got_signal++;
}

static int test_signal_frames(void)
{
	char *buf = unmapped_page();
	stack_t ss, old;
	int fails = 0, i;

	signal(SIGUSR1, sig_handler);

	for (i = 0; i < iterations / 10; i++) {
		int status;
		pid_t pid;

		/* Normal path: setup_rt_frame writes the frame with user accesses */
		raise(SIGUSR1);

		/*
		 * Child: sigaltstack on an unmapped page: the frame write
		 * faults in the kernel (fixup), the task gets a SIGSEGV.
		 */
		pid = fork();
		if (pid == 0) {
			ss.ss_sp = buf + 4096;
			ss.ss_size = 4096;
			ss.ss_flags = 0;
			sigaltstack(&ss, &old);
			struct sigaction sa = { .sa_handler = sig_handler,
						.sa_flags = SA_ONSTACK };
			sigaction(SIGUSR1, &sa, NULL);
			raise(SIGUSR1);
			_exit(1);
		}
		if (pid < 0 || waitpid(pid, &status, 0) < 0 ||
		    !WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV)
			fails++;
	}
	if (!got_signal)
		fails++;
	return fails;
}

/* ---- NMIs in kernel mode (perf sampling) --------------------------------- */

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu, -1, 0);
}

static int test_nmi(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.size = sizeof(attr),
		.sample_period = 20000,	/* a lot of NMIs */
		.exclude_user = 1,	/* only count, hence interrupt, in the kernel */
		.disabled = 1,
	};
	char *buf = unmapped_page();
	unsigned long end;
	int fd, fails = 0, fd_fallback = -1;
	long long count = 0;

	fd = perf_open(&attr, 0, -1);
	if (fd < 0) {
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		fd_fallback = fd = perf_open(&attr, 0, -1);
		if (fd < 0) {
			ksft_test_result_skip("NMI: perf_event_open: %s\n",
					      strerror(errno));
			return -1;
		}
		ksft_print_msg("no hardware perf events, falling back to cpu-clock (hrtimer, not NMI)\n");
	}
	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

	/* Spend time in the kernel, including in fixup paths */
	end = now_ns() + 3000000000UL;
	while (now_ns() < end) {
		/* uaccess fixup, a plain syscall and a context switch */
		pread(STDERR_FILENO, buf + 4096, 1, 0);
		getppid();
		sched_yield();
	}

	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (read(fd, &count, sizeof(count)) != sizeof(count) || count == 0)
		fails++;
	ksft_print_msg("%s samples counted: %lld\n",
		       fd_fallback >= 0 ? "cpu-clock" : "cycles", count);
	close(fd);
	return fails;
}

/* ---- Kernel-mode #DB (hw breakpoint on kernel data, root only) ----------- */

static unsigned long kallsyms_lookup(const char *name)
{
	char line[256], sym[128];
	unsigned long addr = 0, a;
	FILE *f = fopen("/proc/kallsyms", "r");
	char t;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx %c %127s", &a, &t, sym) == 3 &&
		    !strcmp(sym, name)) {
			addr = a;
			break;
		}
	}
	fclose(f);
	return addr;
}

static int test_kernel_db(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(attr),
		.bp_type = HW_BREAKPOINT_W,
		.bp_len = HW_BREAKPOINT_LEN_8,
		.sample_period = 1,
		.disabled = 1,
	};
	unsigned long addr = kallsyms_lookup("jiffies_64");
	long long count = 0;
	int fd, cpu, fails = 0, nfd = 0;
	int *fds;

	if (geteuid() != 0 || !addr) {
		ksft_test_result_skip("kernel #DB: needs root and /proc/kallsyms\n");
		return -1;
	}
	attr.bp_addr = addr;

	fds = calloc(ncpus, sizeof(*fds));
	for (cpu = 0; cpu < ncpus; cpu++) {
		fd = perf_open(&attr, -1, cpu);
		if (fd < 0)
			continue;
		fds[nfd++] = fd;
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	}
	if (!nfd) {
		ksft_test_result_skip("kernel #DB: perf_event_open(BREAKPOINT): %s\n",
				      strerror(errno));
		free(fds);
		return -1;
	}

	/* jiffies_64 is written from the timer interrupt: kernel-mode #DB */
	usleep(500000);

	for (cpu = 0; cpu < nfd; cpu++) {
		long long c = 0;

		ioctl(fds[cpu], PERF_EVENT_IOC_DISABLE, 0);
		if (read(fds[cpu], &c, sizeof(c)) == sizeof(c))
			count += c;
		close(fds[cpu]);
	}
	free(fds);
	ksft_print_msg("kernel data breakpoint hits: %lld on %d CPUs\n", count, nfd);
	if (!count)
		fails++;
	return fails;
}

int main(int argc, char **argv)
{
	int opt, ret;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		if (opt == 'n')
			iterations = atoi(optarg);
	}
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	ksft_print_header();
	ksft_set_plan(4);

	ret = test_uaccess_fixups();
	ksft_test_result(ret == 0, "exception table fixups (%d unexpected results)\n", ret);

	ret = test_signal_frames();
	ksft_test_result(ret == 0, "signal frames (%d unexpected results)\n", ret);

	ret = test_nmi();
	if (ret >= 0)
		ksft_test_result(ret == 0, "NMIs in kernel mode\n");

	ret = test_kernel_db();
	if (ret >= 0)
		ksft_test_result(ret == 0, "#DB in kernel mode\n");

	ksft_finished();
}
