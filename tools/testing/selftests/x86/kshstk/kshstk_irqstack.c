// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: deep kernel stacks with interrupts on top.
 *
 * Hardirq and softirq frames share the task's kernel shadow stack
 * (call_on_stack() only switches RSP), and NMIs push a FRED event frame on
 * the level 2 shadow stack and return through ERETS.  The shadow stack is
 * KERNEL_SHSTK_SIZE = THREAD_SIZE/2 (8K, 1024 return addresses): deep
 * call chains plus interrupt and softirq nesting plus NMIs is where it
 * would run out first, and where every ERETS after a nested event must
 * find a consistent frame.  The LKDTM SHSTK_DEPTH_SAFE test measures the
 * depth directly; this test drives the deepest paths reachable from user
 * space, all at once, with a high rate perf cycles event (NMIs in kernel
 * mode) on top:
 *
 *  - timerfd and signalfd storms (hrtimer interrupts, signal delivery into
 *    tasks blocked in the kernel)
 *  - many concurrent epoll_wait() calls with short timeouts
 *  - madvise(MADV_PAGEOUT) and mremap() storms (deep mm paths, TLB
 *    shootdown IPIs to the other CPUs)
 *  - sendmsg()/recvmsg() over AF_UNIX socketpairs with SCM_RIGHTS (deep
 *    net stack with fd passing and the unix GC)
 *
 * The test passes if all workers finish and the machine survives; dmesg
 * is checked when it is readable.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../kselftest.h"

static int duration = 10;
static int only_phase = -1;	/* -p N: run a single phase */
static int ncpus;
static volatile sig_atomic_t stop;
static pid_t *pids;
static int total;

static void on_alarm(int sig)
{
	stop = 1;
}

/* Main process only: a worker that did not finish in time is a failure, not a hang */
static void on_watchdog(int sig)
{
	int j;

	for (j = 0; j < total; j++)
		if (pids[j] > 0)
			kill(pids[j], SIGKILL);
}

static void pin_to(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu % ncpus, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

/* ---- timerfd + signalfd -------------------------------------------------- */

static void timer_signal_worker(int id)
{
	struct itimerspec its = {
		.it_interval = { 0, 200000 },	/* 5 kHz */
		.it_value = { 0, 200000 },
	};
	struct signalfd_siginfo ssi;
	sigset_t mask;
	int tfd, sfd, ep, n;
	uint64_t exp;
	pid_t pid;
	struct epoll_event ev;

	pin_to(id);
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	sfd = signalfd(-1, &mask, SFD_NONBLOCK);
	ep = epoll_create1(0);
	if (tfd < 0 || sfd < 0 || ep < 0)
		_exit(2);
	timerfd_settime(tfd, 0, &its, NULL);
	ev.events = EPOLLIN;
	ev.data.fd = tfd;
	epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev);
	ev.data.fd = sfd;
	epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev);

	/* A sender on another CPU: signals into a task blocked in epoll_wait */
	pid = fork();
	if (pid == 0) {
		union sigval sv = { .sival_int = id };
		pid_t parent = getppid();

		alarm(duration);	/* alarms are not inherited */
		pin_to(id + 1);
		while (!stop) {
			kill(parent, SIGUSR1);
			sigqueue(parent, SIGRTMIN, sv);
			sched_yield();
		}
		_exit(0);
	}
	while (!stop) {
		n = epoll_wait(ep, &ev, 1, 10);
		if (n <= 0)
			continue;
		if (ev.data.fd == tfd) {
			if (read(tfd, &exp, sizeof(exp)) < 0 && errno != EAGAIN)
				_exit(3);
		} else {
			/* Bounded: the sender can outpace this loop */
			for (n = 0; n < 64 && read(sfd, &ssi, sizeof(ssi)) == sizeof(ssi); n++)
				;
		}
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	_exit(0);
}

/* ---- epoll_wait with timeouts -------------------------------------------- */

static void epoll_worker(int id)
{
	int ep, i, pfd[2];
	struct epoll_event ev;
	char c = 0;

	ep = epoll_create1(0);
	if (ep < 0 || pipe2(pfd, O_NONBLOCK))
		_exit(4);
	ev.events = EPOLLIN;
	ev.data.fd = pfd[0];
	epoll_ctl(ep, EPOLL_CTL_ADD, pfd[0], &ev);
	for (i = 0; !stop; i++) {
		if ((i & 1023) == 0)
			pin_to(i >> 10);	/* migrate while sleeping in epoll */
		if (i & 1) {
			/* Woken by data rather than by the timer */
			if (write(pfd[1], &c, 1) == 1 && epoll_wait(ep, &ev, 1, 1000) > 0)
				read(pfd[0], &c, 1);
		} else {
			epoll_wait(ep, &ev, 1, 1);	/* 1 ms timeout: hrtimer */
		}
	}
	_exit(0);
}

/* ---- madvise(MADV_PAGEOUT) / mremap -------------------------------------- */

static void mm_worker(int id)
{
	size_t len = 64 * 4096;
	char *p, *q;
	int i;

	pin_to(id);
	p = mmap(NULL, len * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		_exit(5);
	munmap(p + len, len);
	for (i = 0; !stop; i++) {
		int j;

		for (j = 0; j < 64; j++)
			p[j * 4096] = i;
		if (madvise(p, len, MADV_PAGEOUT) && errno != EINVAL)
			_exit(6);
		/* Move it (TLB flush IPIs to every CPU that ran this mm), and back */
		q = mremap(p, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, p + len);
		if (q == MAP_FAILED)
			_exit(7);
		q = mremap(q, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, p);
		if (q == MAP_FAILED)
			_exit(8);
		if ((i & 7) == 0)
			madvise(p, len, MADV_DONTNEED);
		if ((i & 63) == 0)
			pin_to(id + (i >> 6));	/* spread the mm across CPUs */
	}
	_exit(0);
}

/* ---- AF_UNIX with SCM_RIGHTS --------------------------------------------- */

static void unix_worker(int id)
{
	int sv[2], fds[4], i;
	char buf[64];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	union {
		char cbuf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = u.cbuf, .msg_controllen = sizeof(u.cbuf),
	};
	struct cmsghdr *cm;
	pid_t pid;

	pin_to(id);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv))
		_exit(9);
	for (i = 0; i < 4; i++)
		fds[i] = (i & 1) ? sv[0] : open("/proc/self/exe", O_RDONLY);
	if (fds[0] < 0)
		_exit(10);

	pid = fork();
	if (pid == 0) {
		/* Receiver on another CPU: wakeups cross CPUs */
		alarm(duration + 5);
		pin_to(id + 1);
		close(sv[0]);
		while (!stop) {
			int n = recvmsg(sv[1], &msg, 0);

			if (n <= 0)
				break;
			for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
				if (cm->cmsg_type == SCM_RIGHTS) {
					int *rf = (int *)CMSG_DATA(cm);
					int k, nf = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);

					for (k = 0; k < nf; k++)
						close(rf[k]);
				}
			}
			msg.msg_controllen = sizeof(u.cbuf);
			if (write(sv[1], buf, 1) < 0)
				break;
		}
		_exit(0);
	}
	close(sv[1]);
	for (i = 0; !stop; i++) {
		memset(&u, 0, sizeof(u));
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;
		cm->cmsg_len = CMSG_LEN(sizeof(fds));
		memcpy(CMSG_DATA(cm), fds, sizeof(fds));
		msg.msg_controllen = CMSG_SPACE(sizeof(fds));
		iov.iov_len = sizeof(buf);
		if (sendmsg(sv[0], &msg, 0) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		/* The in-flight socket (sv[0] passed over itself) feeds the unix GC */
		if (read(sv[0], buf, 1) < 0 && errno != EINTR)
			break;
	}
	close(sv[0]);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	_exit(0);
}

/* ---- NMIs: perf cycles, kernel only, inherited by all children ----------- */

static int perf_fd = -1;
static bool perf_hw;

static void perf_start(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.size = sizeof(attr),
		.sample_period = 10000,
		.exclude_user = 1,
		.inherit = 1,
		.disabled = 1,
	};

	perf_fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	perf_hw = perf_fd >= 0;
	if (perf_fd < 0) {
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		perf_fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	}
	if (perf_fd >= 0)
		ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

/* ---- driver -------------------------------------------------------------- */

struct phase {
	const char *name;
	void (*fn)(int id);
	int nworkers;
};

int main(int argc, char **argv)
{
	int opt, i, j, nphases, failed_total = 0;
	long before = 0, after = 0;
	bool dmesg_ok;
	int *phase_of;
	FILE *f;

	while ((opt = getopt(argc, argv, "t:p:")) != -1) {
		if (opt == 't')
			duration = atoi(optarg);
		else if (opt == 'p')
			only_phase = atoi(optarg);
	}
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus < 1)
		ncpus = 1;

	const struct phase phases[] = {
		{ "timerfd + signalfd storm",		timer_signal_worker,	ncpus },
		{ "concurrent epoll_wait timeouts",	epoll_worker,		ncpus * 2 },
		{ "madvise(PAGEOUT) + mremap storm",	mm_worker,		ncpus },
		{ "AF_UNIX sendmsg with SCM_RIGHTS",	unix_worker,		ncpus },
	};
	nphases = ARRAY_SIZE(phases);
	int fails[ARRAY_SIZE(phases)];

	memset(fails, 0, sizeof(fails));
	for (i = 0; i < nphases; i++)
		if (only_phase < 0 || only_phase == i)
			total += phases[i].nworkers;
	pids = calloc(total, sizeof(*pids));
	phase_of = calloc(total, sizeof(*phase_of));

	ksft_print_header();
	ksft_set_plan(nphases + 1);

	f = popen("dmesg 2>/dev/null | grep -Eic 'kernel shadow stack|#CP|BUG:|Oops|WARNING'; echo rc=$?", "r");
	dmesg_ok = false;
	if (f) {
		char line[64];

		if (fgets(line, sizeof(line), f)) {
			before = atol(line);
			dmesg_ok = true;
		}
		pclose(f);
	}
	/* grep -c on an empty dmesg (unreadable) still prints 0: double check */
	if (dmesg_ok && access("/dev/kmsg", R_OK))
		dmesg_ok = false;

	perf_start();
	ksft_print_msg("%d CPUs, %ds, %d workers, perf %s sampling in kernel mode\n",
		       ncpus, duration, total,
		       perf_fd < 0 ? "NOT" : perf_hw ? "cycles (NMI)" : "cpu-clock (hrtimer)");

	signal(SIGCHLD, SIG_DFL);
	signal(SIGALRM, on_watchdog);
	alarm(duration + 30);
	for (i = 0, j = 0; i < nphases; i++) {
		int k;

		if (only_phase >= 0 && only_phase != i)
			continue;
		for (k = 0; k < phases[i].nworkers; k++, j++) {
			phase_of[j] = i;
			pids[j] = fork();
			if (pids[j] == 0) {
				signal(SIGALRM, on_alarm);
				alarm(duration);
				phases[i].fn(k);
				_exit(0);
			}
			if (pids[j] < 0)
				ksft_exit_fail_msg("fork: %s\n", strerror(errno));
		}
	}
	for (j = 0; j < total; j++) {
		int status;

		if (waitpid(pids[j], &status, 0) < 0 || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0) {
			ksft_print_msg("%s worker: status 0x%x%s\n",
				       phases[phase_of[j]].name, status,
				       WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ?
				       " (killed by the watchdog: did not finish in time)" : "");
			fails[phase_of[j]]++;
			failed_total++;
		}
		pids[j] = 0;
	}
	alarm(0);
	if (perf_fd >= 0) {
		long long count = 0;

		ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
		if (read(perf_fd, &count, sizeof(count)) == sizeof(count))
			ksft_print_msg("perf samples (all workers): %lld\n", count);
	}
	for (i = 0; i < nphases; i++) {
		if (only_phase >= 0 && only_phase != i)
			ksft_test_result_skip("%s (not selected)\n", phases[i].name);
		else if (fails[i])
			ksft_test_result_fail("%s: %d worker(s) failed\n", phases[i].name, fails[i]);
		else
			ksft_test_result_pass("%s\n", phases[i].name);
	}

	if (dmesg_ok) {
		f = popen("dmesg 2>/dev/null | grep -Eic 'kernel shadow stack|#CP|BUG:|Oops|WARNING'", "r");
		if (f) {
			char line[64];

			if (fgets(line, sizeof(line), f))
				after = atol(line);
			pclose(f);
		}
		ksft_test_result(after == before, "kernel log clean (%ld new messages)\n", after - before);
	} else {
		ksft_test_result_skip("kernel log check (dmesg not readable)\n");
	}

	ksft_finished();
}
