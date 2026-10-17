// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: context switch and thread lifecycle stress.
 *
 * Every task has its own kernel shadow stack, switched with
 * RSTORSSP/SAVEPREVSSP in __switch_to_asm(), seeded by
 * kernel_shstk_setup_thread(), freed from a deferred work item, with
 * IA32_PL0_SSP updated lazily on return to user mode.  Any slip in that
 * machinery shows up as a #CP (fatal) or a shadow stack #PF (Oops) under
 * load, so this test simply generates a lot of load of the right shapes:
 *
 *  - fork()/wait() churn (new shadow stacks, first switch-in, exit, free)
 *  - clone(CLONE_VM) thread churn (same, shared mm)
 *  - pipe ping-pong between pinned pairs (context switches at high rate)
 *  - sched_yield() storms, including on migrating tasks
 *  - signal delivery and sigreturn (XRSTOR of supervisor state, PL0_SSP)
 *  - user shadow stack enabled tasks (both shadow stacks switched together)
 *
 * The test passes if the machine is still alive at the end: the failure
 * mode of the code under test is a kernel panic, not a wrong result.  It
 * still checks for unexpected child deaths.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#include "../../kselftest.h"

#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE	0x5001
#define ARCH_SHSTK_DISABLE	0x5002
#define ARCH_SHSTK_SHSTK	(1ULL << 0)
#endif

static int duration = 10;	/* seconds per phase, -t */
static int ncpus;
static volatile sig_atomic_t stop;

static void on_alarm(int sig)
{
	stop = 1;
}

static void on_usr1(int sig)
{
	/* Only here so that delivery happens */
}

static void run_for(int secs)
{
	stop = 0;
	alarm(secs);
}

static void pin_to(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu % ncpus, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

static bool cpuinfo_has(const char *flag)
{
	char line[4096];
	bool found = false;
	FILE *f = fopen("/proc/cpuinfo", "r");

	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "flags", 5))
			continue;
		char *p = line;
		size_t n = strlen(flag);

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

/* ---- Phase: fork churn ------------------------------------------------- */

static void fork_worker(int id)
{
	unsigned long n = 0;

	pin_to(id);
	while (!stop) {
		pid_t pid = fork();

		if (pid == 0) {
			/* A bit of kernel work, then a context switch or two */
			sched_yield();
			getppid();
			_exit(0);
		}
		if (pid < 0) {
			if (errno == EAGAIN) {
				usleep(1000);
				continue;
			}
			_exit(2);
		}
		if (waitpid(pid, NULL, 0) < 0)
			_exit(3);
		n++;
	}
	_exit(0);
}

/* ---- Phase: thread churn ----------------------------------------------- */

static void *thread_fn(void *arg)
{
	sched_yield();
	return NULL;
}

static void thread_worker(int id)
{
	pin_to(id);
	while (!stop) {
		pthread_t t[8];
		int i;

		for (i = 0; i < 8; i++)
			if (pthread_create(&t[i], NULL, thread_fn, NULL))
				_exit(4);
		for (i = 0; i < 8; i++)
			pthread_join(t[i], NULL);
	}
	_exit(0);
}

/* ---- Phase: pipe ping-pong (context switch rate) ------------------------ */

static void pingpong_worker(int id)
{
	int a[2], b[2];
	char c = 0;
	pid_t pid;

	if (pipe(a) || pipe(b))
		_exit(5);
	pid = fork();
	if (pid < 0)
		_exit(6);
	if (pid == 0) {
		/* Partner on the same CPU forces a switch per message */
		close(a[1]);
		close(b[0]);
		pin_to(id);
		while (read(a[0], &c, 1) == 1)
			if (write(b[1], &c, 1) != 1)
				break;
		_exit(0);
	}
	close(a[0]);
	close(b[1]);
	pin_to(id);
	while (!stop) {
		if (write(a[1], &c, 1) != 1 || read(b[0], &c, 1) != 1)
			_exit(7);
	}
	close(a[1]);	/* EOF for the partner */
	waitpid(pid, NULL, 0);
	_exit(0);
}

/* ---- Phase: yield storm with migration ---------------------------------- */

static void yield_worker(int id)
{
	unsigned long n = 0;

	while (!stop) {
		if ((n++ & 1023) == 0)
			pin_to(n >> 10);	/* wander across CPUs */
		sched_yield();
	}
	_exit(0);
}

/* ---- Phase: signals ------------------------------------------------------ */

static void signal_worker(int id)
{
	pid_t pid;

	pin_to(id);
	signal(SIGUSR1, on_usr1);
	pid = fork();
	if (pid < 0)
		_exit(8);
	if (pid == 0) {
		pin_to(id + 1);
		while (!stop)
			sched_yield();
		_exit(0);
	}
	while (!stop) {
		kill(pid, SIGUSR1);
		raise(SIGUSR1);
		sched_yield();
	}
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
	_exit(0);
}

/* ---- Phase: user shadow stack tasks -------------------------------------- */

static long arch_prctl_raw(unsigned long op, unsigned long arg)
{
	long ret;

	/* Must be raw: no function returns between enabling and here */
	asm volatile("syscall" : "=a" (ret)
		     : "0" (SYS_arch_prctl), "D" (op), "S" (arg)
		     : "rcx", "r11", "memory");
	return ret;
}

static void *ushstk_thread_fn(void *arg)
{
	sched_yield();
	raise(SIGUSR1);
	return NULL;
}

static void ushstk_worker(int id)
{
	pin_to(id);
	signal(SIGUSR1, on_usr1);

	/* Enable at the outermost frame; this function never returns */
	if (arch_prctl_raw(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK))
		_exit(0);	/* no user shadow stack support, phase is a no-op */

	while (!stop) {
		pthread_t t[4];
		pid_t pid;
		int i;

		for (i = 0; i < 4; i++)
			if (pthread_create(&t[i], NULL, ushstk_thread_fn, NULL))
				_exit(9);
		for (i = 0; i < 4; i++)
			pthread_join(t[i], NULL);

		pid = fork();
		if (pid == 0) {
			sched_yield();
			raise(SIGUSR1);
			_exit(0);
		}
		if (pid > 0)
			waitpid(pid, NULL, 0);
	}
	_exit(0);
}

/* ---- Driver -------------------------------------------------------------- */

struct phase {
	const char *name;
	void (*fn)(int id);
	int nworkers;
};

static int run_phase(const struct phase *ph)
{
	int nworkers = ph->nworkers, i, failed = 0;
	pid_t *pids;

	pids = calloc(nworkers, sizeof(*pids));
	if (!pids)
		return -1;

	for (i = 0; i < nworkers; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			signal(SIGALRM, on_alarm);
			run_for(duration);
			ph->fn(i);
			_exit(0);
		}
		if (pids[i] < 0) {
			ksft_print_msg("fork: %s\n", strerror(errno));
			nworkers = i;
			break;
		}
	}

	for (i = 0; i < nworkers; i++) {
		int status;

		if (waitpid(pids[i], &status, 0) < 0 ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			ksft_print_msg("%s worker %d: status 0x%x\n",
				       ph->name, i, status);
			failed++;
		}
	}
	free(pids);
	return failed;
}

int main(int argc, char **argv)
{
	int opt, i, failed;
	bool active;

	while ((opt = getopt(argc, argv, "t:")) != -1) {
		if (opt == 't')
			duration = atoi(optarg);
	}

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus < 1)
		ncpus = 1;

	active = cpuinfo_has("kernel_shstk");

	const struct phase phases[] = {
		{ "fork",	fork_worker,	ncpus },
		{ "thread",	thread_worker,	ncpus },
		{ "pingpong",	pingpong_worker, ncpus },
		{ "yield",	yield_worker,	ncpus * 2 },
		{ "signal",	signal_worker,	ncpus },
		{ "ushstk",	ushstk_worker,	ncpus },
	};

	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(phases));
	ksft_print_msg("kernel_shstk %s, %d CPUs, %ds per phase\n",
		       active ? "active" : "NOT active (running anyway)",
		       ncpus, duration);

	/* The children must not be reaped by a stray SIGCHLD handler */
	signal(SIGCHLD, SIG_DFL);

	for (i = 0; i < ARRAY_SIZE(phases); i++) {
		failed = run_phase(&phases[i]);
		if (failed)
			ksft_test_result_fail("%s: %d worker(s) failed\n",
					      phases[i].name, failed);
		else
			ksft_test_result_pass("%s\n", phases[i].name);
	}

	ksft_finished();
}
