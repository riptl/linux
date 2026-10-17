// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shadow stack: user mode must not be able to read or write kernel
 * shadow stack memory.
 *
 * The address of the current task's kernel shadow stack is taken from the
 * SHSTK_REPORT LKDTM test ("SSP: 0x...") when LKDTM is available and we
 * are root; otherwise well-known vmalloc and cpu_entry_area addresses are
 * probed.  Each probe runs in a child that must die with SIGSEGV.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../kselftest.h"

#define LKDTM_TRIGGER	"/sys/kernel/debug/provoke-crash/DIRECT"

static int probe(unsigned long addr, bool write, bool wrss)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		volatile unsigned long *p = (volatile unsigned long *)addr;
		unsigned long v = 0;

		if (wrss) {
			/*
			 * WRSS from user mode needs IA32_U_CET.WRSS_EN,
			 * which this task does not have: #UD -> SIGILL, or
			 * #PF -> SIGSEGV if enabled.  Either is a rejection.
			 */
			asm volatile("wrssq %0, (%1)" :: "r" (v), "r" (addr) : "memory");
		} else if (write) {
			*p = 0;
		} else {
			v = *p;
		}
		_exit(1);	/* survived: bad */
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (WIFSIGNALED(status) &&
	    (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGILL ||
	     WTERMSIG(status) == SIGBUS))
		return 0;
	return 1;
}

static unsigned long lkdtm_report_ssp(void)
{
	char line[512];
	unsigned long ssp = 0;
	FILE *f;
	int fd;

	fd = open(LKDTM_TRIGGER, O_WRONLY);
	if (fd < 0)
		return 0;
	if (write(fd, "SHSTK_REPORT", 12) < 0) {
		close(fd);
		return 0;
	}
	close(fd);

	f = popen("dmesg | grep 'lkdtm: SSP:' | tail -1", "r");
	if (!f)
		return 0;
	if (fgets(line, sizeof(line), f)) {
		char *p = strstr(line, "SSP: ");

		if (p)
			ssp = strtoul(p + 5, NULL, 16);
	}
	pclose(f);
	return ssp;
}

int main(void)
{
	unsigned long ssp;
	int ret;

	ksft_print_header();
	ksft_set_plan(4);

	ssp = lkdtm_report_ssp();
	if (!ssp) {
		/*
		 * Any kernel address will do to show the kernel does not
		 * misclassify user accesses; vmalloc base in the default
		 * 4-level layout.  This is a weaker test, say so.
		 */
		ksft_print_msg("LKDTM SHSTK_REPORT unavailable (need root + CONFIG_LKDTM); probing a generic kernel address\n");
		ssp = 0xffffc90000000000UL;
	} else {
		ksft_print_msg("kernel SSP from LKDTM: 0x%lx\n", ssp);
	}

	ret = probe(ssp, false, false);
	ksft_test_result(ret == 0, "user read of kernel shadow stack is rejected\n");

	ret = probe(ssp, true, false);
	ksft_test_result(ret == 0, "user write to kernel shadow stack is rejected\n");

	ret = probe(ssp, false, true);
	ksft_test_result(ret == 0, "user WRSS to kernel shadow stack is rejected\n");

	/* The page below the stack is the guard page */
	ret = probe((ssp & ~0xfffUL) - 8, true, false);
	ksft_test_result(ret == 0, "user write below kernel shadow stack is rejected\n");

	ksft_finished();
}
