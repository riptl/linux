// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for kshstk_error_inject.sh: function error injection through a
 * BPF kprobe program that calls bpf_override_return() (needs
 * CONFIG_BPF_KPROBE_OVERRIDE), for kernels without CONFIG_FAIL_FUNCTION.
 *
 * Usage: kshstk_bpf_override <__x64_sys_mkdir|__x64_sys_uname|__x64_sys_getppid> [iterations]
 *
 * Loads a four instruction program (r2 = -EINVAL; call override_return;
 * r0 = 0; exit), attaches it to a perf kprobe event on the function, calls
 * the matching syscall and checks that it fails with EINVAL.  Written
 * against the raw bpf(2) and perf_event_open(2) interfaces so that it does
 * not need libbpf in the guest.
 *
 * Exit codes: 0 ok, 1 wrong result, 2 setup error, 4 the kernel refused
 * the override (no CONFIG_BPF_KPROBE_OVERRIDE).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#define BPF_ALU64_IMM(OP, DST, IMM)					\
	((struct bpf_insn) { .code = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
			     .dst_reg = DST, .imm = IMM })
#define BPF_MOV64_IMM(DST, IMM)						\
	((struct bpf_insn) { .code = BPF_ALU64 | BPF_MOV | BPF_K,	\
			     .dst_reg = DST, .imm = IMM })
#define BPF_EMIT_CALL(FUNC)						\
	((struct bpf_insn) { .code = BPF_JMP | BPF_CALL, .imm = FUNC })
#define BPF_EXIT_INSN()							\
	((struct bpf_insn) { .code = BPF_JMP | BPF_EXIT })

static int bpf_load(void)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_IMM(BPF_REG_2, -EINVAL),
		BPF_EMIT_CALL(BPF_FUNC_override_return),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	static char log[8192];
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_KPROBE;
	attr.insns = (uintptr_t)prog;
	attr.insn_cnt = sizeof(prog) / sizeof(prog[0]);
	attr.license = (uintptr_t)"GPL";
	attr.log_buf = (uintptr_t)log;
	attr.log_size = sizeof(log);
	attr.log_level = 1;
	attr.kern_version = 0;

	int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

	if (fd < 0 && strstr(log, "unknown func"))
		return -4;
	if (fd < 0)
		fprintf(stderr, "# BPF_PROG_LOAD: %s\n%s", strerror(errno), log);
	return fd;
}

static int kprobe_pmu_type(void)
{
	FILE *f = fopen("/sys/bus/event_source/devices/kprobe/type", "r");
	int type = -1;

	if (!f)
		return -1;
	if (fscanf(f, "%d", &type) != 1)
		type = -1;
	fclose(f);
	return type;
}

int main(int argc, char **argv)
{
	const char *target = argc > 1 ? argv[1] : "__x64_sys_mkdir";
	int iterations = argc > 2 ? atoi(argv[2]) : 200;
	struct perf_event_attr pe;
	int prog, type, ev, i, fails = 0, ret;
	char dir[] = "/tmp/kshstk_bpf_override.XXXXXX";
	struct utsname un;

	type = kprobe_pmu_type();
	if (type < 0) {
		fprintf(stderr, "# no kprobe PMU (CONFIG_KPROBE_EVENTS)\n");
		return 2;
	}
	prog = bpf_load();
	if (prog == -4)
		return 4;
	if (prog < 0)
		return 2;

	memset(&pe, 0, sizeof(pe));
	pe.type = type;
	pe.size = sizeof(pe);
	pe.kprobe_func = (uintptr_t)target;
	pe.probe_offset = 0;
	pe.sample_period = 1;
	ev = syscall(__NR_perf_event_open, &pe, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (ev < 0) {
		fprintf(stderr, "# perf_event_open(kprobe %s): %s\n", target, strerror(errno));
		return 2;
	}
	if (ioctl(ev, PERF_EVENT_IOC_SET_BPF, prog)) {
		/* -EINVAL here: the function is not in the error injection list */
		fprintf(stderr, "# PERF_EVENT_IOC_SET_BPF: %s\n", strerror(errno));
		return errno == EINVAL ? 4 : 2;
	}
	if (ioctl(ev, PERF_EVENT_IOC_ENABLE, 0)) {
		fprintf(stderr, "# PERF_EVENT_IOC_ENABLE: %s\n", strerror(errno));
		return 2;
	}

	if (!mkdtemp(dir))
		return 2;
	strcat(dir, "/d");

	for (i = 0; i < iterations; i++) {
		errno = 0;
		if (!strcmp(target, "__x64_sys_mkdir"))
			ret = syscall(__NR_mkdir, dir, 0700);
		else if (!strcmp(target, "__x64_sys_uname"))
			ret = syscall(__NR_uname, &un);
		else
			ret = syscall(__NR_getppid) > 0 ? -1 : 0;
		if (!strcmp(target, "__x64_sys_getppid")) {
			/* Cannot see the override from here; it must not succeed either */
			if (ret != -1 && errno != EINVAL)
				fails++;
			continue;
		}
		if (ret != -1 || errno != EINVAL)
			fails++;
	}

	ioctl(ev, PERF_EVENT_IOC_DISABLE, 0);
	close(ev);
	close(prog);
	rmdir(dir);
	dir[strlen(dir) - 2] = '\0';
	rmdir(dir);

	if (fails) {
		fprintf(stderr, "# %d of %d calls did not return the injected EINVAL\n",
			fails, iterations);
		return 1;
	}
	return 0;
}
