#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: ftrace, function_graph, kprobes, kretprobes, fprobes.
#
# All of these redirect returns or rewrite instructions and need matching
# shadow stack updates:
#   - function tracer:      ftrace_caller RET rebalancing (SHSTK_WRITE_RET_TOP)
#   - function_graph:       return_to_handler replaces the parent return
#   - kprobe (INT3):        INT3 CALL/RET emulation, single-step of every
#                           instruction type (optimization off), optprobes
#                           (optimization on)
#   - kretprobe/fprobe:     rethook trampoline swaps the return address
#                           (FTRACE_SHSTK_SYNC / fred_shstk_replace_ret)
# Each step enables the mechanism, generates matching load, and disables
# it again.  Failure is a #CP (panic) or an Oops.

DIR=$(cd "$(dirname "$0")" && pwd)
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_root
kshstk_require_active

TRACEFS=$(kshstk_tracefs)
if [ -z "$TRACEFS" ] || [ ! -f "$TRACEFS/current_tracer" ]; then
	ktap_skip_all "tracefs not available"
	exit $KSFT_SKIP
fi
cd "$TRACEFS" || exit $KSFT_SKIP

# Pick a function that forks hit: kernel_clone on current kernels
if grep -qw kernel_clone /proc/kallsyms; then
	FORK_FN=kernel_clone
else
	FORK_FN=_do_fork
fi

load() {
	# forks, syscalls, context switches, a bit of file I/O
	for i in $(seq 30); do
		(cat /proc/self/maps > /dev/null; ls /proc > /dev/null) &
	done
	wait
}

reset_tracing() {
	echo nop > current_tracer 2>/dev/null
	echo 0 > tracing_on 2>/dev/null
	echo > set_ftrace_filter 2>/dev/null
	echo > set_graph_function 2>/dev/null
	echo 0 > events/kprobes/enable 2>/dev/null
	echo 0 > events/fprobes/enable 2>/dev/null
	echo > kprobe_events 2>/dev/null
	echo > dynamic_events 2>/dev/null
	echo 1 > tracing_on 2>/dev/null
}
reset_tracing
trap reset_tracing EXIT

DMESG=$(mktemp)
kshstk_dmesg_snapshot "$DMESG"

check() { # description
	local n=$(kshstk_dmesg_new_faults "$DMESG")
	if [ "$n" = "0" ]; then
		ktap_test_pass "$1"
	else
		ktap_test_fail "$1 ($n shadow stack messages in dmesg)"
	fi
	kshstk_dmesg_snapshot "$DMESG"
}

tests=0
has() { [ -f "$1" ] && [ -w "$1" ]; }
has current_tracer && tests=$((tests + 2))
has kprobe_events && tests=$((tests + 4))
has dynamic_events && grep -q fprobe README 2>/dev/null && tests=$((tests + 1))
tests=$((tests + 1))	# ftracetest
ktap_print_header
ktap_set_plan $tests

# 1. Function tracer on everything
if has current_tracer; then
	echo function > current_tracer
	load
	echo nop > current_tracer
	check "function tracer, all functions"

# 2. function_graph: the return hook
	if grep -q function_graph available_tracers; then
		echo function_graph > current_tracer
		load
		# Deep, hot paths too
		echo '*' > set_graph_function
		load
		echo nop > current_tracer
		echo > set_graph_function
		check "function_graph tracer (return_to_handler)"
	else
		ktap_test_skip "function_graph not available"
	fi
fi

if has kprobe_events; then
	OPT=/proc/sys/debug/kprobes-optimization
	DEFAULT=$(cat $OPT 2>/dev/null || echo 1)

# 3. INT3 kprobe at function entry (unoptimized) and kretprobe through rethook
	echo 0 > $OPT 2>/dev/null
	echo "p:kp_entry $FORK_FN" > kprobe_events
	echo "r:kp_ret $FORK_FN \$retval" >> kprobe_events
	echo "p:kp_read vfs_read" >> kprobe_events
	echo "r:kp_read_ret vfs_read" >> kprobe_events
	echo 1 > events/kprobes/enable
	load
	echo 0 > events/kprobes/enable
	hits=$(grep -c "kp_" trace || true)
	echo > kprobe_events
	if [ "$hits" -gt 0 ]; then
		check "INT3 kprobe + kretprobe (rethook), $hits hits"
	else
		ktap_test_fail "INT3 kprobe + kretprobe: no hits"
	fi

# 4. Single-step / emulation of every instruction in a function: a probe at
#    each instruction boundary of the fork function.  CALLs and RETs inside
#    it exercise INT3 CALL/RET emulation (fred_shstk_emulate_call/ret).
	n=0
	for off in $(seq 0 4 255) $(seq 1 4 255) $(seq 2 4 255) $(seq 3 4 255); do
		echo "p:kp_off $FORK_FN+$off" > kprobe_events 2>/dev/null || continue
		echo 1 > events/kprobes/enable 2>/dev/null || { echo > kprobe_events; continue; }
		(true)
		(true)
		echo 0 > events/kprobes/enable
		echo > kprobe_events
		n=$((n + 1))
	done
	check "INT3 kprobe at $n instruction boundaries of $FORK_FN"

# 5. The same with optimization on (jump optimized probes)
	echo 1 > $OPT 2>/dev/null
	echo "p:kp_opt $FORK_FN" > kprobe_events
	echo "p:kp_opt2 vfs_read" >> kprobe_events
	echo 1 > events/kprobes/enable
	sleep 0.5	# the optimizer runs delayed
	load
	grep -q OPTIMIZED /sys/kernel/debug/kprobes/list 2>/dev/null && optd=" (optimized)" || optd=""
	echo 0 > events/kprobes/enable
	echo > kprobe_events
	check "kprobe with optimization on$optd"

# 6. Many kretprobes on hot functions at once
	echo 0 > $OPT 2>/dev/null
	: > kprobe_events
	for fn in vfs_read vfs_write do_sys_openat2 schedule __x64_sys_getppid kmalloc_noprof __kmalloc_cache_noprof kfree; do
		grep -qw "$fn" available_filter_functions && \
			echo "r:ret_$fn $fn" >> kprobe_events 2>/dev/null
	done
	echo 1 > events/kprobes/enable
	load
	echo 0 > events/kprobes/enable
	echo > kprobe_events
	echo "$DEFAULT" > $OPT 2>/dev/null
	check "kretprobes on hot functions"
fi

# 7. fprobe exit hooks (rethook via ftrace)
if has dynamic_events && grep -q fprobe README 2>/dev/null; then
	echo "f:fp_read vfs_read%return \$retval" > dynamic_events 2>/dev/null
	echo "f:fp_fork $FORK_FN%return \$retval" >> dynamic_events 2>/dev/null
	echo 1 > events/fprobes/enable 2>/dev/null
	load
	echo 0 > events/fprobes/enable 2>/dev/null
	echo > dynamic_events
	check "fprobe return probes"
fi

# 8. The ftrace selftest suite's kprobe, ftrace and dynevent groups.  Takes
#    several minutes, so only with KSHSTK_FTRACETEST=1 in the environment.
FTRACETEST="$DIR/../../ftrace/ftracetest"
if [ "${KSHSTK_FTRACETEST:-0}" = "1" ] && [ -x "$FTRACETEST" ]; then
	FTLOG=${KSHSTK_FTRACETEST_LOG:-/tmp/kshstk-ftracetest}
	mkdir -p "$FTLOG"
	out=$(cd "$DIR/../../ftrace" && ./ftracetest -l "$FTLOG" test.d/kprobe test.d/ftrace test.d/dynevent 2>&1)
	# Failures and unresolved tests by name, then the summary
	echo "$out" | grep -E "\[(FAIL|UNRESOLVED)\]" | sed 's/^/# /'
	echo "$out" | tail -7 | sed 's/^/# /'
	if echo "$out" | grep -q "# of failed: *0$"; then
		check "ftracetest kprobe/ftrace/dynevent"
	else
		ktap_test_fail "ftracetest kprobe/ftrace/dynevent"
	fi
else
	ktap_test_skip "ftracetest (set KSHSTK_FTRACETEST=1 to run it)"
fi

rm -f "$DMESG"
ktap_finished
