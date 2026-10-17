#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: function error injection.
#
# Error injection (fail_function, BPF bpf_override_return()) makes a probed
# function "return" an error without running: the kprobe pre-handler calls
# override_function_with_return(), which points regs->ip at
# just_return_func (arch/x86/lib/error-inject.c), a bare RET.  When that RET
# executes, the regular stack top is the return address into the caller of
# the skipped function.  The shadow stack must agree, and there are two
# different ways to get there:
#
#  - kprobe on the ftrace location (CONFIG_KPROBES_ON_FTRACE, the usual
#    case for function entry): ftrace_regs_caller sees the changed
#    regs->ip, FTRACE_SHSTK_SYNC must rewrite the shadow stack slot for the
#    fentry return and the RET lands in just_return_func with both stacks
#    holding the caller's return address.
#
#  - INT3 kprobe (functions without an fentry site, or kprobes on ftrace
#    disabled): the #BP returns through ERETS to the new regs->ip, which
#    fred_shstk_sync_frame() must mirror into the shadow stack event frame.
#
# A mismatch is a fatal #CP.  The test injects -EINVAL into a syscall entry
# point from the error_injection list, triggers it from user space and
# checks that the syscall returns the injected error and dmesg stays clean.
#
# Interfaces, in order of preference:
#  1. /sys/kernel/debug/fail_function (CONFIG_FAIL_FUNCTION=y, which needs
#     CONFIG_FAULT_INJECTION=y and CONFIG_FAULT_INJECTION_DEBUG_FS=y)
#  2. a BPF kprobe program calling bpf_override_return() through the
#     kshstk_bpf_override helper (CONFIG_BPF_KPROBE_OVERRIDE=y)
# Skips when neither is available.

DIR=$(dirname "$0")
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_root
kshstk_require_active

DEBUGFS=/sys/kernel/debug
[ -d $DEBUGFS/tracing ] || [ -d $DEBUGFS/kprobes ] || mount -t debugfs nodev $DEBUGFS 2>/dev/null

FEI=$DEBUGFS/fail_function
LIST=$DEBUGFS/error_injection/list
if [ ! -r "$LIST" ]; then
	ktap_skip_all "no $LIST (CONFIG_FUNCTION_ERROR_INJECTION)"
	exit $KSFT_SKIP
fi

# Injection targets, each with a user space trigger whose failure is
# observable from the shell, and the expected error text for -EINVAL.
# mkdir(2) and uname(2) are what coreutils mkdir and uname call.
TARGETS="__x64_sys_mkdir __x64_sys_uname __x64_sys_getppid"
pick_target() {
	local t
	for t in $TARGETS; do
		grep -q "^$t " "$LIST" && echo "$t" && return 0
	done
	return 1
}
TARGET=$(pick_target) || {
	ktap_skip_all "no suitable syscall in $LIST"
	exit $KSFT_SKIP
}

TMPD=$(mktemp -d)
trigger() { # expects the injected -EINVAL
	case $TARGET in
	__x64_sys_mkdir)
		mkdir "$TMPD/d" 2>&1 | grep -q 'Invalid argument' && [ ! -d "$TMPD/d" ] ;;
	__x64_sys_uname)
		uname -r 2>&1 | grep -q 'Invalid argument' ;;
	__x64_sys_getppid)
		# No error path visible from the shell; bash calls getppid at
		# startup and ignores the result, so only (b) is checked.
		bash -c : ;;
	esac
}
trigger_ok() { # must work again after the injection is removed
	case $TARGET in
	__x64_sys_mkdir) mkdir "$TMPD/d2" && rmdir "$TMPD/d2" ;;
	__x64_sys_uname) uname -r > /dev/null ;;
	*) true ;;
	esac
}

DMESG=$(mktemp)
kshstk_dmesg_snapshot "$DMESG"
new_bad() {
	dmesg 2>/dev/null | comm --nocheck-order -13 "$DMESG" - | \
		grep -Eic 'kernel shadow stack|control protection|#CP|BUG:|Oops|WARNING' || true
}
ITER=${ITER:-200}

if [ -d "$FEI" ] && [ -w "$FEI/inject" ]; then
	ktap_print_header
	ktap_set_plan 3
	ktap_print_msg "fail_function on $TARGET, $ITER iterations"

	cleanup() {
		echo > "$FEI/inject" 2>/dev/null
		rm -rf "$TMPD" "$DMESG"
	}
	trap cleanup EXIT

	echo "$TARGET" > "$FEI/inject" || ktap_exit_fail_msg "cannot inject $TARGET"
	echo 100 > "$FEI/probability"
	echo -1 > "$FEI/times"
	echo 0 > "$FEI/interval"
	echo 0 > "$FEI/verbose"
	printf '%#x' -22 > "$FEI/$TARGET/retval"	# -EINVAL, as an unsigned hex value

	fails=0
	i=0
	while [ $i -lt $ITER ]; do
		trigger || fails=$((fails + 1))
		i=$((i + 1))
	done
	if [ $fails = 0 ]; then
		ktap_test_pass "$TARGET returns the injected -EINVAL ($ITER calls)"
	else
		ktap_test_fail "$TARGET: $fails of $ITER calls did not return the injected error"
	fi

	# Concurrent callers: several CPUs hitting the override at once
	for c in 1 2 3 4 5 6 7 8; do
		(i=0; while [ $i -lt 50 ]; do trigger_ok; trigger; i=$((i + 1)); done) &
	done
	wait
	echo "!$TARGET" > "$FEI/inject"
	if trigger_ok; then
		ktap_test_pass "$TARGET works again after removing the injection"
	else
		ktap_test_fail "$TARGET still fails after removing the injection"
	fi
elif [ -x "$DIR/kshstk_bpf_override" ]; then
	trap 'rm -rf "$TMPD" "$DMESG"' EXIT
	# The helper loads the program, attaches it to a kprobe on the target,
	# calls the syscall ITER times and checks the injected error itself.
	# Exit code 4 means the kernel refused bpf_override_return().
	"$DIR/kshstk_bpf_override" "$TARGET" "$ITER"
	rc=$?
	if [ $rc = 4 ]; then
		ktap_skip_all "neither CONFIG_FAIL_FUNCTION nor CONFIG_BPF_KPROBE_OVERRIDE is available: enable CONFIG_FAULT_INJECTION=y CONFIG_FAULT_INJECTION_DEBUG_FS=y CONFIG_FAIL_FUNCTION=y (or CONFIG_BPF_KPROBE_OVERRIDE=y) to test override_function_with_return()"
		exit $KSFT_SKIP
	fi
	ktap_print_header
	ktap_set_plan 2
	ktap_print_msg "no $FEI (CONFIG_FAIL_FUNCTION); BPF bpf_override_return() on $TARGET"
	case $rc in
	0) ktap_test_pass "BPF bpf_override_return() on $TARGET returns the injected error ($ITER calls)" ;;
	*) ktap_test_fail "BPF bpf_override_return() on $TARGET: helper exit code $rc" ;;
	esac
else
	ktap_skip_all "no $FEI: enable CONFIG_FAULT_INJECTION=y CONFIG_FAULT_INJECTION_DEBUG_FS=y CONFIG_FAIL_FUNCTION=y (or CONFIG_BPF_KPROBE_OVERRIDE=y and build kshstk_bpf_override)"
	rm -rf "$TMPD" "$DMESG"
	exit $KSFT_SKIP
fi

n=$(new_bad)
if [ "$n" = 0 ]; then
	ktap_test_pass "no shadow stack violation / BUG / WARNING in dmesg after error injection"
else
	dmesg | comm --nocheck-order -13 "$DMESG" - | grep -Ei 'shadow stack|#CP|BUG:|Oops|WARNING' | head -5 | sed 's/^/# /'
	ktap_test_fail "$n kernel messages after error injection"
fi

ktap_finished
