#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: the LKDTM based tests that do not take the machine
# down, plus WARN/exception continuation.
#
#  SHSTK_REPORT         mapping and SSP sanity
#  SHSTK_WRITE_NOFAULT  ordinary store rejected through the exception table
#  SHSTK_WRSS_SELF      WRSS to the own shadow stack works
#  WARNING              WARN_ON continuation rewrites regs->ip (ud2 + fixup)
#  WARNING_MESSAGE      same, with a message
#  CFI_FORWARD_PROTO    an ordinary indirect call path under shadow stacks
#  SHSTK_DEPTH_SAFE     shadow stack depth report, 500 frame recursion
#
# The Oops tests (SHSTK_WRITE_SHSTK, SHSTK_WRSS_TEXT, SHSTK_WRSS_DATA,
# SHSTK_RSTORSSP_NOT_SHSTK, EXCEPTION) are only run when panic_on_oops is
# off, and kill the writing process.  SHSTK_RET_MISMATCH,
# SHSTK_RSTORSSP_BAD_TOKEN and SHSTK_DEPTH_OVERFLOW (shadow stack overflow
# into the guard page, a #PF/#DF with the stack full) always take the
# machine down and are never run here; use
#   echo SHSTK_RET_MISMATCH > /sys/kernel/debug/provoke-crash/DIRECT
# by hand with a crash kernel loaded.

DIR=$(cd "$(dirname "$0")" && pwd)
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_root
kshstk_require_active

TRIGGER=/sys/kernel/debug/provoke-crash/DIRECT
if [ ! -w $TRIGGER ]; then
	# LKDTM_KO=/path/to/lkdtm.ko: an out-of-tree build for a kernel without CONFIG_LKDTM
	if [ -n "$LKDTM_KO" ] && [ -f "$LKDTM_KO" ]; then
		insmod "$LKDTM_KO" 2>/dev/null || true
	else
		modprobe -q lkdtm 2>/dev/null || true
	fi
fi
if [ ! -w $TRIGGER ]; then
	ktap_skip_all "LKDTM not available (CONFIG_LKDTM)"
	exit $KSFT_SKIP
fi
if ! grep -q '^SHSTK_REPORT$' $TRIGGER; then
	ktap_skip_all "LKDTM has no SHSTK tests"
	exit $KSFT_SKIP
fi

run() { # test expected-regex
	local test=$1 expect=$2 DMESG LOG
	DMESG=$(mktemp); LOG=$(mktemp)
	[ -w /sys/kernel/debug/clear_warn_once ] && echo 1 > /sys/kernel/debug/clear_warn_once
	dmesg > "$DMESG"
	echo "$test" | cat > $TRIGGER 2>/dev/null || true
	dmesg | comm --nocheck-order -13 "$DMESG" - > "$LOG" || true
	if grep -Eqi "$expect" "$LOG"; then
		ktap_test_pass "$test"
	elif grep -q XFAIL: "$LOG"; then
		ktap_test_skip "$test: $(grep XFAIL: "$LOG" | head -1 | sed 's/.*XFAIL: //')"
	else
		sed 's/^/# /' "$LOG"
		ktap_test_fail "$test: missing '$expect'"
	fi
	rm -f "$DMESG" "$LOG"
}

SAFE="SHSTK_REPORT|ok: shadow stack mapping
SHSTK_WRITE_NOFAULT|ok: ordinary store to the shadow stack was rejected
SHSTK_WRSS_SELF|ok: WRSS to the shadow stack succeeded
WARNING|WARNING:
WARNING_MESSAGE|message trigger
CFI_FORWARD_PROTO|Calling mismatched prototype
SHSTK_DEPTH_SAFE|ok: shadow stack depth"
OOPS="SHSTK_WRITE_SHSTK|call trace:|shadow stack
SHSTK_WRSS_TEXT|kernel shadow stack access
SHSTK_WRSS_DATA|kernel shadow stack access
SHSTK_RSTORSSP_NOT_SHSTK|kernel shadow stack access
EXCEPTION|call trace:"

poo=$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null || echo 1)
n=$(echo "$SAFE" | wc -l)
[ "$poo" = "0" ] && n=$((n + $(echo "$OOPS" | wc -l)))

ktap_print_header
ktap_set_plan $n

# No pipe into the loop: the ktap counters must survive it
while IFS='|' read -r t e; do run "$t" "$e"; done <<EOT
$SAFE
EOT
if [ "$poo" = "0" ]; then
	while IFS='|' read -r t e; do run "$t" "$e"; done <<EOT
$OOPS
EOT
else
	ktap_print_msg "panic_on_oops=1: skipping the Oops tests (SHSTK_WRITE_SHSTK, SHSTK_WRSS_*, SHSTK_RSTORSSP_NOT_SHSTK)"
fi

ktap_finished
