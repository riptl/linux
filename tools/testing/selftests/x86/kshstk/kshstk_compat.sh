#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: 32-bit compat processes under 64-bit load.
#
# kshstk_compat32 is a freestanding 32-bit program that drives int $0x80,
# the compat vDSO entry, compat signal frames (rt and non-rt sigreturn,
# sigaltstack), #BP and #PF from compat mode, fork and clone.  All of
# them return to user mode through ERETU to a 32-bit code segment, which
# verifies SSP against IA32_PL0_SSP.  Run many instances at once, together
# with the 64-bit stress test so that compat and 64-bit tasks keep
# switching on every CPU, and check dmesg.

DIR=$(dirname "$0")
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_active

PROG="$DIR/kshstk_compat32"
if [ ! -x "$PROG" ]; then
	ktap_skip_all "kshstk_compat32 not built (needs gcc -m32)"
	exit $KSFT_SKIP
fi
if ! "$PROG" > /dev/null 2>&1; then
	rc=$?
	if [ $rc = 126 ] || [ $rc = 127 ] || [ $rc = 134 ] || [ $rc = 132 ]; then
		ktap_skip_all "32-bit binaries cannot run here (CONFIG_IA32_EMULATION / ia32_emulation=0)"
		exit $KSFT_SKIP
	fi
	ktap_print_header
	ktap_set_plan 1
	ktap_test_fail "kshstk_compat32 single run failed with exit code $rc"
	ktap_finished
fi

N=${N:-200}
SECS=${SECS:-5}
DMESG=$(mktemp)
kshstk_dmesg_snapshot "$DMESG"
trap 'rm -f "$DMESG"' EXIT

ktap_print_header
ktap_set_plan 3

# 1. The 64-bit stress in the background, the 32-bit storm in the foreground
if [ -x "$DIR/kshstk_stress" ]; then
	"$DIR/kshstk_stress" -t $SECS > /dev/null 2>&1 &
	STRESS=$!
else
	STRESS=""
fi

end=$(( $(date +%s) + SECS ))
rounds=0
failed=0
while [ "$(date +%s)" -lt $end ]; do
	i=0
	while [ $i -lt $N ]; do
		"$PROG" > /dev/null 2>&1 || failed=$((failed + 1)) &
		i=$((i + 1))
	done
	wait $(jobs -p | grep -v "^$STRESS$") 2>/dev/null
	rounds=$((rounds + 1))
done
# The failure counter lives in the subshells; count non-zero exits this way instead
failed=0
i=0
while [ $i -lt 20 ]; do
	"$PROG" > /dev/null 2>&1 || failed=$((failed + 1))
	i=$((i + 1))
done
if [ $failed = 0 ]; then
	ktap_test_pass "$rounds rounds of $N concurrent compat processes, 20 sequential checks"
else
	ktap_test_fail "compat program failed $failed of 20 sequential runs"
fi

if [ -n "$STRESS" ]; then
	if wait $STRESS; then
		ktap_test_pass "64-bit stress alongside the compat storm"
	else
		ktap_test_fail "64-bit stress failed alongside the compat storm"
	fi
else
	ktap_test_skip "kshstk_stress not built"
fi

n=$(kshstk_dmesg_new_faults "$DMESG")
if [ "$n" = 0 ] || [ "$n" = "" ]; then
	if [ "$(id -u)" = 0 ]; then
		ktap_test_pass "no shadow stack messages in dmesg"
	else
		ktap_test_skip "dmesg not readable (not root)"
	fi
else
	ktap_test_fail "$n shadow stack messages in dmesg"
fi

ktap_finished
