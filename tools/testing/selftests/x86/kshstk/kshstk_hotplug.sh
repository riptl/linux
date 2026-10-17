#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: CPU hotplug cycles.
#
# Every CPU enables its shadow stack from start_secondary() and must come
# back cleanly after being offlined, including when IA32_S_CET.SH_STK_EN
# survived the offline (some platforms do not reset it on wakeup; see
# setup_cet()).  Offline/online each secondary CPU several times, with
# load on it right after it comes back, then do a batch of CPUs at once.
# A regression is a #CP during bringup, which panics the box.

DIR=$(cd "$(dirname "$0")" && pwd)
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_root
kshstk_require_active

CYCLES=${CYCLES:-3}
SYSFS=/sys/devices/system/cpu

cpus=$(ls -d $SYSFS/cpu[0-9]* | sed 's/.*cpu//' | sort -n)
hp=""
for c in $cpus; do
	[ -f $SYSFS/cpu$c/online ] && hp="$hp $c"
done
if [ -z "$hp" ]; then
	ktap_skip_all "no hotpluggable CPUs"
	exit $KSFT_SKIP
fi
nhp=$(echo $hp | wc -w)

ktap_print_header
ktap_set_plan $((nhp + 1))

load_cpu() { # cpu
	# A few forks and context switches pinned to the fresh CPU
	taskset -c $1 sh -c 'for i in 1 2 3 4 5 6 7 8; do (true); done; for i in $(seq 200); do :; done' 2>/dev/null
}

cycle_cpu() { # cpu
	local c=$1 i
	for i in $(seq $CYCLES); do
		echo 0 > $SYSFS/cpu$c/online || return 1
		[ "$(cat $SYSFS/cpu$c/online)" = "0" ] || return 1
		echo 1 > $SYSFS/cpu$c/online || return 1
		[ "$(cat $SYSFS/cpu$c/online)" = "1" ] || return 1
		load_cpu $c
	done
	return 0
}

for c in $hp; do
	if cycle_cpu $c; then
		ktap_test_pass "cpu$c: $CYCLES offline/online cycles"
	else
		echo 1 > $SYSFS/cpu$c/online 2>/dev/null
		ktap_test_fail "cpu$c: offline/online failed"
	fi
done

# Batch: half the hotpluggable CPUs down at once, then back up, under load
batch=$(echo $hp | tr ' ' '\n' | awk 'NR % 2 == 0' | tr '\n' ' ')
ok=1
for c in $batch; do echo 0 > $SYSFS/cpu$c/online || ok=0; done
(for i in $(seq 50); do (true); done) &
for c in $batch; do echo 1 > $SYSFS/cpu$c/online || ok=0; done
wait
for c in $batch; do [ "$(cat $SYSFS/cpu$c/online)" = "1" ] || ok=0; done
if [ $ok = 1 ]; then
	ktap_test_pass "batch offline/online of $(echo $batch | wc -w) CPUs"
else
	ktap_test_fail "batch offline/online"
fi

ktap_finished
