#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Kernel shadow stack: an INT3 kprobe at every instruction of a few hot
# functions, with and without jump optimization.
#
# A kprobe either single-steps a copy of the probed instruction, emulates
# it (CALL, RET, JMP, Jcc, PUSH, POP, ...), "boosts" it with a JMP back, or
# with optimization on replaces it with a jump to an optprobe trampoline
# that CALLs the handler and returns.  Each of those paths must leave the
# shadow stack consistent with the regular stack: the INT3 handler returns
# through ERETS with a changed regs->ip (fred_shstk_sync_frame), emulated
# CALL/RET adjust the event frame's SSP (fred_shstk_emulate_call/ret), and
# the optprobe trampoline's own CALL/RET pair must balance.  Probing every
# byte offset of a real function hits every instruction type the function
# contains; offsets that are not instruction boundaries are rejected by
# kprobe_events and skipped.
#
# Per probe: register, enable, run matching load, disable, remove, and
# check that nothing shadow stack related, no BUG/Oops and no WARNING
# appeared in dmesg.  Reported per function and per mode.
#
# KSHSTK_QUICK=1 limits the sweep to 2 functions and 400 offsets each.
# MAX_OFFSETS=N overrides the offset cap (default: function size, at most
# 2048 bytes).  A #CP is fatal, so the failure mode is a dead box.

DIR=$(dirname "$0")
. "$DIR/kshstk_lib.sh"
. "$DIR/../../kselftest/ktap_helpers.sh"

kshstk_require_root
kshstk_require_active

TRACEFS=$(kshstk_tracefs)
if [ -z "$TRACEFS" ] || [ ! -w "$TRACEFS/kprobe_events" ]; then
	ktap_skip_all "tracefs/kprobe_events not available (CONFIG_KPROBE_EVENTS)"
	exit $KSFT_SKIP
fi
OPT=/proc/sys/debug/kprobes-optimization
if [ ! -w $OPT ]; then
	ktap_skip_all "$OPT not available (CONFIG_OPTPROBES)"
	exit $KSFT_SKIP
fi
OPT_DEFAULT=$(cat $OPT)

CANDIDATES="kernel_clone vfs_read vfs_write do_sys_openat2 __x64_sys_getppid schedule ksys_write filemap_read"
MAX_SIZE=2048
if [ "${KSHSTK_QUICK:-0}" = "1" ]; then
	MAX_SIZE=${MAX_OFFSETS:-400}
	NFUNCS=2
else
	MAX_SIZE=${MAX_OFFSETS:-$MAX_SIZE}
	NFUNCS=99
fi

cd "$TRACEFS" || exit $KSFT_SKIP

# Function size from kallsyms: next symbol's address minus this one's.
# The addresses are real for root; the first match of the exact name wins.
# Only the low 32 bits are used: awk numbers are doubles and lose the low
# bits of a full 64-bit kernel address.
func_size() { # name
	awk -v fn="$1" -v max="$MAX_SIZE" '
		function lo32(a) { return strtonum("0x" substr(a, length(a) - 7)) }
		$3 == fn && !found { start = lo32($1); found = 1; next }
		found && lo32($1) > start {
			sz = lo32($1) - start
			if (sz > max) sz = max
			print sz; exit
		}
	' /proc/kallsyms
}

FUNCS=""
n=0
for fn in $CANDIDATES; do
	[ $n -ge $NFUNCS ] && break
	grep -qx "$fn" available_filter_functions || continue
	sz=$(func_size "$fn")
	[ -n "$sz" ] && [ "$sz" -gt 0 ] || continue
	FUNCS="$FUNCS $fn:$sz"
	n=$((n + 1))
done
if [ -z "$FUNCS" ]; then
	ktap_skip_all "none of the candidate functions is traceable"
	exit $KSFT_SKIP
fi

TMP=$(mktemp)
cleanup() {
	echo 0 > events/kprobes/enable 2>/dev/null
	echo > kprobe_events 2>/dev/null
	echo "$OPT_DEFAULT" > $OPT 2>/dev/null
	echo 1 > tracing_on 2>/dev/null
	rm -f "$TMP"
}
trap cleanup EXIT

# The handlers still run with the ring buffer off; this just avoids churn
echo 0 > tracing_on
echo > kprobe_events

BAD='kernel shadow stack|control protection|#CP|BUG:|Oops|WARNING'
bad_count() { dmesg 2>/dev/null | grep -Ec "$BAD" || true; }

# Load that goes through all the candidate functions: forks (kernel_clone,
# schedule), a read of a page cache file (vfs_read, filemap_read), a write
# to tmpfs (vfs_write, ksys_write), opens (do_sys_openat2), and a bash
# startup for getppid.
load() {
	(:)
	cat "$0" > /dev/null
	echo x > "$TMP"
	: < /proc/self/status
	bash -c :
}

# Returns the hit count of the probe through kprobe_profile
probe_hits() {
	awk '$1 == "kpi" { print $2; exit }' kprobe_profile 2>/dev/null
}

sweep() { # function size mode(0|1)
	local fn=$1 size=$2 mode=$3 off placed=0 hit=0 optd=0 fails=0 before after
	local t0=$(date +%s)

	before=$(bad_count)
	off=0
	while [ $off -lt $size ]; do
		if ! echo "p:kpi $fn+$off" > kprobe_events 2>/dev/null; then
			off=$((off + 1))
			continue
		fi
		placed=$((placed + 1))
		if ! echo 1 > events/kprobes/kpi/enable 2>/dev/null; then
			echo > kprobe_events
			off=$((off + 1))
			continue
		fi
		# The optimizer runs from delayed work (OPTIMIZE_DELAY jiffies)
		[ "$mode" = 1 ] && sleep 0.01
		load
		if [ "$mode" = 1 ] && grep -q OPTIMIZED /sys/kernel/debug/kprobes/list 2>/dev/null; then
			optd=$((optd + 1))
		fi
		h=$(probe_hits)
		[ -n "$h" ] && [ "$h" -gt 0 ] && hit=$((hit + 1))
		echo 0 > events/kprobes/kpi/enable
		echo > kprobe_events
		after=$(bad_count)
		if [ "$after" != "$before" ]; then
			fails=$((fails + 1))
			dmesg | grep -E "$BAD" | tail -3 | sed "s/^/# $fn+$off: /"
			before=$after
		fi
		off=$((off + 1))
	done
	ktap_print_msg "$fn: $placed probes in $size bytes, $hit hit, $optd optimized, $(( $(date +%s) - t0 ))s"
	[ $fails = 0 ]
}

nf=$(echo $FUNCS | wc -w)
ktap_print_header
ktap_set_plan $((nf * 2))
ktap_print_msg "functions:$FUNCS (offset cap $MAX_SIZE)"

for mode in 0 1; do
	echo $mode > $OPT
	[ "$mode" = 0 ] && desc="INT3 kprobes (single-step/emulation/boost)" || desc="optimized kprobes (jump + trampoline)"
	for f in $FUNCS; do
		fn=${f%%:*}
		sz=${f##*:}
		if sweep "$fn" "$sz" "$mode"; then
			ktap_test_pass "$desc at every instruction of $fn"
		else
			ktap_test_fail "$desc at every instruction of $fn (kernel messages above)"
		fi
	done
done

ktap_finished
