# SPDX-License-Identifier: GPL-2.0
# Shared helpers for the kernel shadow stack shell tests.

KSFT_SKIP=4

kshstk_require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "# must be run as root"
		exit $KSFT_SKIP
	fi
}

# The feature is active when the CPU flag shows and the boot log says so.
kshstk_require_active() {
	# KSHSTK_FORCE=1: run anyway (baseline comparison on a kernel without the feature)
	[ "${KSHSTK_FORCE:-0}" = "1" ] && return 0
	if ! grep -qw kernel_shstk /proc/cpuinfo; then
		echo "# kernel_shstk not in /proc/cpuinfo (no FRED, nokernelshstk, or incompatible mitigation)"
		exit $KSFT_SKIP
	fi
}

kshstk_tracefs() {
	if [ -d /sys/kernel/tracing ] && [ -f /sys/kernel/tracing/trace ]; then
		echo /sys/kernel/tracing
	elif mount | grep -q tracefs; then
		mount | grep tracefs | head -1 | cut -d' ' -f3
	else
		mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null && echo /sys/kernel/tracing
	fi
}

# Count new "shadow stack" / #CP related kernel messages since a dmesg snapshot.
kshstk_dmesg_snapshot() {
	dmesg > "$1" 2>/dev/null || : > "$1"
}

kshstk_dmesg_new_faults() {
	dmesg 2>/dev/null | comm --nocheck-order -13 "$1" - | \
		grep -Eic 'kernel shadow stack violation|kernel shadow stack access|control protection|#CP|Unexpected .* #CP' || true
}
