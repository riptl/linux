# SPDX-License-Identifier: GPL-2.0
# Tests for the x86 kernel (supervisor) shadow stack,
# CONFIG_X86_KERNEL_SHADOW_STACK.

CFLAGS += -O2 -g -Wall -pthread $(KHDR_INCLUDES)
CFLAGS += -I $(top_srcdir)/tools/testing/selftests/

TEST_GEN_PROGS := kshstk_stress kshstk_events kshstk_user_access \
		  kshstk_ushstk kshstk_irqstack
TEST_GEN_PROGS_EXTENDED := kshstk_bpf_override
TEST_PROGS := kshstk_hotplug.sh kshstk_tracing.sh kshstk_lkdtm.sh \
	      kshstk_kprobe_insns.sh kshstk_error_inject.sh kshstk_compat.sh
TEST_FILES := kshstk_lib.sh

# kshstk_compat32 is a freestanding 32-bit binary (no 32-bit libc needed);
# lib.mk's default rule links against libc, so it gets its own rule.  Only
# built when the compiler can produce 32-bit code.
CAN_BUILD_I386 := $(shell echo 'void _start(void){}' | \
	$(CC) -m32 -nostdlib -static -ffreestanding -x c - -o /dev/null 2>/dev/null && echo 1)
ifeq ($(CAN_BUILD_I386),1)
TEST_GEN_FILES := kshstk_compat32
endif

include ../../lib.mk

# User shadow stack enabled binary: the kernel only enables it for
# executables that advertise shadow stack support (-fcf-protection=full).
$(OUTPUT)/kshstk_ushstk: CFLAGS += -fcf-protection=full -mshstk

$(OUTPUT)/kshstk_compat32: kshstk_compat32.c
	$(CC) -m32 -O2 -Wall -nostdlib -static -ffreestanding \
		-fno-stack-protector -fno-pie -no-pie -fno-asynchronous-unwind-tables \
		-Wl,-z,noexecstack $< -o $@
