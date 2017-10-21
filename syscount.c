#include <linux/kconfig.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/bpf.h>
#pragma clang diagnostic pop

#include "bpf_helpers.h"

#define printt(fmt, ...)                                           \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

struct bpf_map_def SEC("maps/pids_to_watch") pids_to_watch = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/syscall_count") syscall_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1024,
	.map_flags = 0,
};

// arg list generated with
// https://github.com/iovisor/bcc/blob/master/tools/tplist.py
struct sys_enter_args {
	unsigned long long unused; // syscall preemble
	long id;
	unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_sys_enter(struct sys_enter_args *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u32 tgid = pid >> 32;
	u32 syscall_id = ctx->id;
	u32 *exists = NULL;
	u64 *count_ptr = NULL;
	u64 current_count = 1, one = 1;

	// for demo purposes, only count read
	if (syscall_id != 3) {
		return 0;
	}

	exists = bpf_map_lookup_elem(&pids_to_watch, &tgid);
	if (exists == NULL || !*exists) {
		return 0;
	}

	printt("tracepoint syscall %u\n", syscall_id);

	count_ptr = bpf_map_lookup_elem(&syscall_count, &syscall_id);
	if (count_ptr != NULL) {
		(*count_ptr)++;
		current_count = *count_ptr;
	} else {
		bpf_map_update_elem(&syscall_count, &syscall_id, &one, BPF_ANY);
	}

	printt("current count %lu\n", current_count);
	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the gobpf elf 
// loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
