/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct trace_event_raw_sys_symlinkat {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char *oldname;
	int newdfd;
	const char *newname;
};

struct trace_event_raw_sys_symlink {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char *oldname;
	const char *newname;
};

struct event {
	__u32 pid;
	__u8 oldname[255];
	__u8 newname[255];
	__u64 timestamp;
};

const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int symlink_helper(const char *oldname, const char *newname)
{
	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	event->pid = pid;
	u64 timestamp = bpf_ktime_get_ns();
	event->timestamp = timestamp;
	bpf_probe_read_user_str(&event->oldname, sizeof(event->oldname), oldname);
	bpf_probe_read_user_str(&event->newname, sizeof(event->newname), newname);
	bpf_ringbuf_submit(event, 0);
	return 0;
}


SEC("tracepoint/syscalls/sys_symlink")
int trace_symlink(struct trace_event_raw_sys_symlink *ctx)
{
	return symlink_helper(ctx->oldname, ctx->newname);
}

SEC("tracepoint/syscalls/sys_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_symlinkat *ctx)
{
	return symlink_helper(ctx->oldname, ctx->newname);
}
