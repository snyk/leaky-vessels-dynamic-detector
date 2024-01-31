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

struct trace_event_raw_sys_unlinkat {
	u64 _unused;
    u32 nr;
    u64 dfd;
    char *pathname;
    u64 flags;
    u64 mode;
};

struct trace_event_raw_sys_unlink {
	u64 _unused;
    u32 nr;
    char *pathname;
    u64 mode;
};

struct event {
	__u32 pid;
	__u8 pathname[255];
	__u64 timestamp;
};

const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int unlink_helper(const char *pathname)
{
	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	event->pid = pid;
	u64 timestamp = bpf_ktime_get_ns();
	event->timestamp = timestamp;
	bpf_probe_read_user_str(&event->pathname, sizeof(event->pathname), pathname);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_unlink")
int trace_unlink(struct trace_event_raw_sys_unlink *ctx)
{
	return unlink_helper(ctx->pathname);
}

SEC("tracepoint/syscalls/sys_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_unlinkat *ctx)
{
	return unlink_helper(ctx->pathname);
}
