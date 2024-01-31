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

struct trace_event_raw_sys_chdir {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char * filename;
};

struct event {
	__u32 pid;
	__u8 path[255];
};

const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_chdir")
int trace_chdir(struct trace_event_raw_sys_chdir *ctx)
{
	if (!ctx) return 0;

	const char *path = (const char *)ctx->filename;

	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	event->pid = pid;
	bpf_probe_read_user_str(&event->path, sizeof(event->path), path);
	bpf_ringbuf_submit(event, 0);
	return 0;
}
