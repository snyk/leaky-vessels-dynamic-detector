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

struct trace_event_raw_sys_mount {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char *dev_name;
	const char *dir_name;
	const char *type;
	unsigned long flags;
	const void *data;
};

struct event {
	__u32 pid;
	__u8 dev_name[255];
	__u8 dir_name[255];
	__u8 fs_type[16];
	__u64 timestamp;
};

const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_mount")
int trace_mount(struct trace_event_raw_sys_mount *ctx)
{
	if (!ctx) return 0;

	const char *dev_name = (const char *)ctx->dev_name;
	const char *dir_name = (const char *)ctx->dir_name;
	const char *fs_type = (const char *)ctx->type;

	struct event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	event->pid = pid;
	u64 timestamp = bpf_ktime_get_ns();
	event->timestamp = timestamp;
	bpf_probe_read_user_str(&event->dev_name, sizeof(event->dev_name), dev_name);
	bpf_probe_read_user_str(&event->dir_name, sizeof(event->dir_name), dir_name);
	bpf_probe_read_user_str(&event->fs_type, sizeof(event->fs_type), fs_type);
	bpf_ringbuf_submit(event, 0);
	return 0;
}
