// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/oom_kill_process")
int kprobe_oom_kill_process(struct pt_regs *ctx) {
	struct event *task_info;
	struct oom_control *oc = (struct oom_control *)PT_REGS_PARM1(ctx);

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);

	if (!task_info) {
		return 0;
	}

	struct task_struct *p;
        bpf_probe_read(&p, sizeof(p), &oc->chosen);
	bpf_probe_read(&task_info->pid, sizeof(task_info->pid), &p->pid);
	bpf_probe_read(&task_info->comm, sizeof(task_info->comm), (void *)&p->comm);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
