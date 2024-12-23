from bcc import BPF

# eBPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data {
    u32 pid;
    u32 ppid;
    u64 start_time;
    char comm[TASK_COMM_LEN];
    char fname[256];
};

BPF_PERF_OUTPUT(events);

int trace_exec(struct pt_regs *ctx) {
    struct event_data data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.start_time = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    struct event_data data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    if (pid != tid)
        return 0;
    
    data.pid = pid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Attach kprobes
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_exec")
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="trace_exit")

# Process event callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"{'EXEC' if event.start_time else 'EXIT'} - PID: {event.pid}, PPID: {event.ppid}, Command: {event.comm.decode()}")

# Attach event printer
b["events"].open_perf_buffer(print_event)

# Main loop
print("Monitoring process events... Press Ctrl+C to exit")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
