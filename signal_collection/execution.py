from bcc import BPF

# eBPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data {
    u32 pid;
    u32 ppid;
    u64 start_time;
    u64 end_time;
    char comm[TASK_COMM_LEN];
    char args[256];
};

BPF_HASH(start_times, u32, u64);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_data data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    data.pid = pid;
    data.start_time = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    start_times.update(&pid, &data.start_time);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct event_data data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    u64 *start_ts = start_times.lookup(&pid);
    if (start_ts) {
        data.pid = pid;
        data.end_time = bpf_ktime_get_ns();
        data.start_time = *start_ts;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data.ppid = task->real_parent->tgid;
        
        events.perf_submit(args, &data, sizeof(data));
        start_times.delete(&pid);
    }
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Process event callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.end_time:
        duration_ms = (event.end_time - event.start_time) / 1000000
        print(f"EXIT  - PID: {event.pid}, PPID: {event.ppid}, Command: {event.comm.decode()}, Duration: {duration_ms:.2f}ms")
    else:
        print(f"START - PID: {event.pid}, PPID: {event.ppid}, Command: {event.comm.decode()}")

# Attach event printer
b["events"].open_perf_buffer(print_event)

print("Monitoring process execution events... Press Ctrl+C to exit")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
