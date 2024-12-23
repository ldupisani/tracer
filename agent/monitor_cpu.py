from bcc import BPF
from time import sleep, strftime

# BPF program
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct cpu_val {
    u64 cpu_time;
};

BPF_HASH(cpu_stats, struct key_t, struct cpu_val);

TRACEPOINT_PROBE(sched, sched_switch) {
    struct key_t key = {};
    u64 cpu_time;
    
    // Get PID and command
    key.pid = args->prev_pid;
    bpf_probe_read_kernel(&key.comm, sizeof(key.comm), args->prev_comm);
    
    // Calculate CPU time
    struct cpu_val *val, zero = {};
    val = cpu_stats.lookup_or_try_init(&key, &zero);
    if (val) {
        val->cpu_time += bpf_ktime_get_ns();
    }
    
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Print header
print("%-6s %-16s %s" % ("PID", "COMM", "CPU TIME(ms)"))

# Print CPU stats
while True:
    try:
        sleep(1)
        for k, v in b["cpu_stats"].items():
            print("%-9s %-6d %-16s %d" % (
                strftime("%H:%M:%S"),
                k.pid,
                k.comm.decode(),
                v.cpu_time / 1000000)
            )
    except KeyboardInterrupt:
        exit()
