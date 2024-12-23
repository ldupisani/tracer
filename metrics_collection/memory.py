from bcc import BPF
from time import sleep

# BPF program
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

struct mem_info {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 size;
};

BPF_HASH(mem_stats, u32, struct mem_info);

TRACEPOINT_PROBE(kmem, kmalloc) {
    struct mem_info info = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get process info
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    info.pid = pid;
    info.size = args->bytes_alloc;
    
    mem_stats.update(&pid, &info);
    return 0;
}

TRACEPOINT_PROBE(kmem, kfree) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    mem_stats.delete(&pid);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Print header
print("%-6s %-16s %-8s" % ("PID", "COMM", "SIZE(bytes)"))

# Print memory stats
while True:
    try:
        sleep(1)
        for pid, info in b["mem_stats"].items():
            print("%-6d %-16s %-8d" % (
                info.pid,
                info.comm.decode(),
                info.size
            ))
    except KeyboardInterrupt:
        exit()
