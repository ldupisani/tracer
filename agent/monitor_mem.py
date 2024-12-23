from bcc import BPF
from time import sleep, strftime
from collections import defaultdict

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

struct mem_info {
    u64 total_size;    
    u64 allocations;   
    char comm[TASK_COMM_LEN];
};

BPF_HASH(mem_stats, u32, struct mem_info);

TRACEPOINT_PROBE(kmem, kmalloc) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct mem_info *info, zero = {};
    
    info = mem_stats.lookup_or_try_init(&pid, &zero);
    if (info) {
        info->total_size += args->bytes_alloc;
        info->allocations++;
        bpf_get_current_comm(&info->comm, sizeof(info->comm));
    }
    return 0;
}

TRACEPOINT_PROBE(kmem, kfree) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct mem_info *info = mem_stats.lookup(&pid);
    if (info) {
        // For kfree, we can only track the count of deallocations
        if (info->allocations > 0) {
            info->allocations--;
        }
    }
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Store historical data
historical_data = defaultdict(list)

print("%-9s %-6s %-16s %-10s %-10s" % ("TIME", "PID", "COMM", "TOTAL(KB)", "ALLOCS"))

while True:
    try:
        sleep(1)
        for pid, info in b["mem_stats"].items():
            total_kb = info.total_size / 1024
            historical_data[pid.value].append(total_kb)
            
            print("%-9s %-6d %-16s %-10.2f %-10d" % (
                strftime("%H:%M:%S"),
                pid.value,
                info.comm.decode(),
                total_kb,
                info.allocations
            ))
    except KeyboardInterrupt:
        exit()
