// At the outset we want to keep as much of our code in the BPF program as possible.
// This is because the BPF program is loaded into the kernel and runs in kernel space.
// We only want to push the data to user space when we need to.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

// FILTERING HELPER FUNCTIONS

static __always_inline bool str_starts_with(const char *str, const char *prefix) {
    char c1, c2;
    for (int i = 0; i < 8; i++) {  // Limited comparison due to BPF verifier
        c1 = str[i];
        c2 = prefix[i];
        if (c2 == 0) return true;   // Reached end of prefix
        if (c1 != c2) return false; // Mismatch
        if (c1 == 0) return false;  // Reached end of str
    }
    return true;
}

static __always_inline bool is_shell_script(const char *str) {
    char c;
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN - 3; i++) {
        if (str[i] == '.' && str[i+1] == 's' && str[i+2] == 'h')
            return true;
        if (str[i] == 0)
            return false;
    }
    return false;
}

static __always_inline bool should_filter_command(const char *comm) {
    return str_starts_with(comm, "ps") || is_shell_script(comm);
}

// PROCESS LIFECYCLE MONITORING

#define ARGSIZE  128
#define MAXARG   20

struct data_t {
    u32 pid;
    u32 ppid;
    u64 start_time;
    u64 end_time;
    u64 cpu_time;
    u64 mem_size;
    char comm[TASK_COMM_LEN];
    char argdata[ARGSIZE];
    int retval;
    u8 is_exec_event;
};

BPF_HASH(start_times, u32, u64);
BPF_PERF_OUTPUT(events);

// Process start
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    data.pid = pid;
    data.start_time = bpf_ktime_get_ns();
    data.cpu_time = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (should_filter_command(data.comm)) {
        return 0;
    }   
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    start_times.update(&pid, &data.start_time);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Proxess exit
TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    u64 *start_ts = start_times.lookup(&pid);
    if (start_ts) {
        data.pid = pid;
        data.end_time = bpf_ktime_get_ns();
        data.start_time = *start_ts;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        if (should_filter_command(data.comm)) {
            return 0;
        }  
        
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data.ppid = task->real_parent->tgid;
        
        events.perf_submit(args, &data, sizeof(data));
        start_times.delete(&pid);
    }
    return 0;
}

// Process execve
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct data_t data = {.pid = pid, .is_exec_event = true};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (should_filter_command(data.comm)) {
        return 0;
    } 

    bpf_probe_read_user_str(&data.argdata, sizeof(data.argdata), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        const char *argp;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == 0)
            break;
        
        struct data_t arg_data = {.pid = pid, .is_exec_event = true};
        if (bpf_probe_read_user_str(&arg_data.argdata, sizeof(arg_data.argdata), argp) > 0) {
            events.perf_submit(ctx, &arg_data, sizeof(arg_data));
        }
    }
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.retval = PT_REGS_RC(ctx);
    data.is_exec_event = true;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// CPU TIME MONITORING

struct process_cpu_time {
    u64 oncpu_time;
    u64 offcpu_time;
};

BPF_HASH(oncpu_start, u32, u64);
BPF_HASH(offcpu_start, u32, u64);
BPF_HASH(cpu_time, u32, struct process_cpu_time);

static inline void update_cpu_time(u32 pid, u64 delta, int oncpu) {
    struct process_cpu_time *time = cpu_time.lookup(&pid);
    if (!time) {
        struct process_cpu_time zero = {};
        cpu_time.insert(&pid, &zero);
        time = cpu_time.lookup(&pid);
        if (!time)
            return;
    }
    if (oncpu)
        time->oncpu_time += delta;
    else
        time->offcpu_time += delta;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *start_ts = start_times.lookup(&pid);
    if (start_ts) {

        u64 *last_ts = oncpu_start.lookup(&prev_pid);
        if (last_ts) {
            update_cpu_time(prev_pid, ts - *last_ts, 1);
            oncpu_start.delete(&prev_pid);
        } 
        oncpu_start.update(&next_pid, &ts);

    }
    return 0;
}


// MEMORY MONITORING

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