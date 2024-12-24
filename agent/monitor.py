from bcc import BPF
from time import time

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

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

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    data.pid = pid;
    data.start_time = bpf_ktime_get_ns();
    data.cpu_time = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    start_times.update(&pid, &data.start_time);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

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
        
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        data.ppid = task->real_parent->tgid;
        
        events.perf_submit(args, &data, sizeof(data));
        start_times.delete(&pid);
    }
    return 0;
}

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
        u64 *start_ts = start_times.lookup(&key.pid);
        if (start_ts) {
            struct data_t data = {};
            data.pid = key.pid;
            data.cpu_time = val->cpu_time;
            data.start_time = *start_ts;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            struct task_struct *task;
            task = (struct task_struct *)bpf_get_current_task();
            data.ppid = task->real_parent->tgid;

            events.perf_submit(args, &data, sizeof(data));
        }
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

        u64 *start_ts = start_times.lookup(&pid);
        if (start_ts) {
            struct data_t data = {};
            data.pid = pid;
            data.mem_size = info->total_size;
            data.start_time = *start_ts;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            struct task_struct *task;
            task = (struct task_struct *)bpf_get_current_task();
            data.ppid = task->real_parent->tgid;

            events.perf_submit(args, &data, sizeof(data));
        }
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

        u64 *start_ts = start_times.lookup(&pid);
        if (start_ts) {
            struct data_t data = {};
            data.pid = pid;
            data.mem_size = info->total_size;
            data.start_time = *start_ts;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            struct task_struct *task;
            task = (struct task_struct *)bpf_get_current_task();
            data.ppid = task->real_parent->tgid;

            events.perf_submit(args, &data, sizeof(data));
        }
    }
    return 0;
}


"""

b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="do_ret_sys_execve")

partial_commands = {}

print("%-9s %-6s %-6s %-16s %-25s %s" % (
    "TIME", "PID", "PPID", "COMM", "EVENT", "DETAILS"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    if event.is_exec_event:
        # Handle execve events
        if event.argdata:
            if event.pid not in partial_commands:
                partial_commands[event.pid] = {
                    'parts': [],
                    'ppid': event.ppid,
                    'comm': event.comm.decode('utf-8', 'replace')
                }
            partial_commands[event.pid]['parts'].append(event.argdata.decode('utf-8', 'replace'))
        elif hasattr(event, 'retval'):
            if event.pid in partial_commands:
                cmd_info = partial_commands[event.pid]
                full_command = ' '.join(cmd_info['parts'])
                print("%-9d %-6d %-6d %-16s %-25s %s" % (
                    int(time()),
                    event.pid,
                    cmd_info['ppid'],
                    cmd_info['comm'],
                    "EXECVE",
                    full_command))
                del partial_commands[event.pid]
    else:
        # Handle process lifecycle events
        if not all(hasattr(event, attr) for attr in ['pid', 'ppid', 'comm']):
            return
        try:
            comm = event.comm.decode()
        except:
            comm = "<decode error>"
        if event.end_time:
            duration_ms = (event.end_time - event.start_time) / 1000000
            print("%-9d %-6d %-6d %-16s %-25s Duration: %.2fms" % (
                int(time()),
                event.pid,
                event.ppid,
                event.comm.decode(),
                "EXIT",
                duration_ms))
        elif event.mem_size:
            print("%-9d %-6d %-6d %-16s %-25s %.2fkb" % (
                int(time()),
                event.pid,
                event.ppid,
                event.comm.decode(),
                "MEM",
                event.mem_size / 1024))
        elif event.cpu_time:
            print("%-9d %-6d %-6d %-16s %-25s %.2fms" % (
                int(time()),
                event.pid,
                event.ppid,
                event.comm.decode(),
                "CPU",
                event.cpu_time / 1000000))
        else:
            print("%-9d %-6d %-6d %-16s %-25s" % (
                int(time()),
                event.pid,
                event.ppid,
                comm,
                "START"))

b["events"].open_perf_buffer(print_event)
print("Tracing process events... Ctrl+C to quit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
