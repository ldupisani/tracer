from bcc import BPF
from time import time
import duckdb

# SYSTEM LEVEL PROCESS MONITORING
# This code does most of the heavy lifting for process monitoring.
# The amount of events it raises shoudl be constrained by the PIDs that run during pipeline execution.

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

// CREATE A RATE LIMITER

#define RATE_LIMIT 16    
#define BURST_LIMIT 32
#define NS_PER_SEC 1000000000ULL

struct rate_limit {
    u64 tokens;
    u64 last_time;
};

BPF_HASH(rate_limiter, u32, struct rate_limit, 100);

static __always_inline bool check_rate_limit(u32 pid) {
    u64 now = bpf_ktime_get_ns();
    struct rate_limit new_rl = {};
    struct rate_limit *rl = rate_limiter.lookup_or_try_init(&pid, &new_rl);
    if (!rl)
        return false;

    u64 elapsed = now - rl->last_time;
    u64 tokens = rl->tokens + elapsed * RATE_LIMIT / NS_PER_SEC;
    tokens = tokens > BURST_LIMIT ? BURST_LIMIT : tokens;

    if (tokens >= 1) {
        rl->tokens = tokens - 1;
        rl->last_time = now;
        return true;
    }
    
    rl->tokens = 0;
    rl->last_time = now;
    return false;
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

    if (!check_rate_limit(key.pid))
        return 0;

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
    if (!check_rate_limit(pid))
        return 0;

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
    if (!check_rate_limit(pid))
        return 0;

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

# SEQUENCED EVENT LOG
# We are using an in memory duckcb database to store all trace events in sequence.
# This will be output to parquet files for ingestion and and analysis in further stages of the pipeline.

# Create a DuckDB connection
db = duckdb.connect()

# Create a table that will store our process lifecycle events
db.execute("CREATE SEQUENCE id_sequence START 1")
db.execute("""
    CREATE TABLE metrics_stream (
        id INTEGER DEFAULT nextval('id_sequence'),
        pid UINTEGER,
        ppid UINTEGER,
        time UBIGINT,
        command VARCHAR,
        type VARCHAR,
        metric UBIGINT,
        arguments VARCHAR
    )
""")

print("%-9s %-6s %-6s %-16s %-25s %s %s" % ("TIME", "PID", "PPID", "COMM", "EVENT", "METRIC", "DETAILS"))

def store_event(time, pid, ppid, command, type, metric, details):
    # print("%-9d %-6d %-6d %-16s %-25s %d %s" % (
    #     time,
    #     pid,
    #     ppid,
    #     command,
    #     type,
    #     metric,
    #     details)   
    # )
    db.execute(f" INSERT INTO metrics_stream VALUES (DEFAULT, {time}, {pid}, {ppid}, '{command}', '{type}', {metric}, '{details}')")


def process_event(cpu, data, size):
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
                store_event(int(time()), event.pid, cmd_info['ppid'], cmd_info['comm'], "EXECVE", 0, full_command)
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
            duration = (event.end_time - event.start_time)
            # duration_ms = duration / 1000000
            store_event(int(time()), event.pid, event.ppid, event.comm.decode(), "EXIT", duration, "")
        elif event.mem_size:
            size = event.mem_size;
            # size_kb = event.mem_size / 1024
            store_event(int(time()), event.pid, event.ppid, event.comm.decode(), "MEM", size, "")
        elif event.cpu_time:
            cpu_allocation = event.cpu_time
            store_event(int(time()), event.pid, event.ppid, event.comm.decode(), "CPU", cpu_allocation, "")
        else:
            store_event(int(time()), event.pid, event.ppid, comm, "START", 0, "")

def persist_metrics():
    db.execute("COPY metrics_stream TO 'metrics_stream.parquet' (FORMAT 'parquet', CODEC 'zstd')")

b["events"].open_perf_buffer(process_event, page_cnt=16384)
print("Tracing process events... Ctrl+C to quit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        persist_metrics()
        db.close()
        exit()
