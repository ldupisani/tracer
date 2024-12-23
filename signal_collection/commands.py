from bcc import BPF
from time import strftime

# BPF program
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define MAXARG   20

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // Process ID
    u32 ppid; // Parent Process ID
    char comm[TASK_COMM_LEN]; // Process name
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(tasks, u32, struct data_t);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get PPID through task_struct
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    data.type = EVENT_ARG;
    
    __submit_arg(ctx, (void *)filename, &data);  // Submit program name

    // Submit up to MAXARG arguments
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        const char *argp;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == 0)
            break;
        if (__submit_arg(ctx, (void *)(argp), &data) == 0)
            break;
    }

    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    data.pid = pid;
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)

# Attach probes
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="do_ret_sys_execve")

# Process event
print("%-9s %-6s %-6s %-16s %-6s %s" % (
    "TIME", "PID", "PPID", "COMM", "RET", "ARGS"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type == 0:  # EVENT_ARG
        argv = event.argv.decode('utf-8', 'replace')
        if argv:
            print("%-9s %-6d %-6d %-16s %-6s %s" % (
                strftime("%H:%M:%S"), event.pid, event.ppid,
                event.comm.decode('utf-8', 'replace'), "", argv))
    elif event.type == 1:  # EVENT_RET
        print("%-9s %-6d %-6d %-16s %-6d %s" % (
            strftime("%H:%M:%S"), event.pid, event.ppid,
            event.comm.decode('utf-8', 'replace'), event.retval, ""))

# Loop with callback
b["events"].open_perf_buffer(print_event)
print("Tracing execve syscalls... Ctrl+C to quit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
