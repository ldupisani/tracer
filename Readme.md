# 1. Pipelines simulation and signal collection

## Pipeline Simulation

I've added two basic test pipelines and associated execution scripts. For starters these are just using basic commands to see if tracing actually is occuring.

exe_1.sh -> pipeline_1.sh
exe_2.sh -> pipeline_2.sh

TODO: The next step is to creatier heftier processes that are easier to identify, potentially Python programs that take up more time and resources.

## Signal Collection

I created individual signal collection test programs to identify the probes I will combine in my agent software at a later stage.

### Prerequisites

The following tools need to be installed and created on an Ubuntu installation for these programs to work:

- sudo apt install libbpfcc-dev python3-bpfcc bpfcc-tools
- sudo apt install linux-tools-common linux-tools-generic
- bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

### signals.py

This was just a basic program to check that kprobes are working fine with execve systems calls and the like.

### execution.py

This tool collects start and end events for:

- Process ID
- Parent Process ID
- Type: Enter or Exit

### commands.py

This tool gives more information about a process and its arguments:

- Process ID
- Command name
- Process arguments

## Metrics Collection

These are individual metric colleciton programs.

### cpu.py

Streams current CPU usage at fixed intervals.

- Process ID
- Binary name
- CPU time in millisesonds

### memory.py

Streams current memory usage metrics at fixed intervals. It's questionable that the memory usage declared is in bytes, but I will debug that later when I create the agent.

- Process ID
- Binary name
- Memory usage

# 2. Agent Architecture

## Processing

There is a natural split between the datasets. I will keep one program to monitor lifecycle events, and create two other programs to monitor cpu and memory

### monitor_lifecycle.py

Here I combine all data required about process executions from my previous signal_collection programs. This can be used to identify when a process executes, starts and stops. This can later be used at a high level to detect when a process stops, and if it was successful or failed.

### monitor_cpu.py

Monitors the cpu usage information asynchronously to build a graph of resources. This can be useful at a later stage to help identify issues like infinite recursion, or deadlocks.

### monitor_mem.py

Monitors the memory usage information asynchronously to build a graph of resources. This can be useful at a later stage to help identify issues like memory leaks.
