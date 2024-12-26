# 0. Prerequisites

The following tools need to be installed and created on an Ubuntu installation for these programs to work:

- sudo apt install libbpfcc-dev python3-bpfcc bpfcc-tools
- sudo apt install linux-tools-common linux-tools-generic
- sudo apt install -y libelf-dev zlib1g-dev libbpf-dev
- bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

### duckdb python setup for Ubuntu

We need to run bcc in Python as sudo, but duckdb doesn't like to be installed outside a virtual environement, and its difficult to do the bpf setup inside of a virtual environment. Also there isn't a Python library that can be installed via pip for Ubuntu, so we have to do the setup ourselves:

- sudo apt -y install python3-pybind11
- git clone https://github.com/duckdb/duckdb.git
- cd duckdb/tools/pythonpkg
- sudo python3 setup.py install

# 1. Pipelines simulation and signal collection

## Pipeline Simulation

I've added two basic test pipelines and associated execution scripts. For starters these are just using basic commands to see if tracing actually is occuring.

exe_1.sh -> pipeline_1.sh
exe_2.sh -> pipeline_2.sh

TODO: The next step is to creatier heftier processes that are easier to identify, potentially Python programs that take up more time and resources.

## Signal Collection

I created individual signal collection test programs to identify the probes I will combine in my agent software at a later stage.

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

These are individual metric colleciton programs I created to monitor system usage of processes.

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

## Processing (Idea 1)

The initial idea was to three individual monitoring programs, output their values and then combine them later.

### monitor_lifecycle.py

Here I combine all data required about process executions from my previous signal_collection programs. This can be used to identify when a process executes, starts and stops. This can later be used at a high level to detect when a process stops, and if it was successful or failed.

### monitor_cpu.py

Monitors the cpu usage information asynchronously to build a graph of resources. This can be useful at a later stage to help identify issues like infinite recursion, or deadlocks.

### monitor_mem.py

Monitors the memory usage information asynchronously to build a graph of resources. This can be useful at a later stage to help identify issues like memory leaks.

## Processing (Idea2)

There are a couple of problems with splitting out the monitoring programs:

- If you poll for memory and cpu stats at an interval a process could start and stop without ever reporting these statistics.
- You create an overcomplicated structure to filter out irrelevant processes that aren't running during your pipeline.

### monitor.py

This is a much simpler solution. Assuming that you only start the monitoring agent whenever you start a pipeline job. You can track only those binaries that run while the pipeline is running. I.e when CPU or Memory stats change, check to see if the PID matches a process we are currently tracking first.

It's ok to also keep track of background tasks that pop up during this time, since interfering processes my also lead to failures in the pipeline. Think for example about a scheduled task that runs in the background, consumes all resources and causes your pipeline to fail.

I created this new simplified single monitor, that will raise lifecycle events. But will also raise memory events whenever there is allocation or dealocation of memory in a process, and will also report back on current resource usage in the correct order.

When the monitor is terminated it writes the metrics to a parquet file for further analysis.

# 3. Query Validation

The basic query function logic have been added. I changed the tracing structure a bit to ensure that there is a numerical metric for each event.

I also added some filtering to exlude traces for shell scripts. This is done directly in the BPF code to reduce the amount of events before it gets pushed to user space.

## Execution Time Analysis

Since the data is pretty well formatted at the outset this is a really basic query grouped on the full command and aggregating the duration metric that is output on an EXIT event.

## Query Validation

This is also a fairly simple query. It has an inner query to find the top CPU usage for each PID during its exection. It then gets aggregates this top value for each execution to compute the total CPU time at the command/binary level without the additional arguments.
