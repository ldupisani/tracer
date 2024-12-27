from bcc import BPF
from time import time
import duckdb

# SYSTEM LEVEL PROCESS MONITORING

# The bpf_code does most of the heavy lifting in kernel space.
# For now we just have one file that contains the BPF code, but this can be split into multiple files
# if we want to make it more modular and extensible.

file_path = 'bpf.c'

with open(file_path, 'r') as file:
    bpf_code = file.read()

b = BPF(text=bpf_code)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
b.attach_kretprobe(event=b.get_syscall_fnname("execve"), fn_name="do_ret_sys_execve")

partial_commands = {}

# TRANSFORMATION 

def get_cpu_time(process_id):
    cpu_time = b.get_table("cpu_time")
    for k, v in cpu_time.items():
        pid = k.value
        if process_id == k.value:
            return v.oncpu_time
    return 0

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
                cmd_info['full_command'] = ' '.join(cmd_info['parts'])
                store_event(int(time()), event.pid, cmd_info['ppid'], cmd_info['comm'], "EXECVE", 0, cmd_info['full_command'])
    else:
        # Handle process lifecycle events
        if not all(hasattr(event, attr) for attr in ['pid', 'ppid', 'comm']):
            return
        try:
            comm = event.comm.decode()
        except:
            comm = "<decode error>"


        if event.end_time:
            full_command = ""
            if event.pid in partial_commands and 'full_command' in partial_commands[event.pid]:
                full_command = partial_commands[event.pid]['full_command']
            duration = (event.end_time - event.start_time)
            store_event(int(time()), event.pid, event.ppid, event.comm.decode(), "CPU", get_cpu_time(event.pid), full_command)
            store_event(int(time()), event.pid, event.ppid, event.comm.decode(), "EXIT", duration, full_command)            
        else:
            store_event(int(time()), event.pid, event.ppid, comm, "START", 0, "")


# SEQUENCED EVENT LOG

# We are using an in memory duckcb database to store all trace events in sequence.
# This will be used to generate metrics and insights in the next stage of the pipeline.

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
        full_command VARCHAR
    )
""")


print("%-9s %-6s %-6s %-16s %-25s %s %s" % ("TIME", "PID", "PPID", "COMM", "EVENT", "METRIC", "DETAILS"))

def store_event(time, pid, ppid, command, type, metric, details):
    print("%-9d %-6d %-6d %-16s %-25s %d %s" % (
        time,
        pid,
        ppid,
        command,
        type,
        metric,
        details)   
    )
    db.execute(f" INSERT INTO metrics_stream VALUES (DEFAULT, {time}, {pid}, {ppid}, '{command}', '{type}', {metric}, '{command} {details}')")


# PERSISTENCE

# This will be output to parquet files for ingestion and and analysis in further stages of the pipeline.
# Currently the file is written to disk when the monitoring process exits, but this can be
# changed to stream the data to a remote storage system.

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
