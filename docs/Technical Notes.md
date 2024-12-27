# Design Decisions

I spent some time getting my bearings with eBPF and its support on various Linux distros. I considered using Rust, but thought it would be better to get a working prototype done before delving into that.

I do make the BPF code do most of the heavy lifing in this example, including filtering the processes that I watch, only raising entry and exit events, and pulling minimal information into user space.

# Query Construction

Ultimately the queries were very easy to construct. I simply loaded the parquet files back into a duck db python scripts.

Because I record the execution time on process exit from the BPF program I can aggregate this on the full command and order them by descending value.

For the prototype I'm only storing a CPU usage event on exit too. The query however is constructed in such a way that if I was streaming CPU events on a conitnuous basis it will select the maximum CPU time per binary execution in a subquery, and aggregates all of these into the total CPU time consumed.

# Challenges and Improvements

By far the biggest challenge was getting a decent work environment up and running. Since I'm using a recent Mac, I have to use an ARM based Linux distro. In the end I went with an Ubuntu virtualbox instance.

Of course this could all be done in Rust, or C++. But if I had to extend this Python example, I would make modular BPF code instance and establish a standard protocol up between kernel and use space to inject only the needed traces and output those into individual output streams that could later be merged for analysis

# Assumptions

One of the assumptions I made, is that you only really need the monitoring application running when a pipeline is being executed. You can conditionally start up the monitor for debugging purposes whenever you do a run and end the process when it stops. That way you are only tracking processes that run during the pipeline execution.

# Screenshots

I have taken screenshots and added them to this repo.
