#!/bin/bash

# Execute system commands with controlled timeouts
timeout 3s vmstat -n 1
timeout 2s lsof -i
timeout 4s iostat
timeout 1s w
timeout 2s last -n 5
