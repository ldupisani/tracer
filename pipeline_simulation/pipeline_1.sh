#!/bin/bash

# Execute system commands with controlled timeouts
timeout 2s ps aux
timeout 3s df -h
timeout 1s ls -la /bin
timeout 4s uname -a
timeout 2s pwd