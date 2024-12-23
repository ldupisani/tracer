#!/bin/bash

TARGET_SCRIPT="./pipeline_1.sh"
if [ ! -x "$TARGET_SCRIPT" ]; then
    echo "Error: $TARGET_SCRIPT not found or not executable"
    exit 1
fi

success_count=0
for i in $(seq 1 100); do
    echo "Running execution #$i"
    echo $TARGET_SCRIPT
    $TARGET_SCRIPT &
done

wait

echo -e "\nAll scripts executed"
