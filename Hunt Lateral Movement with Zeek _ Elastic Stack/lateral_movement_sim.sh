#!/bin/bash

# Simulate SSH scanning
for i in {1..5}; do
    timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no user@127.0.0.$i 2>/dev/null
    sleep 1
done

# Simulate SMB enumeration
for i in {1..3}; do
    timeout 2 nc -zv 127.0.0.$i 445 2>/dev/null
    sleep 1
done

# Simulate RDP attempts
for i in {1..3}; do
    timeout 2 nc -zv 127.0.0.$i 3389 2>/dev/null
    sleep 1
done
