#!/bin/bash
# Simulated malicious persistence script
echo "$(date): Suspicious process started" >> /tmp/malware.log
sleep 3600 &
