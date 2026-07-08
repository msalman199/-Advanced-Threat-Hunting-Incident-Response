#!/bin/bash

echo "=== FILE INTEGRITY ANALYSIS ==="

# Check for recently modified system files
echo "[+] Recently modified system files (last 7 days):"
find /etc /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null | head -20

# Check for SUID/SGID files
echo -e "\n[+] SUID/SGID files:"
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20

# Check for world-writable files
echo -e "\n[+] World-writable files:"
find / -type f -perm -002 2>/dev/null | head -10

# Check for files in tmp directories
echo -e "\n[+] Files in temporary directories:"
find /tmp /var/tmp /dev/shm -type f 2>/dev/null | head -10

# Check for hidden files in unusual locations
echo -e "\n[+] Hidden files in system directories:"
find /etc /usr /var -name ".*" -type f 2>/dev/null | head -10
