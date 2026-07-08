#!/usr/bin/env python3
import os
import glob
import subprocess

def check_autostart_locations():
    locations = [
        '/etc/systemd/system/',
        '/lib/systemd/system/',
        '/usr/lib/systemd/system/',
        '/etc/init.d/',
        '/etc/rc*.d/',
        '/etc/cron.d/',
        '/var/spool/cron/crontabs/',
        '/etc/crontab'
    ]
    
    print("=== AUTOSTART ANALYSIS ===")
    for location in locations:
        if os.path.exists(location):
            print(f"\n[+] Checking: {location}")
            if os.path.isfile(location):
                try:
                    with open(location, 'r') as f:
                        content = f.read()
                        if content.strip():
                            print(f"Content found in {location}")
                except:
                    pass
            else:
                files = glob.glob(f"{location}*")
                for file in files[:10]:  # Limit output
                    if os.path.isfile(file):
                        print(f"  - {file}")

def check_suspicious_processes():
    print("\n=== SUSPICIOUS PROCESS ANALYSIS ===")
    try:
        result = subprocess.run(['ps', 'auxf'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        suspicious_keywords = ['tmp', 'dev/shm', 'var/tmp', 'hidden']
        for line in lines:
            for keyword in suspicious_keywords:
                if keyword in line.lower():
                    print(f"[!] Suspicious: {line.strip()}")
                    break
    except:
        print("Error analyzing processes")

if __name__ == "__main__":
    check_autostart_locations()
    check_suspicious_processes()
