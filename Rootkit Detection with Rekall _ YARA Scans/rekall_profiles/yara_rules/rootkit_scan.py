#!/usr/bin/env python3

import subprocess
import sys
import os

def run_yara_scan(memory_file, rule_file):
    """Run YARA scan on memory dump"""
    print(f"Running YARA scan with {rule_file}...")
    try:
        result = subprocess.run(['yara', rule_file, memory_file], 
                              capture_output=True, text=True)
        if result.stdout:
            print("YARA Matches Found:")
            print(result.stdout)
            return True
        else:
            print("No YARA matches found.")
            return False
    except Exception as e:
        print(f"YARA scan error: {e}")
        return False

def run_rekall_analysis(memory_file):
    """Run Rekall analysis commands"""
    commands = [
        ['rekall', '-f', memory_file, '--profile', 'Linux64', 'pslist'],
        ['rekall', '-f', memory_file, '--profile', 'Linux64', 'lsmod'],
        ['rekall', '-f', memory_file, '--profile', 'Linux64', 'netstat']
    ]
    
    for cmd in commands:
        print(f"\nRunning: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.stdout:
                print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
        except Exception as e:
            print(f"Command failed: {e}")

def main():
    memory_file = "test_memory.raw"
    rule_files = ["yara_rules/rootkit_signatures.yar", "yara_rules/advanced_rootkit.yar"]
    
    print("=== Rootkit Detection Analysis ===\n")
    
    # Run YARA scans
    detections = 0
    for rule_file in rule_files:
        if os.path.exists(rule_file):
            if run_yara_scan(memory_file, rule_file):
                detections += 1
        else:
            print(f"Rule file not found: {rule_file}")
    
    print(f"\n=== Rekall Memory Analysis ===")
    run_rekall_analysis(memory_file)
    
    print(f"\n=== Analysis Summary ===")
    print(f"YARA rule files with detections: {detections}")
    print("Review output above for potential rootkit indicators.")

if __name__ == "__main__":
    main()
