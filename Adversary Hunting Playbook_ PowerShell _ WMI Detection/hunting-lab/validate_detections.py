#!/usr/bin/env python3
import json

def validate_detections():
    print("=== DETECTION VALIDATION ===")
    
    # Count PowerShell detections
    try:
        with open('powershell_logs.json', 'r') as f:
            ps_logs = len(f.readlines())
        print(f"PowerShell logs processed: {ps_logs}")
    except FileNotFoundError:
        print("PowerShell logs: Not found")
    
    # Count WMI detections
    try:
        with open('wmi_logs.json', 'r') as f:
            wmi_logs = len(f.readlines())
        print(f"WMI logs processed: {wmi_logs}")
    except FileNotFoundError:
        print("WMI logs: Not found")
    
    # Check detection outputs
    detection_files = [
        'powershell_detections.txt',
        'wmi_detections.txt',
        'comprehensive_hunting_report.txt'
    ]
    
    for file in detection_files:
        try:
            with open(file, 'r') as f:
                content = f.read()
                if content:
                    print(f"✓ {file}: Generated successfully")
                else:
                    print(f"✗ {file}: Empty file")
        except FileNotFoundError:
            print(f"✗ {file}: Not found")
    
    print("\n=== VALIDATION COMPLETE ===")

if __name__ == "__main__":
    validate_detections()
