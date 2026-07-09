#!/usr/bin/env python3
import csv
import re
from collections import defaultdict

def analyze_insider_threats(timeline_file):
    threat_indicators = {
        'data_exfiltration': [],
        'unauthorized_access': [],
        'suspicious_commands': [],
        'external_communication': [],
        'usb_activity': []
    }
    
    with open(timeline_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            event = row['event'].lower()
            
            # Detect data exfiltration patterns
            if any(keyword in event for keyword in ['copy', 'stolen_data', 'financial_data', 'customer_database']):
                threat_indicators['data_exfiltration'].append(row)
            
            # Detect unauthorized access
            if any(keyword in event for keyword in ['sudo', 'root', 'passwd']):
                threat_indicators['unauthorized_access'].append(row)
            
            # Detect suspicious commands
            if any(keyword in event for keyword in ['7z', 'archive', 'compress', 'encrypt']):
                threat_indicators['suspicious_commands'].append(row)
            
            # Detect external communication
            if any(keyword in event for keyword in ['upload', 'file-sharing', 'external']):
                threat_indicators['external_communication'].append(row)
            
            # Detect USB activity
            if any(keyword in event for keyword in ['usb', 'mount', 'removable']):
                threat_indicators['usb_activity'].append(row)
    
    return threat_indicators

# Analyze threats
threats = analyze_insider_threats('master_timeline.csv')

print("=== INSIDER THREAT ANALYSIS REPORT ===\n")

for category, events in threats.items():
    if events:
        print(f"{category.upper().replace('_', ' ')}:")
        print("-" * 40)
        for event in events:
            print(f"  {event['timestamp']} | {event['source']} | {event['event'][:60]}...")
        print()

# Generate threat score
total_indicators = sum(len(events) for events in threats.values())
print(f"THREAT LEVEL: {'HIGH' if total_indicators > 10 else 'MEDIUM' if total_indicators > 5 else 'LOW'}")
print(f"Total Indicators: {total_indicators}")
