#!/usr/bin/env python3
import csv
from datetime import datetime
import re

def parse_filesystem_timeline(file_path):
    events = []
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append({
                'timestamp': f"{row['Date']} {row['Time']}",
                'source': 'FileSystem',
                'event': f"File Activity: {row['File Name']} ({row['Type']}, {row['Size']} bytes)",
                'artifact': 'MFT'
            })
    return events

def parse_system_logs(file_path):
    events = []
    with open(file_path, 'r') as f:
        for line in f:
            # Parse syslog format
            match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            if match:
                timestamp = match.group(1)
                events.append({
                    'timestamp': f"2024-{timestamp}",
                    'source': 'SystemLog',
                    'event': line.strip(),
                    'artifact': 'syslog'
                })
    return events

def parse_network_logs(file_path):
    events = []
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    timestamp = f"{parts[0]} {parts[1]}"
                    events.append({
                        'timestamp': timestamp,
                        'source': 'Network',
                        'event': parts[2].strip(),
                        'artifact': 'network_log'
                    })
    return events

# Collect all events
all_events = []
all_events.extend(parse_filesystem_timeline('evidence/filesystem/file_timeline.csv'))
all_events.extend(parse_system_logs('evidence/logs/system_events.log'))
all_events.extend(parse_network_logs('evidence/logs/network_activity.log'))

# Sort by timestamp
all_events.sort(key=lambda x: x['timestamp'])

# Create master timeline
print("=== MASTER TIMELINE: INSIDER DATA THEFT CASE ===\n")
print(f"{'Timestamp':<20} | {'Source':<12} | {'Event'}")
print("-" * 80)

for event in all_events:
    print(f"{event['timestamp']:<20} | {event['source']:<12} | {event['event'][:50]}...")

# Save to file
with open('master_timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'source', 'event', 'artifact'])
    writer.writeheader()
    writer.writerows(all_events)

print(f"\nMaster timeline saved to: master_timeline.csv")
