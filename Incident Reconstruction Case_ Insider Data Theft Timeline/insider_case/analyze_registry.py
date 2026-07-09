#!/usr/bin/env python3
import re
from datetime import datetime

def parse_registry_timeline(file_path):
    timeline_events = []
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract recent documents
    recent_docs = re.findall(r'"(\d+)"="([^"]+)"', content)
    last_accessed = re.search(r'"LastAccessed"="([^"]+)"', content)
    
    if last_accessed:
        timestamp = last_accessed.group(1)
        for doc in recent_docs:
            if doc[0].isdigit():
                timeline_events.append({
                    'timestamp': timestamp,
                    'source': 'Registry',
                    'event': f'Recent Document Access: {doc[1]}',
                    'artifact': 'RecentDocs'
                })
    
    # Extract command history
    commands = re.findall(r'"[a-z]"="([^"]+)"', content)
    for cmd in commands:
        timeline_events.append({
            'timestamp': timestamp,
            'source': 'Registry',
            'event': f'Command Executed: {cmd}',
            'artifact': 'RunMRU'
        })
    
    return timeline_events

# Parse registry data
events = parse_registry_timeline('evidence/registry/user_activity.reg')
for event in events:
    print(f"{event['timestamp']} | {event['source']} | {event['event']}")
