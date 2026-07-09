#!/usr/bin/env python3
import json
import datetime
from collections import defaultdict

def analyze_timeline(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    
    events_by_time = defaultdict(list)
    suspicious_events = []
    
    for event in data.get('objects', []):
        timestamp = event.get('datetime')
        message = event.get('message', '')
        tags = event.get('tag', [])
        
        if any(tag in ['suspicious', 'c2', 'exfiltration'] for tag in tags):
            suspicious_events.append({
                'time': timestamp,
                'message': message,
                'source': event.get('source', ''),
                'tags': tags
            })
    
    print("=== ATTACK TIMELINE ANALYSIS ===")
    print(f"Total suspicious events found: {len(suspicious_events)}")
    print("\nSuspicious Events Timeline:")
    
    for event in sorted(suspicious_events, key=lambda x: x['time']):
        print(f"{event['time']} - {event['source']}: {event['message']}")
    
    return suspicious_events

if __name__ == "__main__":
    analyze_timeline('timeline_export.json')
