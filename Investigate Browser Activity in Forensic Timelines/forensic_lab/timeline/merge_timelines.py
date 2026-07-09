#!/usr/bin/env python3
import csv
import datetime
from collections import defaultdict

def parse_browser_data():
    events = []
    
    # Parse Firefox data
    try:
        with open('../browser_data/firefox_history.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['visit_time']:
                    events.append({
                        'timestamp': row['visit_time'],
                        'source': 'Firefox',
                        'event': f"Visited: {row['url']}",
                        'details': row['title']
                    })
    except FileNotFoundError:
        pass
    
    # Parse Chromium data
    try:
        with open('../browser_data/chromium_history.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['visit_time']:
                    events.append({
                        'timestamp': row['visit_time'],
                        'source': 'Chromium',
                        'event': f"Visited: {row['url']}",
                        'details': row['title']
                    })
    except FileNotFoundError:
        pass
    
    return events

def create_unified_timeline():
    browser_events = parse_browser_data()
    
    # Sort by timestamp
    browser_events.sort(key=lambda x: x['timestamp'])
    
    # Write unified timeline
    with open('unified_timeline.csv', 'w', newline='') as f:
        fieldnames = ['timestamp', 'source', 'event', 'details']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(browser_events)
    
    print(f"Created unified timeline with {len(browser_events)} browser events")

if __name__ == "__main__":
    create_unified_timeline()
