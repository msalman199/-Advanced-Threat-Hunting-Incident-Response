#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime

def extract_logon_events(json_file):
    """Extract and categorize logon/logoff events"""
    
    with open(json_file, 'r') as f:
        events = json.load(f)
    
    logon_events = []
    
    for event in events:
        event_id = event.get('EventID')
        
        # Process different logon event types
        if event_id in [4624, 4634, 4625]:
            logon_event = {
                'timestamp': event.get('TimeCreated'),
                'event_id': event_id,
                'event_type': get_event_type(event_id),
                'username': event.get('TargetUserName'),
                'workstation': event.get('WorkstationName'),
                'logon_type': event.get('LogonType'),
                'source_ip': event.get('SourceNetworkAddress', 'N/A'),
                'process_id': event.get('ProcessId'),
                'failure_reason': event.get('FailureReason', 'N/A')
            }
            logon_events.append(logon_event)
    
    return logon_events

def get_event_type(event_id):
    """Map event IDs to human-readable types"""
    event_types = {
        4624: 'Successful Logon',
        4634: 'Logoff',
        4625: 'Failed Logon'
    }
    return event_types.get(event_id, 'Unknown')

def main():
    print("Extracting logon/logoff events...")
    
    events = extract_logon_events('sample_security_events.json')
    
    # Convert to DataFrame for analysis
    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')
    
    print(f"\nExtracted {len(events)} logon/logoff events:")
    print(df.to_string(index=False))
    
    # Save extracted events
    df.to_csv('extracted_logon_events.csv', index=False)
    print("\nEvents saved to extracted_logon_events.csv")

if __name__ == "__main__":
    main()
