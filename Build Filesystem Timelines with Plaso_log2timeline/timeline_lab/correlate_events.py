#!/usr/bin/env python3
import pandas as pd
import re

def correlate_attack_sequence(csv_file):
    """Identify potential attack sequences"""
    
    df = pd.read_csv(csv_file)
    df['datetime'] = pd.to_datetime(df['datetime'])
    df_sorted = df.sort_values('datetime')
    
    print("=== ATTACK SEQUENCE ANALYSIS ===\n")
    
    # Define attack phases
    attack_phases = {
        'reconnaissance': [r'google\.com', r'search'],
        'weaponization': [r'malicious.*site', r'download'],
        'delivery': [r'usb.*connected', r'network.*connection'],
        'exploitation': [r'failed.*login', r'suspicious.*process'],
        'installation': [r'nc\.exe', r'executable'],
        'command_control': [r'pastebin', r'exfiltration'],
        'actions': [r'file.*access', r'passwd']
    }
    
    detected_phases = {}
    
    for phase, patterns in attack_phases.items():
        matches = []
        for pattern in patterns:
            phase_matches = df_sorted[df_sorted['message'].str.contains(pattern, case=False, na=False)]
            matches.extend(phase_matches.to_dict('records'))
        
        if matches:
            detected_phases[phase] = sorted(matches, key=lambda x: x['datetime'])
    
    # Display attack timeline
    print("DETECTED ATTACK PHASES:")
    for phase, events in detected_phases.items():
        print(f"\n{phase.upper()}:")
        for event in events:
            print(f"  {event['datetime']} - {event['message']}")
    
    # Calculate attack duration
    if detected_phases:
        all_events = []
        for events in detected_phases.values():
            all_events.extend(events)
        
        all_events.sort(key=lambda x: x['datetime'])
        start_time = pd.to_datetime(all_events[0]['datetime'])
        end_time = pd.to_datetime(all_events[-1]['datetime'])
        duration = end_time - start_time
        
        print(f"\nATTACK SUMMARY:")
        print(f"Start Time: {start_time}")
        print(f"End Time: {end_time}")
        print(f"Total Duration: {duration}")
        print(f"Phases Detected: {len(detected_phases)}")

if __name__ == "__main__":
    correlate_attack_sequence('timeline.csv')
