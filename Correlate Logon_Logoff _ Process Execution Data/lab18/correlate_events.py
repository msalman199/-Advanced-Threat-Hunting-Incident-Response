#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime, timedelta
import base64

def extract_process_events(json_file):
    """Extract process execution events"""
    
    with open(json_file, 'r') as f:
        events = json.load(f)
    
    process_events = []
    
    for event in events:
        event_id = event.get('EventID')
        
        if event_id in [4688, 4689]:
            process_event = {
                'timestamp': event.get('TimeCreated'),
                'event_id': event_id,
                'event_type': 'Process Creation' if event_id == 4688 else 'Process Termination',
                'process_name': event.get('ProcessName'),
                'process_id': event.get('ProcessId'),
                'parent_process_id': event.get('ParentProcessId'),
                'command_line': event.get('CommandLine', 'N/A'),
                'username': event.get('SubjectUserName'),
                'workstation': event.get('WorkstationName')
            }
            process_events.append(process_event)
    
    return process_events

def decode_powershell_command(command_line):
    """Decode base64 encoded PowerShell commands"""
    if '-enc' in command_line:
        try:
            encoded_part = command_line.split('-enc ')[1].strip()
            decoded = base64.b64decode(encoded_part).decode('utf-16le')
            return decoded
        except:
            return command_line
    return command_line

def correlate_logon_process_events(logon_file, process_file):
    """Correlate logon events with process execution"""
    
    # Load logon events
    logon_df = pd.read_csv(logon_file)
    logon_df['timestamp'] = pd.to_datetime(logon_df['timestamp'])
    
    # Load process events
    process_events = extract_process_events(process_file)
    process_df = pd.DataFrame(process_events)
    process_df['timestamp'] = pd.to_datetime(process_df['timestamp'])
    
    # Decode PowerShell commands
    process_df['decoded_command'] = process_df['command_line'].apply(decode_powershell_command)
    
    correlations = []
    
    # Find process events within 10 minutes of logon events
    for _, logon in logon_df.iterrows():
        if logon['event_type'] == 'Successful Logon':
            time_window_start = logon['timestamp']
            time_window_end = logon['timestamp'] + timedelta(minutes=10)
            
            related_processes = process_df[
                (process_df['timestamp'] >= time_window_start) &
                (process_df['timestamp'] <= time_window_end) &
                (process_df['username'] == logon['username']) &
                (process_df['workstation'] == logon['workstation'])
            ]
            
            for _, process in related_processes.iterrows():
                correlation = {
                    'logon_time': logon['timestamp'],
                    'process_time': process['timestamp'],
                    'username': logon['username'],
                    'workstation': logon['workstation'],
                    'logon_type': logon['logon_type'],
                    'source_ip': logon['source_ip'],
                    'process_name': process['process_name'],
                    'command_line': process['command_line'],
                    'decoded_command': process['decoded_command'],
                    'time_diff_seconds': (process['timestamp'] - logon['timestamp']).total_seconds(),
                    'suspicious_indicators': analyze_suspicious_activity(process)
                }
                correlations.append(correlation)
    
    return correlations

def analyze_suspicious_activity(process):
    """Identify suspicious process execution patterns"""
    indicators = []
    
    command_line = process.get('decoded_command', '').lower()
    process_name = process.get('process_name', '').lower()
    
    # Check for suspicious commands
    suspicious_commands = [
        'net user', 'net localgroup', 'whoami', 'systeminfo',
        'tasklist', 'netstat', 'ipconfig', 'start-sleep',
        'invoke-expression', 'downloadstring', 'powershell -enc'
    ]
    
    for cmd in suspicious_commands:
        if cmd in command_line:
            indicators.append(f"Suspicious command: {cmd}")
    
    # Check for administrative tools
    admin_tools = ['net.exe', 'powershell.exe', 'cmd.exe', 'wmic.exe']
    for tool in admin_tools:
        if tool in process_name:
            indicators.append(f"Administrative tool: {tool}")
    
    # Check for encoded commands
    if '-enc' in command_line:
        indicators.append("Base64 encoded PowerShell command")
    
    return '; '.join(indicators) if indicators else 'None detected'

def main():
    print("Correlating logon and process execution events...")
    
    correlations = correlate_logon_process_events(
        'extracted_logon_events.csv',
        'sample_process_events.json'
    )
    
    if correlations:
        df = pd.DataFrame(correlations)
        df = df.sort_values('logon_time')
        
        print(f"\nFound {len(correlations)} correlations:")
        for _, corr in df.iterrows():
            print(f"\n--- Correlation ---")
            print(f"User: {corr['username']} on {corr['workstation']}")
            print(f"Logon: {corr['logon_time']} (Type: {corr['logon_type']}, IP: {corr['source_ip']})")
            print(f"Process: {corr['process_time']} (+{corr['time_diff_seconds']:.0f}s)")
            print(f"Command: {corr['decoded_command']}")
            print(f"Suspicious: {corr['suspicious_indicators']}")
        
        # Save correlations
        df.to_csv('logon_process_correlations.csv', index=False)
        print(f"\nCorrelations saved to logon_process_correlations.csv")
    else:
        print("No correlations found.")

if __name__ == "__main__":
    main()
