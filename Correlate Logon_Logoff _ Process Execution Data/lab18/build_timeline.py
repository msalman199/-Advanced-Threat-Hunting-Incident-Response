#!/usr/bin/env python3
import pandas as pd
import json
from datetime import datetime

def create_comprehensive_timeline():
    """Create a comprehensive timeline of all user activities"""
    
    # Load all event data
    logon_df = pd.read_csv('extracted_logon_events.csv')
    correlations_df = pd.read_csv('logon_process_correlations.csv')
    
    # Convert timestamps
    logon_df['timestamp'] = pd.to_datetime(logon_df['timestamp'])
    correlations_df['logon_time'] = pd.to_datetime(correlations_df['logon_time'])
    correlations_df['process_time'] = pd.to_datetime(correlations_df['process_time'])
    
    timeline_events = []
    
    # Add logon/logoff events to timeline
    for _, event in logon_df.iterrows():
        timeline_event = {
            'timestamp': event['timestamp'],
            'event_category': 'Authentication',
            'event_type': event['event_type'],
            'username': event['username'],
            'workstation': event['workstation'],
            'source_ip': event['source_ip'],
            'details': f"Logon Type: {event['logon_type']}",
            'risk_level': calculate_auth_risk(event)
        }
        timeline_events.append(timeline_event)
    
    # Add process execution events to timeline
    for _, corr in correlations_df.iterrows():
        timeline_event = {
            'timestamp': corr['process_time'],
            'event_category': 'Process Execution',
            'event_type': 'Command Execution',
            'username': corr['username'],
            'workstation': corr['workstation'],
            'source_ip': corr['source_ip'],
            'details': corr['decoded_command'],
            'risk_level': calculate_process_risk(corr['suspicious_indicators'])
        }
        timeline_events.append(timeline_event)
    
    # Create timeline DataFrame
    timeline_df = pd.DataFrame(timeline_events)
    timeline_df = timeline_df.sort_values('timestamp')
    
    return timeline_df

def calculate_auth_risk(event):
    """Calculate risk level for authentication events"""
    if event['event_type'] == 'Failed Logon':
        return 'Medium'
    elif event['logon_type'] == 3 and event['event_type'] == 'Successful Logon':
        return 'Medium'  # Network logon
    elif 'admin' in str(event['username']).lower():
        return 'High'
    else:
        return 'Low'

def calculate_process_risk(suspicious_indicators):
    """Calculate risk level for process execution"""
    if suspicious_indicators == 'None detected':
        return 'Low'
    elif 'net user' in suspicious_indicators or 'powershell' in suspicious_indicators:
        return 'High'
    else:
        return 'Medium'

def generate_timeline_report(timeline_df):
    """Generate a comprehensive timeline report"""
    
    print("=== SUSPICIOUS USER ACTIVITY TIMELINE ===\n")
    
    # Group by user for analysis
    users = timeline_df['username'].unique()
    
    for user in users:
        user_events = timeline_df[timeline_df['username'] == user].sort_values('timestamp')
        
        print(f"USER: {user}")
        print("-" * 50)
        
        high_risk_count = len(user_events[user_events['risk_level'] == 'High'])
        medium_risk_count = len(user_events[user_events['risk_level'] == 'Medium'])
        
        print(f"Total Events: {len(user_events)}")
        print(f"High Risk Events: {high_risk_count}")
        print(f"Medium Risk Events: {medium_risk_count}")
        print()
        
        # Show timeline for this user
        for _, event in user_events.iterrows():
            risk_indicator = "🔴" if event['risk_level'] == 'High' else "🟡" if event['risk_level'] == 'Medium' else "🟢"
            print(f"{event['timestamp']} [{event['risk_level']}] {event['event_category']}: {event['event_type']}")
            print(f"  Workstation: {event['workstation']}")
            print(f"  Source IP: {event['source_ip']}")
            print(f"  Details: {event['details']}")
            print()
        
        print("=" * 70)
        print()

def identify_attack_patterns(timeline_df):
    """Identify potential attack patterns"""
    
    patterns = []
    
    # Group events by user and workstation
    for user in timeline_df['username'].unique():
        user_events = timeline_df[timeline_df['username'] == user].sort_values('timestamp')
        
        # Check for privilege escalation pattern
        auth_events = user_events[user_events['event_category'] == 'Authentication']
        process_events = user_events[user_events['event_category'] == 'Process Execution']
        
        if len(auth_events) > 0 and len(process_events) > 0:
            # Check for admin commands after logon
            admin_commands = process_events[process_events['details'].str.contains('net user|administrator', case=False, na=False)]
            
            if len(admin_commands) > 0:
                patterns.append({
                    'pattern_type': 'Privilege Escalation',
                    'user': user,
                    'description': f'User {user} executed administrative commands after logon',
                    'risk_level': 'High',
                    'events_count': len(admin_commands)
                })
        
        # Check for failed logon followed by successful logon
        failed_logons = auth_events[auth_events['event_type'] == 'Failed Logon']
        successful_logons = auth_events[auth_events['event_type'] == 'Successful Logon']
        
        if len(failed_logons) > 0 and len(successful_logons) > 0:
            patterns.append({
                'pattern_type': 'Brute Force Attempt',
                'user': user,
                'description': f'Failed logon attempts followed by successful logon for {user}',
                'risk_level': 'High',
                'events_count': len(failed_logons)
            })
    
    return patterns

def main():
    print("Building comprehensive timeline of suspicious user activity...")
    
    # Create timeline
    timeline_df = create_comprehensive_timeline()
    
    # Generate report
    generate_timeline_report(timeline_df)
    
    # Identify attack patterns
    patterns = identify_attack_patterns(timeline_df)
    
    if patterns:
        print("=== IDENTIFIED ATTACK PATTERNS ===\n")
        for pattern in patterns:
            print(f"Pattern: {pattern['pattern_type']}")
            print(f"User: {pattern['user']}")
            print(f"Risk Level: {pattern['risk_level']}")
            print(f"Description: {pattern['description']}")
            print(f"Related Events: {pattern['events_count']}")
            print("-" * 50)
    
    # Save timeline
    timeline_df.to_csv('suspicious_activity_timeline.csv', index=False)
    print(f"\nTimeline saved to suspicious_activity_timeline.csv")
    
    # Save patterns
    if patterns:
        with open('attack_patterns.json', 'w') as f:
            json.dump(patterns, f, indent=2, default=str)
        print("Attack patterns saved to attack_patterns.json")

if __name__ == "__main__":
    main()
