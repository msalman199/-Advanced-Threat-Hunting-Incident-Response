#!/usr/bin/env python3
import json
import re
from collections import defaultdict

class WMIAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.wmi_events = []
        self.abuse_patterns = {
            'process_enumeration': r'SELECT.*FROM.*Win32_Process',
            'service_enumeration': r'SELECT.*FROM.*Win32_Service',
            'system_info': r'SELECT.*FROM.*Win32_ComputerSystem',
            'user_enumeration': r'SELECT.*FROM.*Win32_UserAccount',
            'network_enumeration': r'SELECT.*FROM.*Win32_NetworkAdapter'
        }
    
    def load_events(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if 'WMI' in event.get('provider', ''):
                        self.wmi_events.append(event)
                except:
                    continue
    
    def analyze_abuse_patterns(self):
        print("=== WMI Abuse Analysis ===\n")
        
        pattern_counts = defaultdict(int)
        suspicious_events = []
        
        for event in self.wmi_events:
            command = event.get('command_line', '')
            
            for pattern_name, pattern in self.abuse_patterns.items():
                if re.search(pattern, command, re.IGNORECASE):
                    pattern_counts[pattern_name] += 1
                    
                    if event.get('suspicious', False):
                        suspicious_events.append({
                            'timestamp': event['timestamp'],
                            'pattern': pattern_name,
                            'command': command,
                            'user': event.get('user', 'Unknown')
                        })
        
        print("Pattern Detection Summary:")
        for pattern, count in pattern_counts.items():
            print(f"  {pattern}: {count} occurrences")
        
        print(f"\nSuspicious WMI Events Found: {len(suspicious_events)}")
        for event in suspicious_events:
            print(f"\n  Timestamp: {event['timestamp']}")
            print(f"  Pattern: {event['pattern']}")
            print(f"  User: {event['user']}")
            print(f"  Command: {event['command']}")
    
    def detect_anomalies(self):
        print("\n=== WMI Anomaly Detection ===\n")
        
        user_activity = defaultdict(int)
        time_patterns = defaultdict(int)
        
        for event in self.wmi_events:
            user_activity[event.get('user', 'Unknown')] += 1
            hour = event['timestamp'].split('T')[1].split(':')[0]
            time_patterns[hour] += 1
        
        print("User Activity Analysis:")
        for user, count in sorted(user_activity.items(), key=lambda x: x[1], reverse=True):
            if count > 5:  # Threshold for suspicious activity
                print(f"  ⚠️  {user}: {count} WMI queries (HIGH)")
            else:
                print(f"  ✓  {user}: {count} WMI queries")
        
        print("\nTime-based Analysis:")
        for hour, count in sorted(time_patterns.items()):
            if count > 10:
                print(f"  ⚠️  Hour {hour}: {count} queries (SPIKE)")
            else:
                print(f"  ✓  Hour {hour}: {count} queries")

if __name__ == "__main__":
    analyzer = WMIAnalyzer('etw_events.json')
    analyzer.load_events()
    analyzer.analyze_abuse_patterns()
    analyzer.detect_anomalies()
