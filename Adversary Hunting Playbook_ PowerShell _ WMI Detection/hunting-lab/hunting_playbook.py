#!/usr/bin/env python3
import json
import re
from datetime import datetime
from collections import defaultdict, Counter

class ComprehensiveHunter:
    def __init__(self):
        # Initialize both hunters
        self.powershell_patterns = {
            'malicious': [
                r'Invoke-WebRequest.*http',
                r'DownloadString',
                r'ExecutionPolicy\s+Bypass',
                r'WindowStyle\s+Hidden',
                r'EncodedCommand',
                r'IEX\s*\(',
                r'System\.Net\.WebClient'
            ],
            'recon': [
                r'Get-Process',
                r'Get-WmiObject',
                r'Get-NetTCPConnection',
                r'Get-Service',
                r'whoami',
                r'net\s+user'
            ]
        }
        
        self.wmi_suspicious_classes = [
            'Win32_Process', 'Win32_Service', 'Win32_StartupCommand',
            'Win32_LoggedOnUser', 'Win32_NetworkAdapterConfiguration'
        ]
    
    def analyze_timeline(self, all_events):
        """Analyze events for temporal patterns"""
        timeline_analysis = {
            'rapid_succession': [],
            'user_patterns': defaultdict(list),
            'host_patterns': defaultdict(list)
        }
        
        # Sort events by timestamp
        sorted_events = sorted(all_events, key=lambda x: x.get('timestamp', ''))
        
        # Check for rapid succession attacks
        for i in range(len(sorted_events) - 1):
            current = sorted_events[i]
            next_event = sorted_events[i + 1]
            
            if (current.get('user') == next_event.get('user') and 
                current.get('severity', 'LOW') in ['HIGH', 'CRITICAL']):
                timeline_analysis['rapid_succession'].append({
                    'user': current.get('user'),
                    'events': [current, next_event]
                })
        
        # Group by user and host
        for event in all_events:
            user = event.get('user', 'unknown')
            host = event.get('host', 'unknown')
            timeline_analysis['user_patterns'][user].append(event)
            timeline_analysis['host_patterns'][host].append(event)
        
        return timeline_analysis
    
    def correlate_events(self, powershell_events, wmi_events):
        """Correlate PowerShell and WMI events for advanced threats"""
        correlations = []
        
        # Combine all events
        all_events = powershell_events + wmi_events
        
        # Look for same user/host combinations
        user_host_combos = defaultdict(list)
        for event in all_events:
            key = f"{event.get('user', 'unknown')}@{event.get('host', 'unknown')}"
            user_host_combos[key].append(event)
        
        # Find suspicious correlations
        for combo, events in user_host_combos.items():
            if len(events) > 1:
                has_powershell = any('powershell' in event.get('type', '') for event in events)
                has_wmi = any('wmi' in event.get('type', '') for event in events)
                
                if has_powershell and has_wmi:
                    correlations.append({
                        'user_host': combo,
                        'events': events,
                        'correlation_type': 'PowerShell + WMI',
                        'risk_level': 'HIGH'
                    })
        
        return correlations
    
    def generate_hunting_report(self, powershell_file, wmi_file):
        """Generate comprehensive hunting report"""
        # Process PowerShell logs
        powershell_events = []
        try:
            with open(powershell_file, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        command = log_entry.get('command', '')
                        alerts = []
                        
                        for category, patterns in self.powershell_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, command, re.IGNORECASE):
                                    alerts.append(f"{category.upper()}: {pattern}")
                        
                        if alerts:
                            event = log_entry.copy()
                            event['alerts'] = alerts
                            event['type'] = 'powershell'
                            event['severity'] = 'HIGH' if any('MALICIOUS' in alert for alert in alerts) else 'MEDIUM'
                            powershell_events.append(event)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"Warning: {powershell_file} not found")
        
        # Process WMI logs
        wmi_events = []
        try:
            with open(wmi_file, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        query = log_entry.get('query', '')
                        alerts = []
                        
                        for wmi_class in self.wmi_suspicious_classes:
                            if wmi_class in query:
                                alerts.append(f"WMI_CLASS: {wmi_class}")
                        
                        if alerts:
                            event = log_entry.copy()
                            event['alerts'] = alerts
                            event['type'] = 'wmi'
                            event['severity'] = 'MEDIUM'
                            wmi_events.append(event)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"Warning: {wmi_file} not found")
        
        # Perform analysis
        timeline_analysis = self.analyze_timeline(powershell_events + wmi_events)
        correlations = self.correlate_events(powershell_events, wmi_events)
        
        # Generate report
        print("=" * 60)
        print("COMPREHENSIVE THREAT HUNTING REPORT")
        print("=" * 60)
        
        print(f"\nEVENT SUMMARY:")
        print(f"PowerShell Events: {len(powershell_events)}")
        print(f"WMI Events: {len(wmi_events)}")
        print(f"Total Events: {len(powershell_events + wmi_events)}")
        
        print(f"\nCORRELATIONS FOUND: {len(correlations)}")
        for correlation in correlations:
            print(f"\n  User/Host: {correlation['user_host']}")
            print(f"  Type: {correlation['correlation_type']}")
            print(f"  Risk Level: {correlation['risk_level']}")
            print(f"  Events: {len(correlation['events'])}")
        
        print(f"\nRAPID SUCCESSION ATTACKS: {len(timeline_analysis['rapid_succession'])}")
        for attack in timeline_analysis['rapid_succession']:
            print(f"  User: {attack['user']} - {len(attack['events'])} events")
        
        print(f"\nTOP ACTIVE USERS:")
        user_counts = Counter()
        for events in timeline_analysis['user_patterns'].values():
            for event in events:
                user_counts[event.get('user', 'unknown')] += 1
        
        for user, count in user_counts.most_common(5):
            print(f"  {user}: {count} events")
        
        print(f"\nTOP ACTIVE HOSTS:")
        host_counts = Counter()
        for events in timeline_analysis['host_patterns'].values():
            for event in events:
                host_counts[event.get('host', 'unknown')] += 1
        
        for host, count in host_counts.most_common(5):
            print(f"  {host}: {count} events")
        
        # Detailed event listing
        print(f"\nDETAILED EVENTS:")
        all_events = sorted(powershell_events + wmi_events, 
                          key=lambda x: x.get('timestamp', ''))
        
        for event in all_events:
            print(f"\n  Timestamp: {event.get('timestamp')}")
            print(f"  Type: {event.get('type', 'unknown').upper()}")
            print(f"  Host: {event.get('host')}")
            print(f"  User: {event.get('user')}")
            print(f"  Severity: {event.get('severity')}")
            if event.get('command'):
                print(f"  Command: {event.get('command')[:100]}...")
            if event.get('query'):
                print(f"  Query: {event.get('query')}")
            print(f"  Alerts: {', '.join(event.get('alerts', []))}")

if __name__ == "__main__":
    hunter = ComprehensiveHunter()
    hunter.generate_hunting_report('powershell_logs.json', 'wmi_logs.json')
