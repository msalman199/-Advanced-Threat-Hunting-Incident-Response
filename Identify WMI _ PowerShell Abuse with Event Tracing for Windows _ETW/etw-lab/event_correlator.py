#!/usr/bin/env python3
import json
import datetime
from collections import defaultdict

class EventCorrelator:
    def __init__(self, log_file):
        self.log_file = log_file
        self.events = []
        self.correlation_rules = {
            'wmi_powershell_combo': {
                'description': 'WMI query followed by PowerShell execution',
                'time_window': 300,  # 5 minutes
                'severity': 'HIGH'
            },
            'multiple_wmi_queries': {
                'description': 'Multiple WMI queries from same user',
                'count_threshold': 5,
                'time_window': 600,  # 10 minutes
                'severity': 'MEDIUM'
            },
            'powershell_download_execution': {
                'description': 'PowerShell download and execution pattern',
                'time_window': 60,  # 1 minute
                'severity': 'CRITICAL'
            }
        }
    
    def load_events(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    # Parse timestamp
                    event['parsed_time'] = datetime.datetime.fromisoformat(event['timestamp'])
                    self.events.append(event)
                except:
                    continue
        
        # Sort events by timestamp
        self.events.sort(key=lambda x: x['parsed_time'])
    
    def correlate_wmi_powershell(self):
        print("=== WMI-PowerShell Correlation Analysis ===\n")
        
        correlations = []
        wmi_events = [e for e in self.events if 'WMI' in e.get('provider', '')]
        ps_events = [e for e in self.events if 'PowerShell' in e.get('provider', '')]
        
        for wmi_event in wmi_events:
            for ps_event in ps_events:
                time_diff = abs((ps_event['parsed_time'] - wmi_event['parsed_time']).total_seconds())
                
                if (time_diff <= self.correlation_rules['wmi_powershell_combo']['time_window'] and
                    wmi_event.get('user') == ps_event.get('user')):
                    
                    correlations.append({
                        'type': 'wmi_powershell_combo',
                        'wmi_event': wmi_event,
                        'ps_event': ps_event,
                        'time_diff': time_diff,
                        'user': wmi_event.get('user'),
                        'severity': 'HIGH'
                    })
        
        print(f"WMI-PowerShell Correlations Found: {len(correlations)}")
        for corr in correlations:
            print(f"\n  🔗 Correlation Alert - {corr['severity']}")
            print(f"     User: {corr['user']}")
            print(f"     Time Gap: {corr['time_diff']:.1f} seconds")
            print(f"     WMI Query: {corr['wmi_event'].get('command_line', 'N/A')[:80]}...")
            print(f"     PowerShell: {corr['ps_event'].get('script_block', 'N/A')[:80]}...")
    
    def detect_attack_chains(self):
        print("\n=== Attack Chain Detection ===\n")
        
        user_timelines = defaultdict(list)
        
        # Group events by user
        for event in self.events:
            user = event.get('user', 'Unknown')
            user_timelines[user].append(event)
        
        attack_chains = []
        
        for user, timeline in user_timelines.items():
            if len(timeline) < 3:  # Need at least 3 events for a chain
                continue
            
            # Look for suspicious patterns
            suspicious_events = [e for e in timeline if e.get('suspicious', False)]
            
            if len(suspicious_events) >= 2:
                # Check if events are within a reasonable time window
                first_event = suspicious_events[0]
                last_event = suspicious_events[-1]
                time_span = (last_event['parsed_time'] - first_event['parsed_time']).total_seconds()
                
                if time_span <= 1800:  # 30 minutes
                    attack_chains.append({
                        'user': user,
                        'events': suspicious_events,
                        'time_span': time_span,
                        'severity': 'CRITICAL' if len(suspicious_events) >= 3 else 'HIGH'
                    })
        
        print(f"Attack Chains Detected: {len(attack_chains)}")
        for chain in attack_chains:
            print(f"\n  🚨 Attack Chain - {chain['severity']}")
            print(f"     User: {chain['user']}")
            print(f"     Duration: {chain['time_span']:.1f} seconds")
            print(f"     Events in Chain: {len(chain['events'])}")
            
            for i, event in enumerate(chain['events'], 1):
                print(f"       {i}. {event['provider']} - {event.get('event_id')}")
                if 'command_line' in event:
                    print(f"          Command: {event['command_line'][:60]}...")
                if 'script_block' in event:
                    print(f"          Script: {event['script_block'][:60]}...")
    
    def generate_threat_report(self):
        print("\n=== Threat Intelligence Report ===\n")
        
        total_events = len(self.events)
        suspicious_events = len([e for e in self.events if e.get('suspicious', False)])
        
        providers = defaultdict(int)
        users = defaultdict(int)
        
        for event in self.events:
            providers[event.get('provider', 'Unknown')] += 1
            users[event.get('user', 'Unknown')] += 1
        
        print(f"Total Events Analyzed: {total_events}")
        print(f"Suspicious Events: {suspicious_events} ({suspicious_events/total_events*100:.1f}%)")
        
        print("\nTop Event Providers:")
        for provider, count in sorted(providers.items(), key=lambda x: x[1], reverse=True):
            print(f"  {provider}: {count} events")
        
        print("\nUser Activity Summary:")
        for user, count in sorted(users.items(), key=lambda x: x[1], reverse=True):
            risk_level = "HIGH" if count > 10 else "MEDIUM" if count > 5 else "LOW"
            print(f"  {user}: {count} events ({risk_level} risk)")
        
        # Calculate risk score
        risk_score = (suspicious_events / total_events) * 100 if total_events > 0 else 0
        risk_level = "CRITICAL" if risk_score > 40 else "HIGH" if risk_score > 20 else "MEDIUM" if risk_score > 10 else "LOW"
        
        print(f"\nOverall Risk Assessment: {risk_level} ({risk_score:.1f}% suspicious activity)")

if __name__ == "__main__":
    correlator = EventCorrelator('etw_events.json')
    correlator.load_events()
    correlator.correlate_wmi_powershell()
    correlator.detect_attack_chains()
    correlator.generate_threat_report()
