#!/usr/bin/env python3
import json
from datetime import datetime, timedelta
from collections import defaultdict

class EventCorrelator:
    def __init__(self):
        self.events = []
        self.attack_patterns = {
            'kerberoasting': {
                'indicators': ['RC4-HMAC', 'bulk_tgs_requests', 'spn_enumeration'],
                'threshold': 2,
                'timeframe': 300  # 5 minutes
            },
            'credential_dumping': {
                'indicators': ['lsass_access', 'memory_dump', 'suspicious_process'],
                'threshold': 2,
                'timeframe': 180  # 3 minutes
            }
        }
    
    def add_event(self, event_type, description, severity='MEDIUM'):
        """Add security event to correlation engine"""
        event = {
            'timestamp': datetime.now(),
            'type': event_type,
            'description': description,
            'severity': severity
        }
        self.events.append(event)
    
    def simulate_events(self):
        """Generate simulated security events"""
        print("=== GENERATING SIMULATED EVENTS ===")
        
        # Simulate Kerberoasting events
        self.add_event('spn_enumeration', 'SPN enumeration detected', 'LOW')
        self.add_event('bulk_tgs_requests', 'Multiple TGS requests from 192.168.1.100', 'MEDIUM')
        self.add_event('RC4-HMAC', 'RC4 encryption in service tickets', 'HIGH')
        
        # Simulate credential dumping events
        self.add_event('suspicious_process', 'mimikatz.exe detected', 'HIGH')
        self.add_event('lsass_access', 'Unusual LSASS memory access', 'HIGH')
        self.add_event('memory_dump', 'Memory dump file created', 'MEDIUM')
        
        print(f"Generated {len(self.events)} security events")
    
    def correlate_events(self):
        """Correlate events to detect attack patterns"""
        print("\n=== EVENT CORRELATION ANALYSIS ===")
        
        detected_attacks = []
        
        for attack_name, pattern in self.attack_patterns.items():
            matching_events = []
            
            # Find events matching attack indicators
            for event in self.events:
                for indicator in pattern['indicators']:
                    if indicator in event['type'] or indicator in event['description'].lower():
                        matching_events.append(event)
                        break
            
            # Check if threshold is met within timeframe
            if len(matching_events) >= pattern['threshold']:
                # Check timeframe
                if matching_events:
                    time_diff = (matching_events[-1]['timestamp'] - matching_events[0]['timestamp']).seconds
                    if time_diff <= pattern['timeframe']:
                        detected_attacks.append({
                            'attack_type': attack_name,
                            'confidence': min(100, (len(matching_events) / pattern['threshold']) * 50),
                            'events': matching_events,
                            'timeframe': time_diff
                        })
        
        return detected_attacks
    
    def generate_correlation_report(self):
        """Generate correlation analysis report"""
        attacks = self.correlate_events()
        
        print(f"\n=== ATTACK CORRELATION REPORT ===")
        print(f"Analysis completed at: {datetime.now()}")
        print(f"Total events analyzed: {len(self.events)}")
        print(f"Potential attacks detected: {len(attacks)}")
        
        for attack in attacks:
            print(f"\n🚨 ATTACK DETECTED: {attack['attack_type'].upper()}")
            print(f"Confidence Level: {attack['confidence']:.1f}%")
            print(f"Timeframe: {attack['timeframe']} seconds")
            print("Contributing Events:")
            
            for event in attack['events']:
                print(f"  - [{event['severity']}] {event['type']}: {event['description']}")
                print(f"    Time: {event['timestamp'].strftime('%H:%M:%S')}")
    
    def export_results(self):
        """Export correlation results to JSON"""
        attacks = self.correlate_events()
        
        export_data = {
            'analysis_time': datetime.now().isoformat(),
            'total_events': len(self.events),
            'detected_attacks': []
        }
        
        for attack in attacks:
            attack_data = {
                'type': attack['attack_type'],
                'confidence': attack['confidence'],
                'timeframe': attack['timeframe'],
                'event_count': len(attack['events'])
            }
            export_data['detected_attacks'].append(attack_data)
        
        with open('correlation_results.json', 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\nResults exported to correlation_results.json")

if __name__ == "__main__":
    correlator = EventCorrelator()
    correlator.simulate_events()
    correlator.generate_correlation_report()
    correlator.export_results()
