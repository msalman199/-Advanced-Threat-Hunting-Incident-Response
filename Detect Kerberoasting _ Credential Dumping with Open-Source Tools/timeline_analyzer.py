#!/usr/bin/env python3
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import json

class TimelineAnalyzer:
    def __init__(self):
        self.timeline_events = []
    
    def load_correlation_data(self):
        """Load data from correlation analysis"""
        try:
            with open('correlation_results.json', 'r') as f:
                data = json.load(f)
            print("Loaded correlation data successfully")
            return data
        except FileNotFoundError:
            print("No correlation data found. Run event correlator first.")
            return None
    
    def create_attack_timeline(self):
        """Create attack progression timeline"""
        print("=== ATTACK TIMELINE ANALYSIS ===")
        
        # Simulate attack progression
        base_time = datetime.now() - timedelta(minutes=10)
        
        timeline = [
            {'time': base_time, 'event': 'Initial reconnaissance', 'severity': 'LOW'},
            {'time': base_time + timedelta(minutes=2), 'event': 'SPN enumeration', 'severity': 'MEDIUM'},
            {'time': base_time + timedelta(minutes=4), 'event': 'TGS requests initiated', 'severity': 'MEDIUM'},
            {'time': base_time + timedelta(minutes=6), 'event': 'Credential dumping attempt', 'severity': 'HIGH'},
            {'time': base_time + timedelta(minutes=8), 'event': 'LSASS access detected', 'severity': 'HIGH'},
            {'time': base_time + timedelta(minutes=10), 'event': 'Hash extraction completed', 'severity': 'CRITICAL'}
        ]
        
        print("Attack Progression Timeline:")
        for event in timeline:
            print(f"{event['time'].strftime('%H:%M:%S')} [{event['severity']}] {event['event']}")
        
        return timeline
    
    def analyze_attack_velocity(self, timeline):
        """Analyze attack progression speed"""
        print(f"\n=== ATTACK VELOCITY ANALYSIS ===")
        
        if len(timeline) < 2:
            print("Insufficient data for velocity analysis")
            return
        
        total_time = (timeline[-1]['time'] - timeline[0]['time']).seconds
        event_count = len(timeline)
        
        print(f"Total attack duration: {total_time} seconds")
        print(f"Total events: {event_count}")
        print(f"Average time between events: {total_time / (event_count - 1):.1f} seconds")
        
        # Analyze escalation pattern
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        escalation_rate = 0
        
        for i in range(1, len(timeline)):
            current_severity = severity_levels.get(timeline[i]['severity'], 0)
            previous_severity = severity_levels.get(timeline[i-1]['severity'], 0)
            if current_severity > previous_severity:
                escalation_rate += 1
        
        print(f"Escalation events: {escalation_rate}")
        print(f"Escalation rate: {(escalation_rate / (event_count - 1)) * 100:.1f}%")

if __name__ == "__main__":
    analyzer = TimelineAnalyzer()
    correlation_data = analyzer.load_correlation_data()
    timeline = analyzer.create_attack_timeline()
    analyzer.analyze_attack_velocity(timeline)
