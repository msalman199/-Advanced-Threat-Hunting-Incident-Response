#!/usr/bin/env python3
import json
import re
from collections import defaultdict

class WMIHunter:
    def __init__(self):
        self.suspicious_classes = [
            'Win32_Process',
            'Win32_Service',
            'Win32_StartupCommand',
            'Win32_LoggedOnUser',
            'Win32_NetworkAdapterConfiguration',
            'Win32_ComputerSystem',
            'Win32_OperatingSystem',
            'Win32_UserAccount',
            'Win32_Group'
        ]
        
        self.high_risk_queries = [
            r'Win32_Process.*WHERE.*CommandLine',
            r'Win32_Service.*WHERE.*State',
            r'Win32_StartupCommand',
            r'Win32_LoggedOnUser',
            r'Win32_NetworkAdapter.*WHERE.*IPEnabled'
        ]
    
    def analyze_wmi_query(self, query, process, user):
        alerts = []
        risk_score = 0
        
        # Check for suspicious WMI classes
        for wmi_class in self.suspicious_classes:
            if wmi_class in query:
                alerts.append(f"WMI_CLASS: {wmi_class}")
                risk_score += 1
        
        # Check for high-risk query patterns
        for pattern in self.high_risk_queries:
            if re.search(pattern, query, re.IGNORECASE):
                alerts.append(f"HIGH_RISK_QUERY: {pattern}")
                risk_score += 2
        
        # Check for suspicious processes
        if process.lower() in ['powershell.exe', 'cmd.exe', 'wmic.exe']:
            alerts.append(f"SUSPICIOUS_PROCESS: {process}")
            risk_score += 1
        
        # Determine severity
        if risk_score >= 4:
            severity = 'CRITICAL'
        elif risk_score >= 2:
            severity = 'HIGH'
        else:
            severity = 'MEDIUM'
        
        return alerts, severity, risk_score
    
    def hunt_wmi_logs(self, log_file):
        detections = []
        user_activity = defaultdict(int)
        host_activity = defaultdict(int)
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    query = log_entry.get('query', '')
                    process = log_entry.get('process', '')
                    user = log_entry.get('user', '')
                    host = log_entry.get('host', '')
                    
                    # Track activity patterns
                    user_activity[user] += 1
                    host_activity[host] += 1
                    
                    alerts, severity, risk_score = self.analyze_wmi_query(query, process, user)
                    
                    if alerts:
                        detection = {
                            'timestamp': log_entry.get('timestamp'),
                            'host': host,
                            'user': user,
                            'process': process,
                            'query': query,
                            'namespace': log_entry.get('namespace'),
                            'alerts': alerts,
                            'severity': severity,
                            'risk_score': risk_score
                        }
                        detections.append(detection)
                        
                except json.JSONDecodeError:
                    continue
        
        return detections, user_activity, host_activity
    
    def generate_summary(self, detections, user_activity, host_activity):
        print("\n=== WMI Activity Summary ===")
        print(f"Total Detections: {len(detections)}")
        
        severity_counts = defaultdict(int)
        for detection in detections:
            severity_counts[detection['severity']] += 1
        
        print("\nSeverity Distribution:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        print("\nTop Active Users:")
        for user, count in sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {user}: {count} queries")
        
        print("\nTop Active Hosts:")
        for host, count in sorted(host_activity.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {host}: {count} queries")

if __name__ == "__main__":
    hunter = WMIHunter()
    detections, user_activity, host_activity = hunter.hunt_wmi_logs('wmi_logs.json')
    
    print("=== WMI Threat Hunting Results ===")
    for detection in detections:
        print(f"\nTimestamp: {detection['timestamp']}")
        print(f"Host: {detection['host']}")
        print(f"User: {detection['user']}")
        print(f"Process: {detection['process']}")
        print(f"Severity: {detection['severity']} (Risk Score: {detection['risk_score']})")
        print(f"Query: {detection['query']}")
        print(f"Namespace: {detection['namespace']}")
        print("Alerts:")
        for alert in detection['alerts']:
            print(f"  - {alert}")
    
    hunter.generate_summary(detections, user_activity, host_activity)
