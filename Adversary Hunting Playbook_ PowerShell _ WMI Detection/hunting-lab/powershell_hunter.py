#!/usr/bin/env python3
import json
import re
from datetime import datetime

class PowerShellHunter:
    def __init__(self):
        self.suspicious_patterns = [
            r'Invoke-WebRequest.*http',
            r'DownloadString',
            r'ExecutionPolicy\s+Bypass',
            r'WindowStyle\s+Hidden',
            r'EncodedCommand',
            r'IEX\s*\(',
            r'powershell.*-c.*http',
            r'System\.Net\.WebClient'
        ]
        
        self.recon_patterns = [
            r'Get-Process',
            r'Get-WmiObject',
            r'Get-NetTCPConnection',
            r'Get-Service',
            r'whoami',
            r'net\s+user',
            r'Get-LocalUser'
        ]
    
    def analyze_command(self, command):
        alerts = []
        
        # Check for malicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                alerts.append(f"MALICIOUS: {pattern}")
        
        # Check for reconnaissance patterns
        for pattern in self.recon_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                alerts.append(f"RECON: {pattern}")
        
        return alerts
    
    def hunt_logs(self, log_file):
        detections = []
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    command = log_entry.get('command', '')
                    alerts = self.analyze_command(command)
                    
                    if alerts:
                        detection = {
                            'timestamp': log_entry.get('timestamp'),
                            'host': log_entry.get('host'),
                            'user': log_entry.get('user'),
                            'command': command,
                            'alerts': alerts,
                            'severity': 'HIGH' if any('MALICIOUS' in alert for alert in alerts) else 'MEDIUM'
                        }
                        detections.append(detection)
                        
                except json.JSONDecodeError:
                    continue
        
        return detections

if __name__ == "__main__":
    hunter = PowerShellHunter()
    detections = hunter.hunt_logs('powershell_logs.json')
    
    print("=== PowerShell Threat Hunting Results ===")
    for detection in detections:
        print(f"\nTimestamp: {detection['timestamp']}")
        print(f"Host: {detection['host']}")
        print(f"User: {detection['user']}")
        print(f"Severity: {detection['severity']}")
        print(f"Command: {detection['command']}")
        print("Alerts:")
        for alert in detection['alerts']:
            print(f"  - {alert}")
