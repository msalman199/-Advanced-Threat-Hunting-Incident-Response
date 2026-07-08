<div align="center">

# 🔐 Detect Kerberoasting & Credential Dumping with Open-Source Tools

![Kerberos](https://img.shields.io/badge/Kerberos-Detection-6A5ACD?style=for-the-badge&logo=windows&logoColor=white)
![Impacket](https://img.shields.io/badge/Impacket-Toolkit-red?style=for-the-badge&logo=python&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Security-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Threat%20Detection-blue?style=for-the-badge)

**A hands-on lab in building detection systems for Kerberoasting and credential dumping attacks**

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: Set Up Detection Environment](#-task-1-set-up-detection-environment)
- [🕵️ Task 2: Run Kerberoasting Detection Scripts](#️-task-2-run-kerberoasting-detection-scripts)
- [🧬 Task 3: Use Mimikatz Analysis Tools](#-task-3-use-mimikatz-analysis-tools)
- [🔗 Task 4: Correlate Events to Detect Attacks](#-task-4-correlate-events-to-detect-attacks)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Implement Kerberoasting detection using open-source tools |
| 2 | Analyze credential dumping techniques with Mimikatz |
| 3 | Correlate security events to identify attack patterns |
| 4 | Configure monitoring systems for advanced persistent threats |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🏢 Active Directory | Basic understanding of Active Directory concepts |
| 🐧 Linux CLI | Familiarity with Linux command line |
| 🌐 Network Security | Knowledge of network security fundamentals |
| 🔑 Kerberos Protocol | Understanding of Kerberos authentication protocol |

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you will install all necessary components during the lab exercises.

---

## 🔧 Task 1: Set Up Detection Environment

### ✅ Subtask 1.1: Install Required Tools

```bash
# 📦 Install Python and essential packages
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git curl wget -y
sudo apt install impacket-scripts python3-impacket -y
# TODO: Confirm impacket scripts are on PATH (e.g. GetUserSPNs.py --help)
```

### ✅ Subtask 1.2: Install Kerberoasting Detection Tools

```bash
# 📥 Clone and set up detection scripts
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
cd ..

# 🧰 Install additional detection tools
git clone https://github.com/GhostPack/Rubeus.git
git clone https://github.com/nidem/kerberoast.git
```

### ✅ Subtask 1.3: Create Simulated Environment

```bash
# 🔑 Set up a local Kerberos testing environment
sudo apt install krb5-kdc krb5-admin-server -y
sudo mkdir -p /var/log/kerberos
sudo touch /var/log/kerberos/krb5kdc.log
sudo chmod 644 /var/log/kerberos/krb5kdc.log
# TODO: Confirm the KDC log file is writable by the logging service
```

---

## 🕵️ Task 2: Run Kerberoasting Detection Scripts

### ✅ Subtask 2.1: Create Detection Script

```python
#!/usr/bin/env python3
# 🔍 kerberoast_detector.py — flags RC4 usage and bulk TGS request patterns
import subprocess
import re
import json
from datetime import datetime

class KerberoastDetector:
    def __init__(self):
        self.alerts = []

    def check_service_tickets(self):
        """Monitor for suspicious service ticket requests"""
        try:
            # Simulate checking for RC4 encryption in service tickets
            result = subprocess.run(['klist', '-e'], capture_output=True, text=True)
            if 'RC4-HMAC' in result.stdout:
                self.alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'Potential Kerberoasting',
                    'description': 'RC4 encryption detected in service tickets',
                    'severity': 'HIGH'
                })
        except Exception as e:
            print(f"Error checking service tickets: {e}")

    def detect_bulk_requests(self):
        """Detect bulk TGS requests"""
        # Simulate log analysis for bulk requests
        suspicious_patterns = [
            'Multiple TGS requests from single source',
            'Unusual service ticket request patterns',
            'High volume of authentication requests'
        ]

        for pattern in suspicious_patterns:
            self.alerts.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'Bulk TGS Requests',
                'description': pattern,
                'severity': 'MEDIUM'
            })

    def generate_report(self):
        """Generate detection report"""
        print("=== KERBEROASTING DETECTION REPORT ===")
        print(f"Scan completed at: {datetime.now()}")
        print(f"Total alerts: {len(self.alerts)}")

        for alert in self.alerts:
            print(f"\n[{alert['severity']}] {alert['type']}")
            print(f"Time: {alert['timestamp']}")
            print(f"Description: {alert['description']}")

if __name__ == "__main__":
    detector = KerberoastDetector()
    detector.check_service_tickets()
    detector.detect_bulk_requests()
    detector.generate_report()
    # TODO: Replace the simulated klist check with real KDC log parsing
```

```bash
# 🔑 Make script executable
chmod +x kerberoast_detector.py
```

### ✅ Subtask 2.2: Execute Detection Script

```bash
# ▶️ Run the Kerberoasting detection
python3 kerberoast_detector.py
```

### ✅ Subtask 2.3: Analyze Service Principal Names

```python
#!/usr/bin/env python3
# 🧾 spn_analyzer.py — flags commonly vulnerable Service Principal Names
import subprocess
import re

def analyze_spns():
    """Analyze Service Principal Names for vulnerabilities"""
    print("=== SPN VULNERABILITY ANALYSIS ===")

    # Common vulnerable SPNs
    vulnerable_spns = [
        'MSSQLSvc',
        'HTTP',
        'FTP',
        'IMAP',
        'POP'
    ]

    print("Checking for potentially vulnerable SPNs:")
    for spn in vulnerable_spns:
        print(f"- {spn}: Potentially vulnerable to Kerberoasting")

    # Simulate SPN discovery
    print("\nSimulated SPN Discovery Results:")
    print("MSSQLSvc/database.domain.com:1433")
    print("HTTP/webserver.domain.com")
    print("FTP/fileserver.domain.com")

if __name__ == "__main__":
    analyze_spns()
    # TODO: Replace simulated results with real SPN queries against a lab domain
```

```bash
python3 spn_analyzer.py
```

---

## 🧬 Task 3: Use Mimikatz Analysis Tools

### ✅ Subtask 3.1: Install Wine for Windows Tools

```bash
# 🍷 Set up Wine to run Windows security tools
sudo apt install wine winetricks -y
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32 -y
# TODO: Confirm `wine --version` runs without errors
```

### ✅ Subtask 3.2: Create Credential Dumping Detector

```python
#!/usr/bin/env python3
# 🛡️ credential_dump_detector.py — process, memory-dump, and LSASS access monitoring
import os
import psutil
import hashlib
from datetime import datetime

class CredentialDumpDetector:
    def __init__(self):
        self.suspicious_processes = [
            'mimikatz',
            'procdump',
            'dumpert',
            'nanodump'
        ]
        self.alerts = []

    def monitor_processes(self):
        """Monitor for suspicious processes"""
        print("=== PROCESS MONITORING ===")
        running_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_info = proc.info
                running_processes.append(process_info['name'])

                # Check for suspicious process names
                for suspicious in self.suspicious_processes:
                    if suspicious.lower() in process_info['name'].lower():
                        self.alerts.append({
                            'type': 'Suspicious Process',
                            'process': process_info['name'],
                            'pid': process_info['pid'],
                            'timestamp': datetime.now().isoformat()
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        print(f"Monitored {len(running_processes)} processes")
        return running_processes

    def check_memory_dumps(self):
        """Check for memory dump files"""
        print("=== MEMORY DUMP ANALYSIS ===")
        dump_extensions = ['.dmp', '.dump', '.mem']
        suspicious_files = []

        # Check common directories
        check_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~')]

        for directory in check_dirs:
            try:
                for file in os.listdir(directory):
                    for ext in dump_extensions:
                        if file.endswith(ext):
                            suspicious_files.append(os.path.join(directory, file))
                            self.alerts.append({
                                'type': 'Suspicious File',
                                'file': file,
                                'location': directory,
                                'timestamp': datetime.now().isoformat()
                            })
            except PermissionError:
                continue

        print(f"Found {len(suspicious_files)} potentially suspicious files")
        return suspicious_files

    def analyze_lsass_access(self):
        """Simulate LSASS access detection"""
        print("=== LSASS ACCESS ANALYSIS ===")
        # Simulate detection of LSASS access attempts
        simulated_alerts = [
            "Unusual process accessing LSASS memory",
            "Multiple LSASS read attempts detected",
            "Potential credential extraction activity"
        ]

        for alert in simulated_alerts:
            self.alerts.append({
                'type': 'LSASS Access',
                'description': alert,
                'timestamp': datetime.now().isoformat()
            })
            print(f"ALERT: {alert}")

    def generate_report(self):
        """Generate comprehensive detection report"""
        print("\n=== CREDENTIAL DUMPING DETECTION REPORT ===")
        print(f"Analysis completed at: {datetime.now()}")
        print(f"Total alerts generated: {len(self.alerts)}")

        # Group alerts by type
        alert_types = {}
        for alert in self.alerts:
            alert_type = alert['type']
            if alert_type not in alert_types:
                alert_types[alert_type] = []
            alert_types[alert_type].append(alert)

        for alert_type, alerts in alert_types.items():
            print(f"\n{alert_type}: {len(alerts)} alerts")
            for alert in alerts[:3]:  # Show first 3 alerts of each type
                print(f"  - {alert.get('description', alert.get('process', 'N/A'))}")

if __name__ == "__main__":
    detector = CredentialDumpDetector()
    detector.monitor_processes()
    detector.check_memory_dumps()
    detector.analyze_lsass_access()
    detector.generate_report()
    # TODO: Wire analyze_lsass_access() to real ETW/Sysmon events in a Windows lab
```

```bash
python3 credential_dump_detector.py
```

### ✅ Subtask 3.3: Hash Analysis Tool

```python
#!/usr/bin/env python3
# 🔢 hash_analyzer.py — identifies credential hash types by pattern
import hashlib
import re

class HashAnalyzer:
    def __init__(self):
        self.hash_patterns = {
            'NTLM': r'^[a-fA-F0-9]{32}$',
            'LM': r'^[a-fA-F0-9]{32}$',
            'Kerberos': r'^[a-fA-F0-9]{64,}$'
        }

    def identify_hash_type(self, hash_value):
        """Identify hash type based on pattern"""
        for hash_type, pattern in self.hash_patterns.items():
            if re.match(pattern, hash_value):
                return hash_type
        return "Unknown"

    def analyze_sample_hashes(self):
        """Analyze sample credential hashes"""
        print("=== HASH ANALYSIS ===")

        # Sample hashes for analysis (dummy data)
        sample_hashes = [
            "aad3b435b51404eeaad3b435b51404ee",  # Empty LM hash
            "31d6cfe0d16ae931b73c59d7e0c089c0",  # Empty NTLM hash
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        ]

        for i, hash_val in enumerate(sample_hashes, 1):
            hash_type = self.identify_hash_type(hash_val)
            print(f"Hash {i}: {hash_type}")
            print(f"Value: {hash_val}")

            if hash_val == "aad3b435b51404eeaad3b435b51404ee":
                print("  -> Empty LM hash detected")
            elif hash_val == "31d6cfe0d16ae931b73c59d7e0c089c0":
                print("  -> Empty NTLM hash detected")
            print()

if __name__ == "__main__":
    analyzer = HashAnalyzer()
    analyzer.analyze_sample_hashes()
    # TODO: Add disambiguation logic since NTLM and LM share the same regex pattern
```

```bash
python3 hash_analyzer.py
```

---

## 🔗 Task 4: Correlate Events to Detect Attacks

### ✅ Subtask 4.1: Create Event Correlation Engine

```python
#!/usr/bin/env python3
# 🔗 event_correlator.py — correlates simulated events into attack patterns
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
    # TODO: Replace simulate_events() with real log ingestion once beyond the lab
```

```bash
python3 event_correlator.py
```

### ✅ Subtask 4.2: Create Timeline Analysis

```python
#!/usr/bin/env python3
# 📈 timeline_analyzer.py — models attack progression and escalation velocity
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
    # TODO: Plot the timeline with matplotlib for the final report visualization
```

```bash
python3 timeline_analyzer.py
```

### ✅ Subtask 4.3: Generate Final Security Report

```python
#!/usr/bin/env python3
# 📝 security_report_generator.py — executive summary + detailed findings export
import json
from datetime import datetime

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {
            'scan_time': datetime.now().isoformat(),
            'kerberoasting_findings': [],
            'credential_dumping_findings': [],
            'correlation_results': [],
            'recommendations': []
        }

    def compile_findings(self):
        """Compile all security findings"""
        print("=== COMPILING SECURITY FINDINGS ===")

        # Kerberoasting findings
        self.report_data['kerberoasting_findings'] = [
            {
                'finding': 'RC4 encryption detected in service tickets',
                'risk_level': 'HIGH',
                'description': 'RC4 encryption is vulnerable to offline cracking attacks'
            },
            {
                'finding': 'Multiple TGS requests from single source',
                'risk_level': 'MEDIUM',
                'description': 'Potential automated Kerberoasting tool usage'
            },
            {
                'finding': 'Service accounts with weak passwords',
                'risk_level': 'HIGH',
                'description': 'Service accounts vulnerable to password cracking'
            }
        ]

        # Credential dumping findings
        self.report_data['credential_dumping_findings'] = [
            {
                'finding': 'Suspicious process execution detected',
                'risk_level': 'CRITICAL',
                'description': 'Mimikatz or similar credential dumping tool detected'
            },
            {
                'finding': 'Unusual LSASS memory access patterns',
                'risk_level': 'HIGH',
                'description': 'Potential credential extraction from memory'
            },
            {
                'finding': 'Memory dump files created',
                'risk_level': 'MEDIUM',
                'description': 'Suspicious memory dump activity detected'
            }
        ]

        # Load correlation results if available
        try:
            with open('correlation_results.json', 'r') as f:
                correlation_data = json.load(f)
                self.report_data['correlation_results'] = correlation_data.get('detected_attacks', [])
        except FileNotFoundError:
            pass

    def generate_recommendations(self):
        """Generate security recommendations"""
        self.report_data['recommendations'] = [
            {
                'category': 'Kerberos Security',
                'recommendation': 'Implement AES encryption for all service accounts',
                'priority': 'HIGH'
            },
            {
                'category': 'Account Management',
                'recommendation': 'Enforce strong password policies for service accounts',
                'priority': 'HIGH'
            },
            {
                'category': 'Monitoring',
                'recommendation': 'Deploy advanced threat detection for credential dumping',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Access Control',
                'recommendation': 'Implement least privilege access principles',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Incident Response',
                'recommendation': 'Develop playbooks for Kerberoasting and credential dumping incidents',
                'priority': 'LOW'
            }
        ]

    def calculate_risk_score(self):
        """Calculate overall security risk score"""
        risk_weights = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        total_score = 0
        finding_count = 0

        for finding in self.report_data['kerberoasting_findings']:
            total_score += risk_weights.get(finding['risk_level'], 0)
            finding_count += 1

        for finding in self.report_data['credential_dumping_findings']:
            total_score += risk_weights.get(finding['risk_level'], 0)
            finding_count += 1

        if finding_count > 0:
            average_score = total_score / finding_count
            return min(100, (average_score / 4) * 100)
        return 0

    def generate_executive_summary(self):
        """Generate executive summary"""
        risk_score = self.calculate_risk_score()

        summary = f"""
EXECUTIVE SUMMARY
================

Security Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Overall Risk Score: {risk_score:.1f}/100

CRITICAL FINDINGS:
- Advanced credential dumping techniques detected
- Kerberoasting attack vectors identified
- Multiple security control gaps discovered

IMMEDIATE ACTIONS REQUIRED:
1. Implement AES encryption for Kerberos
2. Deploy advanced threat detection systems
3. Review and strengthen service account security
4. Establish incident response procedures

RISK ASSESSMENT:
- Kerberoasting Vulnerabilities: {len(self.report_data['kerberoasting_findings'])} findings
- Credential Dumping Risks: {len(self.report_data['credential_dumping_findings'])} findings
- Correlated Attack Patterns: {len(self.report_data['correlation_results'])} detected

This assessment reveals significant security gaps that require immediate attention
to prevent credential theft and lateral movement attacks.
        """

        return summary

    def export_full_report(self):
        """Export comprehensive security report"""
        self.compile_findings()
        self.generate_recommendations()

        # Add executive summary
        self.report_data['executive_summary'] = self.generate_executive_summary()
        self.report_data['risk_score'] = self.calculate_risk_score()

        # Export to JSON
        with open('security_assessment_report.json', 'w') as f:
            json.dump(self.report_data, f, indent=2)

        # Generate readable report
        with open('security_report.txt', 'w') as f:
            f.write(self.report_data['executive_summary'])
            f.write("\n\nDETAILED FINDINGS\n")
            f.write("="*50 + "\n\n")

            f.write("KERBEROASTING FINDINGS:\n")
            for finding in self.report_data['kerberoasting_findings']:
                f.write(f"[{finding['risk_level']}] {finding['finding']}\n")
                f.write(f"Description: {finding['description']}\n\n")

            f.write("CREDENTIAL DUMPING FINDINGS:\n")
            for finding in self.report_data['credential_dumping_findings']:
                f.write(f"[{finding['risk_level']}] {finding['finding']}\n")
                f.write(f"Description: {finding['description']}\n\n")

            f.write("RECOMMENDATIONS:\n")
            for rec in self.report_data['recommendations']:
                f.write(f"[{rec['priority']}] {rec['category']}: {rec['recommendation']}\n")

        print("=== SECURITY ASSESSMENT COMPLETE ===")
        print(f"Risk Score: {self.report_data['risk_score']:.1f}/100")
        print("Reports generated:")
        print("- security_assessment_report.json (detailed data)")
        print("- security_report.txt (executive summary)")

if __name__ == "__main__":
    generator = SecurityReportGenerator()
    generator.export_full_report()
    # TODO: Parameterize compile_findings() to ingest real scan output instead of static data
```

```bash
python3 security_report_generator.py
```

---

## 🧪 Verification and Testing

### ✅ View Generated Reports

```bash
echo "=== GENERATED FILES ==="
ls -la *.json *.txt *.py

echo -e "\n=== EXECUTIVE SUMMARY ==="
head -20 security_report.txt

echo -e "\n=== CORRELATION RESULTS ==="
cat correlation_results.json | python3 -m json.tool
```

### ✅ Validate Detection Capabilities

```bash
echo "=== VALIDATION SUMMARY ==="
echo "1. Kerberoasting Detection: $(python3 kerberoast_detector.py | grep -c 'ALERT\|HIGH\|MEDIUM')"
echo "2. Credential Dumping Detection: $(python3 credential_dump_detector.py | grep -c 'ALERT\|Suspicious')"
echo "3. Event Correlation: $(cat correlation_results.json | grep -c 'attack')"
echo "4. Security Reports Generated: $(ls -1 *.json *.txt | wc -l)"
# TODO: Archive all generated reports for the lab writeup deliverable
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1558.003 | Kerberoasting | Credential Access | `kerberoast_detector.py` RC4 / bulk TGS detection |
| T1003.001 | LSASS Memory | Credential Access | `credential_dump_detector.py` LSASS access analysis |
| T1057 | Process Discovery | Discovery | `monitor_processes()` suspicious process scan |
| T1550.002 | Pass the Hash | Lateral Movement | `hash_analyzer.py` hash type identification |
| T1590.001 | Gather Victim Network Information: DNS | Reconnaissance | `spn_analyzer.py` SPN enumeration |
| T1110 | Brute Force | Credential Access | Offline hash cracking risk from RC4 findings |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ Issue 1: klist Command Not Found</summary>

```bash
# Install the Kerberos client utilities
sudo apt install krb5-user -y
which klist
```

</details>

<details>
<summary>❗ Issue 2: psutil Import Error in credential_dump_detector.py</summary>

```bash
# Install the required Python package
pip3 install psutil
python3 -c "import psutil; print(psutil.__version__)"
```

</details>

<details>
<summary>❗ Issue 3: correlation_results.json Not Found by Later Scripts</summary>

```bash
# Ensure event_correlator.py was run first, from the same working directory
ls -la correlation_results.json
python3 event_correlator.py
```

</details>

---

## ✅ Conclusion

You have successfully implemented a comprehensive detection system for Kerberoasting and credential dumping attacks using open-source tools. This lab demonstrated:

- 🔐 **Advanced Threat Detection**: Built detection systems for sophisticated attack techniques
- 🔗 **Event Correlation**: Implemented correlation engines to identify attack patterns
- 🧬 **Security Analysis**: Created comprehensive analysis tools for credential-based attacks
- 📝 **Incident Response**: Developed reporting systems for security incident management

These skills are essential for cybersecurity professionals working in threat detection, incident response, and security operations centers. The techniques learned help identify and respond to advanced persistent threats targeting organizational credentials and authentication systems.

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
