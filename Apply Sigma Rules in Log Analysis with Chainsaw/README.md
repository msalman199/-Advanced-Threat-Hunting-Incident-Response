<div align="center">

# 🪓 Apply Sigma Rules in Log Analysis with Chainsaw

![Chainsaw](https://img.shields.io/badge/Chainsaw-v2.8.1-red?style=for-the-badge&logo=windowsterminal&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange?style=for-the-badge&logo=yaml&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![EVTX](https://img.shields.io/badge/Windows-Event%20Logs-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Blue%20Team-blue?style=for-the-badge)

**A hands-on lab in log-based detection engineering using Chainsaw and the Sigma rule ecosystem**

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: Download and Configure Chainsaw](#-task-1-download-and-configure-chainsaw-for-log-analysis)
- [🕵️ Task 2: Apply Sigma Rules to Event Logs](#️-task-2-apply-sigma-rules-to-event-logs)
- [🔍 Task 3: Identify Suspicious Activities](#-task-3-identify-suspicious-activities-in-the-logs)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)
- [🌍 Real-World Applications](#-real-world-applications)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure Chainsaw for Windows event log analysis |
| 2 | Apply Sigma rules to detect security incidents in log data |
| 3 | Identify suspicious activities using rule-based detection |
| 4 | Analyze detection results and understand threat patterns |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🪟 Windows Event Logs | Basic understanding of event log structure |
| 🐧 Linux CLI | Familiarity with Linux command line operations |
| 🚨 Security Concepts | Knowledge of security incident detection concepts |
| 📄 YAML | Understanding of YAML file structure |

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required tools during the lab exercises.

---

## 🔧 Task 1: Download and Configure Chainsaw for Log Analysis

### ✅ Step 1.1: Install Required Dependencies

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 🧰 Install essential tools
sudo apt install -y wget curl unzip git build-essential
```

### ✅ Step 1.2: Download and Install Chainsaw

```bash
# 📁 Create working directory
mkdir ~/chainsaw-lab && cd ~/chainsaw-lab

# ⬇️ Download latest Chainsaw release
wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.8.1/chainsaw_x86_64-unknown-linux-gnu.tar.gz

# 📂 Extract Chainsaw
tar -xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz

# 🔑 Make executable and move to PATH
chmod +x chainsaw
sudo mv chainsaw /usr/local/bin/

# 🔎 Verify installation
chainsaw --version
# TODO: Confirm version output matches v2.8.1
```

### ✅ Step 1.3: Download Sample Windows Event Logs

```bash
# 📁 Create logs directory
mkdir ~/chainsaw-lab/logs

# ⬇️ Download sample Windows event logs for analysis
wget -O ~/chainsaw-lab/logs/Security.evtx "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Lateral%20Movement/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.evtx"

wget -O ~/chainsaw-lab/logs/System.evtx "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Defense%20Evasion/sysmon_wmi_T1047_wbemtest.evtx"

# 📊 Verify downloaded files
ls -la ~/chainsaw-lab/logs/
# TODO: Note file sizes and confirm both .evtx files downloaded successfully
```

---

## 🕵️ Task 2: Apply Sigma Rules to Event Logs

### ✅ Step 2.1: Download Sigma Rules Repository

```bash
# 📥 Clone Sigma rules repository
cd ~/chainsaw-lab
git clone https://github.com/SigmaHQ/sigma.git

# 📂 Navigate to Windows-specific rules
cd sigma/rules/windows
ls -la
```

### ✅ Step 2.2: Convert Sigma Rules for Chainsaw

```bash
# 🐍 Install Python and required packages
sudo apt install -y python3 python3-pip
pip3 install pysigma pysigma-backend-splunk

# 📁 Create custom Sigma rules directory
mkdir ~/chainsaw-lab/custom-rules

# 📋 Copy relevant Sigma rules for analysis
cp ~/chainsaw-lab/sigma/rules/windows/process_creation/proc_creation_win_susp_powershell_empire.yml ~/chainsaw-lab/custom-rules/
cp ~/chainsaw-lab/sigma/rules/windows/builtin/security/win_security_susp_failed_logons.yml ~/chainsaw-lab/custom-rules/
cp ~/chainsaw-lab/sigma/rules/windows/sysmon/sysmon_wmi_susp_scripting.yml ~/chainsaw-lab/custom-rules/
# TODO: Review each copied rule and note its detection logic field
```

### ✅ Step 2.3: Run Chainsaw with Sigma Rules

```bash
# 🎯 Analyze logs using built-in Sigma rules
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/ --mapping ~/chainsaw-lab/sigma/tools/config/generic/windows-audit.yml --output ~/chainsaw-lab/results.json

# 📊 Generate detailed CSV report
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/ --csv --output ~/chainsaw-lab/detailed-results.csv

# 👀 Display initial results
head -20 ~/chainsaw-lab/detailed-results.csv
# TODO: Record which rules triggered on the sample logs
```

---

## 🔍 Task 3: Identify Suspicious Activities in the Logs

### ✅ Step 3.1: Analyze Detection Results

```bash
# 📖 View JSON results with formatting
cat ~/chainsaw-lab/results.json | python3 -m json.tool | head -50

# 🔢 Count total detections
grep -c "detection" ~/chainsaw-lab/results.json

# 🚨 Search for high-severity detections
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/ --level high --output ~/chainsaw-lab/high-severity.json
```

### ✅ Step 3.2: Focus on Specific Attack Techniques

```bash
# ↔️ Search for lateral movement indicators
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/windows/builtin/security/ --output ~/chainsaw-lab/lateral-movement.json

# 💻 Look for PowerShell-based attacks
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/windows/powershell/ --output ~/chainsaw-lab/powershell-attacks.json

# 🧩 Analyze WMI-related suspicious activities
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/windows/sysmon/ --output ~/chainsaw-lab/wmi-activities.json
```

### ✅ Step 3.3: Create Custom Detection Report

```bash
# 🕰️ Generate comprehensive timeline analysis
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/ --json --full --output ~/chainsaw-lab/timeline-analysis.json
```

```python
#!/usr/bin/env python3
# 📊 generate-report.py — summarizes Chainsaw/Sigma detection output
import json
import sys
from collections import Counter

def analyze_detections(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)

        if not isinstance(data, list):
            data = [data]

        print("=== CHAINSAW SIGMA DETECTION SUMMARY ===\n")

        # Count detections by rule
        rule_counts = Counter()
        severity_counts = Counter()

        for detection in data:
            if 'detections' in detection:
                for det in detection['detections']:
                    rule_name = det.get('rule', 'Unknown Rule')
                    severity = det.get('level', 'unknown')
                    rule_counts[rule_name] += 1
                    severity_counts[severity] += 1

        print(f"Total Detections: {sum(rule_counts.values())}")
        print(f"Unique Rules Triggered: {len(rule_counts)}\n")

        print("Top 5 Most Triggered Rules:")
        for rule, count in rule_counts.most_common(5):
            print(f"  - {rule}: {count} detections")

        print(f"\nDetections by Severity:")
        for severity, count in severity_counts.items():
            print(f"  - {severity.upper()}: {count}")

    except Exception as e:
        print(f"Error analyzing file: {e}")

if __name__ == "__main__":
    analyze_detections("~/chainsaw-lab/timeline-analysis.json")
    # TODO: Add export-to-CSV option for the summary report
```

```bash
# 🔑 Make script executable and run
chmod +x ~/chainsaw-lab/generate-report.py
python3 ~/chainsaw-lab/generate-report.py
```

### ✅ Step 3.4: Investigate Specific Incidents

```bash
# 🔐 Search for authentication failures (Event ID 4625)
chainsaw search ~/chainsaw-lab/logs/ -e 4625 --output ~/chainsaw-lab/auth-failures.json

# ⚙️ Look for process creation events (Event ID 4688)
chainsaw search ~/chainsaw-lab/logs/ -e 4688 --output ~/chainsaw-lab/process-creation.json

# 🕰️ Display timeline of events
chainsaw dump ~/chainsaw-lab/logs/ --csv | head -20
# TODO: Cross-reference timestamps against known attack sample metadata
```

### ✅ Step 3.5: Validate Detection Accuracy

```bash
#!/bin/bash
# 🧪 validate-detections.sh — sanity-checks detection output

echo "=== DETECTION VALIDATION REPORT ==="
echo "Timestamp: $(date)"
echo

# Count different types of detections
echo "Detection Statistics:"
echo "- Total log entries processed: $(chainsaw dump ~/chainsaw-lab/logs/ --csv | wc -l)"
echo "- Sigma rule matches: $(grep -c 'detection' ~/chainsaw-lab/results.json 2>/dev/null || echo '0')"
echo "- High severity alerts: $(grep -c 'high' ~/chainsaw-lab/high-severity.json 2>/dev/null || echo '0')"

echo
echo "File Analysis:"
for file in ~/chainsaw-lab/logs/*.evtx; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        size=$(du -h "$file" | cut -f1)
        echo "- $filename: $size"
    fi
done

echo
echo "Most Common Event IDs:"
chainsaw dump ~/chainsaw-lab/logs/ --csv | cut -d',' -f3 | sort | uniq -c | sort -nr | head -5
```

```bash
# 🔑 Make script executable and run
chmod +x ~/chainsaw-lab/validate-detections.sh
./~/chainsaw-lab/validate-detections.sh
# TODO: Save this output alongside the CSV report for your lab writeup
```

---

## 🧠 Key Findings and Analysis

### Understanding Detection Results

**Critical Detection Categories:**

| Category | Description |
|---|---|
| 🔑 Authentication Anomalies | Failed login attempts and suspicious account activities |
| ⚙️ Process Execution | Unusual command-line executions and PowerShell usage |
| ↔️ Lateral Movement | Network authentication and remote access patterns |
| 🧷 Persistence Mechanisms | Registry modifications and scheduled task creation |

### Common Sigma Rule Patterns

```bash
# 📄 View sample Sigma rule structure
cat ~/chainsaw-lab/custom-rules/proc_creation_win_susp_powershell_empire.yml | head -20
```

**Rule Components:**

| Component | Purpose |
|---|---|
| Detection Logic | Defines what patterns to match |
| False Positive Filters | Reduces noise from legitimate activities |
| Severity Levels | Prioritizes alerts based on threat level |
| MITRE ATT&CK Mapping | Links detections to attack techniques |

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1003 | OS Credential Dumping (DCSync) | Credential Access | `Security.evtx` sample |
| T1021 | Remote Services | Lateral Movement | Chainsaw lateral-movement hunt |
| T1047 | Windows Management Instrumentation | Execution | `System.evtx` sample |
| T1059.001 | PowerShell | Execution | Sigma PowerShell rule set |
| T1110 | Brute Force (Failed Logons) | Credential Access | Event ID 4625 search |
| T1547 | Boot or Logon Autostart Execution | Persistence | Persistence detection category |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ Issue 1: Chainsaw Not Finding Rules</summary>

```bash
# Verify Sigma rules path
ls -la ~/chainsaw-lab/sigma/rules/windows/
chainsaw hunt ~/chainsaw-lab/logs/ -s ~/chainsaw-lab/sigma/rules/ --dry-run
```

</details>

<details>
<summary>❗ Issue 2: No Detections Generated</summary>

```bash
# Check log file format and content
file ~/chainsaw-lab/logs/*.evtx
chainsaw dump ~/chainsaw-lab/logs/ | head -10
```

</details>

<details>
<summary>❗ Issue 3: JSON Parsing Errors</summary>

```bash
# Validate JSON output
python3 -m json.tool ~/chainsaw-lab/results.json > /dev/null && echo "Valid JSON" || echo "Invalid JSON"
```

</details>

---

## ✅ Conclusion

In this lab, you successfully implemented Sigma rule-based detection using Chainsaw for Windows event log analysis. You learned to:

- 🔧 Configure Chainsaw as a powerful log analysis tool
- 📜 Apply industry-standard Sigma rules for threat detection
- 🕵️ Identify suspicious activities through automated rule matching
- 📊 Generate comprehensive security incident reports
- ✅ Validate detection accuracy and reduce false positives

This hands-on experience demonstrates how security analysts use rule-based detection systems to identify threats in enterprise environments. The combination of Chainsaw and Sigma rules provides a scalable approach to security monitoring that can be adapted to various organizational needs and threat landscapes.

## 🌍 Real-World Applications

| Application | Description |
|---|---|
| 🏢 SOC Operations | Automated threat detection in security operations centers |
| 🚨 Incident Response | Rapid identification of compromise indicators |
| 🎯 Threat Hunting | Proactive search for advanced persistent threats |
| 📋 Compliance Monitoring | Ensuring adherence to security policies and regulations |

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
