# 🔐 Correlate Logon/Logoff + Process Execution Data

<div align="center">

# 🕵️ Windows Authentication & Process Correlation for DFIR

**Correlate Windows logon/logoff events with process execution data to reconstruct attacker activity and identify suspicious user behavior.**

---

### 🎯 Technologies & Tools

![Windows Security](https://img.shields.io/badge/Windows-Security_Logs-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-Parsing-black?style=for-the-badge&logo=json)
![EVTX](https://img.shields.io/badge/EVTX-Event_Logs-success?style=for-the-badge)
![DFIR](https://img.shields.io/badge/Digital_Forensics-Incident_Response-critical?style=for-the-badge)
![Threat Hunting](https://img.shields.io/badge/Threat-Hunting-red?style=for-the-badge)
![Blue Team](https://img.shields.io/badge/Blue-Team-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-darkred?style=for-the-badge)
![Windows Event Logs](https://img.shields.io/badge/Event_Logs-Analysis-blueviolet?style=for-the-badge)

</div>

---

# 📖 Overview

Windows Security Event Logs provide valuable evidence during incident response investigations. By correlating **authentication events** (logon/logoff) with **process creation events**, analysts can reconstruct attacker activity, detect privilege escalation attempts, identify lateral movement, and uncover malicious user behavior.

In this lab, you'll build automated Python tools to parse Windows Security logs, correlate authentication with executed commands, generate investigation timelines, detect attack patterns, and create executive security reports.

---

# 🎯 Learning Objectives

After completing this lab, you will be able to:

- ✅ Extract Windows logon/logoff events
- ✅ Parse Windows Security Event Logs
- ✅ Correlate authentication with process execution
- ✅ Detect suspicious command execution
- ✅ Decode Base64 PowerShell commands
- ✅ Build comprehensive attack timelines
- ✅ Identify privilege escalation attempts
- ✅ Detect brute-force attack patterns
- ✅ Generate executive investigation reports

---

# 🧰 Technologies Used

| Category | Tools |
|----------|------|
| Event Log Parsing | Python EVTX |
| Data Processing | Pandas |
| Data Format | JSON |
| Windows Security | Event IDs |
| Automation | Python 3 |
| Operating System | Ubuntu Linux |
| Scripting | Bash |
| Incident Response | DFIR |
| Threat Hunting | Timeline Correlation |
| Reporting | CSV + JSON |

---

# 📋 Prerequisites

Before beginning this lab, you should understand:

- Windows Security Event Logs
- Linux command line
- JSON file structure
- Authentication events
- Process execution concepts
- Basic incident response workflow

---

# 🖥️ Lab Environment

This lab is performed on an **Al Nafi Cloud Linux Machine**.

Environment includes:

- Ubuntu Linux
- Python 3
- Pip
- Git
- Internet connectivity
- No pre-installed forensic software
- Full administrative privileges

---

# 📁 Project Structure

```text
Correlate-Logon-Process-Events/
│
├── sample_security_events.json
├── sample_process_events.json
├── extracted_logon_events.csv
├── logon_process_correlations.csv
├── suspicious_activity_timeline.csv
├── attack_patterns.json
│
├── extract_logon_events.py
├── correlate_events.py
├── build_timeline.py
├── timeline_summary.py
│
└── README.md
```

---

# 🚀 Lab Tasks

---

# 🔑 Task 1 — Extract Authentication Events

---

## 📦 Step 1.1 Install Required Tools

Install the required Python libraries and dependencies.

### Installed Packages

- Python 3
- Git
- Pandas
- python-evtx
- xmltodict

### Skills Learned

- Python environment setup
- Windows log analysis preparation
- Dependency management
- Security tooling installation

---

## 📂 Step 1.2 Create Sample Windows Event Logs

Generate Windows Security log data containing:

- Successful Logon (4624)
- Failed Logon (4625)
- Logoff (4634)

Captured fields include:

- Username
- Workstation
- Source IP
- Process ID
- Authentication type

---

## 🔍 Step 1.3 Extract Logon Events

Develop a Python parser that extracts authentication events.

### Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |

Output:

- CSV report
- Chronological authentication timeline

---

# ⚙️ Task 2 — Correlate Process Execution

---

## 💻 Step 2.1 Generate Process Execution Events

Create sample process execution events.

Included examples:

- cmd.exe
- powershell.exe
- net.exe

Information collected:

- Process ID
- Parent Process
- Command Line
- Username
- Workstation

---

## 🔗 Step 2.2 Correlate Authentication with Process Activity

Automatically match:

- Successful logons
- Executed commands
- User sessions
- Workstations
- Time windows

This provides complete visibility into user behavior after authentication.

---

## 🔐 Suspicious Activity Detection

Automatically detect:

✔ Base64 Encoded PowerShell

✔ net user commands

✔ Administrator activation

✔ whoami execution

✔ systeminfo enumeration

✔ ipconfig discovery

✔ netstat usage

✔ Download activity

✔ Administrative tools

---

## 🧠 PowerShell Decoding

The lab automatically detects and decodes:

- Base64 encoded PowerShell
- Encoded payloads
- Hidden attacker commands

This allows investigators to view the original malicious command.

---

# 📅 Task 3 — Build User Activity Timeline

---

## 📊 Step 3.1 Generate Investigation Timeline

Merge:

- Authentication events
- Process execution
- User sessions
- Risk scores
- Source IPs

The resulting timeline reconstructs the complete sequence of user activity.

---

## 🚨 Risk Assessment

Each event is automatically classified as:

🟢 Low Risk

🟡 Medium Risk

🔴 High Risk

Risk calculations consider:

- Failed logons
- Administrative accounts
- Encoded PowerShell
- Administrative commands
- Privilege escalation attempts

---

## 🛡️ Attack Pattern Detection

Automatically identify attack techniques including:

### 🔴 Privilege Escalation

Indicators:

- net user
- Administrator activation
- Administrative command execution

---

### 🔴 Brute Force

Indicators:

- Multiple failed logons
- Successful authentication after failures

---

### 🟠 Suspicious Process Execution

Indicators:

- PowerShell
- CMD
- WMIC
- Encoded commands

---

## 📈 Step 3.2 Executive Timeline Summary

Generate an executive report containing:

- Timeline statistics
- User risk assessment
- High-risk events
- Attack patterns
- Security recommendations
- Investigation summary

Suitable for management reporting and incident response documentation.

---

## ✅ Step 3.3 Verify Investigation Results

Validate generated artifacts.

Files produced include:

- Authentication CSV
- Correlation CSV
- Timeline CSV
- Attack Patterns JSON
- Executive Summary

---

# 🔬 Investigation Workflow

```text
Windows Security Logs
          │
          ▼
Authentication Parsing
          │
          ▼
Process Event Parsing
          │
          ▼
PowerShell Decoding
          │
          ▼
Event Correlation
          │
          ▼
Timeline Creation
          │
          ▼
Risk Assessment
          │
          ▼
Attack Pattern Detection
          │
          ▼
Executive Report
```

---

# 🎯 Skills Gained

Upon completing this lab, you will gain hands-on experience in:

- Windows Event Log Analysis
- Authentication Investigation
- Process Correlation
- Threat Hunting
- Incident Response
- DFIR Automation
- PowerShell Analysis
- Attack Timeline Reconstruction
- Privilege Escalation Detection
- Brute Force Detection
- Python Automation
- Executive Security Reporting

---

# 💼 Real-World Applications

These techniques are widely used by:

- 🛡️ SOC Analysts
- 🔍 DFIR Investigators
- 🚨 Incident Response Teams
- 🕵️ Threat Hunters
- ☁️ Cloud Security Engineers
- 🏢 Enterprise Security Teams
- 🔐 Blue Team Operators
- 🧪 Malware Analysts

---

# 📚 Key Takeaways

✅ Parsed Windows Security Logs

✅ Extracted authentication events

✅ Correlated user logons with process execution

✅ Decoded Base64 PowerShell payloads

✅ Built complete attack timelines

✅ Calculated user risk scores

✅ Identified privilege escalation attempts

✅ Detected brute-force attacks

✅ Generated executive investigation reports

---

# 🌟 Why Authentication Correlation Matters

Authentication logs alone rarely tell the full story of an attack. By combining **logon/logoff events** with **process execution data**, investigators gain valuable context about what a user actually did after logging in.

This correlation enables defenders to detect insider threats, lateral movement, privilege escalation, malicious PowerShell activity, and attacker behavior with far greater accuracy than analyzing individual event logs in isolation.

---

# 🎓 Conclusion

This lab provides a practical introduction to **Windows authentication correlation and process execution analysis** for Digital Forensics and Incident Response (DFIR). Using Python automation, Windows Security Event IDs, and timeline analysis, you successfully reconstructed user activity, detected suspicious behavior, identified attack patterns, and produced actionable security intelligence.

These skills are fundamental for SOC analysts, DFIR professionals, and threat hunters responsible for investigating Windows-based security incidents and responding to modern cyber threats.

---

<div align="center">

## ⭐ If you found this project useful, consider giving it a star!

**Happy Threat Hunting & Happy Investigating! 🛡️🔍**

</div>
