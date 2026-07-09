# ⏱️ Build Filesystem Timelines with Plaso/log2timeline

<div align="center">

# 🔍 Digital Forensics Timeline Analysis using Plaso

**Reconstruct attack timelines, correlate forensic artifacts, and uncover malicious activity through filesystem timeline analysis.**

---

### 🎯 Technologies & Tools

![Linux](https://img.shields.io/badge/Linux-Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Plaso](https://img.shields.io/badge/Plaso-log2timeline-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualization-orange?style=for-the-badge)
![Autopsy](https://img.shields.io/badge/Autopsy-Digital_Forensics-success?style=for-the-badge)
![Sleuth Kit](https://img.shields.io/badge/The_Sleuth_Kit-Forensics-critical?style=for-the-badge)
![Timeline Analysis](https://img.shields.io/badge/Timeline-Analysis-blueviolet?style=for-the-badge)
![Incident Response](https://img.shields.io/badge/Incident_Response-Cybersecurity-red?style=for-the-badge)
![Digital Forensics](https://img.shields.io/badge/Digital_Forensics-Investigation-darkgreen?style=for-the-badge)

</div>

---

# 📖 Overview

Digital forensic investigations often require analysts to reconstruct the sequence of events that occurred during a security incident. **Plaso (log2timeline)** is a powerful open-source framework that aggregates timestamps from multiple artifact sources and builds a comprehensive forensic timeline.

In this lab, you will learn how to install and configure Plaso, generate forensic timelines from filesystem artifacts, analyze suspicious events, correlate attack phases, visualize timelines, and create professional investigation reports.

---

# 🎯 Learning Objectives

By completing this lab, you will be able to:

- ✅ Install and configure Plaso/log2timeline
- ✅ Build forensic timelines from filesystem artifacts
- ✅ Extract timeline data into multiple formats
- ✅ Analyze suspicious security events
- ✅ Identify attack sequences
- ✅ Correlate forensic evidence across artifacts
- ✅ Generate timeline visualizations
- ✅ Produce professional forensic investigation reports
- ✅ Perform incident response using timeline analysis

---

# 🧰 Technologies Used

| Category | Tools |
|----------|------|
| Timeline Analysis | Plaso (log2timeline) |
| Timeline Processing | psort.py |
| Digital Forensics | The Sleuth Kit |
| GUI Analysis | Autopsy |
| Programming | Python 3 |
| Data Analysis | Pandas |
| Visualization | Matplotlib |
| Hex Analysis | Hexedit |
| Operating System | Ubuntu Linux |
| Scripting | Bash |

---

# 📋 Prerequisites

Before beginning this lab, you should have:

- Basic Linux command-line knowledge
- Understanding of filesystem structures
- Familiarity with log files
- Knowledge of forensic investigation concepts
- Understanding of common cyber attack patterns
- Basic Python knowledge

---

# 🖥️ Lab Environment

This lab uses an **Al Nafi Cloud Linux Machine**.

Environment features include:

- Ubuntu Linux
- Bare-metal cloud instance
- Root access
- Internet connectivity
- No pre-installed forensic software
- Manual installation of required tools

---

# 📁 Project Structure

```text
Build-Filesystem-Timelines/
│
├── timeline.plaso
├── timeline.csv
├── filtered_timeline.csv
├── auth_events.csv
├── timeline.body
├── timeline_chart.png
├── investigation_report.txt
│
├── analyze_timeline.py
├── correlate_events.py
├── visualize_timeline.py
├── generate_report.py
│
├── sample_data/
│
└── README.md
```

---

# 🚀 Lab Tasks

---

# 🛠️ Task 1 — Configure Plaso Environment

---

## 📦 Step 1.1 Install Plaso & Dependencies

Install all required forensic components.

### Software Installed

- Plaso
- Python
- Pip
- Development libraries
- Build tools

### Skills Learned

- Installing forensic frameworks
- Preparing Linux investigation systems
- Managing Python dependencies
- Verifying forensic software

---

## 🔧 Step 1.2 Install Additional Forensic Tools

Install supporting investigation utilities.

### Tools

- Sleuth Kit
- Autopsy
- Hexedit
- Pandas
- Matplotlib

These tools enhance timeline generation, visualization, and forensic analysis.

---

## 📂 Step 1.3 Create Sample Investigation Data

Generate sample forensic artifacts including:

- Authentication logs
- Browser history
- System event logs
- Suspicious process execution
- Network connections

This simulated dataset provides realistic investigation scenarios.

---

# 📅 Task 2 — Build Forensic Timeline

---

## 🗂️ Step 2.1 Create Plaso Storage File

Generate the forensic timeline database.

Activities include:

- Parsing artifacts
- Building Plaso storage
- Collecting timestamps
- Preserving evidence

### Output

- timeline.plaso

---

## 📄 Step 2.2 Extract Timeline Data

Convert Plaso storage into readable formats.

Generated files include:

- CSV timeline
- Bodyfile format
- Timeline preview

These outputs can be analyzed manually or imported into forensic tools.

---

## 🔍 Step 2.3 Generate Filtered Timelines

Filter events based on:

- Date ranges
- Authentication events
- Specific parsers
- Selected timeline fields

This helps investigators focus on relevant attack windows.

---

# 🕵️ Task 3 — Investigate Attack Sequences

---

## 📊 Step 3.1 Analyze Timeline Events

Develop a Python script that automatically detects:

- Failed login attempts
- Suspicious processes
- Malware indicators
- Data exfiltration
- Timeline clusters

### Security Indicators

✔ Failed Authentication

✔ Suspicious Process Execution

✔ Malware Downloads

✔ Network Activity

✔ File Access

---

## 📈 Step 3.2 Visualize Timeline

Generate graphical representations of event activity.

Visualizations include:

- Event distribution
- Timeline trends
- Attack progression
- Activity spikes

This provides analysts with an easier way to identify anomalies.

---

## 🔗 Step 3.3 Correlate Attack Phases

Map events to the Cyber Kill Chain.

Correlation phases include:

- 🔍 Reconnaissance
- ⚙️ Weaponization
- 📦 Delivery
- 💥 Exploitation
- 🛠️ Installation
- 🌐 Command & Control
- 🎯 Actions on Objectives

This reveals the complete attack lifecycle.

---

## 📝 Step 3.4 Generate Investigation Report

Automatically produce a professional report containing:

- Executive Summary
- Timeline Statistics
- Key Findings
- Attack Indicators
- Security Recommendations
- Technical Analysis

Suitable for incident response documentation.

---

## ✅ Step 3.5 Verify Analysis Results

Validate investigation output by checking:

- Timeline files
- CSV exports
- Plaso storage
- Visual charts
- Investigation report
- Timeline statistics

Ensure all forensic artifacts were successfully generated.

---

# 🔬 Investigation Workflow

```text
Filesystem Artifacts
         │
         ▼
Plaso Parsing
         │
         ▼
Timeline Database
         │
         ▼
Timeline Extraction
         │
         ▼
Event Filtering
         │
         ▼
Attack Correlation
         │
         ▼
Visualization
         │
         ▼
Investigation Report
```

---

# 🎯 Skills Gained

Upon completing this lab, you will gain experience in:

- Filesystem Timeline Analysis
- Digital Forensics
- Incident Response
- Timeline Correlation
- Attack Reconstruction
- Log Analysis
- Python Automation
- Data Visualization
- Threat Hunting
- IOC Analysis
- Security Investigation
- Forensic Reporting

---

# 💼 Real-World Applications

These techniques are widely used by:

- 🛡️ SOC Analysts
- 🔍 Digital Forensics Investigators
- 🚨 Incident Response Teams
- 🕵️ Threat Hunters
- 🏢 Enterprise Security Teams
- ☁️ Cloud Security Engineers
- 🧪 Malware Researchers
- 👨‍💻 DFIR Professionals

---

# 📚 Key Takeaways

✅ Installed Plaso/log2timeline

✅ Configured forensic environment

✅ Created forensic timeline database

✅ Extracted timeline data

✅ Filtered forensic events

✅ Correlated attack sequences

✅ Visualized security events

✅ Generated professional investigation reports

✅ Performed forensic timeline analysis

---

# 🌟 Why Timeline Analysis Matters

Timeline analysis enables investigators to reconstruct exactly **what happened, when it happened, and how an attacker progressed through a system**. By combining timestamps from logs, filesystem metadata, browser history, and system artifacts, analysts can identify attack patterns, uncover indicators of compromise (IOCs), and build a complete picture of security incidents.

Plaso simplifies this process by collecting and correlating evidence from multiple sources into a unified timeline, making it an indispensable tool for digital forensics and incident response (DFIR).

---

# 🎓 Conclusion

In this lab, you successfully built and analyzed forensic timelines using **Plaso/log2timeline**, one of the industry's leading timeline analysis frameworks. You learned how to collect timeline data, investigate suspicious events, identify attack phases, correlate forensic artifacts, generate visualizations, and produce comprehensive investigation reports.

These skills are essential for modern **Digital Forensics and Incident Response (DFIR)** professionals, enabling rapid reconstruction of attack timelines and supporting effective security investigations across enterprise environments.

---

<div align="center">

## ⭐ If you found this project useful, consider giving it a star!

**Happy Hunting & Happy Investigating! 🔍🛡️**

</div>
