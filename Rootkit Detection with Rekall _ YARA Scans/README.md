# 🛡️ Rootkit Detection with Rekall + YARA Scans
### 🔬 Advanced Memory Forensics & Rootkit Hunting Lab

<p align="center">

![GitHub](https://img.shields.io/badge/GitHub-Lab-black?style=for-the-badge&logo=github)
![Linux](https://img.shields.io/badge/Linux-Ubuntu-E95420?style=for-the-badge&logo=ubuntu)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python)
![Rekall](https://img.shields.io/badge/Rekall-Memory_Forensics-red?style=for-the-badge)
![YARA](https://img.shields.io/badge/YARA-Rule_Engine-green?style=for-the-badge)
![Memory-Forensics](https://img.shields.io/badge/Memory-Forensics-darkred?style=for-the-badge)
![Rootkit-Detection](https://img.shields.io/badge/Rootkit-Detection-purple?style=for-the-badge)
![Malware-Analysis](https://img.shields.io/badge/Malware-Analysis-blue?style=for-the-badge)
![Threat-Hunting](https://img.shields.io/badge/Threat-Hunting-darkgreen?style=for-the-badge)
![Incident-Response](https://img.shields.io/badge/Incident-Response-orange?style=for-the-badge)
![DFIR](https://img.shields.io/badge/DFIR-Professional-success?style=for-the-badge)

</p>

---

# 📖 Overview

Welcome to the **Rootkit Detection with Rekall + YARA Scans** laboratory.

This hands-on **Digital Forensics & Incident Response (DFIR)** lab teaches you how to detect sophisticated **kernel-mode and user-mode rootkits** using the **Rekall Memory Forensics Framework** combined with **YARA signature scanning**.

Rootkits are among the stealthiest malware families because they manipulate operating system internals to hide malicious processes, files, network connections, and kernel modules. Traditional antivirus solutions often fail to detect these threats, making **memory forensics** one of the most effective investigation techniques.

Throughout this lab, you will configure Rekall, create custom YARA signatures, scan memory dumps, analyze hidden processes, inspect kernel modules, investigate network activity, and generate professional forensic reports.

---

# 🎯 Learning Objectives

After completing this lab you will be able to:

- ✅ Install and configure Rekall Memory Forensics
- ✅ Install and configure YARA
- ✅ Create custom YARA detection rules
- ✅ Scan memory dumps for rootkit signatures
- ✅ Detect hidden processes
- ✅ Analyze kernel modules
- ✅ Investigate suspicious system activity
- ✅ Interpret forensic findings
- ✅ Generate professional DFIR reports

---

# 🛠 Technology Stack

| Technology | Purpose |
|------------|----------|
| 🐧 Ubuntu Linux | Analysis Platform |
| 🐍 Python 3 | Automation |
| 🔍 Rekall | Memory Forensics |
| 🎯 YARA | Malware Signature Detection |
| 💾 Memory Dumps | Evidence Source |
| 🛡 Rootkit Detection | Threat Analysis |
| 🔥 Threat Hunting | IOC Discovery |
| 📊 DFIR | Incident Response |
| ⚙ Bash | Automation Scripts |
| 🧬 Linux Kernel | Memory Analysis |

---

# 📚 Prerequisites

Before starting this lab you should understand:

- ✔ Linux command-line basics
- ✔ Memory forensics concepts
- ✔ Malware analysis fundamentals
- ✔ System processes
- ✔ Linux kernel structures
- ✔ Basic cybersecurity concepts

---

# 🖥 Lab Environment

The lab runs on an **Al Nafi Linux Cloud Machine**.

The environment provides:

- 🖥 Ubuntu Linux
- 🌐 Internet connectivity
- 🔧 Administrative privileges
- 🐍 Python environment
- 🔍 Rekall installation
- 🎯 YARA detection engine
- 💾 Memory acquisition exercises

---

# 🚀 Lab Tasks

---

# 📦 Task 1 — Configure Rekall for Memory Analysis

---

## 🔹 Step 1.1 — Install Dependencies

Update the operating system and install required packages.

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y python3 python3-pip git build-essential python3-dev libssl-dev
```

---

## 🔹 Step 1.2 — Install Rekall

Install the Rekall Memory Forensics framework.

```bash
pip3 install --user rekall-agent rekall

echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc

source ~/.bashrc
```

Verify installation.

```bash
rekall --version
```

---

## 🔹 Step 1.3 — Acquire Memory Dump

Install crash dump utilities.

```bash
sudo apt install -y linux-crashdump makedumpfile crash kexec-tools
```

Capture memory.

```bash
sudo dd if=/proc/kcore of=memory_sample.raw bs=1M count=100
```

Create a smaller test sample.

```bash
sudo head -c 50M /proc/kcore > test_memory.raw
```

---

## 🔹 Step 1.4 — Download Rekall Profiles

```bash
mkdir -p ~/rekall_profiles

cd ~/rekall_profiles

wget https://github.com/google/rekall-profiles/archive/master.zip

unzip master.zip
```

---

# 🎯 Task 2 — Deploy YARA Rules

---

## 🔹 Step 2.1 — Install YARA

Install the YARA scanning engine.

```bash
sudo apt install -y yara libyara-dev python3-yara

pip3 install --user yara-python
```

---

## 🔹 Step 2.2 — Create Rootkit Detection Rules

Create a directory for custom rules.

```bash
mkdir -p ~/yara_rules

cd ~/yara_rules
```

Create:

- 📄 rootkit_signatures.yar
- 📄 advanced_rootkit.yar

The rules detect:

- Kernel hooks
- Hidden processes
- Rootkit strings
- Network rootkits
- File hiding
- Kernel modules
- Process hiding
- Syscall manipulation

---

## 🔹 Step 2.3 — Test YARA Rules

Run YARA against the memory image.

```bash
yara rootkit_signatures.yar ~/test_memory.raw

yara advanced_rootkit.yar ~/test_memory.raw
```

Review any matching signatures carefully.

---

# 🔬 Task 3 — Perform Memory Analysis

---

## 🔹 Step 3.1 — Analyze Memory with Rekall

List running processes.

```bash
rekall -f test_memory.raw --profile Linux64 pslist
```

Search for hidden processes.

```bash
rekall -f test_memory.raw --profile Linux64 psscan
```

Inspect kernel modules.

```bash
rekall -f test_memory.raw --profile Linux64 lsmod
```

Look for:

- Hidden processes
- Unknown kernel modules
- Unlinked drivers
- Suspicious kernel objects

---

## 🔹 Step 3.2 — Combine Rekall with YARA

Execute the automated scanner.

```bash
chmod +x rootkit_scan.py

python3 rootkit_scan.py
```

The script automatically:

- Runs YARA rules
- Executes Rekall plugins
- Collects forensic evidence
- Summarizes detections

---

## 🔹 Step 3.3 — Generate Investigation Report

Run the reporting script.

```bash
chmod +x generate_report.sh

./generate_report.sh
```

View report.

```bash
cat rootkit_analysis_report.txt
```

The report includes:

- YARA detections
- Process analysis
- Kernel module analysis
- Investigation summary

---

## 🔹 Step 3.4 — Interpret Findings

Run the interpretation guide.

```bash
python3 interpret_results.py
```

Review:

- High-risk indicators
- Medium-risk indicators
- Low-risk findings
- Recommended investigation steps

---

# 🔍 Indicators of Compromise (IOCs)

## 🧠 Process Indicators

- Hidden processes
- Unlinked tasks
- Parent-child anomalies
- Unknown executables
- Suspicious command lines

---

## 💾 Kernel Indicators

- Hooked system calls
- Modified syscall tables
- Unknown kernel modules
- Hidden drivers
- Kernel object manipulation

---

## 🎯 YARA Indicators

- Rootkit signatures
- Backdoor strings
- Hooking APIs
- Kernel manipulation
- Process hiding techniques

---

## 🌐 Network Indicators

- Hidden sockets
- Unknown listening ports
- Backdoor communications
- Suspicious outbound traffic
- Covert channels

---

## 📁 File System Indicators

- Hidden files
- Hidden directories
- VFS manipulation
- File system hooks
- Unexpected permissions

---

# 🧪 Verification

Verify installed software.

```bash
rekall --version

yara --version

python3 --version
```

Verify generated reports.

```bash
ls -la *.txt
```

Check YARA rule files.

```bash
ls -la yara_rules
```

Validate memory dump.

```bash
file test_memory.raw
```

---

# 🧰 Troubleshooting

## 🚫 Rekall Cannot Read Memory Dump

Verify profile compatibility.

```bash
rekall -f test_memory.raw --profile Linux64 pslist
```

---

## 🚫 No YARA Matches

Ensure rule syntax is correct.

```bash
yara rootkit_signatures.yar test_memory.raw
```

---

## 🚫 Missing Rekall Profile

Download updated Rekall profiles.

```bash
cd ~/rekall_profiles
```

Verify extraction completed successfully.

---

# 📊 Risk Interpretation Guide

## 🔴 High Risk

- Rootkit YARA signatures detected
- Hidden processes discovered
- Hooked syscall table
- Hidden kernel modules
- Unknown kernel drivers

Immediate incident response is recommended.

---

## 🟠 Medium Risk

- Suspicious kernel hooks
- Unknown network connections
- Unexpected memory allocations
- Modified kernel objects

Requires further investigation.

---

## 🟢 Low Risk

- Normal kernel modules
- Expected processes
- Legitimate system activity
- No suspicious YARA matches

Continue routine monitoring.

---

# 🏆 Skills Gained

After completing this lab you will understand how to:

- 🧠 Perform Linux memory forensics
- 🎯 Create custom YARA rules
- 🔍 Hunt advanced rootkits
- 🛡 Detect hidden kernel modules
- 💾 Analyze memory dumps
- 🌐 Investigate hidden network activity
- 📊 Generate DFIR reports
- 🔥 Correlate forensic evidence
- ⚙ Automate memory analysis
- 🚨 Investigate advanced persistent threats

---

# 🎓 Conclusion

Congratulations!

You have successfully completed an advanced **Rootkit Detection with Rekall & YARA** laboratory.

During this lab you learned how to combine **memory forensics** and **signature-based detection** to identify sophisticated rootkits that attempt to conceal themselves within operating system memory.

The techniques covered—including **hidden process detection**, **kernel module inspection**, **YARA rule development**, and **memory analysis**—are widely used by cybersecurity professionals to investigate advanced persistent threats (APTs), rootkits, and stealth malware.

These skills are valuable for professionals working as:

- 🔵 Digital Forensics Analysts
- 🔵 Incident Responders
- 🔵 Threat Hunters
- 🔵 Malware Analysts
- 🔵 SOC Analysts
- 🔵 DFIR Engineers

Mastering Rekall and YARA provides a powerful foundation for detecting malware that traditional endpoint security tools may overlook.

---

# ⭐ If You Found This Lab Helpful

If this repository helped you learn **Memory Forensics**, **Rootkit Detection**, and **YARA Rule Development**:

⭐ Star this repository

🍴 Fork this repository

📢 Share it with the cybersecurity community

🤝 Contribute additional DFIR, Rekall, and Malware Analysis labs

Happy Threat Hunting! 🛡️🔍
