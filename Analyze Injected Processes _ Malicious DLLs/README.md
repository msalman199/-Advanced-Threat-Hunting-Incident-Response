# 🧠 Analyze Injected Processes & Malicious DLLs
### 🔬 Advanced Memory Forensics & Malware Investigation Lab

<p align="center">

![GitHub](https://img.shields.io/badge/GitHub-Lab-black?style=for-the-badge&logo=github)
![Linux](https://img.shields.io/badge/Linux-Ubuntu-E95420?style=for-the-badge&logo=ubuntu)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python)
![Volatility3](https://img.shields.io/badge/Volatility-3-red?style=for-the-badge)
![Memory-Forensics](https://img.shields.io/badge/Memory-Forensics-darkred?style=for-the-badge)
![Digital-Forensics](https://img.shields.io/badge/Digital-Forensics-blue?style=for-the-badge)
![Malware-Analysis](https://img.shields.io/badge/Malware-Analysis-purple?style=for-the-badge)
![DLL-Analysis](https://img.shields.io/badge/DLL-Analysis-green?style=for-the-badge)
![Threat-Hunting](https://img.shields.io/badge/Threat-Hunting-darkgreen?style=for-the-badge)
![Incident-Response](https://img.shields.io/badge/Incident-Response-orange?style=for-the-badge)
![DFIR](https://img.shields.io/badge/DFIR-Professional-success?style=for-the-badge)

</p>

---

# 📖 Overview

Welcome to the **Analyze Injected Processes & Malicious DLLs** laboratory.

This hands-on **Digital Forensics & Incident Response (DFIR)** lab demonstrates how modern malware injects malicious code into legitimate Windows processes to evade detection. Using **Volatility 3** and other open-source forensic tools, you will investigate memory dumps, identify process injection techniques, extract malicious DLLs, analyze malware behavior, and document forensic findings.

The lab mirrors real-world investigations performed by **SOC Analysts, Incident Responders, Threat Hunters, Malware Analysts, and Digital Forensics professionals** when responding to advanced cyber threats.

---

# 🎯 Learning Objectives

After completing this lab, you will be able to:

- ✅ Install and configure Volatility 3
- ✅ Analyze Windows memory dumps
- ✅ Detect process injection techniques
- ✅ Identify process hollowing
- ✅ Extract malicious DLLs from memory
- ✅ Analyze DLL injection artifacts
- ✅ Investigate malware persistence
- ✅ Examine suspicious network activity
- ✅ Analyze registry modifications
- ✅ Generate professional memory forensics reports

---

# 🛠 Technology Stack

| Technology | Purpose |
|------------|----------|
| 🐧 Ubuntu Linux | Analysis Platform |
| 🐍 Python 3 | Volatility Runtime |
| 🔍 Volatility 3 | Memory Forensics Framework |
| 🧬 Windows Memory Dump | Investigation Target |
| 📦 PE Files | Executable Analysis |
| 🛡 Malware Analysis | Threat Investigation |
| 🔥 Threat Hunting | IOC Discovery |
| 📊 DFIR | Incident Response |
| ⚙ Bash | Automation |
| 🧾 Hexdump & Strings | Binary Inspection |

---

# 📚 Prerequisites

Before starting this lab you should understand:

- ✔ Linux command line basics
- ✔ Operating system processes
- ✔ Memory management concepts
- ✔ Malware fundamentals
- ✔ Windows PE file structure *(recommended)*
- ✔ Basic incident response workflow

---

# 🖥 Lab Environment

This lab runs on an **Al Nafi Linux Cloud Machine**.

The environment provides:

- 🖥 Ubuntu Linux
- 🌐 Internet access
- 🔧 Administrative privileges
- 🐍 Python environment
- 🔍 Manual installation of Volatility 3
- 💾 Windows memory dump analysis

---

# 🚀 Lab Tasks

---

# 📦 Task 1 — Set Up Analysis Environment

---

## 🔹 Step 1.1 — Update System & Install Tools

Update packages and install required software.

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install python3 python3-pip git wget unzip -y

pip3 install volatility3

sudo apt install hexdump binutils file -y

vol3 --help
```

---

## 🔹 Step 1.2 — Download Memory Dump

Create your working directory and obtain a sample infected memory dump.

```bash
mkdir ~/memory_analysis

cd ~/memory_analysis

wget https://github.com/volatilityfoundation/volatility/raw/master/contrib/plugins/malware/samples/zeus.vmem \
-O infected_memory.vmem
```

Alternative sample:

```bash
wget https://www.memoryanalysis.net/samples/stuxnet.vmem \
-O infected_memory.vmem
```

Verify the file:

```bash
ls -lh infected_memory.vmem

file infected_memory.vmem
```

---

# 🔬 Task 2 — Analyze Memory Dump for Injected Processes

---

## 🔹 Step 2.1 — Gather System Information

Identify the operating system and running processes.

```bash
vol3 -f infected_memory.vmem windows.info

vol3 -f infected_memory.vmem windows.pslist > process_list.txt

vol3 -f infected_memory.vmem windows.pstree
```

Search for common Windows processes:

```bash
grep -E "(svchost|explorer|winlogon|csrss)" process_list.txt
```

---

## 🔹 Step 2.2 — Detect Process Injection

Check for process hollowing and injected code.

```bash
vol3 -f infected_memory.vmem windows.malfind
```

Inspect suspicious memory regions:

```bash
vol3 -f infected_memory.vmem windows.memmap --pid [PID]

vol3 -f infected_memory.vmem windows.vadinfo --pid [PID]

vol3 -f infected_memory.vmem windows.dlllist --pid [PID]
```

Look for:

- 🚨 Process hollowing
- 🚨 Reflective DLL loading
- 🚨 Executable memory pages
- 🚨 Suspicious VAD regions

---

## 🔹 Step 2.3 — Dump Process Memory

Extract suspicious process memory.

```bash
vol3 -f infected_memory.vmem windows.memmap --pid [PID] --dump

vol3 -f infected_memory.vmem windows.procdump --pid [PID]
```

Inspect memory:

```bash
hexdump -C pid.[PID].dmp | head -50
```

Search for suspicious strings:

```bash
strings pid.[PID].dmp | grep -E "(http|ftp|\.exe|\.dll)"
```

---

# 🧩 Task 3 — Extract & Analyze Malicious DLLs

---

## 🔹 Step 3.1 — Identify Loaded DLLs

List DLLs loaded into suspicious processes.

```bash
vol3 -f infected_memory.vmem windows.dlllist --pid [PID] > dll_list.txt
```

Identify unsigned DLLs:

```bash
grep -v "C:\\Windows\\System32" dll_list.txt
```

Search for unusual locations:

```bash
grep -E "(Temp|AppData|Users)" dll_list.txt
```

---

## 🔹 Step 3.2 — Dump Malicious DLLs

Extract DLLs from memory.

```bash
vol3 -f infected_memory.vmem windows.dlldump \
--pid [PID] \
--base [DLL_BASE]
```

Extract all DLLs:

```bash
vol3 -f infected_memory.vmem windows.dlldump --pid [PID]
```

Review extracted DLLs:

```bash
ls -la *.dll
```

Analyze each DLL:

```bash
for dll in *.dll
do
echo "=== $dll ==="
file "$dll"
strings "$dll" | head
echo ""
done
```

---

## 🔹 Step 3.3 — Investigate DLL Injection

Search for reflective DLL loading.

```bash
vol3 -f infected_memory.vmem windows.handles --pid [PID] | grep section
```

Inspect executable memory:

```bash
vol3 -f infected_memory.vmem windows.vadinfo --pid [PID] | grep -E "(PAGE_EXECUTE|PRIVATE)"
```

Search injection APIs:

```bash
strings infected_memory.vmem | grep -E "(LoadLibrary|GetProcAddress|VirtualAlloc)"
```

---

# 🌐 Task 4 — Investigate Malware Activity

---

## 🔹 Step 4.1 — Analyze Network Connections

Extract network activity.

```bash
vol3 -f infected_memory.vmem windows.netstat

vol3 -f infected_memory.vmem windows.netscan
```

Identify:

- 🌐 Command & Control servers
- 🌐 Suspicious outbound traffic
- 🌐 Unknown listening ports

Extract domains:

```bash
strings infected_memory.vmem | grep -E "([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
```

---

## 🔹 Step 4.2 — Examine Registry Persistence

List registry hives.

```bash
vol3 -f infected_memory.vmem windows.registry.hivelist
```

Inspect startup persistence.

```bash
vol3 -f infected_memory.vmem windows.registry.printkey \
--key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

Review installed services.

```bash
vol3 -f infected_memory.vmem windows.svcscan
```

---

## 🔹 Step 4.3 — Analyze File System Activity

Inspect open files.

```bash
vol3 -f infected_memory.vmem windows.handles --pid [PID] | grep File
```

Locate suspicious executables.

```bash
vol3 -f infected_memory.vmem windows.filescan
```

Recover files:

```bash
vol3 -f infected_memory.vmem windows.dumpfiles --virtaddr [ADDRESS]
```

---

## 🔹 Step 4.4 — Generate Investigation Report

Create a professional forensic report.

```bash
cat > analysis_report.txt << EOF

=== Memory Forensics Analysis Report ===

Date: $(date)

Memory Dump: infected_memory.vmem

Suspicious Processes

Injected DLLs

Network Activity

Registry Persistence

Recommendations

EOF
```

Display report:

```bash
cat analysis_report.txt
```

---

# 🔍 Indicators of Compromise (IOCs)

## 🧠 Process Indicators

- Process hollowing
- Parent-child anomalies
- Suspicious executable paths
- Unusual command lines
- Injected threads

---

## 📦 DLL Indicators

- Unsigned DLLs
- Reflective DLL loading
- DLLs outside System32
- DLL hijacking
- Manual mapping

---

## 💾 Memory Indicators

- PAGE_EXECUTE_READWRITE
- RWX memory pages
- Shellcode
- Injected VAD regions
- Hidden memory allocations

---

## 🌐 Network Indicators

- C2 communications
- Unknown remote IPs
- Beaconing traffic
- Suspicious DNS requests
- Reverse shells

---

## ⚙ Persistence Indicators

- Registry Run keys
- Scheduled tasks
- Installed services
- Startup folders
- DLL search-order hijacking

---

# 🧪 Verification

Verify installed tools.

```bash
vol3 --version

python3 --version
```

Check extracted artifacts.

```bash
ls -la *.dll *.dmp
```

Verify generated reports.

```bash
ls -la *.txt
```

Validate memory dump.

```bash
file infected_memory.vmem
```

---

# 🧰 Troubleshooting

## 🚫 Memory Dump Not Recognized

```bash
vol3 -f infected_memory.vmem windows.info.Info
```

---

## 🚫 No Suspicious Processes

```bash
vol3 -f infected_memory.vmem windows.malfind --pid ALL
```

---

## 🚫 DLL Extraction Fails

Inspect memory regions first.

```bash
vol3 -f infected_memory.vmem windows.vadinfo --pid [PID]
```

---

# 🏆 Skills Gained

After completing this lab you will understand how to:

- 🧠 Perform Windows memory forensics
- 🔍 Detect injected processes
- 📦 Extract malicious DLLs
- 🛡 Analyze malware persistence
- 🌐 Investigate network-based threats
- 📊 Generate DFIR reports
- 🔥 Hunt advanced malware
- ⚡ Investigate process hollowing
- 🧩 Analyze reflective DLL injection
- 🚨 Respond to advanced cyber incidents

---

# 🎓 Conclusion

Congratulations!

You have successfully completed an advanced **Memory Forensics & Malware Investigation** lab focused on **Injected Processes and Malicious DLL Analysis** using **Volatility 3**.

During this lab you learned how to identify **process injection**, **DLL hijacking**, **reflective DLL loading**, **memory-resident malware**, and **process hollowing** while investigating infected Windows memory images.

These skills are fundamental for professionals working as:

- 🔵 Digital Forensics Analysts
- 🔵 SOC Analysts
- 🔵 Incident Responders
- 🔵 Malware Researchers
- 🔵 Threat Hunters
- 🔵 DFIR Engineers

Memory forensics remains one of the most powerful techniques for uncovering sophisticated malware that operates entirely in memory and evades traditional antivirus solutions. Mastering these techniques enables cybersecurity professionals to investigate advanced persistent threats (APTs), document attacker behavior, and respond effectively to modern cyber incidents.

---

# ⭐ If You Found This Lab Helpful

If this repository helped you learn **Memory Forensics** and **Malicious DLL Analysis**:

🌟 Star this repository

🍴 Fork this repository

📢 Share it with the cybersecurity community

🤝 Contribute additional DFIR, Volatility, and Malware Analysis labs

Happy Hunting! 🛡️🔍
