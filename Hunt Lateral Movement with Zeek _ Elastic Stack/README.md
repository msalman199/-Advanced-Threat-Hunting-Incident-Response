<div align="center">

# 🕸️ Hunt Lateral Movement with Zeek & Elastic Stack

![Zeek](https://img.shields.io/badge/Zeek-Network%20Monitor-00A98F?style=for-the-badge&logo=wireshark&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Logstash](https://img.shields.io/badge/Logstash-Pipeline-005571?style=for-the-badge&logo=logstash&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-005571?style=for-the-badge&logo=kibana&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Threat%20Hunting-blue?style=for-the-badge)

**A hands-on lab in detecting lateral movement using Zeek network monitoring and the Elastic Stack**

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔧 Task 1: Install and Configure Zeek](#-task-1-install-and-configure-zeek)
- [📊 Task 2: Install and Configure Elastic Stack](#-task-2-install-and-configure-elastic-stack)
- [🌐 Task 3: Generate Lateral Movement Traffic](#-task-3-generate-lateral-movement-traffic)
- [🕵️ Task 4: Analyze Lateral Movement in Kibana](#️-task-4-analyze-lateral-movement-in-kibana)
- [🔬 Task 5: Advanced Lateral Movement Analysis](#-task-5-advanced-lateral-movement-analysis)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure Zeek network security monitor for traffic analysis |
| 2 | Deploy Elastic Stack (Elasticsearch, Logstash, Kibana) for log analysis |
| 3 | Generate simulated lateral movement traffic patterns |
| 4 | Identify lateral movement indicators using network traffic analysis |
| 5 | Create detection queries and visualizations in Kibana |

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command line knowledge |
| 🌐 Network Protocols | Understanding of network protocols (TCP, SSH, SMB) |
| 📊 Log Analysis | Familiarity with log analysis concepts |
| ↔️ Lateral Movement | Knowledge of lateral movement attack techniques |

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you'll install all required components during the lab.

---

## 🔧 Task 1: Install and Configure Zeek

### ✅ 1.1 Install Zeek Dependencies

```bash
sudo apt update
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev
# TODO: Confirm cmake and gcc/g++ meet Zeek's minimum version requirements
```

### ✅ 1.2 Download and Install Zeek

```bash
cd /tmp
wget https://download.zeek.org/zeek-6.0.3.tar.gz
tar -xzf zeek-6.0.3.tar.gz
cd zeek-6.0.3
./configure --prefix=/opt/zeek
make -j$(nproc)
sudo make install
# TODO: This build can take 15-30+ minutes depending on CPU cores — plan accordingly
```

### ✅ 1.3 Configure Zeek Environment

```bash
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### ✅ 1.4 Configure Zeek Network Interface

```bash
sudo /opt/zeek/bin/zeek -i eth0 local &
```

```bash
# 🔎 Verify Zeek is running
ps aux | grep zeek
# TODO: Replace eth0 with your actual monitoring interface if different
```

---

## 📊 Task 2: Install and Configure Elastic Stack

### ✅ 2.1 Install Java (Required for Elasticsearch)

```bash
sudo apt install -y openjdk-11-jdk
```

### ✅ 2.2 Install Elasticsearch

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install -y elasticsearch
```

```bash
# ⚙️ Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

```yaml
network.host: localhost
http.port: 9200
xpack.security.enabled: false
```

```bash
# ▶️ Start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
# TODO: Confirm cluster health is green/yellow before proceeding to Logstash
```

### ✅ 2.3 Install Logstash

```bash
sudo apt install -y logstash
```

```bash
# ⚙️ Create Logstash configuration for Zeek logs
sudo nano /etc/logstash/conf.d/zeek.conf
```

```ruby
input {
  file {
    path => "/opt/zeek/logs/current/*.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  if [path] =~ "conn" {
    csv {
      separator => "	"
      columns => ["ts","uid","id_orig_h","id_orig_p","id_resp_h","id_resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"]
    }
    mutate {
      convert => { "ts" => "float" }
    }
    date {
      match => [ "ts", "UNIX" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "zeek-logs-%{+YYYY.MM.dd}"
  }
}
```

```bash
# ▶️ Start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash
# TODO: Extend the filter block to also parse ssh.log and dns.log for richer detections
```

### ✅ 2.4 Install Kibana

```bash
sudo apt install -y kibana
```

```bash
# ⚙️ Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# ▶️ Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana
```

---

## 🌐 Task 3: Generate Lateral Movement Traffic

### ✅ 3.1 Install Network Tools

```bash
sudo apt install -y nmap sshpass netcat-openbsd
```

### ✅ 3.2 Create Simulated Internal Network Traffic

```bash
# 📝 Create a simple script to simulate lateral movement
cat > lateral_movement_sim.sh << 'EOF'
#!/bin/bash

# Simulate SSH scanning
for i in {1..5}; do
    timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no user@127.0.0.$i 2>/dev/null
    sleep 1
done

# Simulate SMB enumeration
for i in {1..3}; do
    timeout 2 nc -zv 127.0.0.$i 445 2>/dev/null
    sleep 1
done

# Simulate RDP attempts
for i in {1..3}; do
    timeout 2 nc -zv 127.0.0.$i 3389 2>/dev/null
    sleep 1
done
EOF

chmod +x lateral_movement_sim.sh
# TODO: These loopback addresses (127.0.0.x) are safe for lab traffic generation only
```

### ✅ 3.3 Execute Traffic Generation

```bash
# 🔁 Run the simulation multiple times to generate patterns
for i in {1..10}; do
    ./lateral_movement_sim.sh
    sleep 5
done
```

### ✅ 3.4 Generate Additional Network Scans

```bash
# 🎯 Port scanning simulation
nmap -sS 127.0.0.1-10 -p 22,445,3389 --max-retries 1 --host-timeout 2s
# TODO: Confirm Zeek's conn.log is capturing these scan connections in real time
```

---

## 🕵️ Task 4: Analyze Lateral Movement in Kibana

### ✅ 4.1 Access Kibana Dashboard

```
http://localhost:5601
```

### ✅ 4.2 Create Index Pattern

1. Go to **Management → Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Enter pattern: `zeek-logs-*`
4. Select timestamp field: `@timestamp`
5. Click **Create index pattern**

### ✅ 4.3 Discover Lateral Movement Indicators

Navigate to **Discover** and create these search queries:

**SSH Brute Force Detection:**
```
service:ssh AND conn_state:REJ
```

**Port Scanning Detection:**
```
id_orig_h:127.0.0.1 AND (id_resp_p:445 OR id_resp_p:3389 OR id_resp_p:22)
```

**Multiple Connection Attempts:**
```
id_orig_h:127.0.0.1 AND conn_state:(S0 OR REJ)
```
<!-- TODO: Save each of these searches so they can be reused in the dashboard build -->

### ✅ 4.4 Create Visualizations

Create a Data Table visualization:

1. Go to **Visualize → Create visualization → Data table**
2. Select `zeek-logs-*` index
3. Add metrics: **Count of connections**
4. Add buckets:
   - Terms aggregation on `id_orig_h.keyword`
   - Terms aggregation on `id_resp_p`
5. Apply changes and save as **"Lateral Movement Connections"**

### ✅ 4.5 Build Detection Dashboard

1. Go to **Dashboard → Create dashboard**
2. Add the visualization created above
3. Add a **Line chart** showing connection attempts over time
4. Save dashboard as **"Lateral Movement Detection"**

---

## 🔬 Task 5: Advanced Lateral Movement Analysis

### ✅ 5.1 Create Custom Detection Queries

```json
// 🔍 In Kibana Dev Tools, run this query to detect rapid sequential connections
GET zeek-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"terms": {"id_resp_p": [22, 445, 3389]}}
      ]
    }
  },
  "aggs": {
    "source_ips": {
      "terms": {
        "field": "id_orig_h.keyword",
        "size": 10
      },
      "aggs": {
        "connection_count": {
          "value_count": {
            "field": "uid.keyword"
          }
        }
      }
    }
  }
}
```
<!-- TODO: Add a min_doc_count filter to suppress single-connection noise -->

### ✅ 5.2 Analyze Connection Patterns

Look for these lateral movement indicators:

| Indicator | Description |
|---|---|
| 🔴 High connection failure rates | `REJ`, `S0` connection states |
| 🔴 Sequential IP scanning patterns | Ordered sweep across a subnet |
| 🔴 Multiple service enumeration | Single source touching many ports/hosts |
| 🔴 Unusual connection timing | Off-hours or bursty connection patterns |

---

## 🧪 Verification and Testing

### ✅ Check Service Status

```bash
# ✔️ Verify all services are running
sudo systemctl status elasticsearch
sudo systemctl status logstash  
sudo systemctl status kibana
ps aux | grep zeek
```

### ✅ Validate Data Flow

```bash
# 📁 Check if logs are being generated
ls -la /opt/zeek/logs/current/

# 📊 Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices?v"

# 🔢 Verify log ingestion
curl -X GET "localhost:9200/zeek-logs-*/_count"
# TODO: Compare the document count against expected event volume from Task 3
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Reference |
|---|---|---|---|
| T1021.004 | Remote Services: SSH | Lateral Movement | SSH scanning simulation / `conn_state:REJ` query |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | SMB enumeration (port 445) simulation |
| T1021.001 | Remote Services: RDP | Lateral Movement | RDP connection attempts (port 3389) |
| T1046 | Network Service Discovery | Discovery | `nmap` port scan simulation |
| T1110 | Brute Force | Credential Access | SSH brute-force detection query |
| T1018 | Remote System Discovery | Discovery | Sequential IP scanning pattern analysis |

---

## 🛠️ Troubleshooting

<details>
<summary>❗ If Zeek logs are not appearing</summary>

```bash
# Restart Zeek with verbose logging
sudo pkill zeek
sudo /opt/zeek/bin/zeek -i eth0 local
```

</details>

<details>
<summary>❗ If Elasticsearch connection fails</summary>

```bash
# Check Elasticsearch status
curl -X GET "localhost:9200/_cluster/health?pretty"
```

</details>

<details>
<summary>❗ If Kibana won't load</summary>

```bash
# Check Kibana logs
sudo tail -f /var/log/kibana/kibana.log
```

</details>

---

## ✅ Conclusion

You have successfully implemented a lateral movement detection system using Zeek and Elastic Stack. This lab demonstrated how to:

- 🕸️ Deploy network monitoring with Zeek to capture connection metadata
- 📊 Configure Elastic Stack for centralized log analysis and visualization
- 🌐 Generate realistic lateral movement traffic patterns for testing
- 🔍 Create detection queries to identify suspicious network behavior
- 📈 Build dashboards for ongoing security monitoring

This setup provides a foundation for detecting real-world lateral movement techniques including credential stuffing, network scanning, and service enumeration. The combination of Zeek's network visibility and Elastic Stack's analysis capabilities creates a powerful platform for threat hunting and incident response.

---

<div align="center">

### 🛡️ Al Nafi Cloud Labs
*Empowering the Next Generation of Cybersecurity Professionals*

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cloud%20Security%20Labs-1a1a2e?style=for-the-badge)

</div>
