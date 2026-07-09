#!/usr/bin/env python3
import json
from datetime import datetime

def generate_attack_report():
    report = """
=== INCIDENT ANALYSIS REPORT ===
Generated: {}

ATTACK TIMELINE RECONSTRUCTION:

1. Initial Access (08:29:45)
   - Web application login attempt detected
   - Source: Apache Access Logs
   - Indicator: Admin panel access

2. Credential Compromise (08:30:15)
   - Successful user login: john.doe
   - Source: Windows Event Logs
   - Indicator: Legitimate user account compromise

3. Lateral Movement (08:31:22)
   - Command execution via cmd.exe
   - Source: Windows Event Logs
   - Indicator: Process creation

4. Data Discovery (08:32:45)
   - Sensitive file access detected
   - Source: Windows Event Logs
   - File: C:\\sensitive\\data.txt

5. Web Shell Deployment (08:33:20)
   - File upload to web server
   - Source: Apache Access Logs
   - Indicator: Malicious file upload

6. Command & Control (08:34:15)
   - Web shell execution
   - Source: Apache Access Logs
   - File: /uploads/shell.php

7. Data Exfiltration (08:35:25)
   - Large outbound data transfer
   - Source: Network Traffic Logs
   - Volume: 50MB

RECOMMENDATIONS:
- Implement file integrity monitoring
- Deploy web application firewall
- Monitor for unusual data transfers
- Review user access controls
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    with open('incident_report.txt', 'w') as f:
        f.write(report)
    
    print(report)

if __name__ == "__main__":
    generate_attack_report()
