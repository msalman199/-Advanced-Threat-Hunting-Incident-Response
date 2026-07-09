#!/usr/bin/env python3
import csv
from datetime import datetime

def generate_incident_report():
    report = """
=== INCIDENT RECONSTRUCTION REPORT ===
Case: Insider Data Theft Investigation
Date: {current_date}

EXECUTIVE SUMMARY:
Analysis of digital evidence indicates a systematic data theft operation by an insider.
The incident occurred on January 15, 2024, involving unauthorized access to sensitive
financial and customer data, followed by data exfiltration via USB device and external upload.

TIMELINE OF EVENTS:
""".format(current_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Read and format timeline
    with open('master_timeline.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            report += f"{row['timestamp']} - {row['source']}: {row['event']}\n"
    
    report += """
KEY FINDINGS:
1. Unauthorized access to sensitive files (financial_data.xlsx, customer_database.csv)
2. Use of compression tools to package stolen data
3. USB device insertion and data transfer
4. External file upload to file-sharing service
5. Attempt to cover tracks through command history manipulation

EVIDENCE ARTIFACTS:
- Registry entries showing recent document access
- File system timestamps indicating data access and copying
- System logs showing USB device mounting
- Network logs showing external data transmission

RECOMMENDATIONS:
1. Implement Data Loss Prevention (DLP) solutions
2. Monitor USB device usage
3. Enhance user activity monitoring
4. Review access controls for sensitive data
5. Conduct security awareness training

CASE STATUS: Investigation Complete
THREAT LEVEL: HIGH
"""
    
    return report

# Generate and save report
report_content = generate_incident_report()
print(report_content)

with open('incident_reconstruction_report.txt', 'w') as f:
    f.write(report_content)

print("\nFull report saved to: incident_reconstruction_report.txt")
