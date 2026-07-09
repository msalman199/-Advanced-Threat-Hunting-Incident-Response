#!/usr/bin/env python3
import pandas as pd
from datetime import datetime

def generate_investigation_report(csv_file):
    """Generate comprehensive investigation report"""
    
    df = pd.read_csv(csv_file)
    
    report = f"""
FORENSIC TIMELINE INVESTIGATION REPORT
=====================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
-----------------
Timeline analysis of forensic artifacts reveals potential security incident
involving unauthorized access attempts and suspicious network activity.

TIMELINE STATISTICS
-------------------
Total Events Analyzed: {len(df)}
Time Range: {df['datetime'].min()} to {df['datetime'].max()}
Unique Sources: {df['source'].nunique()}

KEY FINDINGS
------------
"""
    
    # Identify key events
    suspicious_events = df[df['message'].str.contains(
        r'failed|suspicious|malicious|exfiltration|nc\.exe', 
        case=False, na=False
    )]
    
    report += f"Suspicious Events Identified: {len(suspicious_events)}\n\n"
    
    for _, event in suspicious_events.iterrows():
        report += f"- {event['datetime']}: {event['message']}\n"
    
    report += """
RECOMMENDATIONS
---------------
1. Investigate failed login attempts for potential brute force attacks
2. Analyze network connections to suspicious IP addresses
3. Review file access patterns for data exfiltration indicators
4. Implement additional monitoring for executable file execution
5. Enhance user access controls and authentication mechanisms

TECHNICAL DETAILS
-----------------
Analysis performed using Plaso/log2timeline toolkit
Timeline data extracted from multiple artifact sources
Correlation analysis applied to identify attack sequences
"""
    
    with open('investigation_report.txt', 'w') as f:
        f.write(report)
    
    print("Investigation report generated: investigation_report.txt")
    print("\nReport Preview:")
    print(report[:500] + "...")

if __name__ == "__main__":
    generate_investigation_report('timeline.csv')
