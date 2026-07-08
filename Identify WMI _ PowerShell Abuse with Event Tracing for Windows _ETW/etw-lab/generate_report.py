#!/usr/bin/env python3
import json
import datetime

def generate_final_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"etw_analysis_report_{timestamp}.txt"
    
    with open(report_file, 'w') as report:
        report.write("ETW SECURITY ANALYSIS REPORT\n")
        report.write("=" * 50 + "\n")
        report.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Analyst: Security Lab Student\n\n")
        
        # Load events for analysis
        events = []
        try:
            with open('etw_events.json', 'r') as f:
                for line in f:
                    try:
                        events.append(json.loads(line.strip()))
                    except:
                        continue
        except:
            report.write("ERROR: Could not load event data\n")
            return
        
        # Executive Summary
        total = len(events)
        suspicious = len([e for e in events if e.get('suspicious', False)])
        
        report.write("EXECUTIVE SUMMARY\n")
        report.write("-" * 20 + "\n")
        report.write(f"Total Events Analyzed: {total}\n")
        report.write(f"Suspicious Events: {suspicious}\n")
        report.write(f"Risk Level: {calculate_risk_level(suspicious, total)}\n\n")
        
        # Detailed Findings
        report.write("DETAILED FINDINGS\n")
        report.write("-" * 20 + "\n")
        
        wmi_suspicious = [e for e in events if 'WMI' in e.get('provider', '') and e.get('suspicious')]
        ps_suspicious = [e for e in events if 'PowerShell' in e.get('provider', '') and e.get('suspicious')]
        
        report.write(f"WMI Abuse Events: {len(wmi_suspicious)}\n")
        report.write(f"PowerShell Abuse Events: {len(ps_suspicious)}\n\n")
        
        # Top 5 suspicious events
        report.write("TOP SUSPICIOUS EVENTS\n")
        report.write("-" * 20 + "\n")
        
        suspicious_events = [e for e in events if e.get('suspicious')][:5]
        for i, event in enumerate(suspicious_events, 1):
            report.write(f"{i}. {event['timestamp']} - {event['provider']}\n")
            report.write(f"   User: {event.get('user', 'Unknown')}\n")
            if 'command_line' in event:
                report.write(f"   Command: {event['command_line'][:80]}...\n")
            if 'script_block' in event:
                report.write(f"   Script: {event['script_block'][:80]}...\n")
            report.write(f"   Indicators: {', '.join(event.get('indicators', []))}\n\n")
        
        # Recommendations
        report.write("RECOMMENDATIONS\n")
        report.write("-" * 20 + "\n")
        report.write("1. Implement continuous ETW monitoring\n")
        report.write("2. Create alerts for suspicious WMI/PowerShell patterns\n")
        report.write("3. Review and harden PowerShell execution policies\n")
        report.write("4. Monitor privileged account usage\n")
        report.write("5. Implement network segmentation\n\n")
        
        report.write("END OF REPORT\n")
    
    print(f"Final report generated: {report_file}")
    return report_file

def calculate_risk_level(suspicious, total):
    if total == 0:
        return "UNKNOWN"
    percentage = (suspicious / total) * 100
    if percentage >= 30:
        return "CRITICAL"
    elif percentage >= 15:
        return "HIGH"
    elif percentage >= 5:
        return "MEDIUM"
    else:
        return "LOW"

if __name__ == "__main__":
    generate_final_report()
