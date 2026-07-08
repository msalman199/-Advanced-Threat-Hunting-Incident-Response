#!/usr/bin/env python3
import json
import datetime
from collections import defaultdict

def create_dashboard():
    print("=" * 60)
    print("           ETW SECURITY ANALYSIS DASHBOARD")
    print("=" * 60)
    
    # Load and analyze events
    events = []
    try:
        with open('etw_events.json', 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except:
                    continue
    except FileNotFoundError:
        print("Error: etw_events.json not found. Please run the simulator first.")
        return
    
    if not events:
        print("No events found to analyze.")
        return
    
    # Summary Statistics
    total_events = len(events)
    suspicious_events = len([e for e in events if e.get('suspicious', False)])
    wmi_events = len([e for e in events if 'WMI' in e.get('provider', '')])
    ps_events = len([e for e in events if 'PowerShell' in e.get('provider', '')])
    
    print(f"\n📊 EVENT SUMMARY")
    print(f"   Total Events: {total_events}")
    print(f"   Suspicious Events: {suspicious_events}")
    print(f"   WMI Events: {wmi_events}")
    print(f"   PowerShell Events: {ps_events}")
    print(f"   Threat Level: {calculate_threat_level(suspicious_events, total_events)}")
    
    # Top Indicators
    print(f"\n🚨 TOP THREAT INDICATORS")
    indicators = defaultdict(int)
    for event in events:
        for indicator in event.get('indicators', []):
            indicators[indicator] += 1
    
    for indicator, count in sorted(indicators.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {indicator}: {count} occurrences")
    
    # User Risk Analysis
    print(f"\n👤 USER RISK ANALYSIS")
    user_risk = defaultdict(lambda: {'total': 0, 'suspicious': 0})
    
    for event in events:
        user = event.get('user', 'Unknown')
        user_risk[user]['total'] += 1
        if event.get('suspicious', False):
            user_risk[user]['suspicious'] += 1
    
    for user, stats in sorted(user_risk.items(), key=lambda x: x[1]['suspicious'], reverse=True):
        risk_pct = (stats['suspicious'] / stats['total']) * 100 if stats['total'] > 0 else 0
        risk_level = "🔴 HIGH" if risk_pct > 50 else "🟡 MEDIUM" if risk_pct > 20 else "🟢 LOW"
        print(f"   {user}: {stats['suspicious']}/{stats['total']} suspicious ({risk_pct:.1f}%) {risk_level}")
    
    # Timeline Analysis
    print(f"\n⏰ TIMELINE ANALYSIS")
    hourly_activity = defaultdict(int)
    
    for event in events:
        try:
            hour = event['timestamp'].split('T')[1].split(':')[0]
            hourly_activity[hour] += 1
        except:
            continue
    
    for hour in sorted(hourly_activity.keys()):
        count = hourly_activity[hour]
        bar = "█" * min(count // 2, 20)  # Visual bar
        print(f"   {hour}:00 {bar} ({count})")
    
    # Recommendations
    print(f"\n💡 SECURITY RECOMMENDATIONS")
    if suspicious_events > total_events * 0.3:
        print("   🔴 CRITICAL: High volume of suspicious activity detected")
        print("      → Immediate investigation required")
        print("      → Consider isolating affected systems")
    
    if any('download_string' in event.get('indicators', []) for event in events):
        print("   🟡 WARNING: PowerShell download cradles detected")
        print("      → Review network connections")
        print("      → Check for malware downloads")
    
    if any('process_enumeration' in event.get('indicators', []) for event in events):
        print("   🟡 WARNING: Process enumeration via WMI detected")
        print("      → Monitor for lateral movement")
        print("      → Review privileged account usage")
    
    print("\n" + "=" * 60)
    print("Analysis complete. Review findings and take appropriate action.")
    print("=" * 60)

def calculate_threat_level(suspicious, total):
    if total == 0:
        return "UNKNOWN"
    
    percentage = (suspicious / total) * 100
    
    if percentage >= 40:
        return "🔴 CRITICAL"
    elif percentage >= 20:
        return "🟠 HIGH"
    elif percentage >= 10:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

if __name__ == "__main__":
    create_dashboard()
