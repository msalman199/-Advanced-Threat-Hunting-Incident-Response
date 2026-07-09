#!/usr/bin/env python3
import pandas as pd
import json

def create_executive_summary():
    """Create an executive summary of findings"""
    
    # Load timeline data
    timeline_df = pd.read_csv('suspicious_activity_timeline.csv')
    timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])
    
    # Load attack patterns
    try:
        with open('attack_patterns.json', 'r') as f:
            patterns = json.load(f)
    except:
        patterns = []
    
    print("=== EXECUTIVE SUMMARY: USER ACTIVITY ANALYSIS ===\n")
    
    # Overall statistics
    total_events = len(timeline_df)
    high_risk_events = len(timeline_df[timeline_df['risk_level'] == 'High'])
    medium_risk_events = len(timeline_df[timeline_df['risk_level'] == 'Medium'])
    unique_users = timeline_df['username'].nunique()
    unique_workstations = timeline_df['workstation'].nunique()
    
    print("OVERVIEW:")
    print(f"• Total Events Analyzed: {total_events}")
    print(f"• High Risk Events: {high_risk_events}")
    print(f"• Medium Risk Events: {medium_risk_events}")
    print(f"• Users Involved: {unique_users}")
    print(f"• Workstations Involved: {unique_workstations}")
    print()
    
    # Time range analysis
    start_time = timeline_df['timestamp'].min()
    end_time = timeline_df['timestamp'].max()
    print(f"ANALYSIS PERIOD:")
    print(f"• From: {start_time}")
    print(f"• To: {end_time}")
    print()
    
    # User risk assessment
    print("USER RISK ASSESSMENT:")
    user_risk = timeline_df.groupby('username').agg({
        'risk_level': lambda x: (x == 'High').sum(),
        'timestamp': 'count'
    }).rename(columns={'risk_level': 'high_risk_events', 'timestamp': 'total_events'})
    
    for user, data in user_risk.iterrows():
        risk_percentage = (data['high_risk_events'] / data['total_events']) * 100
        print(f"• {user}: {data['high_risk_events']}/{data['total_events']} high-risk events ({risk_percentage:.1f}%)")
    print()
    
    # Attack patterns summary
    if patterns:
        print("IDENTIFIED THREATS:")
        for pattern in patterns:
            print(f"• {pattern['pattern_type']}: {pattern['description']}")
        print()
    
    # Recommendations
    print("RECOMMENDATIONS:")
    if high_risk_events > 0:
        print("• Immediate investigation required for high-risk events")
        print("• Review user access privileges and permissions")
        print("• Implement additional monitoring for identified users")
    
    if any(p['pattern_type'] == 'Privilege Escalation' for p in patterns):
        print("• Investigate privilege escalation attempts")
        print("• Review administrative account usage policies")
    
    if any(p['pattern_type'] == 'Brute Force Attempt' for p in patterns):
        print("• Implement account lockout policies")
        print("• Consider multi-factor authentication")
    
    print("• Continue monitoring for similar activity patterns")
    print()

if __name__ == "__main__":
    create_executive_summary()
