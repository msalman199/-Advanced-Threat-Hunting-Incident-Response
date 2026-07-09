#!/usr/bin/env python3
import pandas as pd
import re
from datetime import datetime

def analyze_timeline(csv_file):
    """Analyze timeline for suspicious patterns"""
    
    # Read timeline data
    df = pd.read_csv(csv_file)
    
    print("=== TIMELINE ANALYSIS REPORT ===\n")
    
    # Basic statistics
    print(f"Total Events: {len(df)}")
    print(f"Date Range: {df['datetime'].min()} to {df['datetime'].max()}")
    print(f"Unique Sources: {df['source'].nunique()}\n")
    
    # Suspicious indicators
    suspicious_patterns = [
        r'nc\.exe',
        r'malicious',
        r'failed.*login',
        r'suspicious',
        r'exfiltration'
    ]
    
    print("=== SUSPICIOUS EVENTS ===")
    for pattern in suspicious_patterns:
        matches = df[df['message'].str.contains(pattern, case=False, na=False)]
        if not matches.empty:
            print(f"\nPattern: {pattern}")
            for _, row in matches.iterrows():
                print(f"  {row['datetime']} - {row['message']}")
    
    # Timeline clustering (events within 5 minutes)
    print("\n=== EVENT CLUSTERING ===")
    df['datetime'] = pd.to_datetime(df['datetime'])
    df_sorted = df.sort_values('datetime')
    
    clusters = []
    current_cluster = []
    
    for _, row in df_sorted.iterrows():
        if not current_cluster:
            current_cluster.append(row)
        else:
            time_diff = (row['datetime'] - current_cluster[-1]['datetime']).total_seconds()
            if time_diff <= 300:  # 5 minutes
                current_cluster.append(row)
            else:
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [row]
    
    if len(current_cluster) > 1:
        clusters.append(current_cluster)
    
    for i, cluster in enumerate(clusters):
        print(f"\nCluster {i+1} ({len(cluster)} events):")
        for event in cluster:
            print(f"  {event['datetime']} - {event['message']}")

if __name__ == "__main__":
    analyze_timeline('timeline.csv')
