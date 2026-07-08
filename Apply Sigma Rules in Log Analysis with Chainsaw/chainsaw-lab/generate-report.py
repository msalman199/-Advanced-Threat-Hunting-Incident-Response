#!/usr/bin/env python3
import json
import sys
from collections import Counter

def analyze_detections(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            data = [data]
        
        print("=== CHAINSAW SIGMA DETECTION SUMMARY ===\n")
        
        # Count detections by rule
        rule_counts = Counter()
        severity_counts = Counter()
        
        for detection in data:
            if 'detections' in detection:
                for det in detection['detections']:
                    rule_name = det.get('rule', 'Unknown Rule')
                    severity = det.get('level', 'unknown')
                    rule_counts[rule_name] += 1
                    severity_counts[severity] += 1
        
        print(f"Total Detections: {sum(rule_counts.values())}")
        print(f"Unique Rules Triggered: {len(rule_counts)}\n")
        
        print("Top 5 Most Triggered Rules:")
        for rule, count in rule_counts.most_common(5):
            print(f"  - {rule}: {count} detections")
        
        print(f"\nDetections by Severity:")
        for severity, count in severity_counts.items():
            print(f"  - {severity.upper()}: {count}")
            
    except Exception as e:
        print(f"Error analyzing file: {e}")

if __name__ == "__main__":
    analyze_detections("~/chainsaw-lab/timeline-analysis.json")
