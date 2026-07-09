#!/usr/bin/env python3
import csv
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse

def analyze_suspicious_domains():
    suspicious_indicators = [
        r'\.tk$', r'\.ml$', r'\.ga$',  # Suspicious TLDs
        r'bit\.ly', r'tinyurl',        # URL shorteners
        r'pastebin', r'hastebin',      # Paste sites
        r'dropbox', r'mega\.nz',       # File sharing
        r'temp-mail', r'10minutemail'  # Temporary email
    ]
    
    suspicious_urls = []
    
    with open('unified_timeline.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row['event'].replace('Visited: ', '')
            domain = urlparse(url).netloc
            
            for pattern in suspicious_indicators:
                if re.search(pattern, domain, re.IGNORECASE):
                    suspicious_urls.append({
                        'timestamp': row['timestamp'],
                        'url': url,
                        'pattern': pattern,
                        'source': row['source']
                    })
                    break
    
    return suspicious_urls

def analyze_time_patterns():
    hourly_activity = defaultdict(int)
    
    with open('unified_timeline.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                timestamp = row['timestamp']
                hour = timestamp.split(' ')[1].split(':')[0]
                hourly_activity[hour] += 1
            except:
                continue
    
    return dict(hourly_activity)

def main():
    print("=== Suspicious Domain Analysis ===")
    suspicious = analyze_suspicious_domains()
    for item in suspicious[:10]:  # Show top 10
        print(f"{item['timestamp']}: {item['url']} (Pattern: {item['pattern']})")
    
    print(f"\nTotal suspicious URLs found: {len(suspicious)}")
    
    print("\n=== Hourly Activity Pattern ===")
    hourly = analyze_time_patterns()
    for hour in sorted(hourly.keys()):
        print(f"Hour {hour}: {hourly[hour]} visits")

if __name__ == "__main__":
    main()
