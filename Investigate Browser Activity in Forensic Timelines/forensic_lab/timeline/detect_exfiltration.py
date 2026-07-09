#!/usr/bin/env python3
import csv
import re
from urllib.parse import urlparse, parse_qs

def detect_data_exfiltration():
    exfiltration_indicators = []
    
    # Patterns indicating potential data exfiltration
    suspicious_patterns = [
        (r'upload', 'File upload activity'),
        (r'data=.*[A-Za-z0-9+/]{20,}', 'Base64 encoded data in URL'),
        (r'file.*download', 'File download activity'),
        (r'export.*data', 'Data export activity'),
        (r'backup.*download', 'Backup download'),
        (r'\.zip|\.rar|\.7z', 'Archive file access'),
        (r'gmail.*attachment', 'Email attachment activity')
    ]
    
    with open('unified_timeline.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row['event'].replace('Visited: ', '')
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    exfiltration_indicators.append({
                        'timestamp': row['timestamp'],
                        'url': url,
                        'indicator': description,
                        'source': row['source']
                    })
    
    return exfiltration_indicators

def analyze_url_parameters():
    large_params = []
    
    with open('unified_timeline.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row['event'].replace('Visited: ', '')
            
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for key, values in params.items():
                        for value in values:
                            if len(value) > 100:  # Suspiciously long parameter
                                large_params.append({
                                    'timestamp': row['timestamp'],
                                    'url': url,
                                    'parameter': key,
                                    'length': len(value),
                                    'source': row['source']
                                })
            except:
                continue
    
    return large_params

def main():
    print("=== Data Exfiltration Analysis ===")
    exfiltration = detect_data_exfiltration()
    
    if exfiltration:
        print(f"Found {len(exfiltration)} potential exfiltration indicators:")
        for item in exfiltration[:10]:
            print(f"{item['timestamp']}: {item['indicator']}")
            print(f"  URL: {item['url'][:80]}...")
            print()
    else:
        print("No obvious exfiltration patterns detected")
    
    print("=== Large URL Parameters Analysis ===")
    large_params = analyze_url_parameters()
    
    if large_params:
        print(f"Found {len(large_params)} URLs with large parameters:")
        for item in large_params[:5]:
            print(f"{item['timestamp']}: Parameter '{item['parameter']}' ({item['length']} chars)")
            print(f"  URL: {item['url'][:80]}...")
            print()
    else:
        print("No URLs with suspiciously large parameters found")

if __name__ == "__main__":
    main()
