#!/usr/bin/env python3
import json
import re
from collections import defaultdict

class PowerShellAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.ps_events = []
        self.malicious_patterns = {
            'download_cradle': r'(IEX|Invoke-Expression).*DownloadString',
            'encoded_command': r'-EncodedCommand|-enc',
            'bypass_execution_policy': r'-ExecutionPolicy\s+Bypass',
            'hidden_window': r'-WindowStyle\s+Hidden',
            'web_request': r'(Invoke-WebRequest|wget|curl)',
            'base64_decode': r'FromBase64String',
            'reflection': r'System\.Reflection',
            'memory_injection': r'VirtualAlloc|WriteProcessMemory'
        }
    
    def load_events(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if 'PowerShell' in event.get('provider', ''):
                        self.ps_events.append(event)
                except:
                    continue
    
    def analyze_malicious_patterns(self):
        print("=== PowerShell Abuse Analysis ===\n")
        
        pattern_detections = defaultdict(list)
        total_suspicious = 0
        
        for event in self.ps_events:
            script_block = event.get('script_block', '')
            
            for pattern_name, pattern in self.malicious_patterns.items():
                if re.search(pattern, script_block, re.IGNORECASE):
                    pattern_detections[pattern_name].append({
                        'timestamp': event['timestamp'],
                        'user': event.get('user', 'Unknown'),
                        'script': script_block[:100] + '...' if len(script_block) > 100 else script_block
                    })
                    
                    if event.get('suspicious', False):
                        total_suspicious += 1
        
        print("Malicious Pattern Detection:")
        for pattern, detections in pattern_detections.items():
            print(f"\n  🔍 {pattern.upper()}: {len(detections)} detections")
            for detection in detections[:3]:  # Show first 3
                print(f"    Time: {detection['timestamp']}")
                print(f"    User: {detection['user']}")
                print(f"    Script: {detection['script']}")
                print()
        
        print(f"Total Suspicious PowerShell Events: {total_suspicious}")
    
    def analyze_obfuscation(self):
        print("\n=== PowerShell Obfuscation Analysis ===\n")
        
        obfuscation_indicators = {
            'string_concatenation': r'\+.*\+.*\+',
            'character_replacement': r'\.replace\(',
            'format_strings': r'-f\s*\(',
            'invoke_expression': r'(IEX|Invoke-Expression)',
            'compressed_data': r'IO\.Compression',
            'random_case': r'[a-z][A-Z][a-z][A-Z]'
        }
        
        obfuscated_events = []
        
        for event in self.ps_events:
            script_block = event.get('script_block', '')
            obfuscation_score = 0
            detected_techniques = []
            
            for technique, pattern in obfuscation_indicators.items():
                if re.search(pattern, script_block, re.IGNORECASE):
                    obfuscation_score += 1
                    detected_techniques.append(technique)
            
            if obfuscation_score >= 2:  # Threshold for obfuscation
                obfuscated_events.append({
                    'timestamp': event['timestamp'],
                    'user': event.get('user', 'Unknown'),
                    'score': obfuscation_score,
                    'techniques': detected_techniques,
                    'script': script_block[:150] + '...' if len(script_block) > 150 else script_block
                })
        
        print(f"Potentially Obfuscated Scripts Found: {len(obfuscated_events)}")
        for event in obfuscated_events:
            print(f"\n  ⚠️  Obfuscation Score: {event['score']}/6")
            print(f"     Timestamp: {event['timestamp']}")
            print(f"     User: {event['user']}")
            print(f"     Techniques: {', '.join(event['techniques'])}")
            print(f"     Script: {event['script']}")

if __name__ == "__main__":
    analyzer = PowerShellAnalyzer('etw_events.json')
    analyzer.load_events()
    analyzer.analyze_malicious_patterns()
    analyzer.analyze_obfuscation()
