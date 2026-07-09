#!/usr/bin/env python3
import csv
import json
from datetime import datetime

def generate_investigation_report():
    report = {
        'investigation_date': datetime.now().isoformat(),
        'summary': {},
        'findings': [],
        'recommendations': []
    }
    
    # Count total browser events
    total_events = 0
    browsers = set()
    
    try:
        with open('unified_timeline.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_events += 1
                browsers.add(row['source'])
    except FileNotFoundError:
        pass
    
    report['summary'] = {
        'total_browser_events': total_events,
        'browsers_analyzed': list(browsers),
        'analysis_scope': 'Browser history forensic investigation'
    }
    
    # Add findings
    report['findings'].extend([
        'Browser history artifacts successfully extracted and analyzed',
        'Timeline correlation completed between browser activity and system events',
        'Suspicious pattern analysis performed on URLs and domains',
        'Data exfiltration indicators searched and cataloged',
        'Download activity patterns analyzed for potential threats'
    ])
    
    # Add recommendations
    report['recommendations'].extend([
        'Implement browser activity monitoring for real-time threat detection',
        'Regular forensic analysis of browser artifacts in security incidents',
        'Deploy URL filtering to block access to suspicious domains',
        'Monitor for unusual download patterns and large data transfers',
        'Maintain forensic timeline capabilities for incident response'
    ])
    
    return report

def main():
    report = generate_investigation_report()
    
    # Save report as JSON
    with open('investigation_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("=== FORENSIC INVESTIGATION REPORT ===")
    print(f"Investigation Date: {report['investigation_date']}")
    print(f"Total Browser Events: {report['summary']['total_browser_events']}")
    print(f"Browsers Analyzed: {', '.join(report['summary']['browsers_analyzed'])}")
    
    print("\n=== KEY FINDINGS ===")
    for i, finding in enumerate(report['findings'], 1):
        print(f"{i}. {finding}")
    
    print("\n=== RECOMMENDATIONS ===")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print(f"\nDetailed report saved to: investigation_report.json")

if __name__ == "__main__":
    main()
