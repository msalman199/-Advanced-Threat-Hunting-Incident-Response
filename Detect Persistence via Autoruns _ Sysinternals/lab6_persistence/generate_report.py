#!/usr/bin/env python3
import os
import datetime

def generate_persistence_report():
    report_file = "persistence_investigation_report.txt"
    
    with open(report_file, 'w') as f:
        f.write("PERSISTENCE INVESTIGATION REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated: {datetime.datetime.now()}\n\n")
        
        # Read and summarize findings
        files_to_analyze = [
            ("enabled_services.txt", "ENABLED SERVICES"),
            ("user_cron.txt", "USER CRON JOBS"),
            ("system_cron.txt", "SYSTEM CRON JOBS"),
            ("autostart_analysis.txt", "AUTOSTART ANALYSIS"),
            ("chkrootkit_results.txt", "ROOTKIT SCAN RESULTS"),
            ("listening_ports.txt", "NETWORK LISTENERS"),
            ("file_integrity.txt", "FILE INTEGRITY CHECK")
        ]
        
        for filename, section_title in files_to_analyze:
            if os.path.exists(filename):
                f.write(f"\n{section_title}\n")
                f.write("-" * len(section_title) + "\n")
                try:
                    with open(filename, 'r') as source:
                        content = source.read()
                        # Limit content to prevent huge reports
                        if len(content) > 2000:
                            f.write(content[:2000] + "\n... (truncated)\n")
                        else:
                            f.write(content)
                except:
                    f.write("Error reading file\n")
        
        # Add recommendations
        f.write("\n\nRECOMMendations\n")
        f.write("-" * 15 + "\n")
        f.write("1. Remove suspicious services: sudo systemctl disable fake-service.service\n")
        f.write("2. Clean cron jobs: crontab -r (for user), edit /etc/cron.d/ (for system)\n")
        f.write("3. Monitor /tmp and /var/tmp for suspicious files\n")
        f.write("4. Regular rootkit scans with chkrootkit and rkhunter\n")
        f.write("5. Implement file integrity monitoring with AIDE\n")

if __name__ == "__main__":
    generate_persistence_report()
    print("Report generated: persistence_investigation_report.txt")
