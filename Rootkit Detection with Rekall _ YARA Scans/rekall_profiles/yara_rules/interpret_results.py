#!/usr/bin/env python3

def interpret_findings():
    print("=== Rootkit Detection Interpretation Guide ===\n")
    
    indicators = {
        "High Risk": [
            "YARA rules matching rootkit signatures",
            "Hidden processes found by psscan but not pslist", 
            "Suspicious kernel modules with no file backing",
            "Modified system call table entries"
        ],
        "Medium Risk": [
            "Unusual network connections",
            "Processes with suspicious names or paths",
            "Modified file system operations",
            "Unexpected kernel hooks"
        ],
        "Low Risk": [
            "Standard system processes",
            "Known legitimate kernel modules",
            "Normal network activity",
            "Expected system calls"
        ]
    }
    
    for risk_level, signs in indicators.items():
        print(f"{risk_level} Indicators:")
        for sign in signs:
            print(f"  • {sign}")
        print()
    
    print("Analysis Steps:")
    print("1. Check YARA matches against known rootkit signatures")
    print("2. Compare process lists for hidden processes")
    print("3. Verify kernel module legitimacy")
    print("4. Examine network connections for backdoors")
    print("5. Cross-reference findings with threat intelligence")

if __name__ == "__main__":
    interpret_findings()
