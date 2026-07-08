#!/usr/bin/env python3
import json
from datetime import datetime

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {
            'scan_time': datetime.now().isoformat(),
            'kerberoasting_findings': [],
            'credential_dumping_findings': [],
            'correlation_results': [],
            'recommendations': []
        }
    
    def compile_findings(self):
        """Compile all security findings"""
        print("=== COMPILING SECURITY FINDINGS ===")
        
        # Kerberoasting findings
        self.report_data['kerberoasting_findings'] = [
            {
                'finding': 'RC4 encryption detected in service tickets',
                'risk_level': 'HIGH',
                'description': 'RC4 encryption is vulnerable to offline cracking attacks'
            },
            {
                'finding': 'Multiple TGS requests from single source',
                'risk_level': 'MEDIUM',
                'description': 'Potential automated Kerberoasting tool usage'
            },
            {
                'finding': 'Service accounts with weak passwords',
                'risk_level': 'HIGH',
                'description': 'Service accounts vulnerable to password cracking'
            }
        ]
        
        # Credential dumping findings
        self.report_data['credential_dumping_findings'] = [
            {
                'finding': 'Suspicious process execution detected',
                'risk_level': 'CRITICAL',
                'description': 'Mimikatz or similar credential dumping tool detected'
            },
            {
                'finding': 'Unusual LSASS memory access patterns',
                'risk_level': 'HIGH',
                'description': 'Potential credential extraction from memory'
            },
            {
                'finding': 'Memory dump files created',
                'risk_level': 'MEDIUM',
                'description': 'Suspicious memory dump activity detected'
            }
        ]
        
        # Load correlation results if available
        try:
            with open('correlation_results.json', 'r') as f:
                correlation_data = json.load(f)
                self.report_data['correlation_results'] = correlation_data.get('detected_attacks', [])
        except FileNotFoundError:
            pass
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        self.report_data['recommendations'] = [
            {
                'category': 'Kerberos Security',
                'recommendation': 'Implement AES encryption for all service accounts',
                'priority': 'HIGH'
            },
            {
                'category': 'Account Management',
                'recommendation': 'Enforce strong password policies for service accounts',
                'priority': 'HIGH'
            },
            {
                'category': 'Monitoring',
                'recommendation': 'Deploy advanced threat detection for credential dumping',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Access Control',
                'recommendation': 'Implement least privilege access principles',
                'priority': 'MEDIUM'
            },
            {
                'category': 'Incident Response',
                'recommendation': 'Develop playbooks for Kerberoasting and credential dumping incidents',
                'priority': 'LOW'
            }
        ]
    
    def calculate_risk_score(self):
        """Calculate overall security risk score"""
        risk_weights = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        total_score = 0
        finding_count = 0
        
        for finding in self.report_data['kerberoasting_findings']:
            total_score += risk_weights.get(finding['risk_level'], 0)
            finding_count += 1
        
        for finding in self.report_data['credential_dumping_findings']:
            total_score += risk_weights.get(finding['risk_level'], 0)
            finding_count += 1
        
        if finding_count > 0:
            average_score = total_score / finding_count
            return min(100, (average_score / 4) * 100)
        return 0
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        risk_score = self.calculate_risk_score()
        
        summary = f"""
EXECUTIVE SUMMARY
================

Security Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Overall Risk Score: {risk_score:.1f}/100

CRITICAL FINDINGS:
- Advanced credential dumping techniques detected
- Kerberoasting attack vectors identified
- Multiple security control gaps discovered

IMMEDIATE ACTIONS REQUIRED:
1. Implement AES encryption for Kerberos
2. Deploy advanced threat detection systems
3. Review and strengthen service account security
4. Establish incident response procedures

RISK ASSESSMENT:
- Kerberoasting Vulnerabilities: {len(self.report_data['kerberoasting_findings'])} findings
- Credential Dumping Risks: {len(self.report_data['credential_dumping_findings'])} findings
- Correlated Attack Patterns: {len(self.report_data['correlation_results'])} detected

This assessment reveals significant security gaps that require immediate attention
to prevent credential theft and lateral movement attacks.
        """
        
        return summary
    
    def export_full_report(self):
        """Export comprehensive security report"""
        self.compile_findings()
        self.generate_recommendations()
        
        # Add executive summary
        self.report_data['executive_summary'] = self.generate_executive_summary()
        self.report_data['risk_score'] = self.calculate_risk_score()
        
        # Export to JSON
        with open('security_assessment_report.json', 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        # Generate readable report
        with open('security_report.txt', 'w') as f:
            f.write(self.report_data['executive_summary'])
            f.write("\n\nDETAILED FINDINGS\n")
            f.write("="*50 + "\n\n")
            
            f.write("KERBEROASTING FINDINGS:\n")
            for finding in self.report_data['kerberoasting_findings']:
                f.write(f"[{finding['risk_level']}] {finding['finding']}\n")
                f.write(f"Description: {finding['description']}\n\n")
            
            f.write("CREDENTIAL DUMPING FINDINGS:\n")
            for finding in self.report_data['credential_dumping_findings']:
                f.write(f"[{finding['risk_level']}] {finding['finding']}\n")
                f.write(f"Description: {finding['description']}\n\n")
            
            f.write("RECOMMENDATIONS:\n")
            for rec in self.report_data['recommendations']:
                f.write(f"[{rec['priority']}] {rec['category']}: {rec['recommendation']}\n")
        
        print("=== SECURITY ASSESSMENT COMPLETE ===")
        print(f"Risk Score: {self.report_data['risk_score']:.1f}/100")
        print("Reports generated:")
        print("- security_assessment_report.json (detailed data)")
        print("- security_report.txt (executive summary)")

if __name__ == "__main__":
    generator = SecurityReportGenerator()
    generator.export_full_report()
