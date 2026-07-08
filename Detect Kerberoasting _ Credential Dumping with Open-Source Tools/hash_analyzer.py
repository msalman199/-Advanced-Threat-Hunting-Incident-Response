#!/usr/bin/env python3
import hashlib
import re

class HashAnalyzer:
    def __init__(self):
        self.hash_patterns = {
            'NTLM': r'^[a-fA-F0-9]{32}$',
            'LM': r'^[a-fA-F0-9]{32}$',
            'Kerberos': r'^[a-fA-F0-9]{64,}$'
        }
    
    def identify_hash_type(self, hash_value):
        """Identify hash type based on pattern"""
        for hash_type, pattern in self.hash_patterns.items():
            if re.match(pattern, hash_value):
                return hash_type
        return "Unknown"
    
    def analyze_sample_hashes(self):
        """Analyze sample credential hashes"""
        print("=== HASH ANALYSIS ===")
        
        # Sample hashes for analysis (dummy data)
        sample_hashes = [
            "aad3b435b51404eeaad3b435b51404ee",  # Empty LM hash
            "31d6cfe0d16ae931b73c59d7e0c089c0",  # Empty NTLM hash
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        ]
        
        for i, hash_val in enumerate(sample_hashes, 1):
            hash_type = self.identify_hash_type(hash_val)
            print(f"Hash {i}: {hash_type}")
            print(f"Value: {hash_val}")
            
            if hash_val == "aad3b435b51404eeaad3b435b51404ee":
                print("  -> Empty LM hash detected")
            elif hash_val == "31d6cfe0d16ae931b73c59d7e0c089c0":
                print("  -> Empty NTLM hash detected")
            print()

if __name__ == "__main__":
    analyzer = HashAnalyzer()
    analyzer.analyze_sample_hashes()
