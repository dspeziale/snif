#!/usr/bin/env python3
"""
Fix script per correggere gli import nei file del sistema
"""

import os
import re


def fix_snmp_imports():
    """Corregge gli import del modulo SNMP nei file"""

    files_to_fix = [
        'advanced_nmap_parser.py',
        'test_nmap_system.py'
    ]

    for filename in files_to_fix:
        if os.path.exists(filename):
            print(f"Fixing imports in {filename}...")

            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()

            # Sostituisce l'import del modulo SNMP
            content = re.sub(
                r'from snmp_parser import SNMPDataParser',
                'from complete_snmp_parser import SNMPDataParser',
                content
            )

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"✓ Fixed {filename}")
        else:
            print(f"✗ File {filename} not found")


def create_snmp_alias():
    """Crea un alias per il modulo SNMP"""
    alias_content = '''"""
Alias module for SNMP parser to maintain backward compatibility
"""

from complete_snmp_parser import SNMPDataParser

__all__ = ['SNMPDataParser']
'''

    with open('snmp_parser.py', 'w', encoding='utf-8') as f:
        f.write(alias_content)

    print("✓ Created snmp_parser.py alias")


if __name__ == "__main__":
    print("Fixing import issues...")
    fix_snmp_imports()
    create_snmp_alias()
    print("All imports fixed!")