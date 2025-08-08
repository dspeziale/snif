# !/usr/bin/env python3
"""
Force use of Advanced Parser with SNMP support
"""

import os
import sys
import sqlite3


def force_advanced_parsing():
    """Force parsing with advanced parser that has SNMP support"""
    print("🚀 FORCING ADVANCED PARSER WITH SNMP SUPPORT")
    print("=" * 50)

    # Add core to path
    sys.path.insert(0, 'core')

    try:
        from advanced_nmap_parser import AdvancedNmapParser
        print("✅ AdvancedNmapParser imported successfully")

        # Initialize advanced parser
        parser = AdvancedNmapParser("instance/nmap_scans.db")
        print("✅ Advanced parser initialized")

        # Check SNMP handlers
        snmp_handlers = [k for k in parser.script_handlers.keys() if k.startswith('snmp-')]
        print(f"✅ SNMP handlers registered: {len(snmp_handlers)}")
        for handler in snmp_handlers:
            print(f"    📋 {handler}")

        # Parse files with advanced parser
        scan_dir = "../scans"
        xml_files = [f for f in os.listdir(scan_dir) if f.endswith('.xml')]

        print(f"\n📁 Found {len(xml_files)} XML files to parse")

        successful_files = []

        for xml_file in xml_files:
            filepath = os.path.join(scan_dir, xml_file)
            print(f"\n🔄 Parsing {xml_file} with advanced parser...")

            try:
                # Use advanced parser directly
                success = parser.parse_file(filepath)
                if success:
                    print(f"✅ {xml_file} parsed successfully")
                    successful_files.append(xml_file)
                else:
                    print(f"❌ {xml_file} failed to parse")
            except Exception as e:
                print(f"❌ {xml_file} error: {e}")

        print(f"\n📊 RESULTS:")
        print(f"Successfully parsed: {len(successful_files)}/{len(xml_files)} files")

        # Check SNMP data in database
        print(f"\n🔍 CHECKING SNMP DATA IN DATABASE...")

        conn = sqlite3.connect("instance/nmap_scans.db")
        cursor = conn.cursor()

        snmp_tables = [
            'snmp_services', 'snmp_processes', 'snmp_software', 'snmp_users',
            'snmp_interfaces', 'snmp_network_connections', 'snmp_system_info', 'snmp_shares'
        ]

        total_snmp_records = 0

        for table in snmp_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                if count > 0:
                    print(f"✅ {table}: {count} records")
                    total_snmp_records += count
                else:
                    print(f"⚪ {table}: 0 records")
            except Exception as e:
                print(f"❌ {table}: Error - {e}")

        conn.close()

        if total_snmp_records > 0:
            print(f"\n🎉 SUCCESS! Found {total_snmp_records} SNMP records in database!")
        else:
            print(f"\n🚨 NO SNMP DATA FOUND! The files might not contain SNMP scripts.")

        return total_snmp_records > 0

    except ImportError as e:
        print(f"❌ Failed to import AdvancedNmapParser: {e}")
        return False
    except Exception as e:
        print(f"❌ Error in advanced parsing: {e}")
        return False


if __name__ == "__main__":
    success = force_advanced_parsing()
    if success:
        print("\n🎯 SNMP parsing is working!")
    else:
        print("\n🚨 SNMP parsing failed - check the files for SNMP scripts")