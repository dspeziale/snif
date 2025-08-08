#!/usr/bin/env python3
"""
Test script for the Nmap Scanner System
This script demonstrates how to use the system and provides testing functionality
"""

import os
import sys
import json
import sqlite3
from pathlib import Path

# Add the current directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nmap_scanner import NmapScannerSystem
from advanced_nmap_parser import AdvancedNmapParser
from nmap_scanner_db import NmapScannerDB


def test_database_creation():
    """Test database creation and schema"""
    print("=== Testing Database Creation ===")

    # Create a test database
    test_db_path = "instance/test_nmap_scans.db"

    try:
        # Remove existing test database
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

        # Create new database
        with NmapScannerDB(test_db_path) as db:
            print("✓ Database created successfully")

            # Check if tables exist
            cursor = db.conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            ORDER BY name
            """)

            tables = [row[0] for row in cursor.fetchall()]
            expected_tables = [
                'scan_runs', 'scan_info', 'host_hints', 'hosts', 'hostnames',
                'ports', 'cpe_entries', 'scripts', 'script_elements', 'script_tables',
                'extra_ports', 'os_detection', 'os_matches', 'os_classes',
                'task_progress', 'runtime_stats', 'vulnerabilities', 'vuln_references',
                'snmp_info', 'processes', 'network_connections'
            ]

            missing_tables = set(expected_tables) - set(tables)
            if missing_tables:
                print(f"✗ Missing tables: {missing_tables}")
                return False
            else:
                print(f"✓ All {len(expected_tables)} tables created successfully")

            # Test indexes
            cursor = db.conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND name LIKE 'idx_%'
            """)
            indexes = [row[0] for row in cursor.fetchall()]
            print(f"✓ Created {len(indexes)} indexes")

        return True

    except Exception as e:
        print(f"✗ Database creation failed: {e}")
        return False


def test_xml_parsing():
    """Test XML file parsing"""
    print("\n=== Testing XML Parsing ===")

    # Create a sample XML file for testing
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.1" start="1640995200" startstr="Sat Jan  1 00:00:00 2022" version="7.97" xmloutputversion="1.05">
<scaninfo type="ping" protocol="ip" numservices="0" services=""/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1640995200" endtime="1640995201">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Test Vendor"/>
<hostnames>
<hostname name="test-host.local" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="Apache httpd" version="2.4.41" method="probed" conf="10"/>
</port>
</ports>
<times srtt="1000" rttvar="1000" to="100000"/>
</host>
<runstats><finished time="1640995201" timestr="Sat Jan  1 00:00:01 2022" elapsed="1.00" summary="Nmap done at Sat Jan  1 00:00:01 2022; 1 IP address (1 host up) scanned in 1.00 seconds" exit="success"/></runstats>
</nmaprun>'''

    # Save sample XML to file
    test_xml_path = "test_sample.xml"
    with open(test_xml_path, 'w') as f:
        f.write(sample_xml)

    try:
        # Test parsing with advanced parser
        test_db_path = "instance/test_nmap_scans.db"

        with AdvancedNmapParser(test_db_path) as parser:
            success = parser.parse_file(test_xml_path)

            if success:
                print("✓ XML parsing successful")

                # Verify data was inserted
                cursor = parser.db.conn.execute("SELECT COUNT(*) FROM scan_runs")
                scan_count = cursor.fetchone()[0]

                cursor = parser.db.conn.execute("SELECT COUNT(*) FROM hosts")
                host_count = cursor.fetchone()[0]

                cursor = parser.db.conn.execute("SELECT COUNT(*) FROM ports")
                port_count = cursor.fetchone()[0]

                print(f"✓ Inserted {scan_count} scans, {host_count} hosts, {port_count} ports")

                # Test duplicate detection
                success2 = parser.parse_file(test_xml_path)
                if success2:
                    cursor = parser.db.conn.execute("SELECT COUNT(*) FROM scan_runs")
                    scan_count2 = cursor.fetchone()[0]

                    if scan_count2 == scan_count:
                        print("✓ Duplicate detection working correctly")
                    else:
                        print("✗ Duplicate detection failed")
                        return False

                return True
            else:
                print("✗ XML parsing failed")
                return False

    except Exception as e:
        print(f"✗ XML parsing test failed: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(test_xml_path):
            os.remove(test_xml_path)


def test_system_integration():
    """Test the complete system integration"""
    print("\n=== Testing System Integration ===")

    try:
        # Initialize the system
        system = NmapScannerSystem("instance/test_nmap_scans.db")

        # Test summary generation
        summary = system.get_scan_summary()
        print(f"✓ Generated summary: {summary}")

        # Test hosts summary
        hosts = system.get_hosts_summary()
        print(f"✓ Found {len(hosts)} hosts")

        if hosts:
            # Test first host details
            host = hosts[0]
            required_fields = ['ip_address', 'status', 'total_ports', 'open_ports']

            if all(field in host for field in required_fields):
                print("✓ Host data structure correct")
            else:
                missing = [f for f in required_fields if f not in host]
                print(f"✗ Host data missing fields: {missing}")
                return False

        # Test service search
        results = system.search_hosts_by_service("http")
        print(f"✓ Service search returned {len(results)} results")

        return True

    except Exception as e:
        print(f"✗ System integration test failed: {e}")
        return False


def test_real_files():
    """Test parsing real XML files from the scans directory"""
    print("\n=== Testing Real XML Files ===")

    scans_dir = "scans"

    if not os.path.exists(scans_dir):
        print(f"✗ Scans directory '{scans_dir}' not found")
        return False

    xml_files = [f for f in os.listdir(scans_dir) if f.lower().endswith('.xml')]

    if not xml_files:
        print(f"✗ No XML files found in '{scans_dir}'")
        return False

    print(f"Found {len(xml_files)} XML files")

    try:
        system = NmapScannerSystem("instance/nmap_scans.db")
        results = system.load_xml_directory(scans_dir)

        successful = sum(1 for success in results.values() if success)
        total = len(results)

        print(f"✓ Loaded {successful}/{total} files successfully")

        # Show results for each file
        for filename, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {filename}")

        # Get final summary
        summary = system.get_scan_summary()
        print(f"\nFinal database summary:")
        for key, value in summary.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")

        return successful > 0

    except Exception as e:
        print(f"✗ Real files test failed: {e}")
        return False


def generate_sample_report():
    """Generate a sample report from the database"""
    print("\n=== Generating Sample Report ===")

    try:
        with AdvancedNmapParser("instance/nmap_scans.db") as parser:
            report = parser.generate_detailed_report()

            # Save report to JSON file
            os.makedirs("reports", exist_ok=True)
            report_file = "reports/nmap_analysis_report.json"

            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"✓ Report generated: {report_file}")

            # Print summary
            summary = report.get('summary', {})
            print("\nReport Summary:")
            for key, value in summary.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")

            print(f"\nDetailed information for {len(report.get('hosts', []))} hosts")

            return True

    except Exception as e:
        print(f"✗ Report generation failed: {e}")
        return False


def run_performance_test():
    """Run a basic performance test"""
    print("\n=== Running Performance Test ===")

    import time

    try:
        start_time = time.time()

        # Test database operations
        with NmapScannerDB("instance/test_performance.db") as db:
            # Create some test data
            for i in range(100):
                cursor = db.conn.execute("""
                INSERT INTO scan_runs (scanner, version, filename, file_hash)
                VALUES (?, ?, ?, ?)
                """, ("nmap", "7.97", f"test_scan_{i}.xml", f"hash_{i}"))

                scan_id = cursor.lastrowid

                # Insert test host
                cursor = db.conn.execute("""
                INSERT INTO hosts (scan_run_id, ip_address, status_state)
                VALUES (?, ?, ?)
                """, (scan_id, f"192.168.1.{i + 1}", "up"))

                host_id = cursor.lastrowid

                # Insert test ports
                for port in [22, 80, 443]:
                    db.conn.execute("""
                    INSERT INTO ports (host_id, protocol, port_id, state, service_name)
                    VALUES (?, ?, ?, ?, ?)
                    """, (host_id, "tcp", port, "open", f"service_{port}"))

            db.conn.commit()

        # Test query performance
        with NmapScannerDB("instance/test_performance.db") as db:
            start_query = time.time()

            cursor = db.conn.execute("""
            SELECT h.ip_address, COUNT(p.id) as port_count
            FROM hosts h
            LEFT JOIN ports p ON h.id = p.host_id
            GROUP BY h.id
            ORDER BY h.ip_address
            """)

            results = cursor.fetchall()
            query_time = time.time() - start_query

            print(f"✓ Queried {len(results)} hosts in {query_time:.3f} seconds")

        total_time = time.time() - start_time
        print(f"✓ Performance test completed in {total_time:.3f} seconds")

        # Cleanup
        if os.path.exists("instance/test_performance.db"):
            os.remove("instance/test_performance.db")

        return True

    except Exception as e:
        print(f"✗ Performance test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("Nmap Scanner System Test Suite")
    print("=" * 40)

    tests = [
        ("Database Creation", test_database_creation),
        ("XML Parsing", test_xml_parsing),
        ("System Integration", test_system_integration),
        ("Real Files Processing", test_real_files),
        ("Report Generation", generate_sample_report),
        ("Performance Test", run_performance_test)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print(f"\nRunning {test_name}...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                failed += 1
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name} FAILED with exception: {e}")

    print("\n" + "=" * 40)
    print(f"Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All tests passed!")

        # Show usage examples
        print("\nUsage Examples:")
        print("---------------")
        print("# Load a single XML file:")
        print("python nmap_scanner.py load_file scans/scan1.xml")
        print()
        print("# Load all XML files from scans directory:")
        print("python nmap_scanner.py load_directory scans")
        print()
        print("# Get summary of scanned data:")
        print("python nmap_scanner.py summary")
        print()
        print("# Search for hosts running a specific service:")
        print("python nmap_scanner.py search_service http")
        print()
        print("# Export hosts to CSV:")
        print("python nmap_scanner.py export_hosts reports/hosts.csv")

    else:
        print("⚠️  Some tests failed. Please check the error messages above.")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())