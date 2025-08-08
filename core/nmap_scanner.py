#!/usr/bin/env python3
"""
Nmap Scanner System - VERSIONE COMPLETA CON SNMP
Main system for parsing and managing Nmap XML scan results with advanced SNMP support
"""

import os
import sys
import logging
import csv
from typing import Dict, List, Optional
from pathlib import Path

# Export the main class for external imports
__all__ = ['NmapScannerSystem']

# Import our custom modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from nmap_scanner_db import NmapScannerDB
    from advanced_nmap_parser import AdvancedNmapParser
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Assicurati che i file nmap_scanner_db.py e advanced_nmap_parser.py siano nella directory core/")
    sys.exit(1)


class NmapScannerSystem:
    """Main system for managing Nmap scan data with advanced SNMP support"""

    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        self.db_path = db_path

        # Setup logging
        os.makedirs("logs", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/nmap_scanner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize the database and create necessary directories"""
        # Ensure directories exist
        for directory in ['instance', 'logs', 'scans', 'reports']:
            os.makedirs(directory, exist_ok=True)

        # Test database connection
        try:
            with NmapScannerDB(self.db_path) as db:
                self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise

    def load_xml_file(self, xml_file_path: str) -> bool:
        """
        Load a single XML file into the database using advanced parser

        Args:
            xml_file_path: Path to the XML file to parse

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.logger.info(f"Loading XML file: {xml_file_path}")

            if not os.path.exists(xml_file_path):
                self.logger.error(f"File not found: {xml_file_path}")
                return False

            if not xml_file_path.lower().endswith('.xml'):
                self.logger.error(f"File is not an XML file: {xml_file_path}")
                return False

            # Use Advanced Parser with SNMP support
            parser = AdvancedNmapParser(self.db_path)
            success = parser.parse_file(xml_file_path)

            if success:
                self.logger.info(f"Successfully loaded: {xml_file_path}")
            else:
                self.logger.error(f"Failed to load: {xml_file_path}")

            return success

        except Exception as e:
            self.logger.error(f"Error loading file {xml_file_path}: {e}")
            return False

    def load_xml_directory(self, directory_path: str) -> Dict[str, bool]:
        """
        Load all XML files from a directory using advanced parser

        Args:
            directory_path: Path to directory containing XML files

        Returns:
            Dict[str, bool]: Dictionary mapping filename to success status
        """
        try:
            self.logger.info(f"Loading XML files from directory: {directory_path}")

            if not os.path.exists(directory_path):
                self.logger.error(f"Directory not found: {directory_path}")
                return {}

            if not os.path.isdir(directory_path):
                self.logger.error(f"Path is not a directory: {directory_path}")
                return {}

            # Find all XML files
            xml_files = [f for f in os.listdir(directory_path) if f.lower().endswith('.xml')]

            if not xml_files:
                self.logger.warning(f"No XML files found in directory: {directory_path}")
                return {}

            self.logger.info(f"Found {len(xml_files)} XML files")

            # Use Advanced Parser with SNMP support
            parser = AdvancedNmapParser(self.db_path)
            results = {}

            for xml_file in xml_files:
                xml_path = os.path.join(directory_path, xml_file)
                self.logger.info(f"Starting to parse file: {xml_path}")

                try:
                    success = parser.parse_file(xml_path)
                    results[xml_file] = success

                    if success:
                        self.logger.info(f"Successfully parsed file: {xml_path}")
                    else:
                        self.logger.error(f"Failed to parse file: {xml_path}")

                except Exception as e:
                    self.logger.error(f"Error parsing file {xml_path}: {e}")
                    results[xml_file] = False

            # Log summary
            successful = sum(1 for success in results.values() if success)
            total = len(results)
            self.logger.info(f"Loaded {successful}/{total} files successfully")

            return results

        except Exception as e:
            self.logger.error(f"Error loading directory {directory_path}: {e}")
            return {}

    def get_scan_summary(self) -> Dict:
        """Get a comprehensive summary of scan data"""
        try:
            with NmapScannerDB(self.db_path) as db:
                stats = db.get_database_stats()

                summary = {
                    'database_size_mb': stats.get('database_size_mb', 0),
                    'total_scans': stats.get('scan_runs_count', 0),
                    'total_hosts': stats.get('hosts_count', 0),
                    'total_ports': stats.get('ports_count', 0),
                    'total_scripts': stats.get('scripts_count', 0),
                    'vulnerabilities': stats.get('vulnerabilities_count', 0),
                    'snmp_services': stats.get('snmp_services_count', 0),
                    'snmp_processes': stats.get('snmp_processes_count', 0),
                    'snmp_software': stats.get('snmp_software_count', 0),
                    'snmp_users': stats.get('snmp_users_count', 0),
                    'snmp_interfaces': stats.get('snmp_interfaces_count', 0),
                    'snmp_connections': stats.get('snmp_network_connections_count', 0),
                    'snmp_shares': stats.get('snmp_shares_count', 0),
                    'ssl_certificates': stats.get('ssl_certificates_count', 0),
                    'ssh_hostkeys': stats.get('ssh_hostkeys_count', 0)
                }

                # Calculate totals
                summary['total_snmp_records'] = (
                        summary['snmp_services'] + summary['snmp_processes'] +
                        summary['snmp_software'] + summary['snmp_users'] +
                        summary['snmp_interfaces'] + summary['snmp_connections'] +
                        summary['snmp_shares']
                )

                return summary

        except Exception as e:
            self.logger.error(f"Error getting scan summary: {e}")
            return {}

    def get_hosts_summary(self) -> List[Dict]:
        """Get summary information for all hosts"""
        try:
            with NmapScannerDB(self.db_path) as db:
                query = """
                SELECT 
                    h.id,
                    h.ip_address,
                    h.status_state as status,
                    h.mac_address,
                    h.vendor,
                    COUNT(p.id) as total_ports,
                    COUNT(CASE WHEN p.state = 'open' THEN 1 END) as open_ports,
                    COUNT(v.id) as vulnerabilities,
                    COUNT(ss.id) as snmp_services,
                    COUNT(sp.id) as snmp_processes,
                    COUNT(ssw.id) as snmp_software
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                LEFT JOIN vulnerabilities v ON h.id = v.host_id
                LEFT JOIN snmp_services ss ON h.id = ss.host_id
                LEFT JOIN snmp_processes sp ON h.id = sp.host_id
                LEFT JOIN snmp_software ssw ON h.id = ssw.host_id
                GROUP BY h.id, h.ip_address, h.status_state, h.mac_address, h.vendor
                ORDER BY h.ip_address
                """

                return db.execute_query(query)

        except Exception as e:
            self.logger.error(f"Error getting hosts summary: {e}")
            return []

    def get_vulnerabilities_summary(self) -> List[Dict]:
        """Get summary of discovered vulnerabilities"""
        try:
            with NmapScannerDB(self.db_path) as db:
                query = """
                SELECT 
                    h.ip_address as host_ip,
                    p.port_id as port,
                    v.vuln_id,
                    v.title,
                    v.severity,
                    v.cvss_score,
                    v.state,
                    v.risk_factor
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                LEFT JOIN ports p ON v.port_id = p.id
                ORDER BY v.cvss_score DESC, v.severity DESC
                """

                return db.execute_query(query)

        except Exception as e:
            self.logger.error(f"Error getting vulnerabilities summary: {e}")
            return []

    def get_snmp_summary(self) -> Dict:
        """Get comprehensive SNMP data summary"""
        try:
            with NmapScannerDB(self.db_path) as db:
                summary = {}

                # Services summary
                services_query = """
                SELECT h.ip_address, ss.service_name, ss.status, ss.startup_type
                FROM snmp_services ss
                JOIN hosts h ON ss.host_id = h.id
                ORDER BY h.ip_address, ss.service_name
                """
                summary['services'] = db.execute_query(services_query)

                # Processes summary
                processes_query = """
                SELECT h.ip_address, sp.process_name, sp.process_path, sp.process_id
                FROM snmp_processes sp
                JOIN hosts h ON sp.host_id = h.id
                ORDER BY h.ip_address, sp.process_name
                """
                summary['processes'] = db.execute_query(processes_query)

                # Software summary
                software_query = """
                SELECT h.ip_address, ssw.software_name, ssw.version, ssw.install_date
                FROM snmp_software ssw
                JOIN hosts h ON ssw.host_id = h.id
                ORDER BY h.ip_address, ssw.software_name
                """
                summary['software'] = db.execute_query(software_query)

                # Users summary
                users_query = """
                SELECT h.ip_address, su.username, su.full_name, su.status
                FROM snmp_users su
                JOIN hosts h ON su.host_id = h.id
                ORDER BY h.ip_address, su.username
                """
                summary['users'] = db.execute_query(users_query)

                # Shares summary
                shares_query = """
                SELECT h.ip_address, ssh.share_name, ssh.share_path, ssh.description
                FROM snmp_shares ssh
                JOIN hosts h ON ssh.host_id = h.id
                ORDER BY h.ip_address, ssh.share_name
                """
                summary['shares'] = db.execute_query(shares_query)

                return summary

        except Exception as e:
            self.logger.error(f"Error getting SNMP summary: {e}")
            return {}

    def search_hosts_by_service(self, service_name: str) -> List[Dict]:
        """Search for hosts running a specific service"""
        try:
            with NmapScannerDB(self.db_path) as db:
                query = """
                SELECT DISTINCT
                    h.ip_address,
                    p.port_id as port,
                    p.protocol,
                    p.service_name,
                    p.service_product as product,
                    p.service_version as version,
                    h.status_state as status
                FROM hosts h
                JOIN ports p ON h.id = p.host_id
                WHERE p.service_name LIKE ? OR p.service_product LIKE ?
                ORDER BY h.ip_address, p.port_id
                """

                search_pattern = f"%{service_name}%"
                return db.execute_query(query, (search_pattern, search_pattern))

        except Exception as e:
            self.logger.error(f"Error searching for service {service_name}: {e}")
            return []

    def export_hosts_csv(self, output_file: str) -> bool:
        """Export hosts summary to CSV"""
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

            hosts = self.get_hosts_summary()

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                if hosts:
                    fieldnames = hosts[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(hosts)

            self.logger.info(f"Exported {len(hosts)} hosts to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting hosts to CSV: {e}")
            return False

    def export_snmp_csv(self, output_file: str) -> bool:
        """Export SNMP data to CSV"""
        try:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

            snmp_data = self.get_snmp_summary()

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Write header
                writer.writerow(['Type', 'Host', 'Name', 'Details', 'Extra'])

                # Write services
                for service in snmp_data.get('services', []):
                    writer.writerow(['Service', service['ip_address'], service['service_name'],
                                     service['status'], service['startup_type']])

                # Write processes
                for process in snmp_data.get('processes', []):
                    writer.writerow(['Process', process['ip_address'], process['process_name'],
                                     process.get('process_path', ''), process.get('process_id', '')])

                # Write software
                for software in snmp_data.get('software', []):
                    writer.writerow(['Software', software['ip_address'], software['software_name'],
                                     software.get('version', ''), software.get('install_date', '')])

                # Write users
                for user in snmp_data.get('users', []):
                    writer.writerow(['User', user['ip_address'], user['username'],
                                     user.get('full_name', ''), user.get('status', '')])

                # Write shares
                for share in snmp_data.get('shares', []):
                    writer.writerow(['Share', share['ip_address'], share['share_name'],
                                     share.get('share_path', ''), share.get('description', '')])

            self.logger.info(f"Exported SNMP data to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting SNMP data to CSV: {e}")
            return False

    def cleanup_database(self) -> bool:
        """Remove duplicate scans and optimize database"""
        try:
            with NmapScannerDB(self.db_path) as db:
                # Remove duplicate scans (same file hash)
                cursor = db.conn.execute("""
                    DELETE FROM scan_runs 
                    WHERE id NOT IN (
                        SELECT MIN(id) 
                        FROM scan_runs 
                        GROUP BY file_hash
                    )
                """)

                removed = cursor.rowcount

                # Vacuum database to reclaim space
                db.cleanup_old_scans(10)  # Keep last 10 scans
                db.vacuum_database()

            self.logger.info(f"Removed {removed} duplicate scans and optimized database")
            return True

        except Exception as e:
            self.logger.error(f"Error cleaning up database: {e}")
            return False


def main():
    """Main function for command-line usage"""
    try:
        if len(sys.argv) < 2:
            print("🚀 Nmap Scanner System with SNMP Support")
            print("=" * 50)
            print("Usage:")
            print("  python nmap_scanner.py load_file <xml_file>")
            print("  python nmap_scanner.py load_directory <directory>")
            print("  python nmap_scanner.py summary")
            print("  python nmap_scanner.py hosts")
            print("  python nmap_scanner.py snmp")
            print("  python nmap_scanner.py vulnerabilities")
            print("  python nmap_scanner.py search_service <service_name>")
            print("  python nmap_scanner.py export_hosts <output_file>")
            print("  python nmap_scanner.py export_snmp <output_file>")
            print("  python nmap_scanner.py cleanup")
            print("\nExamples:")
            print("  python nmap_scanner.py load_directory scans")
            print("  python nmap_scanner.py summary")
            print("  python nmap_scanner.py snmp")
            print("  python nmap_scanner.py search_service http")
            print("  python nmap_scanner.py export_snmp reports/snmp_data.csv")
            return 0

        command = sys.argv[1].lower()
        scanner = NmapScannerSystem()

        if command == "load_file" and len(sys.argv) >= 3:
            xml_file = sys.argv[2]
            success = scanner.load_xml_file(xml_file)
            print(f"File parsing: {'✅ Success' if success else '❌ Failed'}")

        elif command == "load_directory" and len(sys.argv) >= 3:
            directory = sys.argv[2]
            results = scanner.load_xml_directory(directory)
            successful = sum(1 for success in results.values() if success)
            total = len(results)

            print(f"Loaded {successful}/{total} files successfully")
            for filename, success in results.items():
                status = "✅" if success else "❌"
                print(f"  {status} {filename}")

        elif command == "summary":
            summary = scanner.get_scan_summary()
            print("📊 SCAN SUMMARY")
            print("=" * 30)
            print(f"Database size: {summary.get('database_size_mb', 0)} MB")
            print(f"Total scans: {summary.get('total_scans', 0)}")
            print(f"Total hosts: {summary.get('total_hosts', 0)}")
            print(f"Total ports: {summary.get('total_ports', 0)}")
            print(f"Vulnerabilities: {summary.get('vulnerabilities', 0)}")
            print(f"SSL certificates: {summary.get('ssl_certificates', 0)}")
            print()
            print("📋 SNMP DATA")
            print("-" * 30)
            print(f"SNMP Services: {summary.get('snmp_services', 0)}")
            print(f"SNMP Processes: {summary.get('snmp_processes', 0)}")
            print(f"SNMP Software: {summary.get('snmp_software', 0)}")
            print(f"SNMP Users: {summary.get('snmp_users', 0)}")
            print(f"SNMP Interfaces: {summary.get('snmp_interfaces', 0)}")
            print(f"SNMP Connections: {summary.get('snmp_connections', 0)}")
            print(f"SNMP Shares: {summary.get('snmp_shares', 0)}")
            print(f"Total SNMP records: {summary.get('total_snmp_records', 0)}")

        elif command == "hosts":
            hosts = scanner.get_hosts_summary()
            print(f"=== Discovered Hosts ({len(hosts)}) ===")
            for host in hosts:
                print(f"{host['ip_address']} | Status: {host['status']} | "
                      f"Ports: {host['open_ports']}/{host['total_ports']} | "
                      f"SNMP: S:{host.get('snmp_services', 0)} "
                      f"P:{host.get('snmp_processes', 0)} "
                      f"SW:{host.get('snmp_software', 0)}")

        elif command == "snmp":
            snmp_summary = scanner.get_snmp_summary()

            print("🔍 SNMP DATA SUMMARY")
            print("=" * 40)

            for category, data in snmp_summary.items():
                if data:
                    print(f"\n📋 {category.upper()} ({len(data)} records):")
                    for item in data[:5]:  # Show first 5
                        if category == 'services':
                            print(f"  {item['ip_address']}: {item['service_name']} ({item['status']})")
                        elif category == 'processes':
                            print(f"  {item['ip_address']}: {item['process_name']}")
                        elif category == 'software':
                            print(f"  {item['ip_address']}: {item['software_name']} {item.get('version', '')}")
                        elif category == 'users':
                            print(f"  {item['ip_address']}: {item['username']}")
                        elif category == 'shares':
                            print(f"  {item['ip_address']}: {item['share_name']} -> {item.get('share_path', '')}")

                    if len(data) > 5:
                        print(f"  ... and {len(data) - 5} more")

        elif command == "vulnerabilities":
            vulns = scanner.get_vulnerabilities_summary()
            print(f"=== Discovered Vulnerabilities ({len(vulns)}) ===")
            for vuln in vulns[:10]:  # Show top 10
                print(f"Host: {vuln['host_ip']}:{vuln.get('port', 'N/A')} | "
                      f"Risk: {vuln.get('risk_factor', vuln.get('severity', 'Unknown'))} | "
                      f"Title: {vuln.get('title', vuln['vuln_id'])}")

        elif command == "search_service" and len(sys.argv) >= 3:
            service = sys.argv[2]
            results = scanner.search_hosts_by_service(service)
            print(f"=== Hosts running '{service}' ({len(results)}) ===")
            for result in results:
                print(f"{result['ip_address']}:{result['port']} | "
                      f"{result['service_name']} | "
                      f"{result.get('product', '')} {result.get('version', '')}")

        elif command == "export_hosts":
            output_file = sys.argv[2] if len(sys.argv) >= 3 else "reports/hosts_summary.csv"
            success = scanner.export_hosts_csv(output_file)
            print(f"Export hosts: {'✅ Success' if success else '❌ Failed'}")

        elif command == "export_snmp":
            output_file = sys.argv[2] if len(sys.argv) >= 3 else "reports/snmp_data.csv"
            success = scanner.export_snmp_csv(output_file)
            print(f"Export SNMP: {'✅ Success' if success else '❌ Failed'}")

        elif command == "cleanup":
            success = scanner.cleanup_database()
            print(f"Database cleanup: {'✅ Success' if success else '❌ Failed'}")

        else:
            print(f"❌ Unknown command: {command}")
            return 1

    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

    return 0


# Test function for database creation
def test_database_creation():
    """Test database creation with all tables"""
    test_db_path = "test_complete_db.db"

    # Remove existing test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("🧪 Testing complete database creation...")

    try:
        with NmapScannerDB(test_db_path) as db:
            stats = db.get_database_stats()

            print(f"✅ Database created successfully")
            print(f"📊 Database size: {stats['database_size_mb']} MB")

            # Count different types of tables
            main_tables = [k for k in stats.keys() if k.endswith('_count') and
                           not k.startswith('snmp_') and not k.startswith('ssl_') and
                           not k.startswith('ssh_') and not k.startswith('http_') and
                           not k.startswith('smb_')]

            snmp_tables = [k for k in stats.keys() if k.startswith('snmp_') and k.endswith('_count')]
            security_tables = [k for k in stats.keys() if k.endswith('_count') and
                               (k.startswith('ssl_') or k.startswith('ssh_') or
                                k.startswith('http_') or k.startswith('smb_'))]

            print(f"📋 Tables created:")
            print(f"   • {len(main_tables)} tabelle Nmap principali")
            print(f"   • {len(snmp_tables)} tabelle SNMP")
            print(f"   • {len(security_tables)} tabelle sicurezza")
            print(f"   • {len(main_tables) + len(snmp_tables) + len(security_tables)} tabelle totali")

            # Test SNMP tables specifically
            snmp_table_names = [
                'snmp_services', 'snmp_processes', 'snmp_software', 'snmp_users',
                'snmp_interfaces', 'snmp_network_connections', 'snmp_system_info', 'snmp_shares'
            ]

            print(f"\n🔍 Verifica tabelle SNMP:")
            all_snmp_present = True
            for table in snmp_table_names:
                if f"{table}_count" in stats:
                    print(f"   ✅ {table}")
                else:
                    print(f"   ❌ {table} MANCANTE!")
                    all_snmp_present = False

            if all_snmp_present:
                print(f"\n🎉 TUTTI I COMPONENTI CREATI CORRETTAMENTE!")
                print(f"   Database pronto per il parsing SNMP")
                return True
            else:
                print(f"\n🚨 Alcune tabelle SNMP mancanti!")
                return False

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    # finally:
    #     # Clean up test database
    #     if os.path.exists(test_db_path):
    #         os.remove(test_db_path)


if __name__ == "__main__":
    exit(main())