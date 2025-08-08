"""
Nmap Scanner System
Main system for parsing and managing Nmap XML scan results
"""

import os
import sys
import logging
from typing import Dict, List, Optional
from pathlib import Path

# Export the main class for external imports
__all__ = ['NmapScannerSystem']

# Import our custom modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from nmap_scanner_db import NmapScannerDB
from nmap_xml_parser import NmapXMLParser

class NmapScannerSystem:
    """Main system for managing Nmap scan data"""

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
        for directory in ['instance', 'logs', 'scans']:
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
        Load a single XML file into the database

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

            with NmapXMLParser(self.db_path) as parser:
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
        Load all XML files from a directory

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

            with NmapXMLParser(self.db_path) as parser:
                results = parser.parse_directory(directory_path)

            # Log summary
            successful = sum(1 for success in results.values() if success)
            total = len(results)
            self.logger.info(f"Loaded {successful}/{total} files successfully")

            return results

        except Exception as e:
            self.logger.error(f"Error loading directory {directory_path}: {e}")
            return {}

    def get_scan_summary(self) -> Dict:
        """Get a summary of scans in the database"""
        try:
            with NmapScannerDB(self.db_path) as db:
                cursor = db.conn.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        COUNT(DISTINCT filename) as unique_files,
                        MIN(created_at) as first_scan,
                        MAX(created_at) as last_scan
                    FROM scan_runs
                """)
                scan_stats = cursor.fetchone()

                cursor = db.conn.execute("""
                    SELECT COUNT(*) FROM hosts WHERE status_state = 'up'
                """)
                hosts_up = cursor.fetchone()[0]

                cursor = db.conn.execute("""
                    SELECT COUNT(*) FROM ports WHERE state = 'open'
                """)
                open_ports = cursor.fetchone()[0]

                cursor = db.conn.execute("""
                    SELECT COUNT(*) FROM vulnerabilities
                """)
                vulnerabilities = cursor.fetchone()[0]

                return {
                    'total_scans': scan_stats[0],
                    'unique_files': scan_stats[1],
                    'first_scan': scan_stats[2],
                    'last_scan': scan_stats[3],
                    'hosts_up': hosts_up,
                    'open_ports': open_ports,
                    'vulnerabilities': vulnerabilities
                }

        except Exception as e:
            self.logger.error(f"Error getting scan summary: {e}")
            return {}

    def get_hosts_summary(self) -> List[Dict]:
        """Get summary of all discovered hosts"""
        try:
            with NmapScannerDB(self.db_path) as db:
                cursor = db.conn.execute("""
                    SELECT 
                        h.ip_address,
                        h.mac_address,
                        h.vendor,
                        h.status_state,
                        COUNT(p.id) as port_count,
                        COUNT(CASE WHEN p.state = 'open' THEN 1 END) as open_ports,
                        GROUP_CONCAT(DISTINCT p.service_name) as services,
                        sr.filename as scan_file
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    LEFT JOIN scan_runs sr ON h.scan_run_id = sr.id
                    WHERE h.status_state = 'up'
                    GROUP BY h.id, h.ip_address
                    ORDER BY h.ip_address
                """)

                hosts = []
                for row in cursor.fetchall():
                    hosts.append({
                        'ip_address': row[0],
                        'mac_address': row[1],
                        'vendor': row[2],
                        'status': row[3],
                        'total_ports': row[4],
                        'open_ports': row[5],
                        'services': row[6].split(',') if row[6] else [],
                        'scan_file': row[7]
                    })

                return hosts

        except Exception as e:
            self.logger.error(f"Error getting hosts summary: {e}")
            return []

    def get_vulnerabilities_summary(self) -> List[Dict]:
        """Get summary of all discovered vulnerabilities"""
        try:
            with NmapScannerDB(self.db_path) as db:
                cursor = db.conn.execute("""
                    SELECT 
                        v.vuln_id,
                        v.title,
                        v.state,
                        v.risk_factor,
                        v.cvss_score,
                        h.ip_address,
                        p.port_id,
                        p.service_name,
                        COUNT(vr.id) as reference_count
                    FROM vulnerabilities v
                    JOIN scripts s ON v.script_id = s.id
                    JOIN ports p ON s.port_id = p.id
                    JOIN hosts h ON p.host_id = h.id
                    LEFT JOIN vuln_references vr ON v.id = vr.vulnerability_id
                    GROUP BY v.id
                    ORDER BY v.cvss_score DESC, v.risk_factor DESC
                """)

                vulns = []
                for row in cursor.fetchall():
                    vulns.append({
                        'vuln_id': row[0],
                        'title': row[1],
                        'state': row[2],
                        'risk_factor': row[3],
                        'cvss_score': row[4],
                        'host_ip': row[5],
                        'port': row[6],
                        'service': row[7],
                        'reference_count': row[8]
                    })

                return vulns

        except Exception as e:
            self.logger.error(f"Error getting vulnerabilities summary: {e}")
            return []

    def search_hosts_by_service(self, service_name: str) -> List[Dict]:
        """Search for hosts running a specific service"""
        try:
            with NmapScannerDB(self.db_path) as db:
                cursor = db.conn.execute("""
                    SELECT DISTINCT
                        h.ip_address,
                        p.port_id,
                        p.service_name,
                        p.service_product,
                        p.service_version,
                        p.state
                    FROM hosts h
                    JOIN ports p ON h.id = p.host_id
                    WHERE p.service_name LIKE ? AND h.status_state = 'up'
                    ORDER BY h.ip_address, p.port_id
                """, (f"%{service_name}%",))

                results = []
                for row in cursor.fetchall():
                    results.append({
                        'ip_address': row[0],
                        'port': row[1],
                        'service_name': row[2],
                        'product': row[3],
                        'version': row[4],
                        'state': row[5]
                    })

                return results

        except Exception as e:
            self.logger.error(f"Error searching for service {service_name}: {e}")
            return []

    def export_hosts_csv(self, output_file: str = "exports/hosts_summary.csv") -> bool:
        """Export hosts summary to CSV"""
        try:
            import csv

            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            hosts = self.get_hosts_summary()

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['ip_address', 'mac_address', 'vendor', 'status',
                            'total_ports', 'open_ports', 'services', 'scan_file']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for host in hosts:
                    # Convert services list to string
                    host['services'] = ', '.join(host['services'])
                    writer.writerow(host)

            self.logger.info(f"Exported {len(hosts)} hosts to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting hosts to CSV: {e}")
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
                db.conn.execute("VACUUM")
                db.conn.commit()

            self.logger.info(f"Removed {removed} duplicate scans and optimized database")
            return True

        except Exception as e:
            self.logger.error(f"Error cleaning up database: {e}")
            return False


def main():
    """Main function for command-line usage"""
    try:
        if len(sys.argv) < 2:
            print("Usage:")
            print("  python nmap_scanner.py load_file <xml_file>")
            print("  python nmap_scanner.py load_directory <directory>")
            print("  python nmap_scanner.py summary")
            print("  python nmap_scanner.py hosts")
            print("  python nmap_scanner.py vulnerabilities")
            print("  python nmap_scanner.py search_service <service_name>")
            print("  python nmap_scanner.py export_hosts [output_file]")
            print("  python nmap_scanner.py cleanup")
            sys.exit(1)

        scanner = NmapScannerSystem()
        command = sys.argv[1]

        if command == "load_file" and len(sys.argv) >= 3:
            xml_file = sys.argv[2]
            success = scanner.load_xml_file(xml_file)
            print(f"File loading {'successful' if success else 'failed'}")

        elif command == "load_directory" and len(sys.argv) >= 3:
            directory = sys.argv[2]
            results = scanner.load_xml_directory(directory)
            successful = sum(1 for success in results.values() if success)
            total = len(results)
            print(f"Loaded {successful}/{total} files successfully")
            for filename, success in results.items():
                status = "✓" if success else "✗"
                print(f"  {status} {filename}")

        elif command == "summary":
            summary = scanner.get_scan_summary()
            print("=== Scan Database Summary ===")
            for key, value in summary.items():
                print(f"{key.replace('_', ' ').title()}: {value}")

        elif command == "hosts":
            hosts = scanner.get_hosts_summary()
            print(f"=== Discovered Hosts ({len(hosts)}) ===")
            for host in hosts:
                print(f"IP: {host['ip_address']} | Vendor: {host.get('vendor', 'Unknown')} | "
                      f"Open Ports: {host['open_ports']}/{host['total_ports']}")

        elif command == "vulnerabilities":
            vulns = scanner.get_vulnerabilities_summary()
            print(f"=== Discovered Vulnerabilities ({len(vulns)}) ===")
            for vuln in vulns[:10]:  # Show top 10
                print(f"Host: {vuln['host_ip']}:{vuln['port']} | "
                      f"Risk: {vuln.get('risk_factor', 'Unknown')} | "
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
            output_file = sys.argv[2] if len(sys.argv) >= 3 else "exports/hosts_summary.csv"
            success = scanner.export_hosts_csv(output_file)
            print(f"Export {'successful' if success else 'failed'}")

        elif command == "cleanup":
            success = scanner.cleanup_database()
            print(f"Cleanup {'successful' if success else 'failed'}")

        else:
            print(f"Unknown command: {command}")
            return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())