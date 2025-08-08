"""
Nmap XML Parser
Comprehensive parser for Nmap XML output files
"""

import xml.etree.ElementTree as ET
import hashlib
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from nmap_scanner_db import NmapScannerDB


class NmapXMLParser:
    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        self.db = NmapScannerDB(db_path)
        self.logger = logging.getLogger(__name__)

    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of the file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _parse_time_string(self, time_str: str) -> Optional[int]:
        """Convert time string to timestamp"""
        try:
            return int(time_str) if time_str else None
        except (ValueError, TypeError):
            return None

    def _get_text_or_none(self, element, default=None):
        """Get text from element or return None/default"""
        return element.text if element is not None else default

    def _get_attr_or_none(self, element, attr_name, default=None):
        """Get attribute from element or return None/default"""
        if element is not None:
            return element.get(attr_name, default)
        return default

    def parse_file(self, filepath: str) -> bool:
        """Parse a single Nmap XML file"""
        try:
            self.logger.info(f"Starting to parse file: {filepath}")

            # Check if file exists
            if not os.path.exists(filepath):
                self.logger.error(f"File not found: {filepath}")
                return False

            # Calculate file hash to avoid duplicates
            file_hash = self._calculate_file_hash(filepath)
            existing_scan_id = self.db.get_scan_by_hash(file_hash)

            if existing_scan_id:
                self.logger.info(f"File already parsed (hash: {file_hash[:16]}...)")
                return True

            # Parse XML
            tree = ET.parse(filepath)
            root = tree.getroot()

            if root.tag != 'nmaprun':
                self.logger.error(f"Invalid Nmap XML file: {filepath}")
                return False

            # Insert main scan run
            scan_run_id = self._insert_scan_run(root, filepath, file_hash)

            # Parse scan info
            self._parse_scan_info(root, scan_run_id)

            # Parse host hints
            self._parse_host_hints(root, scan_run_id)

            # Parse hosts
            self._parse_hosts(root, scan_run_id)

            # Parse task progress
            self._parse_task_progress(root, scan_run_id)

            # Parse runtime stats
            self._parse_runtime_stats(root, scan_run_id)

            self.db.conn.commit()
            self.logger.info(f"Successfully parsed file: {filepath}")
            return True

        except ET.ParseError as e:
            self.logger.error(f"XML parsing error in {filepath}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error parsing file {filepath}: {e}")
            self.db.conn.rollback()
            return False

    def _insert_scan_run(self, root: ET.Element, filepath: str, file_hash: str) -> int:
        """Insert main scan run data"""
        cursor = self.db.conn.execute("""
        INSERT INTO scan_runs (
            scanner, version, xml_output_version, args, start_time, start_time_str,
            filename, file_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            root.get('scanner'),
            root.get('version'),
            root.get('xmloutputversion'),
            root.get('args'),
            self._parse_time_string(root.get('start')),
            root.get('startstr'),
            os.path.basename(filepath),
            file_hash
        ))

        return cursor.lastrowid

    def _parse_scan_info(self, root: ET.Element, scan_run_id: int):
        """Parse scaninfo elements"""
        for scaninfo in root.findall('scaninfo'):
            self.db.conn.execute("""
            INSERT INTO scan_info (
                scan_run_id, scan_type, protocol, num_services, services
            ) VALUES (?, ?, ?, ?, ?)
            """, (
                scan_run_id,
                scaninfo.get('type'),
                scaninfo.get('protocol'),
                int(scaninfo.get('numservices', 0)),
                scaninfo.get('services')
            ))

    def _parse_host_hints(self, root: ET.Element, scan_run_id: int):
        """Parse hosthint elements"""
        for hosthint in root.findall('hosthint'):
            status = hosthint.find('status')
            addresses = hosthint.findall('address')

            ip_addr = None
            mac_addr = None
            vendor = None

            for addr in addresses:
                if addr.get('addrtype') == 'ipv4':
                    ip_addr = addr.get('addr')
                elif addr.get('addrtype') == 'mac':
                    mac_addr = addr.get('addr')
                    vendor = addr.get('vendor')

            self.db.conn.execute("""
            INSERT INTO host_hints (
                scan_run_id, status_state, status_reason, status_reason_ttl,
                ip_address, mac_address, vendor
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_run_id,
                self._get_attr_or_none(status, 'state'),
                self._get_attr_or_none(status, 'reason'),
                self._parse_time_string(self._get_attr_or_none(status, 'reason_ttl')),
                ip_addr,
                mac_addr,
                vendor
            ))

    def _parse_hosts(self, root: ET.Element, scan_run_id: int):
        """Parse host elements"""
        for host in root.findall('host'):
            host_id = self._insert_host(host, scan_run_id)

            # Parse hostnames
            self._parse_hostnames(host, host_id)

            # Parse ports
            self._parse_ports(host, host_id)

            # Parse extra ports
            self._parse_extra_ports(host, host_id)

            # Parse OS detection
            self._parse_os_detection(host, host_id)

    def _insert_host(self, host: ET.Element, scan_run_id: int) -> int:
        """Insert host data"""
        status = host.find('status')
        addresses = host.findall('address')

        ip_addr = None
        mac_addr = None
        vendor = None

        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                ip_addr = addr.get('addr')
            elif addr.get('addrtype') == 'mac':
                mac_addr = addr.get('addr')
                vendor = addr.get('vendor')

        cursor = self.db.conn.execute("""
        INSERT INTO hosts (
            scan_run_id, start_time, end_time, status_state, status_reason,
            status_reason_ttl, ip_address, mac_address, vendor
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_run_id,
            self._parse_time_string(host.get('starttime')),
            self._parse_time_string(host.get('endtime')),
            self._get_attr_or_none(status, 'state'),
            self._get_attr_or_none(status, 'reason'),
            self._parse_time_string(self._get_attr_or_none(status, 'reason_ttl')),
            ip_addr,
            mac_addr,
            vendor
        ))

        return cursor.lastrowid

    def _parse_hostnames(self, host: ET.Element, host_id: int):
        """Parse hostname elements"""
        hostnames = host.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                self.db.conn.execute("""
                INSERT INTO hostnames (host_id, hostname, hostname_type)
                VALUES (?, ?, ?)
                """, (
                    host_id,
                    hostname.get('name'),
                    hostname.get('type')
                ))

    def _parse_ports(self, host: ET.Element, host_id: int):
        """Parse port elements"""
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = self._insert_port(port, host_id)

                # Parse scripts for this port
                self._parse_scripts(port, port_id)

    def _insert_port(self, port: ET.Element, host_id: int) -> int:
        """Insert port data"""
        state = port.find('state')
        service = port.find('service')

        cursor = self.db.conn.execute("""
        INSERT INTO ports (
            host_id, protocol, port_id, state, reason, reason_ttl,
            service_name, service_product, service_version, service_extra_info,
            service_os_type, service_method, service_conf
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host_id,
            port.get('protocol'),
            int(port.get('portid')),
            self._get_attr_or_none(state, 'state'),
            self._get_attr_or_none(state, 'reason'),
            self._parse_time_string(self._get_attr_or_none(state, 'reason_ttl')),
            self._get_attr_or_none(service, 'name'),
            self._get_attr_or_none(service, 'product'),
            self._get_attr_or_none(service, 'version'),
            self._get_attr_or_none(service, 'extrainfo'),
            self._get_attr_or_none(service, 'ostype'),
            self._get_attr_or_none(service, 'method'),
            int(self._get_attr_or_none(service, 'conf', 0))
        ))

        port_id = cursor.lastrowid

        # Parse CPE entries
        if service is not None:
            for cpe in service.findall('cpe'):
                if cpe.text:
                    self.db.conn.execute("""
                    INSERT INTO cpe_entries (port_id, cpe_string)
                    VALUES (?, ?)
                    """, (port_id, cpe.text))

        return port_id

    def _parse_scripts(self, port: ET.Element, port_id: int):
        """Parse script elements"""
        for script in port.findall('script'):
            script_id = self._insert_script(script, port_id)

            # Parse script elements and tables
            self._parse_script_structure(script, script_id)

            # Check for vulnerability information
            self._parse_vulnerability_info(script, script_id)

    def _insert_script(self, script: ET.Element, port_id: int) -> int:
        """Insert script data"""
        cursor = self.db.conn.execute("""
        INSERT INTO scripts (port_id, script_id, script_output)
        VALUES (?, ?, ?)
        """, (
            port_id,
            script.get('id'),
            script.get('output')
        ))

        return cursor.lastrowid

    def _parse_script_structure(self, script: ET.Element, script_id: int):
        """Parse nested script structure (tables and elements)"""
        for elem in script.findall('elem'):
            self.db.conn.execute("""
            INSERT INTO script_elements (script_id, elem_key, elem_value)
            VALUES (?, ?, ?)
            """, (
                script_id,
                elem.get('key'),
                elem.text
            ))

        for table in script.findall('table'):
            self._parse_script_table(table, script_id, None)

    def _parse_script_table(self, table: ET.Element, script_id: int, parent_table_id: Optional[int]):
        """Recursively parse script tables"""
        cursor = self.db.conn.execute("""
        INSERT INTO script_tables (script_id, parent_table_id, table_key)
        VALUES (?, ?, ?)
        """, (
            script_id,
            parent_table_id,
            table.get('key')
        ))

        table_id = cursor.lastrowid

        # Parse elements within this table
        for elem in table.findall('elem'):
            self.db.conn.execute("""
            INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
            VALUES (?, ?, ?, ?)
            """, (
                script_id,
                elem.get('key'),
                elem.text,
                table.get('key')
            ))

        # Parse nested tables
        for nested_table in table.findall('table'):
            self._parse_script_table(nested_table, script_id, table_id)

    def _parse_vulnerability_info(self, script: ET.Element, script_id: int):
        """Parse vulnerability information from vuln scripts"""
        script_name = script.get('id', '')

        if 'vuln' in script_name:
            # Look for vulnerability tables
            for table in script.findall('table'):
                vuln_id = table.get('key')
                if vuln_id:
                    self._insert_vulnerability(table, script_id, vuln_id)

    def _insert_vulnerability(self, vuln_table: ET.Element, script_id: int, vuln_id: str):
        """Insert vulnerability data"""
        title = ""
        state = ""
        risk_factor = ""
        cvss_score = None
        description = ""
        disclosure_date = None
        exploit_available = False

        # Extract vulnerability details from table elements
        for elem in vuln_table.findall('elem'):
            key = elem.get('key', '').lower()
            value = elem.text or ""

            if key == 'title':
                title = value
            elif key == 'state':
                state = value
            elif key == 'risk_factor':
                risk_factor = value
            elif key == 'cvss':
                try:
                    cvss_score = float(value)
                except ValueError:
                    pass
            elif key == 'description':
                description = value
            elif key == 'disclosure':
                disclosure_date = value
            elif key == 'exploit':
                exploit_available = value.lower() in ['true', 'yes', '1']

        cursor = self.db.conn.execute("""
        INSERT INTO vulnerabilities (
            script_id, vuln_id, title, state, risk_factor, cvss_score,
            description, disclosure_date, exploit_available
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            script_id, vuln_id, title, state, risk_factor, cvss_score,
            description, disclosure_date, exploit_available
        ))

        vuln_table_id = cursor.lastrowid

        # Parse references
        refs_table = vuln_table.find('.//table[@key="refs"]')
        if refs_table is not None:
            for ref_elem in refs_table.findall('elem'):
                if ref_elem.text:
                    self.db.conn.execute("""
                    INSERT INTO vuln_references (vulnerability_id, reference_url)
                    VALUES (?, ?)
                    """, (vuln_table_id, ref_elem.text))

    def _parse_extra_ports(self, host: ET.Element, host_id: int):
        """Parse extraports elements"""
        ports = host.find('ports')
        if ports is not None:
            for extraports in ports.findall('extraports'):
                extrareasons = extraports.find('extrareasons')

                self.db.conn.execute("""
                INSERT INTO extra_ports (
                    host_id, state, count, reason, reason_count, protocol, ports_range
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    host_id,
                    extraports.get('state'),
                    int(extraports.get('count', 0)),
                    self._get_attr_or_none(extrareasons, 'reason'),
                    int(self._get_attr_or_none(extrareasons, 'count', 0)),
                    self._get_attr_or_none(extrareasons, 'proto'),
                    self._get_attr_or_none(extrareasons, 'ports')
                ))

    def _parse_os_detection(self, host: ET.Element, host_id: int):
        """Parse OS detection results"""
        os_elem = host.find('os')
        if os_elem is not None:
            portused = os_elem.find('portused')

            cursor = self.db.conn.execute("""
            INSERT INTO os_detection (
                host_id, port_used_state, port_used_proto, port_used_portid
            ) VALUES (?, ?, ?, ?)
            """, (
                host_id,
                self._get_attr_or_none(portused, 'state'),
                self._get_attr_or_none(portused, 'proto'),
                int(self._get_attr_or_none(portused, 'portid', 0))
            ))

            os_detection_id = cursor.lastrowid

            # Parse OS matches
            for osmatch in os_elem.findall('osmatch'):
                match_cursor = self.db.conn.execute("""
                INSERT INTO os_matches (
                    os_detection_id, os_name, accuracy, line
                ) VALUES (?, ?, ?, ?)
                """, (
                    os_detection_id,
                    osmatch.get('name'),
                    int(osmatch.get('accuracy', 0)),
                    int(osmatch.get('line', 0))
                ))

                os_match_id = match_cursor.lastrowid

                # Parse OS classes
                for osclass in osmatch.findall('osclass'):
                    cpe_list = [cpe.text for cpe in osclass.findall('cpe')]

                    self.db.conn.execute("""
                    INSERT INTO os_classes (
                        os_match_id, os_type, vendor, os_family, os_gen, accuracy, cpe
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        os_match_id,
                        osclass.get('type'),
                        osclass.get('vendor'),
                        osclass.get('osfamily'),
                        osclass.get('osgen'),
                        int(osclass.get('accuracy', 0)),
                        ', '.join(cpe_list) if cpe_list else None
                    ))

    def _parse_task_progress(self, root: ET.Element, scan_run_id: int):
        """Parse taskprogress elements"""
        for taskprogress in root.findall('taskprogress'):
            self.db.conn.execute("""
            INSERT INTO task_progress (
                scan_run_id, task_name, task_time, percent, remaining, etc
            ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_run_id,
                taskprogress.get('task'),
                self._parse_time_string(taskprogress.get('time')),
                float(taskprogress.get('percent', 0.0)),
                int(taskprogress.get('remaining', 0)),
                self._parse_time_string(taskprogress.get('etc'))
            ))

    def _parse_runtime_stats(self, root: ET.Element, scan_run_id: int):
        """Parse runstats element"""
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            hosts = runstats.find('hosts')

            summary = ""
            if hosts is not None:
                up = hosts.get('up', '0')
                down = hosts.get('down', '0')
                total = hosts.get('total', '0')
                summary = f"Hosts: {up} up, {down} down, {total} total"

            self.db.conn.execute("""
            INSERT INTO runtime_stats (
                scan_run_id, finished_time, finished_time_str, elapsed_time, summary
            ) VALUES (?, ?, ?, ?, ?)
            """, (
                scan_run_id,
                self._parse_time_string(self._get_attr_or_none(finished, 'time')),
                self._get_attr_or_none(finished, 'timestr'),
                float(self._get_attr_or_none(finished, 'elapsed', 0.0)),
                summary
            ))

    def parse_directory(self, directory_path: str) -> Dict[str, bool]:
        """Parse all XML files in a directory"""
        results = {}

        if not os.path.exists(directory_path):
            self.logger.error(f"Directory not found: {directory_path}")
            return results

        xml_files = [f for f in os.listdir(directory_path) if f.lower().endswith('.xml')]

        self.logger.info(f"Found {len(xml_files)} XML files in {directory_path}")

        for xml_file in xml_files:
            filepath = os.path.join(directory_path, xml_file)
            results[xml_file] = self.parse_file(filepath)

        return results

    def close(self):
        """Close the database connection"""
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()