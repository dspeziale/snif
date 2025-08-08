"""
Advanced Nmap XML Parser
Extended parser with SNMP and specialized script handling
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nmap_xml_parser import NmapXMLParser
from complete_snmp_parser import SNMPDataParser
import logging

class AdvancedNmapParser(NmapXMLParser):
    """Extended parser with specialized handling for different script types"""

    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        super().__init__(db_path)
        self.snmp_parser = SNMPDataParser(self.db)

        # Define script handlers for different types of scripts
        self.script_handlers = {
            'snmp-processes': self._handle_snmp_processes,
            'snmp-netstat': self._handle_snmp_netstat,
            'snmp-sysdescr': self._handle_snmp_system_info,
            'snmp-interfaces': self._handle_snmp_interfaces,
            'http-vuln-cve': self._handle_http_vuln,
            'smb-vuln': self._handle_smb_vuln,
            'ssl-cert': self._handle_ssl_cert,
            'ssh-hostkey': self._handle_ssh_hostkey,
        }

    def _parse_scripts(self, port, port_id: int):
        """Override to add specialized script handling"""
        # Call parent method first
        super()._parse_scripts(port, port_id)

        # Get host_id for SNMP scripts that need it
        cursor = self.db.conn.execute(
            "SELECT host_id FROM ports WHERE id = ?", (port_id,)
        )
        host_id = cursor.fetchone()[0]

        # Process each script with specialized handlers
        for script in port.findall('script'):
            script_name = script.get('id', '')

            # Check if we have a specialized handler
            for pattern, handler in self.script_handlers.items():
                if pattern in script_name:
                    try:
                        handler(script, port_id, host_id)
                    except Exception as e:
                        self.logger.error(f"Error in specialized handler for {script_name}: {e}")
                    break

    def _handle_snmp_processes(self, script, port_id: int, host_id: int):
        """Handle SNMP process enumeration scripts"""
        script_output = script.get('output', '')

        # Try to extract from structured data first
        processes_from_tables = self.snmp_parser.extract_process_names_from_script_tables(
            self._get_script_db_id(script, port_id), host_id
        )

        # Try to extract from raw output
        processes_from_output = self.snmp_parser.parse_snmp_processes(script_output, host_id)

        total_processes = processes_from_tables + processes_from_output
        self.logger.info(f"Extracted {total_processes} processes for host {host_id}")

    def _handle_snmp_netstat(self, script, port_id: int, host_id: int):
        """Handle SNMP netstat scripts"""
        script_output = script.get('output', '')
        connections = self.snmp_parser.parse_snmp_netstat(script_output, host_id)
        self.logger.info(f"Extracted {connections} network connections for host {host_id}")

    def _handle_snmp_system_info(self, script, port_id: int, host_id: int):
        """Handle SNMP system information scripts"""
        # Extract system info from script elements
        script_db_id = self._get_script_db_id(script, port_id)

        cursor = self.db.conn.execute("""
        SELECT elem_key, elem_value FROM script_elements 
        WHERE script_id = ?
        """, (script_db_id,))

        elements = [{'elem_key': row[0], 'elem_value': row[1]} for row in cursor.fetchall()]
        success = self.snmp_parser.parse_snmp_system_info(elements, host_id)

        if success:
            self.logger.info(f"Extracted SNMP system info for host {host_id}")

    def _handle_snmp_interfaces(self, script, port_id: int, host_id: int):
        """Handle SNMP network interfaces information"""
        script_output = script.get('output', '')

        # Parse network interfaces from script output
        interfaces = self._parse_network_interfaces(script_output)

        for interface in interfaces:
            try:
                # Store interface information in a custom way
                # For now, we'll store it as script elements with a special marker
                self.db.conn.execute("""
                INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
                VALUES (?, ?, ?, ?)
                """, (
                    self._get_script_db_id(script, port_id),
                    f"interface_{interface.get('index', 'unknown')}",
                    f"{interface.get('name', 'Unknown')}: {interface.get('description', '')}",
                    "network_interfaces"
                ))
            except Exception as e:
                self.logger.error(f"Error storing interface info: {e}")

    def _parse_network_interfaces(self, output: str) -> list:
        """Parse network interfaces from script output"""
        interfaces = []

        lines = output.split('\n')
        current_interface = {}

        for line in lines:
            line = line.strip()
            if not line:
                if current_interface:
                    interfaces.append(current_interface)
                    current_interface = {}
                continue

            if ':' in line:
                key, value = line.split(':', 1)
                current_interface[key.strip().lower().replace(' ', '_')] = value.strip()

        if current_interface:
            interfaces.append(current_interface)

        return interfaces

    def _handle_http_vuln(self, script, port_id: int, host_id: int):
        """Handle HTTP vulnerability scripts"""
        script_name = script.get('id', '')
        script_output = script.get('output', '')

        # Look for CVE information in the script name or output
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, script_name + ' ' + script_output)

        if cves:
            script_db_id = self._get_script_db_id(script, port_id)

            for cve in set(cves):  # Remove duplicates
                # Check if vulnerability already exists
                cursor = self.db.conn.execute("""
                SELECT id FROM vulnerabilities 
                WHERE script_id = ? AND vuln_id = ?
                """, (script_db_id, cve))

                if not cursor.fetchone():
                    # Insert new vulnerability
                    self.db.conn.execute("""
                    INSERT INTO vulnerabilities (
                        script_id, vuln_id, title, state, description
                    ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        script_db_id,
                        cve,
                        f"HTTP Vulnerability: {cve}",
                        "VULNERABLE" if "VULNERABLE" in script_output.upper() else "UNKNOWN",
                        script_output[:1000]  # Limit description length
                    ))

    def _handle_smb_vuln(self, script, port_id: int, host_id: int):
        """Handle SMB vulnerability scripts"""
        script_output = script.get('output', '')
        script_db_id = self._get_script_db_id(script, port_id)

        # Common SMB vulnerabilities
        smb_vulns = {
            'ms17-010': 'EternalBlue SMB Vulnerability',
            'ms08-067': 'SMB Remote Code Execution',
            'smb-vuln-conficker': 'Conficker Worm Vulnerability',
            'smb-vuln-cve2009-3103': 'SMB2 Negotiate Protocol Vulnerability'
        }

        script_name = script.get('id', '').lower()

        for vuln_id, title in smb_vulns.items():
            if vuln_id in script_name:
                state = "VULNERABLE" if "VULNERABLE" in script_output.upper() else "NOT VULNERABLE"

                self.db.conn.execute("""
                INSERT INTO vulnerabilities (
                    script_id, vuln_id, title, state, description, risk_factor
                ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    script_db_id,
                    vuln_id.upper(),
                    title,
                    state,
                    script_output[:1000],
                    "HIGH" if state == "VULNERABLE" else "NONE"
                ))
                break

    def _handle_ssl_cert(self, script, port_id: int, host_id: int):
        """Handle SSL certificate information"""
        script_output = script.get('output', '')
        script_db_id = self._get_script_db_id(script, port_id)

        # Extract certificate information
        cert_info = self._parse_ssl_certificate(script_output)

        for key, value in cert_info.items():
            self.db.conn.execute("""
            INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
            VALUES (?, ?, ?, ?)
            """, (script_db_id, key, value, "ssl_certificate"))

    def _parse_ssl_certificate(self, output: str) -> dict:
        """Parse SSL certificate information"""
        import re

        cert_info = {}

        # Common SSL certificate fields
        patterns = {
            'subject': r'Subject:\s*(.+?)(?:\n|$)',
            'issuer': r'Issuer:\s*(.+?)(?:\n|$)',
            'not_before': r'Not valid before:\s*(.+?)(?:\n|$)',
            'not_after': r'Not valid after:\s*(.+?)(?:\n|$)',
            'serial': r'Serial Number:\s*(.+?)(?:\n|$)',
            'signature_algorithm': r'Signature Algorithm:\s*(.+?)(?:\n|$)',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                cert_info[key] = match.group(1).strip()

        return cert_info

    def _handle_ssh_hostkey(self, script, port_id: int, host_id: int):
        """Handle SSH host key information"""
        script_output = script.get('output', '')
        script_db_id = self._get_script_db_id(script, port_id)

        # Parse SSH host keys
        hostkeys = self._parse_ssh_hostkeys(script_output)

        for i, key_info in enumerate(hostkeys):
            for field, value in key_info.items():
                self.db.conn.execute("""
                INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
                VALUES (?, ?, ?, ?)
                """, (script_db_id, field, value, f"hostkey_{i}"))

    def _parse_ssh_hostkeys(self, output: str) -> list:
        """Parse SSH host key information"""
        import re

        hostkeys = []

        # Look for host key blocks
        key_blocks = re.split(r'\n(?=\d+\s+\w+)', output)

        for block in key_blocks:
            if not block.strip():
                continue

            key_info = {}
            lines = block.strip().split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Parse key size and type
                key_match = re.match(r'(\d+)\s+(\w+)', line)
                if key_match:
                    key_info['key_size'] = key_match.group(1)
                    key_info['key_type'] = key_match.group(2)
                    continue

                # Parse fingerprints
                if 'fingerprint' in line.lower():
                    key_info['fingerprint'] = line.split(':', 1)[1].strip()
                elif line.startswith('|'):
                    key_info['ascii_art'] = key_info.get('ascii_art', '') + line + '\n'

            if key_info:
                hostkeys.append(key_info)

        return hostkeys

    def _get_script_db_id(self, script, port_id: int) -> int:
        """Get the database ID for a script"""
        cursor = self.db.conn.execute("""
        SELECT id FROM scripts 
        WHERE port_id = ? AND script_id = ?
        ORDER BY id DESC LIMIT 1
        """, (port_id, script.get('id')))

        result = cursor.fetchone()
        return result[0] if result else None

    def generate_detailed_report(self, host_ip: str = None) -> dict:
        """Generate a detailed report for a specific host or all hosts"""
        report = {
            'summary': {},
            'hosts': [],
            'vulnerabilities': [],
            'services': [],
            'snmp_info': []
        }

        try:
            # Get summary statistics
            report['summary'] = self._get_detailed_summary()

            # Get host information
            host_filter = f"WHERE h.ip_address = '{host_ip}'" if host_ip else ""

            cursor = self.db.conn.execute(f"""
            SELECT DISTINCT h.id, h.ip_address, h.mac_address, h.vendor, h.status_state
            FROM hosts h
            {host_filter}
            ORDER BY h.ip_address
            """)

            for host_row in cursor.fetchall():
                host_id, ip, mac, vendor, status = host_row

                host_info = {
                    'ip_address': ip,
                    'mac_address': mac,
                    'vendor': vendor,
                    'status': status,
                    'ports': self._get_host_ports(host_id),
                    'processes': self.snmp_parser.get_host_processes(host_id),
                    'network_connections': self.snmp_parser.get_host_network_connections(host_id),
                    'snmp_system_info': self.snmp_parser.get_snmp_system_info(host_id),
                    'vulnerabilities': self._get_host_vulnerabilities(host_id)
                }

                report['hosts'].append(host_info)

            return report

        except Exception as e:
            self.logger.error(f"Error generating detailed report: {e}")
            return report

    def _get_detailed_summary(self) -> dict:
        """Get detailed summary statistics"""
        summary = {}

        queries = {
            'total_hosts': "SELECT COUNT(*) FROM hosts WHERE status_state = 'up'",
            'total_ports': "SELECT COUNT(*) FROM ports WHERE state = 'open'",
            'total_services': "SELECT COUNT(DISTINCT service_name) FROM ports WHERE service_name IS NOT NULL",
            'total_vulnerabilities': "SELECT COUNT(*) FROM vulnerabilities",
            'total_processes': "SELECT COUNT(*) FROM processes",
            'total_connections': "SELECT COUNT(*) FROM network_connections",
            'hosts_with_snmp': "SELECT COUNT(DISTINCT host_id) FROM snmp_info"
        }

        for key, query in queries.items():
            try:
                cursor = self.db.conn.execute(query)
                summary[key] = cursor.fetchone()[0]
            except Exception as e:
                self.logger.error(f"Error getting {key}: {e}")
                summary[key] = 0

        return summary

    def _get_host_ports(self, host_id: int) -> list:
        """Get detailed port information for a host"""
        cursor = self.db.conn.execute("""
        SELECT port_id, protocol, state, service_name, service_product, 
               service_version, service_extra_info
        FROM ports
        WHERE host_id = ?
        ORDER BY port_id
        """, (host_id,))

        ports = []
        for row in cursor.fetchall():
            ports.append({
                'port': row[0],
                'protocol': row[1],
                'state': row[2],
                'service_name': row[3],
                'service_product': row[4],
                'service_version': row[5],
                'service_extra_info': row[6]
            })

        return ports

    def _get_host_vulnerabilities(self, host_id: int) -> list:
        """Get vulnerabilities for a specific host"""
        cursor = self.db.conn.execute("""
        SELECT v.vuln_id, v.title, v.state, v.risk_factor, v.cvss_score,
               p.port_id, p.service_name
        FROM vulnerabilities v
        JOIN scripts s ON v.script_id = s.id
        JOIN ports p ON s.port_id = p.id
        WHERE p.host_id = ?
        ORDER BY v.cvss_score DESC, v.risk_factor DESC
        """, (host_id,))

        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                'vuln_id': row[0],
                'title': row[1],
                'state': row[2],
                'risk_factor': row[3],
                'cvss_score': row[4],
                'port': row[5],
                'service': row[6]
            })

        return vulnerabilities