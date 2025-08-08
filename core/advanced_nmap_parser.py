#!/usr/bin/env python3
"""
Advanced Nmap XML Parser - VERSIONE COMPLETA CON SNMP
Extended parser with SNMP and specialized script handling
"""

import sys
import os
import logging
import sqlite3
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import re

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from nmap_xml_parser import NmapXMLParser
except ImportError:
    print("Warning: Could not import NmapXMLParser, using standalone mode")
    NmapXMLParser = object


class FixedSNMPParser:
    """Parser corretto per i dati SNMP da file XML Nmap"""

    def __init__(self, db_connection):
        self.db = db_connection
        self.logger = logging.getLogger(__name__)

    def parse_snmp_script(self, script_element: ET.Element, port_id: int, host_id: int):
        """Parse specifico per script SNMP basato sul tipo"""
        script_id = script_element.get('id', '')
        self.logger.info(f"Parsing SNMP script: {script_id} for host {host_id}")

        if script_id == 'snmp-win32-services':
            return self._parse_win32_services(script_element, host_id)
        elif script_id == 'snmp-processes':
            return self._parse_processes(script_element, host_id)
        elif script_id == 'snmp-win32-software':
            return self._parse_win32_software(script_element, host_id)
        elif script_id == 'snmp-win32-users':
            return self._parse_win32_users(script_element, host_id)
        elif script_id == 'snmp-interfaces':
            return self._parse_interfaces(script_element, host_id)
        elif script_id == 'snmp-netstat':
            return self._parse_netstat(script_element, host_id)
        elif script_id == 'snmp-sysdescr':
            return self._parse_system_description(script_element, host_id)
        elif script_id == 'snmp-win32-shares':
            return self._parse_win32_shares(script_element, host_id)

        self.logger.warning(f"Unhandled SNMP script: {script_id}")
        return 0

    def _parse_win32_services(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei servizi Windows da SNMP"""
        services_parsed = 0
        self.logger.debug(f"Parsing Windows services for host {host_id}")

        # Parsing dai <elem> diretti (lista servizi)
        for elem in script_element.findall('elem'):
            service_name = elem.text
            if service_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_services (host_id, service_name, status, startup_type)
                    VALUES (?, ?, 'unknown', 'unknown')
                    """, (host_id, service_name.strip()))
                    services_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento servizio {service_name}: {e}")

        # Parsing dalle tabelle strutturate
        for table in script_element.findall('table'):
            service_name = None
            status = None
            startup_type = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'name':
                    service_name = elem.text
                elif key == 'state':
                    status = elem.text
                elif key == 'start_mode':
                    startup_type = elem.text

            if service_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_services (host_id, service_name, status, startup_type)
                    VALUES (?, ?, ?, ?)
                    """, (host_id, service_name.strip(), status or 'unknown', startup_type or 'unknown'))
                    services_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento servizio {service_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {services_parsed} servizi per host {host_id}")
        return services_parsed

    def _parse_processes(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei processi attivi da SNMP"""
        processes_parsed = 0
        self.logger.debug(f"Parsing processes for host {host_id}")

        # Parsing dalle tabelle (struttura più dettagliata)
        for table in script_element.findall('table'):
            pid = table.get('key')
            process_name = None
            process_path = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'Name':
                    process_name = elem.text
                elif key == 'Path':
                    process_path = elem.text

            if pid and process_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_processes 
                    (host_id, process_id, process_name, process_path, memory_usage)
                    VALUES (?, ?, ?, ?, NULL)
                    """, (host_id, int(pid), process_name, process_path))
                    processes_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        # Parsing alternativo dai semplici <elem> se non ci sono tabelle
        if processes_parsed == 0:
            for elem in script_element.findall('elem'):
                process_name = elem.text
                if process_name:
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_processes 
                        (host_id, process_id, process_name, process_path, memory_usage)
                        VALUES (?, NULL, ?, NULL, NULL)
                        """, (host_id, process_name.strip()))
                        processes_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {processes_parsed} processi per host {host_id}")
        return processes_parsed

    def _parse_win32_software(self, script_element: ET.Element, host_id: int) -> int:
        """Parse del software installato da SNMP"""
        software_parsed = 0
        self.logger.debug(f"Parsing software for host {host_id}")

        script_output = script_element.get('output', '')

        # Parsing dal testo di output (formato: "Nome Software; Data")
        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if ';' in line:
                parts = line.split(';')
                if len(parts) >= 2:
                    software_name = parts[0].strip()
                    install_date = parts[1].strip()

                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_software 
                        (host_id, software_name, version, install_date, vendor)
                        VALUES (?, ?, NULL, ?, NULL)
                        """, (host_id, software_name, install_date))
                        software_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento software {software_name}: {e}")

        # Parsing alternativo dalle tabelle strutturate
        for table in script_element.findall('table'):
            software_name = None
            install_date = None
            version = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'name':
                    software_name = elem.text
                elif key == 'install_date':
                    install_date = elem.text
                elif key == 'version':
                    version = elem.text

            if software_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_software 
                    (host_id, software_name, version, install_date, vendor)
                    VALUES (?, ?, ?, ?, NULL)
                    """, (host_id, software_name, version, install_date))
                    software_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento software {software_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {software_parsed} software per host {host_id}")
        return software_parsed

    def _parse_win32_users(self, script_element: ET.Element, host_id: int) -> int:
        """Parse degli utenti di sistema da SNMP"""
        users_parsed = 0
        self.logger.debug(f"Parsing users for host {host_id}")

        # Parsing dalle tabelle strutturate
        for table in script_element.findall('table'):
            username = None
            full_name = None
            description = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'name':
                    username = elem.text
                elif key == 'full_name':
                    full_name = elem.text
                elif key == 'description':
                    description = elem.text

            if username:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_users 
                    (host_id, username, full_name, description, status)
                    VALUES (?, ?, ?, ?, 'unknown')
                    """, (host_id, username, full_name, description))
                    users_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento utente {username}: {e}")

        # Parsing alternativo dai semplici elementi
        if users_parsed == 0:
            for elem in script_element.findall('elem'):
                username = elem.text
                if username:
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_users 
                        (host_id, username, full_name, description, status)
                        VALUES (?, ?, NULL, NULL, 'unknown')
                        """, (host_id, username.strip()))
                        users_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento utente {username}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {users_parsed} utenti per host {host_id}")
        return users_parsed

    def _parse_interfaces(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle interfacce di rete da SNMP"""
        interfaces_parsed = 0
        self.logger.debug(f"Parsing interfaces for host {host_id}")

        for table in script_element.findall('table'):
            interface_index = table.get('key')
            interface_name = None
            ip_address = None
            mac_address = None
            status = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'name':
                    interface_name = elem.text
                elif key == 'ip':
                    ip_address = elem.text
                elif key == 'mac':
                    mac_address = elem.text
                elif key == 'status':
                    status = elem.text

            if interface_name or ip_address:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_interfaces 
                    (host_id, interface_name, interface_index, ip_address, mac_address, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (host_id, interface_name,
                         int(interface_index) if interface_index else None,
                         ip_address, mac_address, status or 'unknown'))
                    interfaces_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento interfaccia {interface_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importate {interfaces_parsed} interfacce per host {host_id}")
        return interfaces_parsed

    def _parse_netstat(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle connessioni di rete da SNMP"""
        connections_parsed = 0
        self.logger.debug(f"Parsing network connections for host {host_id}")

        for table in script_element.findall('table'):
            protocol = None
            local_address = None
            local_port = None
            remote_address = None
            remote_port = None
            state = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'protocol':
                    protocol = elem.text
                elif key == 'local_address':
                    local_address = elem.text
                elif key == 'local_port':
                    local_port = elem.text
                elif key == 'remote_address':
                    remote_address = elem.text
                elif key == 'remote_port':
                    remote_port = elem.text
                elif key == 'state':
                    state = elem.text

            if protocol and local_address:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_network_connections 
                    (host_id, protocol, local_address, local_port, remote_address, remote_port, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (host_id, protocol, local_address,
                         int(local_port) if local_port else None,
                         remote_address,
                         int(remote_port) if remote_port else None,
                         state or 'unknown'))
                    connections_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento connessione: {e}")

        self.db.commit()
        self.logger.info(f"Importate {connections_parsed} connessioni per host {host_id}")
        return connections_parsed

    def _parse_system_description(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle informazioni di sistema da SNMP"""
        self.logger.debug(f"Parsing system description for host {host_id}")

        system_description = script_element.get('output', '').strip()

        if system_description:
            try:
                self.db.execute("""
                INSERT OR REPLACE INTO snmp_system_info 
                (host_id, system_description)
                VALUES (?, ?)
                """, (host_id, system_description))
                self.db.commit()
                self.logger.info(f"Importata descrizione sistema per host {host_id}")
                return 1
            except Exception as e:
                self.logger.error(f"Errore inserimento sistema: {e}")

        return 0

    def _parse_win32_shares(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle condivisioni di rete da SNMP"""
        shares_parsed = 0
        self.logger.debug(f"Parsing shares for host {host_id}")

        # Parsing dalle tabelle strutturate
        for table in script_element.findall('table'):
            share_name = None
            share_path = None
            description = None

            for elem in table.findall('elem'):
                key = elem.get('key')
                if key == 'name':
                    share_name = elem.text
                elif key == 'path':
                    share_path = elem.text
                elif key == 'comment':
                    description = elem.text

            if share_name and share_path:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_shares 
                    (host_id, share_name, share_path, description)
                    VALUES (?, ?, ?, ?)
                    """, (host_id, share_name, share_path, description))
                    shares_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        # Parse alternativo dal testo di output
        if shares_parsed == 0:
            script_output = script_element.get('output', '')
            lines = script_output.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        share_name = parts[0].strip()
                        share_path = parts[1].strip()

                        try:
                            self.db.execute("""
                            INSERT OR IGNORE INTO snmp_shares 
                            (host_id, share_name, share_path, description)
                            VALUES (?, ?, ?, NULL)
                            """, (host_id, share_name, share_path))
                            shares_parsed += 1
                        except Exception as e:
                            self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importate {shares_parsed} condivisioni per host {host_id}")
        return shares_parsed


class AdvancedNmapParser(NmapXMLParser):
    """Extended parser with specialized handling for different script types"""

    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        if NmapXMLParser != object:
            super().__init__(db_path)
        else:
            self.db_path = db_path
            self.logger = logging.getLogger(__name__)
            # Initialize our own database connection if parent not available
            from nmap_scanner_db import NmapScannerDB
            self.db = NmapScannerDB(db_path)

        self.snmp_parser = None

        # Define script handlers for different types of scripts
        self.script_handlers = {
            'snmp-processes': self._handle_snmp_script,
            'snmp-netstat': self._handle_snmp_script,
            'snmp-sysdescr': self._handle_snmp_script,
            'snmp-interfaces': self._handle_snmp_script,
            'snmp-win32-services': self._handle_snmp_script,
            'snmp-win32-software': self._handle_snmp_script,
            'snmp-win32-users': self._handle_snmp_script,
            'snmp-win32-shares': self._handle_snmp_script,
            'http-vuln-cve': self._handle_http_vuln,
            'smb-vuln': self._handle_smb_vuln,
            'ssl-cert': self._handle_ssl_cert,
            'ssh-hostkey': self._handle_ssh_hostkey,
        }

    def _get_db_connection(self):
        """Get database connection"""
        if hasattr(self, 'db') and hasattr(self.db, 'conn'):
            return self.db.conn
        else:
            return sqlite3.connect(self.db_path)

    def _parse_scripts(self, port_element, port_id: int):
        """Override to add specialized script handling"""

        # Call parent method first if available
        if hasattr(super(), '_parse_scripts'):
            super()._parse_scripts(port_element, port_id)

        # Get host_id for SNMP scripts that need it
        conn = self._get_db_connection()
        cursor = conn.execute("SELECT host_id FROM ports WHERE id = ?", (port_id,))
        result = cursor.fetchone()
        if not result:
            self.logger.error(f"Could not find host_id for port_id {port_id}")
            return

        host_id = result[0]

        # Initialize SNMP parser if needed
        if not self.snmp_parser:
            self.snmp_parser = FixedSNMPParser(conn)

        # Process each script with specialized handlers
        snmp_scripts_processed = 0
        for script in port_element.findall('script'):
            script_name = script.get('id', '')

            # Check if we have a specialized handler
            for pattern, handler in self.script_handlers.items():
                if pattern in script_name:
                    try:
                        results = handler(script, port_id, host_id)
                        if pattern.startswith('snmp-') and results > 0:
                            snmp_scripts_processed += results
                        self.logger.debug(f"Processed {script_name} with {results} results")
                    except Exception as e:
                        self.logger.error(f"Error in specialized handler for {script_name}: {e}")
                    break

        if snmp_scripts_processed > 0:
            self.logger.info(f"Processed {snmp_scripts_processed} SNMP records for host {host_id}")

    def _handle_snmp_script(self, script, port_id: int, host_id: int):
        """Handle SNMP scripts with specialized parser"""
        try:
            results = self.snmp_parser.parse_snmp_script(script, port_id, host_id)
            script_name = script.get('id', '')
            self.logger.debug(f"Parsed {results} records from {script_name}")
            return results
        except Exception as e:
            self.logger.error(f"Error parsing SNMP script {script.get('id', '')}: {e}")
            return 0

    def _handle_http_vuln(self, script, port_id: int, host_id: int):
        """Handle HTTP vulnerability scripts"""
        script_name = script.get('id', '')
        script_output = script.get('output', '')

        # Look for CVE information in the script name or output
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, script_name + ' ' + script_output)

        if cves:
            conn = self._get_db_connection()
            for cve in set(cves):  # Remove duplicates
                try:
                    conn.execute("""
                    INSERT OR IGNORE INTO vulnerabilities 
                    (host_id, port_id, vuln_id, title, description, severity)
                    VALUES (?, ?, ?, ?, ?, 'unknown')
                    """, (host_id, port_id, cve, f"HTTP Vulnerability {cve}", script_output))
                except Exception as e:
                    self.logger.error(f"Error storing vulnerability {cve}: {e}")

            conn.commit()
            self.logger.info(f"Stored {len(cves)} vulnerabilities from {script_name}")
            return len(cves)
        return 0

    def _handle_smb_vuln(self, script, port_id: int, host_id: int):
        """Handle SMB vulnerability scripts"""
        return self._handle_http_vuln(script, port_id, host_id)

    def _handle_ssl_cert(self, script, port_id: int, host_id: int):
        """Handle SSL certificate information"""
        script_output = script.get('output', '')
        cert_info = self._parse_ssl_certificate(script_output)

        conn = self._get_db_connection()
        try:
            conn.execute("""
            INSERT OR REPLACE INTO ssl_certificates 
            (host_id, port_id, subject, issuer, not_before, not_after, serial)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id, port_id,
                cert_info.get('subject'),
                cert_info.get('issuer'),
                cert_info.get('not_before'),
                cert_info.get('not_after'),
                cert_info.get('serial')
            ))
            conn.commit()
            return 1
        except Exception as e:
            self.logger.error(f"Error storing SSL certificate: {e}")
            return 0

    def _parse_ssl_certificate(self, output: str) -> dict:
        """Parse SSL certificate information"""
        cert_info = {}
        patterns = {
            'subject': r'Subject:\s*(.+?)(?:\n|$)',
            'issuer': r'Issuer:\s*(.+?)(?:\n|$)',
            'not_before': r'Not valid before:\s*(.+?)(?:\n|$)',
            'not_after': r'Not valid after:\s*(.+?)(?:\n|$)',
            'serial': r'Serial Number:\s*(.+?)(?:\n|$)',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                cert_info[key] = match.group(1).strip()

        return cert_info

    def _handle_ssh_hostkey(self, script, port_id: int, host_id: int):
        """Handle SSH host key information"""
        script_output = script.get('output', '')
        hostkeys = self._parse_ssh_hostkeys(script_output)

        conn = self._get_db_connection()
        keys_stored = 0
        for key_info in hostkeys:
            try:
                conn.execute("""
                INSERT OR IGNORE INTO ssh_hostkeys 
                (host_id, port_id, key_type, key_size, fingerprint)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    host_id, port_id,
                    key_info.get('key_type'),
                    key_info.get('key_size'),
                    key_info.get('fingerprint')
                ))
                keys_stored += 1
            except Exception as e:
                self.logger.error(f"Error storing SSH hostkey: {e}")

        conn.commit()
        return keys_stored

    def _parse_ssh_hostkeys(self, output: str) -> list:
        """Parse SSH host key information"""
        hostkeys = []
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

            if key_info:
                hostkeys.append(key_info)

        return hostkeys

    def parse_file(self, filepath: str) -> bool:
        """Parse a file with advanced SNMP support"""
        self.logger.info(f"Parsing file with advanced parser: {filepath}")

        if NmapXMLParser != object and hasattr(super(), 'parse_file'):
            # Use parent method if available
            return super().parse_file(filepath)
        else:
            # Standalone parsing
            return self._standalone_parse_file(filepath)

    def _standalone_parse_file(self, filepath: str) -> bool:
        """Standalone file parsing when parent class not available"""
        try:
            import hashlib

            if not os.path.exists(filepath):
                self.logger.error(f"File not found: {filepath}")
                return False

            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()

            # Check if already parsed
            existing_scan = self.db.get_scan_by_hash(file_hash)
            if existing_scan:
                self.logger.info(f"File already parsed: {filepath}")
                return True

            # Parse XML
            tree = ET.parse(filepath)
            root = tree.getroot()

            if root.tag != 'nmaprun':
                self.logger.error(f"Invalid Nmap XML file: {filepath}")
                return False

            # Basic parsing - this is simplified, you may want to implement full parsing
            self.logger.warning("Using simplified standalone parsing - some features may be limited")

            return True

        except Exception as e:
            self.logger.error(f"Error in standalone parsing of {filepath}: {e}")
            return False


# Test functions
def test_snmp_parsing():
    """Test SNMP parsing functionality"""
    print("🧪 Testing SNMP parsing capabilities...")

    try:
        parser = AdvancedNmapParser()
        print("✅ AdvancedNmapParser created successfully")

        # Check SNMP handlers
        snmp_handlers = [k for k in parser.script_handlers.keys() if k.startswith('snmp-')]
        print(f"✅ {len(snmp_handlers)} SNMP handlers registered:")
        for handler in snmp_handlers:
            print(f"    📋 {handler}")

        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def test_file_parsing(xml_file):
    """Test parsing of a specific XML file"""
    if not os.path.exists(xml_file):
        print(f"❌ Test file not found: {xml_file}")
        return False

    print(f"🧪 Testing parsing of {xml_file}...")

    try:
        parser = AdvancedNmapParser("test_snmp_parsing.db")
        success = parser.parse_file(xml_file)

        if success:
            print(f"✅ {xml_file} parsed successfully")

            # Check for SNMP data
            stats = parser.db.get_database_stats()
            snmp_records = sum(v for k, v in stats.items() if k.startswith('snmp_') and k.endswith('_count'))
            print(f"📊 SNMP records found: {snmp_records}")

        else:
            print(f"❌ {xml_file} parsing failed")

        return success
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Advanced Nmap Parser with SNMP Support")
    print("=" * 50)

    # Test basic functionality
    if test_snmp_parsing():
        print("\n✅ Basic SNMP parsing test passed")

        # Test file parsing if files exist
        test_files = ['scans/sei.xml', 'scans/due.xml', 'scans/quattro.xml']
        for test_file in test_files:
            if os.path.exists(test_file):
                test_file_parsing(test_file)
                break
        else:
            print("\n⚠️ No test files found for parsing test")
    else:
        print("\n❌ Basic SNMP parsing test failed")