#!/usr/bin/env python3
"""
Enhanced SNMP XML Parser for Nmap Results
Parses Nmap XML files with SNMP script outputs and extracts comprehensive system information
"""

import sqlite3
import xml.etree.ElementTree as ET
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SNMPXMLParser:
    def __init__(self, db_path: str = "snmp_scan_results.db"):
        """
        Inizializza il parser SNMP con database SQLite
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def connect_db(self):
        """Connette al database SQLite"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            logger.info(f"Connesso al database: {self.db_path}")
        except Exception as e:
            logger.error(f"Errore connessione database: {e}")
            raise

    def create_tables(self):
        """Crea tutte le tabelle necessarie per i dati SNMP"""

        # Tabella principale degli host
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                vendor TEXT,
                status TEXT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabella system info da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_info (
                ip_address TEXT PRIMARY KEY,
                system_description TEXT,
                system_uptime TEXT,
                hardware_info TEXT,
                software_info TEXT,
                os_build TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella utenti Windows da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                username TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella servizi Windows da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_services (
                service_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                service_name TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella software installato da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_software (
                software_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                software_name TEXT,
                install_date TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella processi in esecuzione da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_processes (
                process_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                process_params TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella interfacce di rete da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_interfaces (
                interface_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                interface_name TEXT,
                interface_ip TEXT,
                netmask TEXT,
                mac_address TEXT,
                interface_type TEXT,
                speed TEXT,
                status TEXT,
                traffic_sent TEXT,
                traffic_received TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella connessioni di rete da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_netstat (
                connection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                protocol TEXT,
                local_address TEXT,
                local_port TEXT,
                remote_address TEXT,
                remote_port TEXT,
                state TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella condivisioni di rete da SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_shares (
                share_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                share_name TEXT,
                share_path TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella credenziali SNMP
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_credentials (
                cred_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                community_string TEXT,
                status TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella porte da scan
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                state TEXT,
                service_name TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        self.conn.commit()
        logger.info("Tabelle SNMP create con successo")

    def parse_xml_file(self, xml_file_path: str) -> bool:
        """Parsing di un file XML di nmap con script SNMP"""
        try:
            logger.info(f"Parsing file: {xml_file_path}")
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Parse ogni host
            for host in root.findall('host'):
                self._parse_host(host)

            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Errore nel parsing di {xml_file_path}: {e}")
            return False

    def _parse_host(self, host_element):
        """Parse di un singolo host"""
        # Estrai informazioni base dell'host
        ip_addr = None
        mac_addr = None
        vendor = None

        for address in host_element.findall('address'):
            if address.get('addrtype') == 'ipv4':
                ip_addr = address.get('addr')
            elif address.get('addrtype') == 'mac':
                mac_addr = address.get('addr')
                vendor = address.get('vendor', '')

        if not ip_addr:
            return

        # Status dell'host
        status_elem = host_element.find('status')
        status = status_elem.get('state') if status_elem is not None else 'unknown'

        # Inserisci host
        self._insert_host(ip_addr, mac_addr, vendor, status)

        # Parse porte
        self._parse_ports(host_element, ip_addr)

        # Parse script SNMP
        self._parse_snmp_scripts(host_element, ip_addr)

    def _insert_host(self, ip_addr: str, mac_addr: str, vendor: str, status: str):
        """Inserisce o aggiorna un host nel database"""
        self.cursor.execute('''
            INSERT OR REPLACE INTO hosts 
            (ip_address, mac_address, vendor, status)
            VALUES (?, ?, ?, ?)
        ''', (ip_addr, mac_addr, vendor, status))

    def _parse_ports(self, host_element, ip_addr: str):
        """Parse delle porte dell'host"""
        ports_elem = host_element.find('ports')
        if ports_elem is None:
            return

        for port in ports_elem.findall('port'):
            port_num = int(port.get('portid'))
            protocol = port.get('protocol')

            state_elem = port.find('state')
            state = state_elem.get('state') if state_elem is not None else 'unknown'

            service_elem = port.find('service')
            service_name = service_elem.get('name') if service_elem is not None else ''

            self.cursor.execute('''
                INSERT OR REPLACE INTO ports 
                (ip_address, port_number, protocol, state, service_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_addr, port_num, protocol, state, service_name))

    def _parse_snmp_scripts(self, host_element, ip_addr: str):
        """Parse di tutti gli script SNMP per un host"""
        for script in host_element.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')

            if script_id == 'snmp-sysdescr':
                self._parse_system_description(ip_addr, output)
            elif script_id == 'snmp-win32-users':
                self._parse_users(ip_addr, script)
            elif script_id == 'snmp-win32-services':
                self._parse_services(ip_addr, script)
            elif script_id == 'snmp-win32-software':
                self._parse_software(ip_addr, script)
            elif script_id == 'snmp-processes':
                self._parse_processes(ip_addr, script)
            elif script_id == 'snmp-interfaces':
                self._parse_interfaces(ip_addr, output)
            elif script_id == 'snmp-netstat':
                self._parse_netstat(ip_addr, output)
            elif script_id == 'snmp-win32-shares':
                self._parse_shares(ip_addr, script)
            elif script_id == 'snmp-brute':
                self._parse_credentials(ip_addr, script)

    def _parse_system_description(self, ip_addr: str, output: str):
        """Parse della descrizione del sistema"""
        lines = output.strip().split('\n')

        hardware_info = ""
        software_info = ""
        os_build = ""
        uptime = ""

        for line in lines:
            line = line.strip()
            if line.startswith('Hardware:'):
                hardware_info = line.replace('Hardware:', '').strip()
            elif line.startswith('Software:'):
                software_info = line.replace('Software:', '').strip()
            elif 'Build' in line:
                os_build = line.strip()
            elif 'uptime:' in line:
                uptime = line.strip()

        self.cursor.execute('''
            INSERT OR REPLACE INTO system_info 
            (ip_address, system_description, system_uptime, hardware_info, software_info, os_build)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ip_addr, output.strip(), uptime, hardware_info, software_info, os_build))

    def _parse_users(self, ip_addr: str, script_element):
        """Parse degli utenti Windows"""
        # Prima cancella utenti esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_users WHERE ip_address = ?', (ip_addr,))

        # Parse da elementi <elem>
        for elem in script_element.findall('elem'):
            username = elem.text
            if username:
                self.cursor.execute('''
                    INSERT INTO snmp_users (ip_address, username)
                    VALUES (?, ?)
                ''', (ip_addr, username.strip()))

    def _parse_services(self, ip_addr: str, script_element):
        """Parse dei servizi Windows"""
        # Prima cancella servizi esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_services WHERE ip_address = ?', (ip_addr,))

        # Parse da elementi <elem>
        for elem in script_element.findall('elem'):
            service_name = elem.text
            if service_name:
                self.cursor.execute('''
                    INSERT INTO snmp_services (ip_address, service_name)
                    VALUES (?, ?)
                ''', (ip_addr, service_name.strip()))

    def _parse_software(self, ip_addr: str, script_element):
        """Parse del software installato"""
        # Prima cancella software esistente per questo host
        self.cursor.execute('DELETE FROM snmp_software WHERE ip_address = ?', (ip_addr,))

        # Parse da tabelle strutturate
        for table in script_element.findall('table'):
            software_name = ""
            install_date = ""

            for elem in table.findall('elem'):
                key = elem.get('key', '')
                value = elem.text or ''

                if key == 'name':
                    software_name = value
                elif key == 'install_date':
                    install_date = value

            if software_name:
                self.cursor.execute('''
                    INSERT INTO snmp_software (ip_address, software_name, install_date)
                    VALUES (?, ?, ?)
                ''', (ip_addr, software_name, install_date))

    def _parse_processes(self, ip_addr: str, script_element):
        """Parse dei processi in esecuzione"""
        # Prima cancella processi esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_processes WHERE ip_address = ?', (ip_addr,))

        # Parse da tabelle strutturate
        for table in script_element.findall('table'):
            pid = None
            process_name = ""
            process_path = ""
            process_params = ""

            # Il PID è nella chiave della tabella
            table_key = table.get('key', '')
            if table_key.isdigit():
                pid = int(table_key)

            for elem in table.findall('elem'):
                key = elem.get('key', '')
                value = elem.text or ''

                if key == 'Name':
                    process_name = value
                elif key == 'Path':
                    process_path = value
                elif key == 'Params':
                    process_params = value

            if process_name:
                self.cursor.execute('''
                    INSERT INTO snmp_processes (ip_address, pid, process_name, process_path, process_params)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip_addr, pid, process_name, process_path, process_params))

    def _parse_interfaces(self, ip_addr: str, output: str):
        """Parse delle interfacce di rete"""
        # Prima cancella interfacce esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_interfaces WHERE ip_address = ?', (ip_addr,))

        # Parse del testo delle interfacce
        current_interface = {}

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Nuova interfaccia se la riga non inizia con spazi
            if not line.startswith(' ') and ':' not in line:
                if current_interface.get('name'):
                    self._insert_interface(ip_addr, current_interface)
                current_interface = {'name': line.replace('\x00', '').strip()}
            else:
                # Parse attributi interfaccia
                if 'IP address:' in line:
                    match = re.search(r'IP address:\s*([^\s]+)', line)
                    if match:
                        current_interface['ip'] = match.group(1)
                elif 'Netmask:' in line:
                    match = re.search(r'Netmask:\s*([^\s]+)', line)
                    if match:
                        current_interface['netmask'] = match.group(1)
                elif 'MAC address:' in line:
                    match = re.search(r'MAC address:\s*([^\s]+)', line)
                    if match:
                        current_interface['mac'] = match.group(1)
                elif 'Type:' in line:
                    match = re.search(r'Type:\s*([^\s]+)', line)
                    if match:
                        current_interface['type'] = match.group(1)
                elif 'Speed:' in line:
                    match = re.search(r'Speed:\s*([^\s]+)', line)
                    if match:
                        current_interface['speed'] = match.group(1)
                elif 'Status:' in line:
                    match = re.search(r'Status:\s*([^\s]+)', line)
                    if match:
                        current_interface['status'] = match.group(1)
                elif 'Traffic stats:' in line:
                    match = re.search(r'Traffic stats:\s*([^,]+),\s*(.+)', line)
                    if match:
                        current_interface['sent'] = match.group(1).strip()
                        current_interface['received'] = match.group(2).strip()

        # Inserisci ultima interfaccia
        if current_interface.get('name'):
            self._insert_interface(ip_addr, current_interface)

    def _insert_interface(self, ip_addr: str, interface: dict):
        """Inserisce un'interfaccia nel database"""
        self.cursor.execute('''
            INSERT INTO snmp_interfaces 
            (ip_address, interface_name, interface_ip, netmask, mac_address, 
             interface_type, speed, status, traffic_sent, traffic_received)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip_addr,
            interface.get('name', ''),
            interface.get('ip', ''),
            interface.get('netmask', ''),
            interface.get('mac', ''),
            interface.get('type', ''),
            interface.get('speed', ''),
            interface.get('status', ''),
            interface.get('sent', ''),
            interface.get('received', '')
        ))

    def _parse_netstat(self, ip_addr: str, output: str):
        """Parse delle connessioni di rete"""
        # Prima cancella connessioni esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_netstat WHERE ip_address = ?', (ip_addr,))

        for line in output.split('\n'):
            line = line.strip()
            if not line or not (line.startswith('TCP') or line.startswith('UDP')):
                continue

            parts = line.split()
            if len(parts) >= 3:
                protocol = parts[0]
                local_addr_port = parts[1]
                remote_addr_port = parts[2]

                # Parse indirizzo e porta locale
                local_parts = local_addr_port.rsplit(':', 1)
                local_addr = local_parts[0] if len(local_parts) > 1 else local_addr_port
                local_port = local_parts[1] if len(local_parts) > 1 else ''

                # Parse indirizzo e porta remota
                remote_parts = remote_addr_port.rsplit(':', 1)
                remote_addr = remote_parts[0] if len(remote_parts) > 1 else remote_addr_port
                remote_port = remote_parts[1] if len(remote_parts) > 1 else ''

                state = parts[3] if len(parts) > 3 else ''

                self.cursor.execute('''
                    INSERT INTO snmp_netstat 
                    (ip_address, protocol, local_address, local_port, remote_address, remote_port, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip_addr, protocol, local_addr, local_port, remote_addr, remote_port, state))

    def _parse_shares(self, ip_addr: str, script_element):
        """Parse delle condivisioni di rete"""
        # Prima cancella condivisioni esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_shares WHERE ip_address = ?', (ip_addr,))

        # Parse da elementi con chiave-valore
        for elem in script_element.findall('elem'):
            share_name = elem.get('key', '')
            share_path = elem.text or ''

            if share_name and share_path:
                self.cursor.execute('''
                    INSERT INTO snmp_shares (ip_address, share_name, share_path)
                    VALUES (?, ?, ?)
                ''', (ip_addr, share_name, share_path))

    def _parse_credentials(self, ip_addr: str, script_element):
        """Parse delle credenziali SNMP"""
        # Prima cancella credenziali esistenti per questo host
        self.cursor.execute('DELETE FROM snmp_credentials WHERE ip_address = ?', (ip_addr,))

        # Parse da tabelle
        for table in script_element.findall('table'):
            community = ""
            status = ""

            for elem in table.findall('elem'):
                key = elem.get('key', '')
                value = elem.text or ''

                if key == 'password':
                    community = value
                elif key == 'state':
                    status = value

            if community:
                self.cursor.execute('''
                    INSERT INTO snmp_credentials (ip_address, community_string, status)
                    VALUES (?, ?, ?)
                ''', (ip_addr, community, status))

    def generate_report(self) -> Dict:
        """Genera un report completo dei dati SNMP"""
        report = {}

        # Statistiche generali
        self.cursor.execute('SELECT COUNT(*) FROM hosts')
        report['total_hosts'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"')
        report['active_hosts'] = self.cursor.fetchone()[0]

        # Statistiche SNMP
        self.cursor.execute('SELECT COUNT(*) FROM snmp_users')
        report['total_users'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM snmp_services')
        report['total_services'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM snmp_software')
        report['total_software'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM snmp_processes')
        report['total_processes'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM snmp_interfaces')
        report['total_interfaces'] = self.cursor.fetchone()[0]

        self.cursor.execute('SELECT COUNT(*) FROM snmp_shares')
        report['total_shares'] = self.cursor.fetchone()[0]

        # Host con più informazioni
        self.cursor.execute('''
            SELECT h.ip_address, h.vendor, s.hardware_info, s.software_info
            FROM hosts h
            LEFT JOIN system_info s ON h.ip_address = s.ip_address
            WHERE h.status = "up"
        ''')
        report['host_details'] = self.cursor.fetchall()

        return report

    def export_to_csv(self, output_dir: str = "exports"):
        """Esporta tutti i dati in file CSV"""
        os.makedirs(output_dir, exist_ok=True)

        tables = [
            'hosts', 'system_info', 'snmp_users', 'snmp_services',
            'snmp_software', 'snmp_processes', 'snmp_interfaces',
            'snmp_netstat', 'snmp_shares', 'snmp_credentials', 'ports'
        ]

        for table in tables:
            self.cursor.execute(f'SELECT * FROM {table}')
            rows = self.cursor.fetchall()

            if rows:
                # Ottieni nomi colonne
                self.cursor.execute(f'PRAGMA table_info({table})')
                columns = [row[1] for row in self.cursor.fetchall()]

                # Scrivi CSV
                csv_path = os.path.join(output_dir, f'{table}.csv')
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    writer.writerows(rows)

                logger.info(f"Esportato {len(rows)} record in {csv_path}")

    def close(self):
        """Chiude la connessione al database"""
        if self.conn:
            self.conn.close()
            logger.info("Connessione database chiusa")


def main():
    """Funzione principale"""
    if len(sys.argv) < 2:
        print("Uso: python snmp_parser.py <file_xml>")
        sys.exit(1)

    xml_file = sys.argv[1]
    if not os.path.exists(xml_file):
        print(f"File non trovato: {xml_file}")
        sys.exit(1)

    parser = SNMPXMLParser("snmp_results.db")

    try:
        # Connetti e crea tabelle
        parser.connect_db()
        parser.create_tables()

        # Parse file XML
        success = parser.parse_xml_file(xml_file)

        if success:
            print(f"✓ File {xml_file} processato con successo")

            # Genera report
            report = parser.generate_report()

            print("\n" + "=" * 50)
            print("REPORT SCANSIONE SNMP")
            print("=" * 50)
            print(f"Host totali: {report['total_hosts']}")
            print(f"Host attivi: {report['active_hosts']}")
            print(f"Utenti trovati: {report['total_users']}")
            print(f"Servizi trovati: {report['total_services']}")
            print(f"Software installato: {report['total_software']}")
            print(f"Processi in esecuzione: {report['total_processes']}")
            print(f"Interfacce di rete: {report['total_interfaces']}")
            print(f"Condivisioni di rete: {report['total_shares']}")

            print(f"\nDettagli host:")
            for ip, vendor, hw, sw in report['host_details']:
                print(f"  {ip} ({vendor or 'N/A'})")
                if hw:
                    print(f"    Hardware: {hw[:60]}...")
                if sw:
                    print(f"    Software: {sw[:60]}...")

            # Esporta in CSV
            parser.export_to_csv()
            print(f"\nDati esportati in directory 'exports/'")
            print(f"Database salvato: snmp_results.db")

        else:
            print(f"✗ Errore nel processare {xml_file}")

    except Exception as e:
        logger.error(f"Errore durante l'esecuzione: {e}")
        sys.exit(1)
    finally:
        parser.close()


if __name__ == "__main__":
    main()