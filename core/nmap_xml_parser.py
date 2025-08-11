#!/usr/bin/env python3
"""
Nmap XML Parser con Database SQLite
Analizza i file XML di nmap e crea un database SQLite normalizzato
La tupla ip/address è la chiave primaria per il sistema
"""

import sqlite3
import xml.etree.ElementTree as ET
import os
import sys
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging


# Configurazione per gestire le date in SQLite senza deprecation warning
def adapt_datetime(dt):
    """Converte datetime in stringa ISO per SQLite"""
    return dt.isoformat()


def convert_datetime(s):
    """Converte stringa ISO da SQLite in datetime"""
    return datetime.fromisoformat(s.decode())


# Registra gli adapter per datetime
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)

# Configurazione logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NmapXMLParser:
    def __init__(self, db_path: str = "../data/nmap_scan_results.db"):
        """
        Inizializza il parser con il percorso del database nella directory data
        """
        # Assicurati che la directory data esista
        os.makedirs("../data", exist_ok=True)
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
        """
        Crea tutte le tabelle necessarie per il database normalizzato
        """

        # Tabella principale degli host (chiave: IP address)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                vendor TEXT,
                status TEXT,
                status_reason TEXT,
                hostname TEXT,
                scan_time TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabella delle scansioni
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner TEXT,
                nmap_version TEXT,
                xml_version TEXT,
                command_line TEXT,
                start_time TIMESTAMP,
                start_str TEXT,
                scan_type TEXT,
                protocol TEXT,
                num_services INTEGER,
                services_scanned TEXT,
                file_source TEXT
            )
        ''')

        # Relazione host-scan
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_scans (
                ip_address TEXT,
                scan_id INTEGER,
                PRIMARY KEY (ip_address, scan_id),
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address),
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')

        # Tabella delle porte aperte
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                state TEXT,
                reason TEXT,
                reason_ttl INTEGER,
                service_name TEXT,
                service_product TEXT,
                service_version TEXT,
                service_extra_info TEXT,
                service_method TEXT,
                service_conf INTEGER,
                PRIMARY KEY (ip_address, port_number, protocol),
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella dei servizi
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                ostype TEXT,
                method TEXT,
                confidence INTEGER,
                PRIMARY KEY (ip_address, port_number, protocol),
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella degli script NSE
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS nse_scripts (
                script_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                script_name TEXT,
                script_output TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle vulnerabilità
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                vuln_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                vuln_references TEXT,
                cvss_score REAL,
                cve_id TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella del software installato
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS installed_software (
                software_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                software_name TEXT,
                install_date TIMESTAMP,
                version TEXT,
                publisher TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella dei processi in esecuzione
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS running_processes (
                process_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                process_params TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle informazioni OS
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS os_info (
                ip_address TEXT PRIMARY KEY,
                os_name TEXT,
                os_version TEXT,
                os_family TEXT,
                os_generation TEXT,
                os_type TEXT,
                os_vendor TEXT,
                accuracy INTEGER,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella degli hostname e domini
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hostnames (
                hostname_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                hostname TEXT,
                hostname_type TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle traceroute
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS traceroute (
                trace_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                hop_number INTEGER,
                hop_ip TEXT,
                hop_hostname TEXT,
                rtt REAL,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Indici per performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_ip ON vulnerabilities(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_software_ip ON installed_software(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_processes_ip ON running_processes(ip_address)')

        self.conn.commit()
        logger.info("Tabelle create con successo")

    def parse_xml_file(self, xml_file_path: str) -> bool:
        """
        Parsing di un singolo file XML di nmap
        """
        try:
            logger.info(f"Parsing file: {xml_file_path}")
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Estrai informazioni della scansione
            scan_info = self._extract_scan_info(root, xml_file_path)
            scan_id = self._insert_scan_info(scan_info)

            # Parse degli host
            hosts = root.findall('host')
            for host in hosts:
                self._parse_host(host, scan_id)

            # Parse degli hosthint (host discovery)
            hosthints = root.findall('hosthint')
            for hint in hosthints:
                self._parse_hosthint(hint, scan_id)

            self.conn.commit()
            logger.info(f"File {xml_file_path} processato con successo")
            return True

        except Exception as e:
            logger.error(f"Errore nel parsing di {xml_file_path}: {e}")
            self.conn.rollback()
            return False

    def _extract_scan_info(self, root, file_path: str) -> Dict:
        """Estrae informazioni generali della scansione"""
        scan_info = {
            'scanner': root.get('scanner', 'nmap'),
            'nmap_version': root.get('version', ''),
            'xml_version': root.get('xmloutputversion', ''),
            'command_line': root.get('args', ''),
            'start_time': None,
            'start_str': root.get('startstr', ''),
            'file_source': os.path.basename(file_path)
        }

        # Converti timestamp se presente
        start_timestamp = root.get('start')
        if start_timestamp:
            try:
                scan_info['start_time'] = datetime.fromtimestamp(int(start_timestamp))
            except:
                pass

        # Estrai info scansione
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            scan_info.update({
                'scan_type': scaninfo.get('type', ''),
                'protocol': scaninfo.get('protocol', ''),
                'num_services': int(scaninfo.get('numservices', 0)),
                'services_scanned': scaninfo.get('services', '')
            })

        return scan_info

    def _insert_scan_info(self, scan_info: Dict) -> int:
        """Inserisce le informazioni della scansione e restituisce l'ID"""
        self.cursor.execute('''
            INSERT INTO scans (
                scanner, nmap_version, xml_version, command_line, 
                start_time, start_str, scan_type, protocol, 
                num_services, services_scanned, file_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_info['scanner'], scan_info['nmap_version'],
            scan_info['xml_version'], scan_info['command_line'],
            scan_info['start_time'], scan_info['start_str'],
            scan_info.get('scan_type'), scan_info.get('protocol'),
            scan_info.get('num_services', 0), scan_info.get('services_scanned'),
            scan_info['file_source']
        ))
        return self.cursor.lastrowid

    def _parse_hosthint(self, hint, scan_id: int):
        """Parse degli hosthint (discovery)"""
        # Estrai indirizzi
        ip_addr = None
        mac_addr = None
        vendor = None

        for address in hint.findall('address'):
            addr_type = address.get('addrtype')
            if addr_type == 'ipv4':
                ip_addr = address.get('addr')
            elif addr_type == 'mac':
                mac_addr = address.get('addr')
                vendor = address.get('vendor', '')

        if ip_addr:
            # Estrai status
            status_elem = hint.find('status')
            status = status_elem.get('state') if status_elem is not None else 'unknown'
            reason = status_elem.get('reason') if status_elem is not None else ''

            self._insert_or_update_host(ip_addr, mac_addr, vendor, status, reason, None, scan_id)

    def _parse_host(self, host, scan_id: int):
        """Parse completo di un host"""
        ip_addr = None
        mac_addr = None
        vendor = None
        status = 'unknown'
        reason = ''
        hostname = None

        # Estrai indirizzi
        for address in host.findall('address'):
            addr_type = address.get('addrtype')
            if addr_type == 'ipv4':
                ip_addr = address.get('addr')
            elif addr_type == 'mac':
                mac_addr = address.get('addr')
                vendor = address.get('vendor', '')

        if not ip_addr:
            return  # Skip se non c'è IP

        # Status
        status_elem = host.find('status')
        if status_elem is not None:
            status = status_elem.get('state', 'unknown')
            reason = status_elem.get('reason', '')

        # Hostname
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')

        # Inserisci/aggiorna host
        self._insert_or_update_host(ip_addr, mac_addr, vendor, status, reason, hostname, scan_id)

        # Parse porte
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                self._parse_port(ip_addr, port)

        # Parse script host-level
        hostscript = host.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                self._parse_nse_script(ip_addr, None, None, script)

        # Parse OS detection
        os_elem = host.find('os')
        if os_elem is not None:
            self._parse_os_info(ip_addr, os_elem)

        # Parse tutti gli hostname
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall('hostname'):
                self._parse_hostname(ip_addr, hn)

    def _insert_or_update_host(self, ip_addr: str, mac_addr: str, vendor: str,
                               status: str, reason: str, hostname: str, scan_id: int):
        """Inserisce o aggiorna un host"""
        # Verifica se esiste
        self.cursor.execute('SELECT ip_address FROM hosts WHERE ip_address = ?', (ip_addr,))
        exists = self.cursor.fetchone()

        if exists:
            # Aggiorna
            self.cursor.execute('''
                UPDATE hosts SET 
                    mac_address = COALESCE(?, mac_address),
                    vendor = COALESCE(?, vendor),
                    status = ?,
                    status_reason = ?,
                    hostname = COALESCE(?, hostname),
                    last_updated = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (mac_addr, vendor, status, reason, hostname, ip_addr))
        else:
            # Inserisci nuovo
            self.cursor.execute('''
                INSERT INTO hosts (
                    ip_address, mac_address, vendor, status, 
                    status_reason, hostname, scan_time
                ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip_addr, mac_addr, vendor, status, reason, hostname))

        # Inserisci relazione host-scan
        self.cursor.execute('''
            INSERT OR IGNORE INTO host_scans (ip_address, scan_id) 
            VALUES (?, ?)
        ''', (ip_addr, scan_id))

    def _parse_port(self, ip_addr: str, port_elem):
        """Parse di una porta"""
        port_num = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol', 'tcp')

        # State
        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'
        reason = state_elem.get('reason') if state_elem is not None else ''
        reason_ttl = state_elem.get('reason_ttl') if state_elem is not None else None

        if reason_ttl:
            try:
                reason_ttl = int(reason_ttl)
            except:
                reason_ttl = None

        # Service info
        service_elem = port_elem.find('service')
        service_name = service_elem.get('name') if service_elem is not None else ''
        service_product = service_elem.get('product') if service_elem is not None else ''
        service_version = service_elem.get('version') if service_elem is not None else ''
        service_extra = service_elem.get('extrainfo') if service_elem is not None else ''
        service_method = service_elem.get('method') if service_elem is not None else ''
        service_conf = service_elem.get('conf') if service_elem is not None else None

        if service_conf:
            try:
                service_conf = int(service_conf)
            except:
                service_conf = None

        # Inserisci porta
        self.cursor.execute('''
            INSERT OR REPLACE INTO ports (
                ip_address, port_number, protocol, state, reason, reason_ttl,
                service_name, service_product, service_version, service_extra_info,
                service_method, service_conf
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip_addr, port_num, protocol, state, reason, reason_ttl,
              service_name, service_product, service_version, service_extra,
              service_method, service_conf))

        # Inserisci servizio se presente
        if service_elem is not None:
            self._parse_service(ip_addr, port_num, protocol, service_elem)

        # Parse script della porta
        for script in port_elem.findall('script'):
            self._parse_nse_script(ip_addr, port_num, protocol, script)

    def _parse_service(self, ip_addr: str, port_num: int, protocol: str, service_elem):
        """Parse informazioni servizio"""
        name = service_elem.get('name', '')
        product = service_elem.get('product', '')
        version = service_elem.get('version', '')
        extra_info = service_elem.get('extrainfo', '')
        ostype = service_elem.get('ostype', '')
        method = service_elem.get('method', '')
        confidence = service_elem.get('conf')

        if confidence:
            try:
                confidence = int(confidence)
            except:
                confidence = None

        self.cursor.execute('''
            INSERT OR REPLACE INTO services (
                ip_address, port_number, protocol, service_name, product,
                version, extra_info, ostype, method, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip_addr, port_num, protocol, name, product, version,
              extra_info, ostype, method, confidence))

    def _parse_nse_script(self, ip_addr: str, port_num: Optional[int],
                          protocol: Optional[str], script_elem):
        """Parse script NSE"""
        script_name = script_elem.get('id', '')
        script_output = script_elem.get('output', '')

        # Parse anche il contenuto degli elementi
        if script_elem.text:
            script_output += '\n' + script_elem.text

        self.cursor.execute('''
            INSERT INTO nse_scripts (
                ip_address, port_number, protocol, script_name, script_output
            ) VALUES (?, ?, ?, ?, ?)
        ''', (ip_addr, port_num, protocol, script_name, script_output))

        # Analizza se è una vulnerabilità
        if any(vuln_keyword in script_name.lower() for vuln_keyword in
               ['vuln', 'cve', 'exploit', 'security']):
            self._parse_vulnerability(ip_addr, port_num, protocol, script_elem)

    def _parse_vulnerability(self, ip_addr: str, port_num: Optional[int],
                             protocol: Optional[str], script_elem):
        """Parse vulnerabilità da script NSE"""
        script_name = script_elem.get('id', '')
        output = script_elem.get('output', '')

        # Estrai CVE se presente
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, output)
        cve_id = ', '.join(cve_matches) if cve_matches else None

        # Determina severità (euristica basica)
        severity = 'medium'
        if any(term in output.lower() for term in ['critical', 'high']):
            severity = 'high'
        elif any(term in output.lower() for term in ['low', 'info']):
            severity = 'low'

        self.cursor.execute('''
            INSERT INTO vulnerabilities (
                ip_address, port_number, protocol, vuln_type, severity,
                title, description, cve_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip_addr, port_num, protocol, script_name, severity,
              script_name, output, cve_id))

    def _parse_os_info(self, ip_addr: str, os_elem):
        """Parse informazioni sistema operativo"""
        # Prendi la prima OS class con accuracy più alta
        best_osmatch = None
        best_accuracy = 0

        for osmatch in os_elem.findall('osmatch'):
            accuracy = int(osmatch.get('accuracy', 0))
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_osmatch = osmatch

        if best_osmatch is not None:
            os_name = best_osmatch.get('name', '')

            # Prendi la prima osclass
            osclass = best_osmatch.find('osclass')
            if osclass is not None:
                os_family = osclass.get('osfamily', '')
                os_generation = osclass.get('osgen', '')
                os_type = osclass.get('type', '')
                os_vendor = osclass.get('vendor', '')
                accuracy = int(osclass.get('accuracy', 0))

                self.cursor.execute('''
                    INSERT OR REPLACE INTO os_info (
                        ip_address, os_name, os_family, os_generation,
                        os_type, os_vendor, accuracy
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip_addr, os_name, os_family, os_generation,
                      os_type, os_vendor, accuracy))

    def _parse_hostname(self, ip_addr: str, hostname_elem):
        """Parse hostname"""
        hostname = hostname_elem.get('name', '')
        hostname_type = hostname_elem.get('type', '')

        if hostname:
            self.cursor.execute('''
                INSERT INTO hostnames (ip_address, hostname, hostname_type)
                VALUES (?, ?, ?)
            ''', (ip_addr, hostname, hostname_type))

    def parse_software_and_processes(self, xml_file_path: str):
        """
        Parse specifico per software installato e processi
        (se presenti negli script NSE)
        """
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            for host in root.findall('host'):
                ip_addr = None
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        ip_addr = address.get('addr')
                        break

                if not ip_addr:
                    continue

                # Cerca script che contengono info su software/processi
                for script in host.findall('.//script'):
                    script_name = script.get('id', '')
                    output = script.get('output', '')

                    # Parse software installato
                    if 'installed' in script_name.lower() or 'software' in script_name.lower():
                        self._parse_installed_software_from_output(ip_addr, output)

                    # Parse processi
                    if 'process' in script_name.lower() or 'ps' in script_name.lower():
                        self._parse_processes_from_output(ip_addr, output)

            self.conn.commit()

        except Exception as e:
            logger.error(f"Errore nel parsing software/processi da {xml_file_path}: {e}")

    def _parse_installed_software_from_output(self, ip_addr: str, output: str):
        """Parse del software installato dall'output degli script"""
        # Pattern per software con data installazione
        software_pattern = r'([^;]+);\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        matches = re.findall(software_pattern, output)

        for software_name, install_date_str in matches:
            try:
                install_date = datetime.fromisoformat(install_date_str)
                self.cursor.execute('''
                    INSERT OR IGNORE INTO installed_software (
                        ip_address, software_name, install_date
                    ) VALUES (?, ?, ?)
                ''', (ip_addr, software_name.strip(), install_date))
            except:
                continue

    def _parse_processes_from_output(self, ip_addr: str, output: str):
        """Parse dei processi dall'output degli script"""
        # Pattern per processi (esempio: PID: nome processo)
        process_pattern = r'(\d+):\s*([^\\]+)\\([^\\]+)\s*(.*)'
        matches = re.findall(process_pattern, output, re.MULTILINE)

        for pid_str, path, name, params in matches:
            try:
                pid = int(pid_str)
                self.cursor.execute('''
                    INSERT OR IGNORE INTO running_processes (
                        ip_address, pid, process_name, process_path, process_params
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (ip_addr, pid, name.strip(), path.strip(), params.strip()))
            except:
                continue

    def process_all_xml_files(self, directory_path: str = "../"):
        """
        Processa tutti i file XML nella directory root del progetto
        """
        xml_files = [f for f in os.listdir(directory_path) if f.endswith('.xml')]

        if not xml_files:
            logger.warning(f"Nessun file XML trovato in {directory_path}")
            return

        logger.info(f"Trovati {len(xml_files)} file XML da processare")

        for xml_file in xml_files:
            file_path = os.path.join(directory_path, xml_file)
            success = self.parse_xml_file(file_path)

            if success:
                # Processa anche software e processi se presenti
                self.parse_software_and_processes(file_path)
            else:
                logger.error(f"Errore nel processare {xml_file}")

    def generate_summary_report(self) -> Dict:
        """
        Genera un report riassuntivo dei dati nel database
        """
        report = {}

        # Conteggio host
        self.cursor.execute('SELECT COUNT(*) FROM hosts')
        report['total_hosts'] = self.cursor.fetchone()[0]

        # Host attivi
        self.cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'")
        report['active_hosts'] = self.cursor.fetchone()[0]

        # Totale porte aperte
        self.cursor.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'")
        report['open_ports'] = self.cursor.fetchone()[0]

        # Vulnerabilità trovate
        self.cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        report['vulnerabilities'] = self.cursor.fetchone()[0]

        # Software installato
        self.cursor.execute('SELECT COUNT(*) FROM installed_software')
        report['installed_software'] = self.cursor.fetchone()[0]

        # Processi in esecuzione
        self.cursor.execute('SELECT COUNT(*) FROM running_processes')
        report['running_processes'] = self.cursor.fetchone()[0]

        # Top 5 porte più comuni
        self.cursor.execute('''
            SELECT port_number, COUNT(*) as count 
            FROM ports WHERE state = 'open' 
            GROUP BY port_number 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        report['top_ports'] = self.cursor.fetchall()

        # Vendor di rete
        self.cursor.execute('''
            SELECT vendor, COUNT(*) as count 
            FROM hosts WHERE vendor IS NOT NULL 
            GROUP BY vendor 
            ORDER BY count DESC
        ''')
        report['vendors'] = self.cursor.fetchall()

        return report

    def close(self):
        """Chiude la connessione al database"""
        if self.conn:
            self.conn.close()
            logger.info("Connessione database chiusa")


def main():
    """Funzione principale"""
    parser = NmapXMLParser("../data/nmap_network_scan.db")

    try:
        # Connetti e crea tabelle
        parser.connect_db()
        parser.create_tables()

        # Processa tutti i file XML nella directory root del progetto
        parser.process_all_xml_files("../xml")

        # Genera report
        report = parser.generate_summary_report()

        print("\n" + "=" * 50)
        print("REPORT RIASSUNTIVO SCANSIONE RETE")
        print("=" * 50)
        print(f"Host totali trovati: {report['total_hosts']}")
        print(f"Host attivi: {report['active_hosts']}")
        print(f"Porte aperte totali: {report['open_ports']}")
        print(f"Vulnerabilità trovate: {report['vulnerabilities']}")
        print(f"Software installato: {report['installed_software']}")
        print(f"Processi in esecuzione: {report['running_processes']}")

        if report['top_ports']:
            print(f"\nTop 5 porte più comuni:")
            for port, count in report['top_ports']:
                print(f"  Porta {port}: {count} host")

        if report['vendors']:
            print(f"\nVendor schede di rete:")
            for vendor, count in report['vendors']:
                print(f"  {vendor}: {count} dispositivi")

        print(f"\nDatabase creato: ../data/nmap_network_scan.db")
        print("=" * 50)

    except Exception as e:
        logger.error(f"Errore durante l'esecuzione: {e}")
        sys.exit(1)
    finally:
        parser.close()


if __name__ == "__main__":
    main()