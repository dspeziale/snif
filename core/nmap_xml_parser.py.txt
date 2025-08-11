#!/usr/bin/env python3
"""
Nmap XML Parser con Database SQLite - Versione con Debug NBT-STAT e Fix Software/Processi
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
        """Connette al database SQLite con gestione datetime"""
        try:
            self.conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
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

        # Tabella delle vulnerabilità (rinominato references in vuln_references)
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
                scan_info['start_time'] = datetime.fromtimestamp(int(start_timestamp)).isoformat()
            except:
                scan_info['start_time'] = None

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
        """Parse degli hosthint (discovery) - solo se il device esiste"""
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

            # FILTRO: Inserisci solo se il dispositivo è effettivamente up/attivo
            if status.lower() in ['up', 'open', 'filtered']:
                logger.debug(f"Aggiunto host hint {ip_addr} con status {status}")
                self._insert_or_update_host(ip_addr, mac_addr, vendor, status, reason, None, scan_id)
            else:
                logger.debug(f"Ignorato host hint {ip_addr} con status {status} (dispositivo non esistente)")

    def _parse_host(self, host, scan_id: int):
        """Parse completo di un host - solo se effettivamente esistente"""
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

        # FILTRO PRINCIPALE: Inserisci solo host che esistono realmente
        if status.lower() not in ['up', 'open']:
            logger.debug(f"Ignorato host {ip_addr} con status '{status}' - dispositivo non esistente")
            return

        # Verifica aggiuntiva: se non ha porte aperte e non risponde, probabilmente non esiste
        ports_elem = host.find('ports')
        has_open_ports = False
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                state_elem = port.find('state')
                if state_elem is not None and state_elem.get('state') in ['open', 'filtered']:
                    has_open_ports = True
                    break

        # Se status è "up" ma non ha porte aperte né MAC address, potrebbe essere falso positivo
        if status.lower() == 'up' and not has_open_ports and not mac_addr:
            # Verifica se ha almeno un hostname o altre info che confermano l'esistenza
            hostnames_elem = host.find('hostnames')
            has_hostname = hostnames_elem is not None and len(hostnames_elem.findall('hostname')) > 0

            if not has_hostname:
                logger.debug(f"Ignorato host {ip_addr} - probabile falso positivo (no porte, no MAC, no hostname)")
                return

        logger.info(f"Processando host esistente: {ip_addr} (status: {status})")

        # Hostname
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')

        # Inserisci/aggiorna host
        self._insert_or_update_host(ip_addr, mac_addr, vendor, status, reason, hostname, scan_id)

        # Parse porte (solo quelle aperte/filtrate)
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
        self.cursor.execute('SELECT ip_address, hostname FROM hosts WHERE ip_address = ?', (ip_addr,))
        result = self.cursor.fetchone()

        if result:
            # Aggiorna - gestisce hostname concatenato
            existing_hostname = result[1] if result[1] else ""
            combined_hostname = existing_hostname

            if hostname and hostname.strip():
                if existing_hostname:
                    # Verifica se hostname già presente
                    hostname_list = existing_hostname.split('|')
                    hostname_list = [h.strip() for h in hostname_list if h.strip()]
                    if hostname not in hostname_list:
                        hostname_list.append(hostname)
                        combined_hostname = '|'.join(hostname_list)
                else:
                    combined_hostname = hostname

            self.cursor.execute('''
                UPDATE hosts SET 
                    mac_address = COALESCE(?, mac_address),
                    vendor = COALESCE(?, vendor),
                    status = ?,
                    status_reason = ?,
                    hostname = ?,
                    last_updated = ?
                WHERE ip_address = ?
            ''', (mac_addr, vendor, status, reason, combined_hostname, datetime.now().isoformat(), ip_addr))
        else:
            # Inserisci nuovo
            self.cursor.execute('''
                INSERT INTO hosts (
                    ip_address, mac_address, vendor, status, 
                    status_reason, hostname, scan_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (ip_addr, mac_addr, vendor, status, reason, hostname, datetime.now().isoformat()))

        # Inserisci relazione host-scan
        self.cursor.execute('''
            INSERT OR IGNORE INTO host_scans (ip_address, scan_id) 
            VALUES (?, ?)
        ''', (ip_addr, scan_id))

    def _parse_port(self, ip_addr: str, port_elem):
        """Parse di una porta - solo se aperta o filtrata"""
        port_num = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol', 'tcp')

        # State
        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'
        reason = state_elem.get('reason') if state_elem is not None else ''
        reason_ttl = state_elem.get('reason_ttl') if state_elem is not None else None

        # FILTRO: Inserisci solo porte aperte, filtrate o con servizi identificati
        if state.lower() not in ['open', 'filtered', 'open|filtered']:
            logger.debug(f"Ignorata porta {port_num}/{protocol} su {ip_addr} - stato: {state}")
            return

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

        logger.debug(f"Aggiunta porta {port_num}/{protocol} su {ip_addr} - stato: {state}")

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
        """Parse script NSE e estrae hostname quando possibile"""
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

        # Estrai hostname da varie fonti (solo se abbiamo output valido)
        if script_output and len(script_output.strip()) > 5:
            hostname = self._extract_hostname_from_script(script_name, script_output)
            if hostname:
                self._update_host_hostname(ip_addr, hostname, f"nse_{script_name}")

            # DEBUG: Se è nbt-stat, stampa il primo campo trovato
            if script_name == 'nbstat' and script_output:
                self._debug_nbt_stat_first_field(ip_addr, script_output)

        # Analizza se è una vulnerabilità
        if any(vuln_keyword in script_name.lower() for vuln_keyword in
               ['vuln', 'cve', 'exploit', 'security']):
            self._parse_vulnerability(ip_addr, port_num, protocol, script_elem)

    def _debug_nbt_stat_first_field(self, ip_addr: str, output: str):
        """DEBUG: Stampa il campo NetBIOS_Computer_Name trovato in nbt-stat"""
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                # Cerca specificamente la riga con NetBIOS_Computer_Name
                if 'NetBIOS_Computer_Name' in line or 'NETBIOS_COMPUTER_NAME' in line:
                    # Estrai il valore del computer name
                    # Pattern tipico: "NetBIOS_Computer_Name: HOSTNAME" oppure "HOSTNAME<00>  UNIQUE  NetBIOS_Computer_Name"
                    if ':' in line:
                        # Formato: NetBIOS_Computer_Name: HOSTNAME
                        computer_name = line.split(':', 1)[1].strip()
                    else:
                        # Formato: HOSTNAME<00>  UNIQUE  NetBIOS_Computer_Name
                        computer_name_match = re.match(r'^([^\s<]+)', line)
                        if computer_name_match:
                            computer_name = computer_name_match.group(1).strip()
                        else:
                            computer_name = "NON_TROVATO"

                    if computer_name and len(computer_name) > 1:
                        print(f"DEBUG nbt-stat {ip_addr}: NetBIOS_Computer_Name = '{computer_name}'")
                        return

            # Se non trova NetBIOS_Computer_Name, cerca il primo campo valido come fallback
            for line in lines:
                line = line.strip()
                if line and not line.startswith('NetBIOS') and '<' in line and '00>' in line:
                    first_field_match = re.match(r'^([^\s<]+)', line)
                    if first_field_match:
                        first_field = first_field_match.group(1).strip()
                        if first_field and len(first_field) > 1:
                            print(f"DEBUG nbt-stat {ip_addr}: Primo campo (fallback) = '{first_field}'")
                            return

        except Exception as e:
            logger.warning(f"Errore debug nbt-stat per {ip_addr}: {e}")

    def _extract_hostname_from_script(self, script_name: str, output: str) -> Optional[str]:
        """Estrae hostname da vari script NSE"""
        hostname = None
        script_name_lower = script_name.lower()

        try:
            # NetBIOS hostname discovery
            if 'nbstat' in script_name_lower or 'netbios' in script_name_lower:
                hostname = self._extract_netbios_hostname(output)

            # SNMP hostname discovery
            elif 'snmp' in script_name_lower:
                hostname = self._extract_snmp_hostname(output)

            # SMB hostname discovery
            elif 'smb' in script_name_lower:
                hostname = self._extract_smb_hostname(output)

            # DNS reverse lookup
            elif 'dns' in script_name_lower or 'reverse' in script_name_lower:
                hostname = self._extract_dns_hostname(output)

            # HTTP server hostname
            elif 'http' in script_name_lower:
                hostname = self._extract_http_hostname(output)

            # SSH hostname
            elif 'ssh' in script_name_lower:
                hostname = self._extract_ssh_hostname(output)

            # DHCP hostname
            elif 'dhcp' in script_name_lower:
                hostname = self._extract_dhcp_hostname(output)

            # Generic hostname patterns
            else:
                hostname = self._extract_generic_hostname(output)

        except Exception as e:
            logger.warning(f"Errore estrazione hostname da {script_name}: {e}")

        if hostname:
            # Pulisci e valida hostname
            hostname = self._clean_hostname(hostname)
            if self._is_valid_hostname(hostname):
                logger.info(f"Hostname estratto da {script_name}: {hostname}")
                return hostname

        return None

    def _extract_netbios_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output NetBIOS - cerca specificamente NetBIOS_Computer_Name"""

        # PRIORITÀ 1: Cerca specificamente NetBIOS_Computer_Name
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if 'NetBIOS_Computer_Name' in line or 'NETBIOS_COMPUTER_NAME' in line:
                # Estrai il valore del computer name
                if ':' in line:
                    # Formato: NetBIOS_Computer_Name: HOSTNAME
                    computer_name = line.split(':', 1)[1].strip()
                    if computer_name and len(computer_name) > 1:
                        return computer_name
                else:
                    # Formato: HOSTNAME<00>  UNIQUE  NetBIOS_Computer_Name
                    computer_name_match = re.match(r'^([^\s<]+)', line)
                    if computer_name_match:
                        computer_name = computer_name_match.group(1).strip()
                        if computer_name and len(computer_name) > 1:
                            return computer_name

        # PRIORITÀ 2: Pattern alternativi se NetBIOS_Computer_Name non trovato
        patterns = [
            r'Computer name:\s*([^\r\n]+)',
            r'NetBIOS name:\s*([^\r\n]+)',
            r'Workstation\s+([^\s]+)',
            r'<00>\s+([^\s]+)\s+<UNIQUE>',
            r'^\s*([A-Za-z0-9_-]+)\s+<00>\s+UNIQUE',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _extract_snmp_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output SNMP"""
        patterns = [
            r'sysName:\s*([^\r\n]+)',
            r'System name:\s*([^\r\n]+)',
            r'1\.3\.6\.1\.2\.1\.1\.5\.0\s*=\s*STRING:\s*([^\r\n]+)',
            r'hostname:\s*([^\r\n]+)',
            r'Name:\s*([^\r\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                # Rimuovi quotes SNMP se presenti
                hostname = hostname.strip('"\'')
                return hostname
        return None

    def _extract_smb_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output SMB"""
        patterns = [
            r'Computer name:\s*([^\r\n]+)',
            r'NetBIOS computer name:\s*([^\r\n]+)',
            r'Server:\s*([^\r\n]+)',
            r'Workgroup:\s*([^\r\n]+)\\([^\r\n]+)',
            r'Domain name:\s*([^\r\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                if len(match.groups()) > 1:
                    return match.group(2).strip()  # Per pattern con gruppi multipli
                return match.group(1).strip()
        return None

    def _extract_dns_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output DNS"""
        patterns = [
            r'PTR record:\s*([^\r\n]+)',
            r'Reverse DNS:\s*([^\r\n]+)',
            r'hostname:\s*([^\r\n]+)',
            r'FQDN:\s*([^\r\n]+)',
            r'([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                # Rimuovi il punto finale se presente
                return hostname.rstrip('.')
        return None

    def _extract_http_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output HTTP"""
        patterns = [
            r'Server:\s*([^\r\n]+)',
            r'Host:\s*([^\r\n]+)',
            r'Location:\s*https?://([^/\r\n]+)',
            r'X-Forwarded-Host:\s*([^\r\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                # Rimuovi porta se presente
                if ':' in hostname:
                    hostname = hostname.split(':')[0]
                return hostname
        return None

    def _extract_ssh_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output SSH"""
        patterns = [
            r'Banner:\s*SSH-[^@]*@([^\r\n\s]+)',
            r'Remote protocol version.*@([^\r\n\s]+)',
            r'SSH server:\s*([^\r\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _extract_dhcp_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname da output DHCP"""
        patterns = [
            r'Hostname:\s*([^\r\n]+)',
            r'Client hostname:\s*([^\r\n]+)',
            r'Option 12:\s*([^\r\n]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _extract_generic_hostname(self, output: str) -> Optional[str]:
        """Estrae hostname con pattern generici"""
        patterns = [
            r'hostname[:\s]+([^\r\n\s]+)',
            r'computer[:\s]+([^\r\n\s]+)',
            r'machine[:\s]+([^\r\n\s]+)',
            r'device[:\s]+([^\r\n\s]+)',
            r'name[:\s]+([a-zA-Z0-9._-]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                # Valida che sembri un hostname valido
                if self._is_valid_hostname(hostname):
                    return hostname
        return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Valida se la stringa è un hostname plausibile"""
        if not hostname or len(hostname) < 2 or len(hostname) > 253:
            return False

        # Escludi IP addresses
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            return False

        # Escludi stringhe troppo generiche
        generic_terms = ['unknown', 'localhost', 'default', 'none', 'null', 'n/a']
        if hostname.lower() in generic_terms:
            return False

        # Valida caratteri hostname (carattere - non all'inizio della classe)
        if re.match(r'^[a-zA-Z0-9._-]+$', hostname):
            return True

        return False

    def _clean_hostname(self, hostname: str) -> str:
        """Pulisce e normalizza hostname"""
        if not hostname:
            return hostname

        # Rimuovi spazi e caratteri speciali (mantieni solo caratteri validi)
        hostname = hostname.strip()
        hostname = re.sub(r'[^a-zA-Z0-9._-|]', '', hostname)

        # Rimuovi punti multipli
        hostname = re.sub(r'\.+', '.', hostname)

        # Rimuovi punto iniziale e finale
        hostname = hostname.strip('.')

        # Converti in lowercase per consistenza
        hostname = hostname.lower()

        return hostname

    def _update_host_hostname(self, ip_addr: str, hostname: str, source: str):
        """Aggiorna hostname nella tabella hosts concatenando tutti gli hostname trovati"""
        if not hostname or not self._is_valid_hostname(hostname):
            return

        # Verifica hostname esistente
        self.cursor.execute('SELECT hostname FROM hosts WHERE ip_address = ?', (ip_addr,))
        result = self.cursor.fetchone()

        combined_hostname = hostname

        if result and result[0]:
            existing_hostnames = result[0]
            # Verifica se questo hostname è già presente
            hostname_list = existing_hostnames.split('|')
            hostname_list = [h.strip() for h in hostname_list if h.strip()]

            if hostname not in hostname_list:
                # Aggiungi il nuovo hostname alla lista
                hostname_list.append(hostname)
                combined_hostname = '|'.join(hostname_list)
                logger.info(f"Hostname aggiunto per {ip_addr}: '{hostname}' (fonte: {source})")
            else:
                logger.debug(f"Hostname '{hostname}' già presente per {ip_addr}")
                # Inserisci comunque nella tabella hostnames per tracking della fonte
                self.cursor.execute('''
                    INSERT INTO hostnames (ip_address, hostname, hostname_type)
                    VALUES (?, ?, ?)
                ''', (ip_addr, hostname, source))
                return
        else:
            logger.info(f"Primo hostname per {ip_addr}: '{hostname}' (fonte: {source})")

        # Aggiorna hostname combinato
        self.cursor.execute('''
            UPDATE hosts SET 
                hostname = ?,
                last_updated = ?
            WHERE ip_address = ?
        ''', (combined_hostname, datetime.now().isoformat(), ip_addr))

        # Inserisci anche nella tabella hostnames per tracking
        self.cursor.execute('''
            INSERT INTO hostnames (ip_address, hostname, hostname_type)
            VALUES (?, ?, ?)
        ''', (ip_addr, hostname, source))

    def _parse_hostname(self, ip_addr: str, hostname_elem):
        """Parse hostname da elementi XML"""
        hostname = hostname_elem.get('name', '')
        hostname_type = hostname_elem.get('type', '')

        if hostname:
            # Aggiorna anche la tabella hosts se è un hostname migliore
            self._update_host_hostname(ip_addr, hostname, f"xml_{hostname_type}")

            self.cursor.execute('''
                INSERT INTO hostnames (ip_address, hostname, hostname_type)
                VALUES (?, ?, ?)
            ''', (ip_addr, hostname, hostname_type))

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

    def parse_software_and_processes(self, xml_file_path: str):
        """Parse specifico per software installato e processi - VERSIONE CORRETTA"""
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

                    # CORREZIONE 1: Nomi script corretti per software
                    if any(software_script in script_name.lower() for software_script in
                           ['smb-enum-software', 'wmi-software', 'snmp-software',
                            'enum-software', 'installed-software']):
                        logger.info(f"Trovato script software: {script_name} per {ip_addr}")
                        self._parse_installed_software_from_script_element(ip_addr, script)

                    # CORREZIONE 2: Nomi script corretti per processi
                    if any(process_script in script_name.lower() for process_script in
                           ['smb-enum-processes', 'wmi-processes', 'snmp-processes',
                            'enum-processes', 'ps-enum', 'process-enum']):
                        logger.info(f"Trovato script processi: {script_name} per {ip_addr}")
                        self._parse_processes_from_script_element(ip_addr, script)

            self.conn.commit()

        except Exception as e:
            logger.error(f"Errore nel parsing software/processi da {xml_file_path}: {e}")

    def _parse_installed_software_from_script_element(self, ip_addr: str, script_element):
        """Parse del software installato dall'elemento script XML - VERSIONE CORRETTA"""
        try:
            # CORREZIONE 3: Parse delle tabelle XML invece del testo
            tables = script_element.findall('table')

            for table in tables:
                software_name = None
                install_date = None
                version = None
                publisher = None

                # Estrai dati dalla tabella
                for elem in table.findall('elem'):
                    key = elem.get('key', '')
                    value = elem.text if elem.text else ''

                    if key == 'name':
                        software_name = value.strip()
                    elif key == 'install_date':
                        install_date = value.strip()
                    elif key == 'version':
                        version = value.strip()
                    elif key == 'publisher':
                        publisher = value.strip()

                # Inserisci solo se abbiamo almeno il nome
                if software_name:
                    # Converti data se presente
                    install_date_formatted = None
                    if install_date:
                        try:
                            # La data è già in formato ISO
                            install_date_formatted = install_date
                        except Exception as e:
                            logger.warning(f"Errore parsing data installazione {install_date}: {e}")

                    logger.info(f"Aggiunto software: {software_name} per {ip_addr}")
                    self.cursor.execute('''
                        INSERT OR IGNORE INTO installed_software (
                            ip_address, software_name, install_date, version, publisher
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (ip_addr, software_name, install_date_formatted, version, publisher))

            # FALLBACK: Se non ci sono tabelle, prova parsing testuale
            if not tables:
                self._parse_installed_software_from_output_fallback(ip_addr, script_element.get('output', ''))

        except Exception as e:
            logger.error(f"Errore parsing software da script element per {ip_addr}: {e}")

    def _parse_installed_software_from_output_fallback(self, ip_addr: str, output: str):
        """Fallback per parsing testuale del software - pattern migliorati"""
        if not output:
            return

        try:
            # Pattern più flessibili per software
            patterns = [
                # Formato: nome; data
                r'([^;\n]+);\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
                # Formato: nome | versione | data
                r'([^|\n]+)\|\s*([^|\n]*)\|\s*(\d{4}-\d{2}-\d{2})',
                # Formato linea semplice con data
                r'^([^0-9\n]+)\s+(\d{4}-\d{2}-\d{2})',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, output, re.MULTILINE)
                for match in matches:
                    if len(match) >= 2:
                        software_name = match[0].strip()
                        install_date_str = match[-1].strip()  # Ultimo elemento è sempre la data
                        version = match[1].strip() if len(match) > 2 else None

                        if software_name and len(software_name) > 3:  # Filtro nomi troppo corti
                            try:
                                # Prova a parsare la data
                                if 'T' in install_date_str:
                                    install_date = install_date_str  # Già formato ISO
                                else:
                                    install_date = datetime.strptime(install_date_str, '%Y-%m-%d').isoformat()

                                self.cursor.execute('''
                                    INSERT OR IGNORE INTO installed_software (
                                        ip_address, software_name, install_date, version
                                    ) VALUES (?, ?, ?, ?)
                                ''', (ip_addr, software_name, install_date, version))

                            except Exception as e:
                                logger.warning(f"Errore parsing data fallback {install_date_str}: {e}")

        except Exception as e:
            logger.warning(f"Errore nel parsing fallback software per {ip_addr}: {e}")

    def _parse_processes_from_script_element(self, ip_addr: str, script_element):
        """Parse dei processi dall'elemento script XML - VERSIONE CORRETTA"""
        try:
            # Parse dalle tabelle XML
            tables = script_element.findall('table')

            for table in tables:
                process_name = None
                pid = None
                process_path = None
                process_params = None

                # Estrai dati dalla tabella
                for elem in table.findall('elem'):
                    key = elem.get('key', '')
                    value = elem.text if elem.text else ''

                    if key in ['name', 'process_name']:
                        process_name = value.strip()
                    elif key in ['pid', 'process_id']:
                        try:
                            pid = int(value.strip())
                        except:
                            pid = None
                    elif key in ['path', 'process_path', 'exe_path']:
                        process_path = value.strip()
                    elif key in ['params', 'arguments', 'cmdline']:
                        process_params = value.strip()

                # Inserisci se abbiamo almeno nome o PID
                if process_name or pid:
                    logger.info(f"Aggiunto processo: {process_name} (PID: {pid}) per {ip_addr}")
                    self.cursor.execute('''
                        INSERT OR IGNORE INTO running_processes (
                            ip_address, pid, process_name, process_path, process_params
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (ip_addr, pid, process_name, process_path, process_params))

            # FALLBACK: Se non ci sono tabelle, prova parsing testuale
            if not tables:
                self._parse_processes_from_output_fallback(ip_addr, script_element.get('output', ''))

        except Exception as e:
            logger.error(f"Errore parsing processi da script element per {ip_addr}: {e}")

    def _parse_processes_from_output_fallback(self, ip_addr: str, output: str):
        """Fallback per parsing testuale dei processi - pattern migliorati"""
        if not output:
            return

        try:
            # Pattern più flessibili per processi
            patterns = [
                # Formato Windows: PID: percorso\nome parametri
                r'(\d+):\s*([^\\]+)\\([^\\]+)\s*(.*)',
                # Formato Linux: PID nome percorso
                r'^\s*(\d+)\s+([^\s]+)\s+([^\n]+)',
                # Formato semplice: nome (PID)
                r'([^\(\n]+)\s*\((\d+)\)',
                # Lista processi con percorsi
                r'([A-Za-z0-9_.-]+\.exe)\s+(\d+)',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        if len(match) >= 2:
                            # Determina formato match
                            if pattern.endswith(r'\.exe)\s+(\d+)'):  # Formato exe + PID
                                process_name = match[0]
                                pid = int(match[1])
                                process_path = None
                                process_params = None
                            elif pattern.startswith(r'([^\(\n]+)'):  # Formato nome (PID)
                                process_name = match[0].strip()
                                pid = int(match[1])
                                process_path = None
                                process_params = None
                            else:  # Formato complesso con percorso
                                pid = int(match[0])
                                if len(match) >= 3:
                                    process_path = match[1]
                                    process_name = match[2]
                                    process_params = match[3] if len(match) > 3 else None
                                else:
                                    process_name = match[1]
                                    process_path = None
                                    process_params = None

                            if process_name and len(process_name) > 1:
                                self.cursor.execute('''
                                    INSERT OR IGNORE INTO running_processes (
                                        ip_address, pid, process_name, process_path, process_params
                                    ) VALUES (?, ?, ?, ?, ?)
                                ''', (ip_addr, pid, process_name, process_path, process_params))

                    except Exception as e:
                        logger.warning(f"Errore parsing processo {match}: {e}")
                        continue

        except Exception as e:
            logger.warning(f"Errore nel parsing fallback processi per {ip_addr}: {e}")

    def debug_available_scripts(self, xml_file_path: str):
        """Funzione di debug per vedere tutti gli script disponibili"""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            scripts_found = set()

            for script in root.findall('.//script'):
                script_name = script.get('id', '')
                if script_name:
                    scripts_found.add(script_name)

            logger.info(f"Script trovati in {xml_file_path}:")
            for script in sorted(scripts_found):
                logger.info(f"  - {script}")

            return scripts_found

        except Exception as e:
            logger.error(f"Errore debug script in {xml_file_path}: {e}")
            return set()

    def test_software_parsing(self):
        """Test rapido per verificare il parsing del software"""
        try:
            # Debug: stampa tutti gli script disponibili
            xml_files = [f for f in os.listdir("../xml") if f.endswith('.xml')]
            all_scripts = set()

            for xml_file in xml_files:
                file_path = os.path.join("../xml", xml_file)
                scripts = self.debug_available_scripts(file_path)
                all_scripts.update(scripts)

            print(f"\nTutti gli script NSE trovati ({len(all_scripts)}):")
            for script in sorted(all_scripts):
                print(f"  - {script}")

            # Cerca specificamente script di software
            software_scripts = [s for s in all_scripts if any(keyword in s.lower()
                                                              for keyword in
                                                              ['software', 'enum', 'installed', 'wmi', 'smb'])]

            print(f"\nScript potenzialmente legati al software ({len(software_scripts)}):")
            for script in sorted(software_scripts):
                print(f"  - {script}")

            # Test parsing su un file specifico
            if xml_files:
                test_file = os.path.join("../xml", xml_files[0])
                print(f"\nTestando parsing su: {test_file}")
                self.parse_software_and_processes(test_file)

                # Verifica risultati
                self.cursor.execute('SELECT COUNT(*) FROM installed_software')
                software_count = self.cursor.fetchone()[0]

                self.cursor.execute('SELECT COUNT(*) FROM running_processes')
                processes_count = self.cursor.fetchone()[0]

                print(f"Software trovati: {software_count}")
                print(f"Processi trovati: {processes_count}")

                if software_count > 0:
                    self.cursor.execute('SELECT software_name, install_date FROM installed_software LIMIT 5')
                    samples = self.cursor.fetchall()
                    print("Esempi software:")
                    for name, date in samples:
                        print(f"  - {name} ({date})")

        except Exception as e:
            logger.error(f"Errore nel test software parsing: {e}")

    def process_hostname_discovery(self, xml_file_path: str):
        """Processo dedicato per discovery hostname da tutti gli script NSE"""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            hostname_found = 0

            for host in root.findall('host'):
                ip_addr = None
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        ip_addr = address.get('addr')
                        break

                if not ip_addr:
                    continue

                # Cerca in tutti gli script NSE
                for script in host.findall('.//script'):
                    script_name = script.get('id', '')
                    output = script.get('output', '')

                    if output and len(output.strip()) > 5:
                        hostname = self._extract_hostname_from_script(script_name, output)
                        if hostname:
                            self._update_host_hostname(ip_addr, hostname, f"discovery_{script_name}")
                            hostname_found += 1

            logger.info(f"Discovery hostname completato: {hostname_found} hostname trovati in {xml_file_path}")
            self.conn.commit()

        except Exception as e:
            logger.error(f"Errore nel discovery hostname da {xml_file_path}: {e}")

    def process_all_xml_files(self, directory_path: str = "../xml"):
        """Processa tutti i file XML nella directory xml del progetto"""
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

                # Esegui discovery hostname dedicato
                self.process_hostname_discovery(file_path)
            else:
                logger.error(f"Errore nel processare {xml_file}")

    def generate_summary_report(self) -> Dict:
        """Genera un report riassuntivo dei dati nel database"""
        report = {}

        # Conteggio host
        self.cursor.execute('SELECT COUNT(*) FROM hosts')
        report['total_hosts'] = self.cursor.fetchone()[0]

        # Host attivi (solo quelli realmente esistenti)
        self.cursor.execute("SELECT COUNT(*) FROM hosts WHERE status IN ('up', 'open')")
        report['active_hosts'] = self.cursor.fetchone()[0]

        # Host con hostname identificati
        self.cursor.execute('SELECT COUNT(*) FROM hosts WHERE hostname IS NOT NULL AND hostname != ""')
        report['hosts_with_hostname'] = self.cursor.fetchone()[0]

        # Genera report aggiuntivo con hostname multipli
        self.cursor.execute('''
            SELECT COUNT(*) FROM hosts 
            WHERE hostname IS NOT NULL AND hostname != "" AND hostname LIKE "%|%"
        ''')
        report['hosts_with_multiple_hostnames'] = self.cursor.fetchone()[0]

        # Totale porte aperte/filtrate (solo quelle significative)
        self.cursor.execute("SELECT COUNT(*) FROM ports WHERE state IN ('open', 'filtered', 'open|filtered')")
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

        # Top 5 porte più comuni (solo quelle aperte/filtrate)
        self.cursor.execute('''
            SELECT port_number, COUNT(*) as count 
            FROM ports WHERE state IN ('open', 'filtered', 'open|filtered') 
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

        # DEBUG: Test parsing software prima dell'elaborazione completa
        print("=== TEST PARSING SOFTWARE ===")
        parser.test_software_parsing()
        print("=" * 50)

        # Processa tutti i file XML nella directory xml del progetto
        parser.process_all_xml_files("../xml")

        # Genera report
        report = parser.generate_summary_report()

        print("\n" + "=" * 50)
        print("REPORT RIASSUNTIVO SCANSIONE RETE")
        print("=" * 50)
        print(f"Host totali trovati: {report['total_hosts']}")
        print(f"Host attivi: {report['active_hosts']}")
        print(f"Host con hostname: {report['hosts_with_hostname']}")
        print(f"Host con hostname multipli: {report['hosts_with_multiple_hostnames']}")
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