#!/usr/bin/env python3
"""
XML Parser - Gestisce il parsing dei file XML di Nmap
"""

import xml.etree.ElementTree as ET
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class XMLParser:
    """Parser specializzato per file XML di Nmap"""

    def __init__(self, database_manager):
        """Inizializza il parser con riferimento al database manager"""
        self.db = database_manager

    def parse_xml_file(self, xml_file_path: str) -> bool:
        """Parsing di un singolo file XML di nmap"""
        try:
            logger.info(f"Parsing file: {xml_file_path}")
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Estrai informazioni della scansione
            scan_info = self._extract_scan_info(root, xml_file_path)
            scan_id = self.db.insert_scan_info(scan_info)

            # Parse degli host
            hosts_parsed = 0
            for host in root.findall('host'):
                if self._parse_host(host, scan_id):
                    hosts_parsed += 1

            logger.info(f"Parsed {hosts_parsed} hosts da {xml_file_path}")
            self.db.commit()
            return True

        except Exception as e:
            logger.error(f"Errore nel parsing di {xml_file_path}: {e}")
            self.db.rollback()
            return False

    def _extract_scan_info(self, root, xml_file_path: str) -> Dict:
        """Estrae informazioni generali della scansione"""
        scan_info = {}

        try:
            # Informazioni di base
            scan_info['xml_file_name'] = xml_file_path.split('/')[-1]

            # Versione nmap e args
            nmaprun = root.find('.')
            if nmaprun is not None:
                scan_info['nmap_version'] = nmaprun.get('version', '')
                scan_info['command_line'] = nmaprun.get('args', '')
                scan_info['scan_args'] = nmaprun.get('scanner', '')

                # Timestamp start
                start_str = nmaprun.get('start')
                if start_str:
                    scan_info['start_time'] = datetime.fromtimestamp(int(start_str))

            # Runstats per tempo di fine e statistiche
            runstats = root.find('.//runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    end_str = finished.get('time')
                    if end_str:
                        scan_info['end_time'] = datetime.fromtimestamp(int(end_str))

                    elapsed_str = finished.get('elapsed')
                    if elapsed_str:
                        scan_info['elapsed_time'] = float(elapsed_str)

                # Statistiche host
                hosts_stats = runstats.find('hosts')
                if hosts_stats is not None:
                    scan_info['total_hosts'] = int(hosts_stats.get('total', 0))
                    scan_info['up_hosts'] = int(hosts_stats.get('up', 0))
                    scan_info['down_hosts'] = int(hosts_stats.get('down', 0))

        except Exception as e:
            logger.warning(f"Errore nell'estrazione scan_info: {e}")

        return scan_info

    def _parse_host(self, host, scan_id: int) -> bool:
        """Parse di un singolo host"""
        try:
            # Estrai indirizzo IP
            ip_addr = None
            mac_addr = None
            vendor = None

            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    ip_addr = address.get('addr')
                elif address.get('addrtype') == 'mac':
                    mac_addr = address.get('addr')
                    vendor = address.get('vendor')

            if not ip_addr:
                return False

            # Status dell'host
            status_elem = host.find('status')
            status = status_elem.get('state') if status_elem is not None else 'unknown'
            status_reason = status_elem.get('reason') if status_elem is not None else ''

            # Hostname primario
            hostname = None
            fqdn = None
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
                    hostname_type = hostname_elem.get('type')
                    if hostname_type == 'PTR':
                        fqdn = hostname

            # Inserisci host nel database
            host_data = {
                'ip_address': ip_addr,
                'mac_address': mac_addr,
                'vendor': vendor,
                'status': status,
                'status_reason': status_reason,
                'hostname': hostname,
                'fqdn': fqdn,
                'scan_id': scan_id
            }
            self.db.insert_host(host_data)

            # Parse porte e servizi
            self._parse_ports_and_services(host, ip_addr)

            # Parse OS detection
            self._parse_os_info(host, ip_addr)

            # Parse script NSE
            self._parse_nse_scripts(host, ip_addr)

            # Parse traceroute
            self._parse_traceroute(host, ip_addr)

            # Parse tutti gli hostname
            self._parse_all_hostnames(host, ip_addr)

            return True

        except Exception as e:
            logger.error(f"Errore nel parsing host: {e}")
            return False

    def _parse_ports_and_services(self, host, ip_addr: str):
        """Parse porte e servizi di un host"""
        ports_elem = host.find('ports')
        if ports_elem is None:
            return

        for port in ports_elem.findall('port'):
            try:
                port_num = int(port.get('portid'))
                protocol = port.get('protocol', 'tcp')

                # Stato della porta
                state_elem = port.find('state')
                if state_elem is not None:
                    port_state = state_elem.get('state')
                    reason = state_elem.get('reason')
                    reason_ttl = state_elem.get('reason_ttl')

                    # Inserisci porta
                    port_data = {
                        'ip_address': ip_addr,
                        'port_number': port_num,
                        'protocol': protocol,
                        'state': port_state,
                        'reason': reason,
                        'reason_ttl': int(reason_ttl) if reason_ttl else None
                    }
                    self.db.insert_port(port_data)

                # Servizio
                service_elem = port.find('service')
                if service_elem is not None:
                    service_data = {
                        'ip_address': ip_addr,
                        'port_number': port_num,
                        'protocol': protocol,
                        'service_name': service_elem.get('name'),
                        'service_product': service_elem.get('product'),
                        'service_version': service_elem.get('version'),
                        'service_info': service_elem.get('extrainfo'),
                        'service_method': service_elem.get('method'),
                        'service_conf': int(service_elem.get('conf', 0))
                    }
                    self.db.insert_service(service_data)

                # Script NSE per questa porta
                for script in port.findall('script'):
                    script_name = script.get('id')
                    script_output = script.get('output', '')

                    script_data = {
                        'ip_address': ip_addr,
                        'port_number': port_num,
                        'protocol': protocol,
                        'script_name': script_name,
                        'script_output': script_output
                    }
                    self.db.insert_nse_script(script_data)

            except Exception as e:
                logger.warning(f"Errore parsing porta {port.get('portid')}: {e}")

    def _parse_os_info(self, host, ip_addr: str):
        """Parse informazioni sistema operativo"""
        os_elem = host.find('os')
        if os_elem is None:
            return

        try:
            # Cerca il match più accurato
            best_match = None
            best_accuracy = 0

            for osmatch in os_elem.findall('osmatch'):
                accuracy = int(osmatch.get('accuracy', 0))
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_match = osmatch

            if best_match is not None:
                os_data = {
                    'ip_address': ip_addr,
                    'os_name': best_match.get('name'),
                    'accuracy': best_accuracy
                }

                # Dettagli dalle osclass
                osclass = best_match.find('osclass')
                if osclass is not None:
                    os_data.update({
                        'os_family': osclass.get('osfamily'),
                        'os_generation': osclass.get('osgen'),
                        'os_type': osclass.get('type'),
                        'os_vendor': osclass.get('vendor')
                    })

                self.db.insert_os_info(os_data)

        except Exception as e:
            logger.warning(f"Errore parsing OS info per {ip_addr}: {e}")

    def _parse_nse_scripts(self, host, ip_addr: str):
        """Parse script NSE a livello host"""
        hostscript = host.find('hostscript')
        if hostscript is None:
            return

        for script in hostscript.findall('script'):
            try:
                script_name = script.get('id')
                script_output = script.get('output', '')

                script_data = {
                    'ip_address': ip_addr,
                    'port_number': None,
                    'protocol': None,
                    'script_name': script_name,
                    'script_output': script_output
                }
                self.db.insert_nse_script(script_data)

            except Exception as e:
                logger.warning(f"Errore parsing script NSE {script.get('id')}: {e}")

    def _parse_traceroute(self, host, ip_addr: str):
        """Parse traceroute information"""
        trace = host.find('trace')
        if trace is None:
            return

        try:
            for hop in trace.findall('hop'):
                hop_data = {
                    'ip_address': ip_addr,
                    'hop_number': int(hop.get('ttl', 0)),
                    'hop_ip': hop.get('ipaddr'),
                    'hop_hostname': hop.get('host'),
                    'rtt': float(hop.get('rtt', 0))
                }

                # Inserisci nella tabella traceroute
                self.db.cursor.execute('''
                    INSERT INTO traceroute 
                    (ip_address, hop_number, hop_ip, hop_hostname, rtt)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    hop_data['ip_address'],
                    hop_data['hop_number'],
                    hop_data['hop_ip'],
                    hop_data['hop_hostname'],
                    hop_data['rtt']
                ))

        except Exception as e:
            logger.warning(f"Errore parsing traceroute per {ip_addr}: {e}")

    def _parse_all_hostnames(self, host, ip_addr: str):
        """Parse tutti gli hostname trovati"""
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is None:
            return

        for hostname_elem in hostnames_elem.findall('hostname'):
            try:
                hostname = hostname_elem.get('name')
                hostname_type = hostname_elem.get('type', 'unknown')

                hostname_data = {
                    'ip_address': ip_addr,
                    'hostname': hostname,
                    'hostname_type': hostname_type
                }
                self.db.insert_hostname(hostname_data)

            except Exception as e:
                logger.warning(f"Errore parsing hostname {hostname_elem.get('name')}: {e}")

    def extract_hostname_from_script(self, script_name: str, output: str) -> Optional[str]:
        """Estrae hostname da output di script NSE"""
        hostname = None

        try:
            if 'nbstat' in script_name.lower():
                # NetBIOS name
                match = re.search(r'NetBIOS name:\s*([^\s,]+)', output, re.IGNORECASE)
                if match:
                    hostname = match.group(1).strip()

            elif 'smb' in script_name.lower():
                # SMB hostname
                patterns = [
                    r'Computer name:\s*([^\s\r\n]+)',
                    r'NetBIOS name:\s*([^\s,\r\n]+)',
                    r'FQDN:\s*([^\s\r\n]+)',
                    r'Domain name:\s*([^\s\r\n]+)'
                ]
                for pattern in patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        hostname = match.group(1).strip()
                        break

            elif 'dns' in script_name.lower():
                # DNS resolution
                match = re.search(r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', output)
                if match:
                    hostname = match.group(1).strip()

        except Exception as e:
            logger.warning(f"Errore estrazione hostname da script {script_name}: {e}")

        return hostname

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
                        hostname = self.extract_hostname_from_script(script_name, output)
                        if hostname:
                            self.db.update_host_hostname(ip_addr, hostname, f"discovery_{script_name}")
                            hostname_found += 1

            logger.info(f"Discovery hostname completato: {hostname_found} hostname trovati in {xml_file_path}")
            self.db.commit()

        except Exception as e:
            logger.error(f"Errore nel discovery hostname da {xml_file_path}: {e}")