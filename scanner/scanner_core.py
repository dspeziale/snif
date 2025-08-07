import subprocess
import xml.etree.ElementTree as ET
import os
import re
from datetime import datetime, timedelta
import logging
from pysnmp.hlapi import *
import socket


class NetworkScanner:
    """Core scanner per network discovery e analysis"""

    def __init__(self, config_manager, db_manager, cache_manager):
        self.config = config_manager
        self.db = db_manager
        self.cache = cache_manager
        self.setup_logging()

    def setup_logging(self):
        """Configura il logging"""
        log_file = self.config.get('logging.file')
        log_level = getattr(logging, self.config.get('logging.level', 'INFO'))

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger(__name__)

    def run_discovery_scan(self):
        """Esegue scansione di discovery della rete"""
        scan_range = self.config.get('network.scan_range')
        self.logger.info(f"Avvio scansione discovery su {scan_range}")

        # Registra scansione
        scan_id = self.db.add_scan_record('discovery', scan_range)

        try:
            # Prepara comando nmap
            xml_file = f"scanner/xml/discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sn',  # Ping scan
                '-PE',  # ICMP Echo
                '-PS22,23,25,53,80,110,443,993,995,1723,3389,5900,8080',  # TCP SYN ping
                f'-T{self.config.get("nmap.timing", "4")}',
                '-oX', xml_file,
                scan_range
            ]

            self.logger.info(f"Comando nmap: {' '.join(nmap_cmd)}")

            # Esegue scansione
            result = subprocess.run(nmap_cmd, capture_output=True, text=True,
                                    timeout=self.config.get('network.timeout', 300))

            if result.returncode != 0:
                raise Exception(f"Nmap fallito: {result.stderr}")

            # Processa risultati
            devices_found = self._parse_discovery_xml(xml_file)

            # Aggiorna record scansione
            self.db.update_scan_record(scan_id, 'completed', devices_found)

            self.logger.info(f"Scansione discovery completata: {devices_found} dispositivi trovati")
            return {'devices_found': devices_found, 'xml_file': xml_file}

        except Exception as e:
            self.logger.error(f"Errore scansione discovery: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def run_services_scan(self, device_id):
        """Esegue scansione servizi su dispositivo specifico"""
        device = self._get_device_by_id(device_id)
        if not device:
            raise Exception("Dispositivo non trovato")

        ip = device['ip_address']
        self.logger.info(f"Avvio scansione servizi su {ip}")

        scan_id = self.db.add_scan_record('services', ip)

        try:
            xml_file = f"scanner/xml/services_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sS',  # TCP SYN scan
                '-sV',  # Service version detection
                '--version-intensity', '5',
                f'-T{self.config.get("nmap.timing", "4")}',
                '-oX', xml_file,
                ip
            ]

            result = subprocess.run(nmap_cmd, capture_output=True, text=True,
                                    timeout=600)

            if result.returncode != 0:
                raise Exception(f"Nmap fallito: {result.stderr}")

            # Processa risultati
            services_found = self._parse_services_xml(xml_file, device_id)

            self.db.update_scan_record(scan_id, 'completed', services_found)

            self.logger.info(f"Scansione servizi completata: {services_found} servizi trovati")
            return {'services_found': services_found, 'xml_file': xml_file}

        except Exception as e:
            self.logger.error(f"Errore scansione servizi: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def run_os_scan(self, device_id):
        """Esegue scansione OS su dispositivo specifico"""
        device = self._get_device_by_id(device_id)
        if not device:
            raise Exception("Dispositivo non trovato")

        ip = device['ip_address']
        self.logger.info(f"Avvio scansione OS su {ip}")

        scan_id = self.db.add_scan_record('os', ip)

        try:
            xml_file = f"scanner/xml/os_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-O',  # OS detection
                '--osscan-guess',
                f'-T{self.config.get("nmap.timing", "4")}',
                '-oX', xml_file,
                ip
            ]

            result = subprocess.run(nmap_cmd, capture_output=True, text=True,
                                    timeout=300)

            # OS scan può fallire parzialmente ma dare risultati utili
            os_info = self._parse_os_xml(xml_file, device_id)

            self.db.update_scan_record(scan_id, 'completed', 1 if os_info else 0)

            self.logger.info(f"Scansione OS completata")
            return {'os_detected': bool(os_info), 'xml_file': xml_file}

        except Exception as e:
            self.logger.error(f"Errore scansione OS: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def run_vulnerability_scan(self, device_id):
        """Esegue scansione vulnerabilità su dispositivo specifico"""
        device = self._get_device_by_id(device_id)
        if not device:
            raise Exception("Dispositivo non trovato")

        ip = device['ip_address']
        self.logger.info(f"Avvio scansione vulnerabilità su {ip}")

        scan_id = self.db.add_scan_record('vulnerability', ip)

        try:
            xml_file = f"scanner/xml/vuln_{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '--script', 'vuln',
                '--script-args', 'vulndb=database',
                f'-T{self.config.get("nmap.timing", "4")}',
                '-oX', xml_file,
                ip
            ]

            result = subprocess.run(nmap_cmd, capture_output=True, text=True,
                                    timeout=900)

            # Processa risultati
            vulns_found = self._parse_vulnerability_xml(xml_file, device_id)

            self.db.update_scan_record(scan_id, 'completed', vulns_found)

            self.logger.info(f"Scansione vulnerabilità completata: {vulns_found} vulnerabilità trovate")
            return {'vulnerabilities_found': vulns_found, 'xml_file': xml_file}

        except Exception as e:
            self.logger.error(f"Errore scansione vulnerabilità: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def run_snmp_scan(self, device_id):
        """Esegue scansione SNMP su dispositivo specifico"""
        device = self._get_device_by_id(device_id)
        if not device:
            raise Exception("Dispositivo non trovato")

        ip = device['ip_address']
        self.logger.info(f"Avvio scansione SNMP su {ip}")

        scan_id = self.db.add_scan_record('snmp', ip)

        try:
            # Prima verifica se SNMP è attivo
            if not self._test_snmp_connectivity(ip):
                self.logger.info(f"SNMP non disponibile su {ip}")
                self.db.update_scan_record(scan_id, 'completed', 0, 'SNMP not available')
                return {'snmp_available': False}

            # Raccoglie informazioni SNMP
            snmp_info = self._collect_snmp_info(ip, device_id)

            self.db.update_scan_record(scan_id, 'completed', 1 if snmp_info else 0)

            self.logger.info(f"Scansione SNMP completata")
            return {'snmp_available': True, 'info_collected': bool(snmp_info)}

        except Exception as e:
            self.logger.error(f"Errore scansione SNMP: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def _get_device_by_id(self, device_id):
        """Ottiene dispositivo dal database"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        device = cursor.fetchone()
        conn.close()
        return dict(device) if device else None

    def _parse_discovery_xml(self, xml_file):
        """Processa XML di discovery scan"""
        if not os.path.exists(xml_file):
            return 0

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            devices_found = 0

            for host in root.findall('host'):
                # Controlla se host è up
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                # Estrae IP
                address_elem = host.find(".//address[@addrtype='ipv4']")
                if address_elem is None:
                    continue

                ip = address_elem.get('addr')

                # Estrae MAC se disponibile
                mac = None
                mac_elem = host.find(".//address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor')
                    if not vendor and mac:
                        vendor = self.cache.get_vendor_from_mac(mac)
                else:
                    vendor = None

                # Estrae hostname
                hostname = None
                hostname_elem = host.find(".//hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

                # Aggiunge dispositivo al database
                self.db.add_device(ip, mac, hostname, vendor)
                devices_found += 1

                self.logger.debug(f"Dispositivo trovato: {ip} ({mac}) - {hostname}")

            return devices_found

        except Exception as e:
            self.logger.error(f"Errore parsing discovery XML: {e}")
            return 0

    def _parse_services_xml(self, xml_file, device_id):
        """Processa XML di services scan"""
        if not os.path.exists(xml_file):
            return 0

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            services_found = 0

            for host in root.findall('host'):
                ports = host.find('ports')
                if ports is None:
                    continue

                for port in ports.findall('port'):
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol')

                    state_elem = port.find('state')
                    if state_elem is None:
                        continue

                    state = state_elem.get('state')
                    if state != 'open':
                        continue

                    # Estrae informazioni servizio
                    service_elem = port.find('service')
                    service_name = None
                    version = None

                    if service_elem is not None:
                        service_name = service_elem.get('name')
                        version = service_elem.get('version')
                        if not version:
                            version = service_elem.get('product')
                        if version and service_elem.get('version'):
                            version += f" {service_elem.get('version')}"

                    # Aggiunge servizio al database
                    self.db.add_service(device_id, port_num, protocol,
                                        service_name, version, state)
                    services_found += 1

            return services_found

        except Exception as e:
            self.logger.error(f"Errore parsing services XML: {e}")
            return 0

    def _parse_os_xml(self, xml_file, device_id):
        """Processa XML di OS scan"""
        if not os.path.exists(xml_file):
            return None

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall('host'):
                os_elem = host.find('os')
                if os_elem is None:
                    continue

                # Cerca OS match con accuracy più alta
                best_match = None
                best_accuracy = 0

                for osmatch in os_elem.findall('osmatch'):
                    accuracy = int(osmatch.get('accuracy', '0'))
                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best_match = osmatch

                if best_match is not None:
                    os_name = best_match.get('name')

                    # Aggiorna dispositivo con info OS
                    conn = self.db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE devices 
                        SET os_name = ? 
                        WHERE id = ?
                    ''', (os_name, device_id))
                    conn.commit()
                    conn.close()

                    return os_name

            return None

        except Exception as e:
            self.logger.error(f"Errore parsing OS XML: {e}")
            return None

    def _parse_vulnerability_xml(self, xml_file, device_id):
        """Processa XML di vulnerability scan"""
        if not os.path.exists(xml_file):
            return 0

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            vulns_found = 0

            for host in root.findall('host'):
                for script in host.findall('.//script'):
                    script_id = script.get('id')
                    if not script_id or 'vuln' not in script_id:
                        continue

                    output = script.get('output', '')

                    # Cerca CVE nel output
                    cve_pattern = r'CVE-\d{4}-\d{4,7}'
                    cves = re.findall(cve_pattern, output)

                    for cve in cves:
                        # Ottieni info CVE da cache/NVD
                        cve_info = self.cache.get_cve_info(cve)

                        if cve_info:
                            self.db.add_vulnerability(
                                device_id, cve,
                                cve_info.get('severity', 'Unknown'),
                                cve_info.get('score', 0.0),
                                cve_info.get('description', '')
                            )
                            vulns_found += 1
                        else:
                            # Aggiungi anche senza info dettagliate
                            self.db.add_vulnerability(device_id, cve, 'Unknown')
                            vulns_found += 1

            return vulns_found

        except Exception as e:
            self.logger.error(f"Errore parsing vulnerability XML: {e}")
            return 0

    def _test_snmp_connectivity(self, ip):
        """Testa se SNMP è disponibile"""
        community_strings = self.config.get('snmp.community_strings', ['public'])

        for community in community_strings:
            try:
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, 161), timeout=5, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
                        lexicographicMode=False,
                        maxRows=1):

                    if errorIndication:
                        continue
                    if errorStatus:
                        continue

                    # Se arriviamo qui, SNMP funziona
                    return True

            except Exception:
                continue

        return False

    def _collect_snmp_info(self, ip, device_id):
        """Raccoglie informazioni SNMP"""
        community_strings = self.config.get('snmp.community_strings', ['public'])

        for community in community_strings:
            try:
                snmp_data = {}

                # Sistema base
                oids = {
                    'sysDescr': '1.3.6.1.2.1.1.1.0',
                    'sysName': '1.3.6.1.2.1.1.5.0',
                    'sysLocation': '1.3.6.1.2.1.1.6.0',
                    'sysContact': '1.3.6.1.2.1.1.4.0',
                    'sysUpTime': '1.3.6.1.2.1.1.3.0'
                }

                for name, oid in oids.items():
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                            SnmpEngine(),
                            CommunityData(community),
                            UdpTransportTarget((ip, 161), timeout=5),
                            ContextData(),
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False,
                            maxRows=1):

                        if not errorIndication and not errorStatus:
                            for varBind in varBinds:
                                snmp_data[name] = str(varBind[1])
                        break

                if snmp_data:
                    # Salva info SNMP
                    snmp_id = self.db.add_snmp_info(
                        device_id, community, '2c',
                        snmp_data.get('sysDescr'),
                        snmp_data.get('sysName')
                    )

                    return snmp_data

            except Exception as e:
                self.logger.error(f"Errore SNMP con community {community}: {e}")
                continue

        return None