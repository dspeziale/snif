import platform
import subprocess
import xml.etree.ElementTree as ET
import os
import re
import socket
import ipaddress
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import logging

from perfmon import ObjectType
from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi import *
from concurrent.futures import ThreadPoolExecutor, as_completed  # NUOVO IMPORT AGGIUNTO

from pysnmp.hlapi.asyncio import nextCmd, CommunityData, UdpTransportTarget, ContextData
from pysnmp.smi.rfc1902 import ObjectIdentity


class NetworkScanner:
    """Core scanner per network discovery e analysis con supporto multiple subnet"""

    def __init__(self, config_manager, db_manager, cache_manager):
        self.config = config_manager
        self.db = db_manager
        self.cache = cache_manager
        self.setup_logging()

        # Verifica capacità nmap
        nmap_status = self.check_nmap_capabilities()
        if nmap_status == "limited":
            self.logger.warning("Modalità limitata: eseguire come amministratore per funzionalità complete")
        elif nmap_status == "unstable":
            self.logger.warning("Nmap instabile rilevato: userò opzioni conservative")
            # Forza timing più lento
            self.config.set('nmap.timing', '2')
        elif not nmap_status:
            raise Exception("Nmap non funzionante - controllare installazione")

    def setup_logging(self):
        """Configura il logging"""
        log_file = self.config.get('logging.file')
        log_level = getattr(logging, self.config.get('logging.level', 'INFO'))

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger(__name__)

    def check_nmap_capabilities(self):
        """Verifica capacità e privilegi nmap"""
        try:
            # Test versione nmap
            result = subprocess.run(
                [self.config.get('nmap.path', 'nmap'), '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.logger.error("Nmap non trovato o non funzionante")
                return False

            version_info = result.stdout
            self.logger.info(f"Nmap version: {version_info.split()[1] if len(version_info.split()) > 1 else 'Unknown'}")

            # Test privilegi su Windows
            if platform.system().lower() == 'windows':
                # Test se può fare SYN scan (richiede privilegi admin)
                test_result = subprocess.run(
                    [self.config.get('nmap.path', 'nmap'), '-sS', '-T4', '--max-retries', '0', '127.0.0.1/32'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if "requires root privileges" in test_result.stderr or "Operation not permitted" in test_result.stderr:
                    self.logger.warning("Nmap non ha privilegi amministratore - alcune scansioni potrebbero fallire")
                    return "limited"
                elif test_result.returncode in [3221225725, -1073741571]:
                    self.logger.warning("Nmap ha problemi di memoria/stack su Windows")
                    return "unstable"

            return True

        except Exception as e:
            self.logger.error(f"Errore verifica nmap: {e}")
            return False

    def _get_subprocess_encoding(self):
        """Ottiene l'encoding appropriato per subprocess su Windows"""
        system = platform.system().lower()
        if system == 'windows':
            # Su Windows usa utf-8 per evitare problemi di encoding
            return 'utf-8'
        else:
            # Su Unix/Linux usa l'encoding di sistema
            return None

    def _run_subprocess_safe(self, cmd, timeout=300, cwd=None):
        """Esegue subprocess con gestione sicura dell'encoding"""
        try:
            # Determina encoding
            encoding = self._get_subprocess_encoding()

            if encoding:
                # Forza encoding specifico
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                    encoding=encoding,
                    errors='replace'  # Sostituisce caratteri non decodificabili
                )
            else:
                # Usa encoding di sistema
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                    errors='replace'
                )

            return result

        except UnicodeDecodeError as e:
            self.logger.warning(f"Errore encoding subprocess: {e}")
            # Fallback con encoding bytes e decodifica manuale
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=False,  # Raw bytes
                    timeout=timeout,
                    cwd=cwd
                )

                # Decodifica manualmente con gestione errori
                stdout = result.stdout.decode('utf-8', errors='replace') if result.stdout else ''
                stderr = result.stderr.decode('utf-8', errors='replace') if result.stderr else ''

                # Crea oggetto result compatibile
                class SafeResult:
                    def __init__(self, returncode, stdout, stderr):
                        self.returncode = returncode
                        self.stdout = stdout
                        self.stderr = stderr

                return SafeResult(result.returncode, stdout, stderr)

            except Exception as fallback_error:
                self.logger.error(f"Errore fallback subprocess: {fallback_error}")
                raise

    def _get_timing_parameter(self):
        """Ottiene il parametro di timing formattato correttamente"""
        timing = self.config.get('nmap.timing', '4')

        # Se è già nel formato corretto (T0, T1, etc.)
        if timing.upper().startswith('T'):
            return timing.upper()

        # Se è solo un numero, aggiunge T
        if timing.isdigit():
            return f'-T{timing}'

        # Mapping per nomi testuali
        timing_map = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }

        return timing_map.get(timing.lower(), '-T4')

    def get_scan_ranges(self):
        """Ottiene i range di scansione dalla configurazione"""
        # Range dalla configurazione
        configured_range = self.config.get('network.scan_range')

        if isinstance(configured_range, list):
            return configured_range
        elif isinstance(configured_range, str):
            return [configured_range]
        else:
            # Fallback: rileva automaticamente la rete locale
            from .utils import get_local_network_range
            local_range = get_local_network_range()
            self.logger.warning(f"Usando range rilevato automaticamente: {local_range}")
            return [local_range]

    def _detect_local_networks(self):
        """Rileva automaticamente le reti locali"""
        local_networks = []

        try:
            # Ottieni tutte le interfacce di rete locali
            interfaces = self._get_local_interfaces()

            for interface in interfaces:
                for ip_info in interface.get('ip_addresses', []):
                    try:
                        # Calcola la rete per ogni IP locale
                        ip = ipaddress.IPv4Address(ip_info['ip'])
                        if ip.is_private:  # Solo IP privati
                            # Assumi /24 se non specificato diversamente
                            prefix = ip_info.get('prefix', 24)
                            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                            network_str = str(network)

                            if network_str not in local_networks:
                                local_networks.append(network_str)
                                self.logger.info(f"Rete locale rilevata: {network_str}")

                    except (ipaddress.AddressValueError, ValueError) as e:
                        self.logger.debug(f"Errore parsing IP {ip_info}: {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Errore rilevamento reti locali: {e}")

        return local_networks

    def _get_local_interfaces(self):
        """Ottiene informazioni sulle interfacce di rete locali"""
        interfaces = []

        try:
            # Usa il comando system-specific
            system = platform.system().lower()

            if system == 'windows':
                interfaces = self._parse_windows_interfaces()
            else:
                interfaces = self._parse_unix_interfaces()

        except Exception as e:
            self.logger.error(f"Errore getting local interfaces: {e}")

        return interfaces

    def _parse_windows_interfaces(self):
        """Parse interfacce Windows con gestione encoding"""
        interfaces = []

        try:
            result = self._run_subprocess_safe(['ipconfig', '/all'], timeout=10)

            if result.returncode != 0:
                return interfaces

            current_interface = {}

            for line in result.stdout.split('\n'):
                line = line.strip()

                if 'adapter' in line.lower() and ':' in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {
                        'name': line,
                        'ip_addresses': []
                    }

                elif 'IPv4' in line and '(' not in line:
                    # Estrae IP address
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        # Assumi /24 per default (potrebbe essere migliorato)
                        current_interface['ip_addresses'].append({
                            'ip': ip,
                            'prefix': 24
                        })

            if current_interface:
                interfaces.append(current_interface)

        except Exception as e:
            self.logger.debug(f"Errore parsing Windows interfaces: {e}")

        return interfaces

    def _parse_unix_interfaces(self):
        """Parse interfacce Unix/Linux"""
        interfaces = []

        try:
            result = self._run_subprocess_safe(['ifconfig'], timeout=10)

            if result.returncode != 0:
                # Prova con 'ip addr' su sistemi più moderni
                result = self._run_subprocess_safe(['ip', 'addr', 'show'], timeout=10)

            if result.returncode != 0:
                return interfaces

            # Parse output ifconfig o ip addr
            current_interface = {}

            for line in result.stdout.split('\n'):
                if not line.startswith(' ') and ':' in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {
                        'name': line.split(':')[0],
                        'ip_addresses': []
                    }

                elif 'inet ' in line and 'inet6' not in line:
                    # Estrae IP e netmask
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)(?:/(\d+))?', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        prefix = int(ip_match.group(2)) if ip_match.group(2) else 24
                        current_interface['ip_addresses'].append({
                            'ip': ip,
                            'prefix': prefix
                        })

            if current_interface:
                interfaces.append(current_interface)

        except Exception as e:
            self.logger.debug(f"Errore parsing Unix interfaces: {e}")

        return interfaces

    def _scan_single_range(self, scan_range):
        """Esegue scansione su un singolo range con comando corretto"""
        self.logger.info(f"Scansione discovery su range {scan_range}")

        try:
            # Prepara comando nmap corretto per discovery
            safe_range = scan_range.replace('/', '_').replace('.', '_')
            xml_file = f"scanner/xml/discovery_{safe_range}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            # Comando nmap per discovery (CORRETTO - rimossa opzione incompatibile)
            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sn',  # Ping scan only - non compatibile con --defeat-rst-ratelimit
                '-PE',  # ICMP Echo
                '-PP',  # ICMP Timestamp
                '-PS80,443,22,23',  # TCP SYN ping su porte comuni
                '-T3',  # Timing normale
                '--max-retries', '2',  # Massimo 2 retry
                '--max-rtt-timeout', '3000ms',  # Timeout RTT fisso a 3 secondi
                '--max-scan-delay', '10ms',  # Ritardo massimo tra probe
                # RIMOSSO: '--defeat-rst-ratelimit',  # Non compatibile con -sn
                '-oX', xml_file,
                scan_range
            ]

            self.logger.debug(f"Comando nmap: {' '.join(nmap_cmd)}")

            # Esegue scansione
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('network.single_range_timeout', 120)
            )

            # Gestione codici di ritorno
            if result.returncode == 0:
                # Successo completo
                pass
            elif result.returncode == 1:
                # Warning - continua comunque
                self.logger.warning(f"Nmap warning per range {scan_range}: {result.stderr}")
            elif result.returncode in [3221225725, -1073741571]:
                # Errori Windows - fallback
                self.logger.warning(f"Errore Windows nmap per {scan_range}, provo comando semplificato")
                return self._scan_single_range_simple(scan_range)
            else:
                # Altri errori - prova fallback
                self.logger.error(f"Nmap fallito (returncode {result.returncode}): {result.stderr}")
                return self._scan_single_range_simple(scan_range)

            # Processa risultati
            devices_found = self._parse_discovery_xml(xml_file)

            # Se non troviamo dispositivi nella rete che contiene il nostro IP, prova fallback
            if devices_found == 0 and self._is_local_network(scan_range):
                self.logger.info(f"Nessun dispositivo trovato nella rete locale {scan_range}, provo metodo alternativo")
                return self._scan_single_range_simple(scan_range)

            return devices_found

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout scansione {scan_range}, provo metodo semplificato")
            return self._scan_single_range_simple(scan_range)
        except Exception as e:
            self.logger.error(f"Errore scansione discovery range {scan_range}: {e}")
            return self._scan_single_range_simple(scan_range)

    def run_discovery_scan(self):
        """Esegue scansione di discovery della rete su tutti i range configurati"""
        ranges = self.get_scan_ranges()
        self.logger.info(f"Range di scansione configurati: {ranges}")
        self.logger.info(f"Avvio scansione discovery su {len(ranges)} range")

        # Registra scansione
        scan_id = self.db.add_scan_record('discovery', f"{len(ranges)} ranges")

        try:
            all_devices_found = 0
            successful_ranges = 0
            failed_ranges = []

            # Scansione parallela di tutti i range
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_range = {
                    executor.submit(self._scan_single_range, range_ip): range_ip
                    for range_ip in ranges
                }

                for future in as_completed(future_to_range):
                    range_ip = future_to_range[future]
                    try:
                        devices_count = future.result()
                        all_devices_found += devices_count
                        successful_ranges += 1
                        self.logger.info(f"Range {range_ip}: {devices_count} dispositivi trovati")
                    except Exception as e:
                        failed_ranges.append(range_ip)
                        self.logger.error(f"Errore scansione parallela range {range_ip}: {e}")

            # Aggiorna record scansione
            status_msg = f"Completata: {successful_ranges}/{len(ranges)} range"
            if failed_ranges:
                status_msg += f". Falliti: {failed_ranges}"

            self.db.update_scan_record(scan_id, 'completed', all_devices_found, status_msg)

            self.logger.info(f"Scansione discovery completata: {all_devices_found} dispositivi totali trovati")
            return {
                'devices_found': all_devices_found,
                'successful_ranges': successful_ranges,
                'failed_ranges': failed_ranges,
                'total_ranges': len(ranges)
            }

        except Exception as e:
            self.logger.error(f"Errore scansione discovery: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def _run_parallel_discovery(self, scan_ranges, max_concurrent):
        """Esegue scansioni discovery in parallelo"""
        total_devices_found = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Avvia tutte le scansioni
            future_to_range = {
                executor.submit(self._run_single_discovery, scan_range): scan_range
                for scan_range in scan_ranges
            }

            # Attendi i risultati
            for future in concurrent.futures.as_completed(future_to_range):
                scan_range = future_to_range[future]
                try:
                    result = future.result()
                    total_devices_found += result['devices_found']
                    self.logger.info(f"Range {scan_range}: {result['devices_found']} dispositivi trovati")
                except Exception as e:
                    self.logger.error(f"Errore scansione parallela range {scan_range}: {e}")

        return total_devices_found

    def _run_single_discovery(self, scan_range):
        """Esegue scansione discovery su un singolo range"""
        self.logger.info(f"Scansione discovery su range {scan_range}")

        # Registra scansione
        scan_id = self.db.add_scan_record('discovery', scan_range)

        try:
            # Valida il range
            if not self._validate_network_range(scan_range):
                raise Exception(f"Range di rete non valido: {scan_range}")

            # Prepara comando nmap
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_range = scan_range.replace('/', '_').replace('.', '_')
            xml_file = f"scanner/xml/discovery_{safe_range}_{timestamp}.xml"

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sn',  # Ping scan
                '-PE',  # ICMP Echo
                '-PS22,23,25,53,80,110,443,993,995,1723,3389,5900,8080',  # TCP SYN ping
                self._get_timing_parameter(),
                '-oX', xml_file,
                scan_range
            ]

            self.logger.debug(f"Comando nmap per {scan_range}: {' '.join(nmap_cmd)}")

            # Esegue scansione con gestione encoding sicura
            result = self._run_subprocess_safe(nmap_cmd, timeout=self.config.get('network.timeout', 300))

            if result.returncode != 0:
                raise Exception(f"Nmap fallito per {scan_range}: {result.stderr}")

            # Processa risultati
            devices_found = self._parse_discovery_xml(xml_file)

            # Aggiorna record scansione
            self.db.update_scan_record(scan_id, 'completed', devices_found)

            return {
                'range': scan_range,
                'devices_found': devices_found,
                'xml_file': xml_file
            }

        except Exception as e:
            self.logger.error(f"Errore scansione discovery range {scan_range}: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def _validate_network_range(self, network_range):
        """Valida un range di rete"""
        try:
            ipaddress.IPv4Network(network_range, strict=False)
            return True
        except ipaddress.AddressValueError:
            return False

    def get_scan_ranges_info(self):
        """Ottiene informazioni sui range di scansione configurati"""
        scan_ranges = self.get_scan_ranges()
        ranges_info = []

        for scan_range in scan_ranges:
            try:
                network = ipaddress.IPv4Network(scan_range, strict=False)
                info = {
                    'range': scan_range,
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address),
                    'num_hosts': network.num_addresses - 2,  # Escludi network e broadcast
                    'is_private': network.is_private,
                    'valid': True
                }
            except Exception as e:
                info = {
                    'range': scan_range,
                    'error': str(e),
                    'valid': False
                }

            ranges_info.append(info)

        return ranges_info

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
                self._get_timing_parameter(),
                '-oX', xml_file,
                ip
            ]

            result = self._run_subprocess_safe(nmap_cmd, timeout=600)

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
                self._get_timing_parameter(),
                '-oX', xml_file,
                ip
            ]

            result = self._run_subprocess_safe(nmap_cmd, timeout=300)

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
                self._get_timing_parameter(),
                '-oX', xml_file,
                ip
            ]

            result = self._run_subprocess_safe(nmap_cmd, timeout=900)

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
        """Processa XML di discovery scan con informazioni migliorate"""
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
                vendor = None
                mac_elem = host.find(".//address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor', '')
                    if not vendor and mac:
                        vendor = self.cache.get_vendor_from_mac(mac)

                # Estrae hostname
                hostname = None
                hostnames = host.findall(".//hostname")
                if hostnames:
                    # Prendi il primo hostname non vuoto
                    for hn in hostnames:
                        name = hn.get('name', '').strip()
                        if name and name != ip:
                            hostname = name
                            break

                # Prova risoluzione DNS se non abbiamo hostname
                if not hostname:
                    try:
                        import socket
                        socket.setdefaulttimeout(2)
                        hostname = socket.gethostbyaddr(ip)[0]
                        self.logger.debug(f"Risolto hostname per {ip}: {hostname}")
                    except:
                        pass
                    finally:
                        socket.setdefaulttimeout(None)

                # Stima tipo dispositivo basato su IP
                device_type = self._estimate_device_type(ip, hostname, mac)

                # Aggiunge dispositivo al database
                device_id = self.db.add_device(ip, mac, hostname, vendor, device_type)
                devices_found += 1

                self.logger.debug(f"Dispositivo trovato: {ip} ({mac}) - {hostname} [{device_type}]")

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

    def _scan_single_range_simple(self, scan_range):
        """Metodo di scansione semplificato e più affidabile"""
        self.logger.info(f"Scansione semplificata su range {scan_range}")

        try:
            safe_range = scan_range.replace('/', '_').replace('.', '_')
            xml_file = f"scanner/xml/discovery_simple_{safe_range}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            # Comando nmap ultra-semplificato e affidabile
            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sn',  # Solo ping scan
                '-PE',  # Solo ICMP Echo
                '-T2',  # Timing lento ma molto stabile
                '--max-retries', '1',
                '--host-timeout', '30s',  # Timeout per singolo host
                '-oX', xml_file,
                scan_range
            ]

            self.logger.debug(f"Comando nmap semplificato: {' '.join(nmap_cmd)}")

            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=180  # Timeout più lungo per T2
            )

            # Accetta anche warning minori
            if result.returncode in [0, 1]:
                devices_found = self._parse_discovery_xml(xml_file)
                self.logger.info(f"Scansione semplificata completata: {devices_found} dispositivi")
                return devices_found
            else:
                self.logger.error(f"Scansione semplificata fallita per {scan_range}: {result.stderr}")
                return 0

        except Exception as e:
            self.logger.error(f"Errore scansione semplificata {scan_range}: {e}")
            return 0

    def _should_have_devices(self, scan_range):
        """Verifica se un range dovrebbe contenere dispositivi (es. range locale)"""
        try:
            from .utils import get_local_network_range, is_private_ip
            import ipaddress

            # Ottieni network del range
            network = ipaddress.IPv4Network(scan_range, strict=False)

            # Se è una rete privata e contiene potenziali gateway comuni
            if any(is_private_ip(str(ip)) for ip in list(network.hosts())[:5]):
                # Controlla se contiene indirizzi gateway comuni
                common_gateways = ['.1', '.254', '.100']
                range_base = str(network.network_address)[:-1]  # es. "192.168.1" da "192.168.1.0"

                for gw_suffix in common_gateways:
                    potential_gw = range_base + gw_suffix
                    if ipaddress.IPv4Address(potential_gw) in network:
                        # Prova ping veloce
                        if self._quick_ping(potential_gw):
                            return True

            return False
        except:
            return False

    def _quick_ping(self, ip):
        """Ping veloce per verificare connettività"""
        try:
            import platform

            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            timeout_val = '1000' if platform.system().lower() == 'windows' else '1'

            result = subprocess.run(
                ['ping', param, '1', timeout_param, timeout_val, ip],
                capture_output=True,
                timeout=3
            )
            return result.returncode == 0
        except:
            return False



    def get_optimized_nmap_command(self, scan_type, target, xml_file):
        """Genera comando nmap ottimizzato in base al sistema e privilegi"""
        base_cmd = [self.config.get('nmap.path', 'nmap')]

        if scan_type == 'discovery':
            if platform.system().lower() == 'windows':
                # Comando Windows-friendly
                cmd = base_cmd + [
                    '-sn',
                    '-PE', '-PP',  # ICMP Echo e Timestamp
                    '-PS80,443,22',  # Solo porte essenziali
                    '-T2',  # Timing lento ma stabile
                    '--max-retries', '1',
                    '--max-rtt-timeout', '2000ms',
                    '--max-scan-delay', '20ms',
                    '-oX', xml_file,
                    target
                ]
            else:
                # Comando Linux/Unix
                cmd = base_cmd + [
                    '-sn',
                    '-PE', '-PP', '-PM',
                    '-PS21,22,23,25,53,80,110,443',
                    f'-T{self.config.get("nmap.timing", "4")}',
                    '-oX', xml_file,
                    target
                ]

        return cmd

    def _is_local_network(self, scan_range):
        """Verifica se il range contiene la nostra rete locale"""
        try:
            import ipaddress
            import socket

            # Ottieni il nostro IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Verifica se il nostro IP è nel range
            network = ipaddress.IPv4Network(scan_range, strict=False)
            return ipaddress.IPv4Address(local_ip) in network

        except Exception:
            return False

    def _estimate_device_type(self, ip, hostname=None, mac=None):
        """Stima il tipo di dispositivo basato su indizi disponibili"""

        # Analisi basata su hostname
        if hostname:
            hostname_lower = hostname.lower()

            if any(term in hostname_lower for term in ['router', 'gateway', 'gw']):
                return 'router'
            elif any(term in hostname_lower for term in ['switch', 'sw']):
                return 'switch'
            elif any(term in hostname_lower for term in ['ap', 'wifi', 'wireless']):
                return 'access_point'
            elif any(term in hostname_lower for term in ['printer', 'print']):
                return 'printer'
            elif any(term in hostname_lower for term in ['server', 'srv']):
                return 'server'
            elif any(term in hostname_lower for term in ['desktop', 'pc', 'workstation']):
                return 'desktop'
            elif any(term in hostname_lower for term in ['laptop', 'notebook']):
                return 'laptop'
            elif any(term in hostname_lower for term in ['phone', 'mobile', 'android', 'iphone']):
                return 'mobile'

        # Analisi basata su MAC (vendor)
        if mac:
            vendor_lower = (self.cache.get_vendor_from_mac(mac) or '').lower()

            if any(term in vendor_lower for term in ['cisco', 'juniper', 'mikrotik']):
                return 'router'
            elif any(term in vendor_lower for term in ['hp', 'canon', 'epson', 'brother']):
                return 'printer'
            elif any(term in vendor_lower for term in ['apple']):
                if any(term in vendor_lower for term in ['iphone', 'ipad']):
                    return 'mobile'
                else:
                    return 'desktop'
            elif any(term in vendor_lower for term in ['samsung', 'lg', 'sony']):
                return 'mobile'

        # Analisi basata su IP
        if ip:
            last_octet = int(ip.split('.')[-1])

            # Gateway comuni
            if last_octet in [1, 254]:
                return 'router'
            # Range server
            elif 10 <= last_octet <= 50:
                return 'server'
            # Range stampanti
            elif 200 <= last_octet <= 220:
                return 'printer'

        return 'unknown'