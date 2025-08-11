#!/usr/bin/env python3
"""
Device Classifier - Classifica automaticamente i dispositivi della rete
Utilizza informazioni da OS detection, servizi, porte, MAC address (OUI), hostname
"""

import os
import re
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
import json

logger = logging.getLogger(__name__)


class DeviceClassifier:
    """Classifier che identifica automaticamente il tipo di dispositivo"""

    def __init__(self, database_manager, cache_dir: str = "../cache"):
        """Inizializza il classifier"""
        self.db = database_manager
        self.cache_dir = cache_dir
        self.oui_cache_file = os.path.join(cache_dir, "oui.txt")
        self.oui_json_cache = os.path.join(cache_dir, "oui_cache.json")
        self.oui_data = {}

        # Assicurati che la directory cache esista
        os.makedirs(cache_dir, exist_ok=True)

        # Carica/aggiorna OUI database
        self._load_or_update_oui_database()

    def _load_or_update_oui_database(self):
        """Carica o aggiorna il database OUI ogni 30 giorni"""
        try:
            # Controlla se il file cache esiste e quando è stato aggiornato
            need_update = True

            if os.path.exists(self.oui_json_cache):
                cache_time = datetime.fromtimestamp(os.path.getmtime(self.oui_json_cache))
                if datetime.now() - cache_time < timedelta(days=30):
                    need_update = False
                    logger.info("OUI cache è aggiornato, carico da file locale")

            if need_update:
                logger.info("Aggiornamento OUI database da IEEE...")
                self._download_oui_database()

            # Carica i dati OUI
            self._load_oui_cache()

        except Exception as e:
            logger.error(f"Errore nel caricamento/aggiornamento OUI database: {e}")
            # Se fallisce, prova a caricare da cache esistente
            if os.path.exists(self.oui_json_cache):
                self._load_oui_cache()

    def _download_oui_database(self):
        """Scarica il database OUI da IEEE"""
        try:
            oui_url = "http://standards-oui.ieee.org/oui/oui.txt"
            logger.info(f"Scaricando OUI database da {oui_url}")

            response = requests.get(oui_url, timeout=30)
            response.raise_for_status()

            # Salva il file raw
            with open(self.oui_cache_file, 'w', encoding='utf-8') as f:
                f.write(response.text)

            # Parse e crea cache JSON ottimizzata
            self._parse_oui_file()

            logger.info("OUI database aggiornato con successo")

        except Exception as e:
            logger.error(f"Errore download OUI database: {e}")
            raise

    def _parse_oui_file(self):
        """Parse del file OUI e creazione cache JSON"""
        try:
            oui_dict = {}

            with open(self.oui_cache_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Pattern per estrarre OUI e vendor
            # Formato: XX-XX-XX   (hex)		VENDOR_NAME
            pattern = r'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)'

            matches = re.findall(pattern, content)

            for oui, vendor in matches:
                # Normalizza OUI (rimuovi trattini e converti in lowercase)
                oui_clean = oui.replace('-', '').lower()
                vendor_clean = vendor.strip()

                oui_dict[oui_clean] = {
                    'vendor': vendor_clean,
                    'oui_original': oui
                }

            # Salva cache JSON
            cache_data = {
                'updated': datetime.now().isoformat(),
                'count': len(oui_dict),
                'oui_data': oui_dict
            }

            with open(self.oui_json_cache, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)

            logger.info(f"Parsed {len(oui_dict)} OUI entries")

        except Exception as e:
            logger.error(f"Errore nel parsing OUI file: {e}")
            raise

    def _load_oui_cache(self):
        """Carica la cache OUI dal file JSON"""
        try:
            with open(self.oui_json_cache, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            self.oui_data = cache_data['oui_data']
            updated = cache_data.get('updated', 'unknown')
            count = cache_data.get('count', 0)

            logger.info(f"Caricati {count} OUI entries (aggiornato: {updated})")

        except Exception as e:
            logger.error(f"Errore caricamento OUI cache: {e}")
            self.oui_data = {}

    def lookup_vendor_by_mac(self, mac_address: str) -> Optional[str]:
        """Cerca il vendor dal MAC address usando OUI database"""
        if not mac_address or not self.oui_data:
            return None

        try:
            # Normalizza MAC address (primi 6 caratteri hex)
            mac_clean = re.sub(r'[^0-9A-Fa-f]', '', mac_address)
            if len(mac_clean) < 6:
                return None

            oui = mac_clean[:6].lower()

            oui_info = self.oui_data.get(oui)
            if oui_info:
                return oui_info['vendor']

            return None

        except Exception as e:
            logger.warning(f"Errore lookup vendor per MAC {mac_address}: {e}")
            return None

    def classify_all_devices(self):
        """Classifica tutti i dispositivi nel database"""
        try:
            logger.info("Inizio classificazione automatica dispositivi...")

            # Crea tabella device_classification se non esiste
            self._create_classification_table()

            # Ottieni tutti gli host
            self.db.cursor.execute('''
                SELECT ip_address FROM hosts WHERE status = 'up'
            ''')

            hosts = self.db.cursor.fetchall()
            classified_count = 0

            for (ip_address,) in hosts:
                device_info = self._classify_single_device(ip_address)
                if device_info:
                    self._save_device_classification(ip_address, device_info)
                    classified_count += 1

            self.db.commit()
            logger.info(f"Classificati {classified_count} dispositivi su {len(hosts)} host attivi")

        except Exception as e:
            logger.error(f"Errore nella classificazione dispositivi: {e}")

    def _create_classification_table(self):
        """Crea la tabella per le classificazioni dei dispositivi"""
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_classification (
                ip_address TEXT PRIMARY KEY,
                device_type TEXT,
                device_subtype TEXT,
                vendor TEXT,
                vendor_oui TEXT,
                confidence_score REAL,
                classification_reasons TEXT,
                os_detected TEXT,
                main_services TEXT,
                hostname_pattern TEXT,
                mac_vendor TEXT,
                updated_at TIMESTAMP,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Indice per performance
        self.db.cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_device_type ON device_classification(device_type)
        ''')

    def _classify_single_device(self, ip_address: str) -> Optional[Dict]:
        """Classifica un singolo dispositivo"""
        try:
            # Raccolta di tutte le informazioni disponibili
            device_data = self._gather_device_info(ip_address)

            if not device_data:
                return None

            # Processo di classificazione
            classification = self._determine_device_type(device_data)

            return classification

        except Exception as e:
            logger.warning(f"Errore classificazione dispositivo {ip_address}: {e}")
            return None

    def _gather_device_info(self, ip_address: str) -> Dict:
        """Raccoglie tutte le informazioni disponibili per un dispositivo"""
        device_data = {
            'ip_address': ip_address,
            'hostname': None,
            'os_info': {},
            'open_ports': [],
            'services': [],
            'mac_address': None,
            'vendor': None,
            'vendor_oui': None,
            'software': [],
            'processes': [],
            'vulnerabilities': []
        }

        try:
            # Informazioni host base
            self.db.cursor.execute('''
                SELECT hostname, mac_address, vendor, status 
                FROM hosts WHERE ip_address = ?
            ''', (ip_address,))

            host_info = self.db.cursor.fetchone()
            if host_info:
                device_data['hostname'] = host_info[0]
                device_data['mac_address'] = host_info[1]
                device_data['vendor'] = host_info[2]

                # Lookup vendor da OUI se disponibile MAC
                if host_info[1]:
                    oui_vendor = self.lookup_vendor_by_mac(host_info[1])
                    if oui_vendor:
                        device_data['vendor_oui'] = oui_vendor

            # Informazioni OS
            self.db.cursor.execute('''
                SELECT os_name, os_family, os_type, os_vendor, accuracy
                FROM os_info WHERE ip_address = ?
            ''', (ip_address,))

            os_info = self.db.cursor.fetchone()
            if os_info:
                device_data['os_info'] = {
                    'os_name': os_info[0],
                    'os_family': os_info[1],
                    'os_type': os_info[2],
                    'os_vendor': os_info[3],
                    'accuracy': os_info[4]
                }

            # Porte aperte e servizi
            self.db.cursor.execute('''
                SELECT p.port_number, p.protocol, p.state, s.service_name, s.service_product, s.service_version
                FROM ports p
                LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
                WHERE p.ip_address = ? AND p.state = 'open'
                ORDER BY p.port_number
            ''', (ip_address,))

            ports_services = self.db.cursor.fetchall()
            for port_info in ports_services:
                port_num, protocol, state, service_name, service_product, service_version = port_info

                device_data['open_ports'].append({
                    'port': port_num,
                    'protocol': protocol,
                    'service': service_name,
                    'product': service_product,
                    'version': service_version
                })

                if service_name:
                    device_data['services'].append(service_name)

            # Software installato
            self.db.cursor.execute('''
                SELECT software_name, version FROM installed_software 
                WHERE ip_address = ? LIMIT 20
            ''', (ip_address,))

            software_list = self.db.cursor.fetchall()
            device_data['software'] = [f"{sw[0]} {sw[1] or ''}".strip() for sw in software_list]

            # Processi (top 10)
            self.db.cursor.execute('''
                SELECT process_name FROM running_processes 
                WHERE ip_address = ? LIMIT 10
            ''', (ip_address,))

            processes_list = self.db.cursor.fetchall()
            device_data['processes'] = [proc[0] for proc in processes_list if proc[0]]

            return device_data

        except Exception as e:
            logger.warning(f"Errore raccolta info per {ip_address}: {e}")
            return device_data

    def _determine_device_type(self, device_data: Dict) -> Dict:
        """Determina il tipo di dispositivo basandosi su tutte le informazioni"""

        classification = {
            'device_type': 'Unknown',
            'device_subtype': None,
            'vendor': device_data.get('vendor_oui') or device_data.get('vendor'),
            'vendor_oui': device_data.get('vendor_oui'),
            'confidence_score': 0.0,
            'classification_reasons': [],
            'os_detected': device_data['os_info'].get('os_name'),
            'main_services': ', '.join(set(device_data['services'][:10])),
            'hostname_pattern': device_data.get('hostname'),
            'mac_vendor': device_data.get('vendor_oui')
        }

        reasons = []
        confidence = 0.0

        # 1. Classificazione basata su OS
        os_classification = self._classify_by_os(device_data['os_info'])
        if os_classification['type'] != 'Unknown':
            classification['device_type'] = os_classification['type']
            classification['device_subtype'] = os_classification['subtype']
            confidence += os_classification['confidence']
            reasons.extend(os_classification['reasons'])

        # 2. Classificazione basata su servizi
        service_classification = self._classify_by_services(device_data['services'], device_data['open_ports'])
        if service_classification['type'] != 'Unknown':
            if classification['device_type'] == 'Unknown':
                classification['device_type'] = service_classification['type']
                classification['device_subtype'] = service_classification['subtype']
            elif service_classification['confidence'] > confidence:
                classification['device_subtype'] = service_classification['subtype']
            confidence += service_classification['confidence']
            reasons.extend(service_classification['reasons'])

        # 3. Classificazione basata su hostname
        hostname_classification = self._classify_by_hostname(device_data.get('hostname'))
        if hostname_classification['type'] != 'Unknown':
            if classification['device_type'] == 'Unknown':
                classification['device_type'] = hostname_classification['type']
            confidence += hostname_classification['confidence']
            reasons.extend(hostname_classification['reasons'])

        # 4. Classificazione basata su vendor/MAC
        vendor_classification = self._classify_by_vendor(device_data.get('vendor_oui') or device_data.get('vendor'))
        if vendor_classification['type'] != 'Unknown':
            if classification['device_type'] == 'Unknown':
                classification['device_type'] = vendor_classification['type']
            confidence += vendor_classification['confidence']
            reasons.extend(vendor_classification['reasons'])

        # 5. Classificazione basata su software
        software_classification = self._classify_by_software(device_data['software'])
        if software_classification['type'] != 'Unknown':
            if classification['device_type'] == 'Unknown':
                classification['device_type'] = software_classification['type']
            confidence += software_classification['confidence']
            reasons.extend(software_classification['reasons'])

        # 6. Classificazione basata su pattern porte
        port_classification = self._classify_by_port_patterns(device_data['open_ports'])
        if port_classification['type'] != 'Unknown':
            if classification['device_type'] == 'Unknown':
                classification['device_type'] = port_classification['type']
            confidence += port_classification['confidence']
            reasons.extend(port_classification['reasons'])

        # Normalizza confidence score (max 1.0)
        classification['confidence_score'] = min(confidence, 1.0)
        classification['classification_reasons'] = '; '.join(reasons)

        return classification

    def _classify_by_os(self, os_info: Dict) -> Dict:
        """Classificazione basata su informazioni OS"""
        if not os_info or not os_info.get('os_name'):
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        os_name = os_info['os_name'].lower()
        os_family = (os_info.get('os_family') or '').lower()
        os_type = (os_info.get('os_type') or '').lower()

        # Patterns per diversi tipi di dispositivi
        patterns = {
            'Server': {
                'patterns': ['server', 'windows server', 'linux', 'ubuntu server', 'centos', 'red hat', 'debian'],
                'subtypes': {
                    'windows server': 'Windows Server',
                    'linux': 'Linux Server',
                    'ubuntu': 'Ubuntu Server',
                    'centos': 'CentOS Server',
                    'debian': 'Debian Server'
                },
                'confidence': 0.8
            },
            'Workstation': {
                'patterns': ['windows 10', 'windows 11', 'windows 7', 'windows 8', 'macos', 'mac os'],
                'subtypes': {
                    'windows 10': 'Windows 10 PC',
                    'windows 11': 'Windows 11 PC',
                    'windows 7': 'Windows 7 PC',
                    'macos': 'MacOS Workstation'
                },
                'confidence': 0.9
            },
            'Network Device': {
                'patterns': ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'pfsense', 'openwrt', 'dd-wrt'],
                'subtypes': {
                    'cisco': 'Cisco Network Device',
                    'juniper': 'Juniper Network Device',
                    'mikrotik': 'MikroTik Router',
                    'ubiquiti': 'Ubiquiti Network Device'
                },
                'confidence': 0.9
            },
            'Mobile Device': {
                'patterns': ['android', 'ios', 'iphone', 'ipad'],
                'subtypes': {
                    'android': 'Android Device',
                    'ios': 'iOS Device',
                    'iphone': 'iPhone',
                    'ipad': 'iPad'
                },
                'confidence': 0.9
            },
            'Embedded System': {
                'patterns': ['embedded', 'firmware', 'busybox', 'openwrt'],
                'confidence': 0.7
            }
        }

        for device_type, config in patterns.items():
            for pattern in config['patterns']:
                if pattern in os_name or pattern in os_family:
                    subtype = None
                    if 'subtypes' in config:
                        for subpattern, subtype_name in config['subtypes'].items():
                            if subpattern in os_name:
                                subtype = subtype_name
                                break

                    return {
                        'type': device_type,
                        'subtype': subtype,
                        'confidence': config['confidence'],
                        'reasons': [f"OS detection: {os_info['os_name']}"]
                    }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _classify_by_services(self, services: List[str], ports_info: List[Dict]) -> Dict:
        """Classificazione basata su servizi in esecuzione"""
        if not services:
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        services_lower = [s.lower() for s in services if s]

        # Patterns per servizi specifici
        service_patterns = {
            'Server': {
                'web': ['http', 'https', 'apache', 'nginx', 'iis'],
                'database': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
                'mail': ['smtp', 'pop3', 'imap', 'exchange'],
                'file': ['ftp', 'sftp', 'smb', 'nfs', 'samba'],
                'dns': ['dns', 'domain'],
                'dhcp': ['dhcp'],
                'print': ['ipp', 'cups', 'printer']
            },
            'Network Device': {
                'management': ['snmp', 'telnet', 'ssh'],
                'routing': ['bgp', 'ospf', 'rip'],
                'switching': ['stp', 'vlan']
            },
            'Storage Device': {
                'storage': ['iscsi', 'nfs', 'smb', 'afp']
            },
            'Security Device': {
                'security': ['ssl-vpn', 'ipsec', 'firewall']
            },
            'IoT Device': {
                'iot': ['mqtt', 'coap', 'upnp']
            }
        }

        scores = {}
        reasons = []

        for device_type, categories in service_patterns.items():
            type_score = 0
            detected_services = []

            for category, category_services in categories.items():
                for service_pattern in category_services:
                    for service in services_lower:
                        if service_pattern in service:
                            type_score += 0.1
                            detected_services.append(service)

            if type_score > 0:
                scores[device_type] = type_score
                reasons.append(f"Services: {', '.join(set(detected_services))}")

        # Trova il tipo con score più alto
        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(scores[best_type], 0.8)

            # Determina sottotipo
            subtype = self._determine_server_subtype(services_lower) if best_type == 'Server' else None

            return {
                'type': best_type,
                'subtype': subtype,
                'confidence': confidence,
                'reasons': reasons
            }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _determine_server_subtype(self, services: List[str]) -> Optional[str]:
        """Determina il sottotipo di server basandosi sui servizi"""
        if any(s in services for s in ['http', 'https', 'apache', 'nginx', 'iis']):
            return 'Web Server'
        elif any(s in services for s in ['mysql', 'postgresql', 'mssql', 'oracle']):
            return 'Database Server'
        elif any(s in services for s in ['smtp', 'pop3', 'imap', 'exchange']):
            return 'Mail Server'
        elif any(s in services for s in ['ftp', 'sftp', 'smb', 'samba']):
            return 'File Server'
        elif any(s in services for s in ['dns', 'domain']):
            return 'DNS Server'
        elif any(s in services for s in ['dhcp']):
            return 'DHCP Server'

        return 'Generic Server'

    def _classify_by_hostname(self, hostname: Optional[str]) -> Dict:
        """Classificazione basata su hostname"""
        if not hostname:
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        hostname_lower = hostname.lower()

        hostname_patterns = {
            'Server': ['srv', 'server', 'web', 'db', 'mail', 'dns', 'dc', 'ad'],
            'Workstation': ['pc', 'desktop', 'workstation', 'ws', 'laptop'],
            'Network Device': ['router', 'switch', 'ap', 'firewall', 'gw', 'gateway'],
            'Printer': ['printer', 'print', 'hp', 'canon', 'epson'],
            'IoT Device': ['iot', 'sensor', 'camera', 'nvr']
        }

        for device_type, patterns in hostname_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return {
                        'type': device_type,
                        'subtype': None,
                        'confidence': 0.5,
                        'reasons': [f"Hostname pattern: {hostname}"]
                    }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _classify_by_vendor(self, vendor: Optional[str]) -> Dict:
        """Classificazione basata su vendor"""
        if not vendor:
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        vendor_lower = vendor.lower()

        vendor_patterns = {
            'Network Device': [
                'cisco', 'juniper', 'mikrotik', 'ubiquiti', 'netgear', 'linksys',
                'tp-link', 'huawei', 'zte', 'alcatel', 'ericsson', 'aruba'
            ],
            'Printer': [
                'hewlett', 'hp', 'canon', 'epson', 'brother', 'lexmark', 'xerox'
            ],
            'Mobile Device': [
                'apple', 'samsung', 'xiaomi', 'huawei', 'oneplus', 'lg'
            ],
            'IoT Device': [
                'raspberry', 'arduino', 'espressif', 'nordic'
            ]
        }

        for device_type, vendors in vendor_patterns.items():
            for vendor_pattern in vendors:
                if vendor_pattern in vendor_lower:
                    return {
                        'type': device_type,
                        'subtype': None,
                        'confidence': 0.6,
                        'reasons': [f"Vendor: {vendor}"]
                    }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _classify_by_software(self, software_list: List[str]) -> Dict:
        """Classificazione basata su software installato"""
        if not software_list:
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        software_lower = [s.lower() for s in software_list]

        software_patterns = {
            'Server': [
                'sql server', 'mysql', 'apache', 'nginx', 'iis', 'exchange',
                'active directory', 'domain controller'
            ],
            'Workstation': [
                'office', 'chrome', 'firefox', 'adobe', 'visual studio', 'photoshop'
            ]
        }

        for device_type, patterns in software_patterns.items():
            detected_software = []
            for pattern in patterns:
                for software in software_lower:
                    if pattern in software:
                        detected_software.append(pattern)

            if detected_software:
                return {
                    'type': device_type,
                    'subtype': None,
                    'confidence': 0.4,
                    'reasons': [f"Software: {', '.join(set(detected_software))}"]
                }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _classify_by_port_patterns(self, ports_info: List[Dict]) -> Dict:
        """Classificazione basata su pattern di porte aperte"""
        if not ports_info:
            return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

        open_ports = [p['port'] for p in ports_info]

        port_patterns = {
            'Server': {
                'web': [80, 443, 8080, 8443],
                'database': [1433, 3306, 5432, 1521, 27017],
                'mail': [25, 110, 143, 993, 995],
                'file': [21, 22, 139, 445, 2049]
            },
            'Network Device': {
                'management': [23, 22, 161, 162, 80, 443],
                'typical': [23, 161]  # Telnet + SNMP sono tipici
            },
            'Printer': [631, 9100, 515],  # IPP, JetDirect, LPD
            'Database Server': [1433, 3306, 5432, 1521, 27017],
            'Domain Controller': [53, 88, 135, 139, 389, 445, 464, 636]
        }

        scores = {}
        reasons = []

        # Check pattern complessi
        for device_type, patterns in port_patterns.items():
            if isinstance(patterns, dict):
                type_score = 0
                for category, category_ports in patterns.items():
                    matches = len(set(open_ports) & set(category_ports))
                    if matches > 0:
                        type_score += matches * 0.1
                        if matches >= 2:  # Almeno 2 porte della categoria
                            type_score += 0.2

                if type_score > 0:
                    scores[device_type] = type_score
                    matching_ports = set(open_ports) & set([p for cat_ports in patterns.values() for p in cat_ports])
                    reasons.append(f"Port pattern {device_type}: {sorted(matching_ports)}")

            elif isinstance(patterns, list):
                matches = len(set(open_ports) & set(patterns))
                if matches > 0:
                    scores[device_type] = matches * 0.15
                    matching_ports = set(open_ports) & set(patterns)
                    reasons.append(f"Port pattern {device_type}: {sorted(matching_ports)}")

        # Trova il tipo con score più alto
        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(scores[best_type], 0.6)

            return {
                'type': best_type,
                'subtype': None,
                'confidence': confidence,
                'reasons': reasons
            }

        return {'type': 'Unknown', 'subtype': None, 'confidence': 0.0, 'reasons': []}

    def _save_device_classification(self, ip_address: str, classification: Dict):
        """Salva la classificazione nel database"""
        try:
            self.db.cursor.execute('''
                INSERT OR REPLACE INTO device_classification 
                (ip_address, device_type, device_subtype, vendor, vendor_oui, 
                 confidence_score, classification_reasons, os_detected, main_services,
                 hostname_pattern, mac_vendor, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                classification['device_type'],
                classification['device_subtype'],
                classification['vendor'],
                classification['vendor_oui'],
                classification['confidence_score'],
                classification['classification_reasons'],
                classification['os_detected'],
                classification['main_services'],
                classification['hostname_pattern'],
                classification['mac_vendor'],
                datetime.now()
            ))

        except Exception as e:
            logger.error(f"Errore salvataggio classificazione per {ip_address}: {e}")

    def get_classification_summary(self) -> Dict:
        """Genera un riassunto delle classificazioni"""
        try:
            summary = {}

            # Conteggio per tipo di dispositivo
            self.db.cursor.execute('''
                SELECT device_type, COUNT(*) as count
                FROM device_classification 
                GROUP BY device_type 
                ORDER BY count DESC
            ''')
            summary['by_type'] = dict(self.db.cursor.fetchall())

            # Conteggio per sottotipo
            self.db.cursor.execute('''
                SELECT device_subtype, COUNT(*) as count
                FROM device_classification 
                WHERE device_subtype IS NOT NULL
                GROUP BY device_subtype 
                ORDER BY count DESC
            ''')
            summary['by_subtype'] = dict(self.db.cursor.fetchall())

            # Vendor più comuni
            self.db.cursor.execute('''
                SELECT vendor_oui, COUNT(*) as count
                FROM device_classification 
                WHERE vendor_oui IS NOT NULL
                GROUP BY vendor_oui 
                ORDER BY count DESC
                LIMIT 10
            ''')
            summary['top_vendors'] = dict(self.db.cursor.fetchall())

            # Classificazioni con confidence alta
            self.db.cursor.execute('''
                SELECT COUNT(*) FROM device_classification 
                WHERE confidence_score >= 0.7
            ''')
            summary['high_confidence'] = self.db.cursor.fetchone()[0]

            # Classificazioni con confidence bassa
            self.db.cursor.execute('''
                SELECT COUNT(*) FROM device_classification 
                WHERE confidence_score < 0.5
            ''')
            summary['low_confidence'] = self.db.cursor.fetchone()[0]

            return summary

        except Exception as e:
            logger.error(f"Errore generazione summary classificazione: {e}")
            return {}

    def export_classification_report(self, output_file: str = "../reports/device_classification_report.txt"):
        """Esporta report dettagliato delle classificazioni"""
        try:
            import os
            os.makedirs("../reports", exist_ok=True)

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("REPORT CLASSIFICAZIONE DISPOSITIVI\n")
                f.write("=" * 50 + "\n\n")

                # Summary
                summary = self.get_classification_summary()

                if summary.get('by_type'):
                    f.write("Distribuzione per tipo dispositivo:\n")
                    for device_type, count in summary['by_type'].items():
                        f.write(f"  {device_type}: {count}\n")
                    f.write("\n")

                if summary.get('by_subtype'):
                    f.write("Distribuzione per sottotipo:\n")
                    for subtype, count in summary['by_subtype'].items():
                        f.write(f"  {subtype}: {count}\n")
                    f.write("\n")

                if summary.get('top_vendors'):
                    f.write("Top 10 vendor (da OUI):\n")
                    for vendor, count in summary['top_vendors'].items():
                        f.write(f"  {vendor}: {count}\n")
                    f.write("\n")

                f.write(f"Classificazioni alta confidenza (>=0.7): {summary.get('high_confidence', 0)}\n")
                f.write(f"Classificazioni bassa confidenza (<0.5): {summary.get('low_confidence', 0)}\n\n")

                # Dettaglio classificazioni
                self.db.cursor.execute('''
                    SELECT h.ip_address, h.hostname, dc.device_type, dc.device_subtype, 
                           dc.vendor_oui, dc.confidence_score, dc.classification_reasons
                    FROM device_classification dc
                    JOIN hosts h ON dc.ip_address = h.ip_address
                    ORDER BY dc.confidence_score DESC, dc.device_type
                ''')

                classifications = self.db.cursor.fetchall()

                if classifications:
                    f.write("DETTAGLIO CLASSIFICAZIONI:\n")
                    f.write("-" * 40 + "\n")

                    for classification in classifications:
                        ip, hostname, dev_type, dev_subtype, vendor, confidence, reasons = classification
                        f.write(f"\nIP: {ip}")
                        if hostname:
                            f.write(f" ({hostname})")
                        f.write(f"\nTipo: {dev_type}")
                        if dev_subtype:
                            f.write(f" - {dev_subtype}")
                        if vendor:
                            f.write(f"\nVendor: {vendor}")
                        f.write(f"\nConfidenza: {confidence:.2f}")
                        f.write(f"\nMotivi: {reasons}")
                        f.write(f"\n{'-' * 30}\n")

                f.write("\nReport generato automaticamente dal Device Classifier\n")

            logger.info(f"Report classificazione esportato in: {output_file}")

        except Exception as e:
            logger.error(f"Errore esportazione report classificazione: {e}")