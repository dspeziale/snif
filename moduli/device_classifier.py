"""
Classificatore intelligente per identificare automaticamente il tipo di dispositivo
basato su MAC address, vendor, porte aperte, servizi e informazioni OS
"""
import re
from typing import Dict, List, Optional, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class DeviceClassifier:
    def __init__(self, config: Dict):
        self.config = config
        self.classification_rules = config.get('device_classification', {}).get('rules', {})
        self._load_extended_rules()

    def _load_extended_rules(self):
        """Carica regole di classificazione estese e pattern matching"""
        self.vendor_patterns = {
            'router': [
                'cisco', 'netgear', 'linksys', 'd-link', 'tp-link', 'asus', 'zyxel',
                'ubiquiti', 'mikrotik', 'juniper', 'fortinet', 'palo alto', 'sonicwall'
            ],
            'switch': [
                'cisco', 'hp', 'dell', 'netgear', 'zyxel', 'ubiquiti', 'extreme',
                'arista', 'juniper', 'brocade'
            ],
            'access_point': [
                'ubiquiti', 'cisco', 'aruba', 'ruckus', 'meraki', 'engenius'
            ],
            'printer': [
                'hp', 'canon', 'epson', 'brother', 'lexmark', 'xerox', 'ricoh',
                'kyocera', 'samsung', 'dell', 'oki'
            ],
            'server': [
                'dell', 'hp', 'ibm', 'lenovo', 'supermicro', 'intel', 'cisco'
            ],
            'workstation': [
                'dell', 'hp', 'lenovo', 'asus', 'msi', 'intel', 'gigabyte'
            ],
            'mobile': [
                'apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus',
                'lg', 'sony', 'htc', 'motorola'
            ],
            'iot': [
                'raspberry pi', 'arduino', 'esp', 'particle', 'adafruit'
            ],
            'camera': [
                'axis', 'hikvision', 'dahua', 'bosch', 'panasonic', 'sony',
                'vivotek', 'mobotix', 'geovision'
            ],
            'voip': [
                'cisco', 'avaya', 'polycom', 'yealink', 'grandstream', 'snom',
                'aastra', 'mitel'
            ]
        }

        self.service_signatures = {
            'router': ['ssh', 'telnet', 'http', 'https', 'snmp', 'upnp'],
            'switch': ['ssh', 'telnet', 'http', 'https', 'snmp'],
            'printer': ['ipp', 'lpd', 'http', 'https', 'snmp', 'jetdirect'],
            'server': ['ssh', 'rdp', 'http', 'https', 'ftp', 'smtp', 'sql'],
            'workstation': ['rdp', 'vnc', 'smb', 'http'],
            'voip': ['sip', 'h323', 'mgcp', 'sccp'],
            'camera': ['http', 'https', 'rtsp', 'onvif'],
            'nas': ['smb', 'nfs', 'ftp', 'http', 'https', 'ssh'],
            'database': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
            'web_server': ['http', 'https', 'apache', 'nginx', 'iis']
        }

        self.port_signatures = {
            'router': [22, 23, 80, 443, 161, 1900, 8080],
            'switch': [22, 23, 80, 443, 161],
            'printer': [80, 443, 515, 631, 9100, 161],
            'server': [22, 80, 443, 3389, 21, 25, 53, 1433, 3306],
            'workstation': [3389, 5900, 445, 135, 139],
            'voip': [5060, 5061, 1720, 2000, 4569],
            'camera': [80, 443, 554, 8080, 1935],
            'nas': [21, 22, 80, 139, 445, 548, 2049],
            'database': [1433, 3306, 5432, 1521, 27017],
            'mail_server': [25, 110, 143, 465, 587, 993, 995]
        }

        self.os_signatures = {
            'server': [
                'windows server', 'linux', 'ubuntu server', 'centos', 'red hat',
                'debian', 'freebsd', 'vmware', 'proxmox'
            ],
            'workstation': [
                'windows 10', 'windows 11', 'macos', 'ubuntu', 'fedora'
            ],
            'router': [
                'ios', 'junos', 'routeros', 'openwrt', 'dd-wrt', 'pfsense'
            ],
            'mobile': [
                'ios', 'android', 'windows phone'
            ]
        }

    def classify_device(self, host_info: Dict[str, Any], scan_data: Dict[str, Any]) -> Optional[str]:
        """Classifica un dispositivo basandosi sui dati disponibili"""
        try:
            scores = {}

            # Analizza vendor/MAC
            vendor_scores = self._analyze_vendor(host_info.get('vendor', ''), host_info.get('mac_address', ''))
            for device_type, score in vendor_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            # Analizza OS
            os_scores = self._analyze_os(host_info.get('os_name', ''), host_info.get('os_family', ''))
            for device_type, score in os_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            # Analizza porte e servizi
            ports_services_scores = self._analyze_ports_services(scan_data)
            for device_type, score in ports_services_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            # Analizza hostname
            hostname_scores = self._analyze_hostname(host_info.get('hostname', ''))
            for device_type, score in hostname_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            # Trova il tipo con score più alto
            if scores:
                best_type = max(scores, key=scores.get)
                best_score = scores[best_type]

                # Soglia minima per classificazione
                if best_score >= 10:
                    logger.debug(f"Device classificato come {best_type} (score: {best_score})")
                    return best_type
                else:
                    logger.debug(f"Score troppo basso per classificazione: {best_score}")

            return 'unknown'

        except Exception as e:
            logger.error(f"Errore classificazione device: {e}")
            return 'unknown'

    def _analyze_vendor(self, vendor: str, mac_address: str) -> Dict[str, float]:
        """Analizza vendor e MAC address per classificazione"""
        scores = {}

        if not vendor:
            return scores

        vendor_lower = vendor.lower()

        # Controlla pattern vendor
        for device_type, patterns in self.vendor_patterns.items():
            for pattern in patterns:
                if pattern in vendor_lower:
                    scores[device_type] = scores.get(device_type, 0) + 25
                    break

        # Analisi specifica per vendor noti
        vendor_specific_rules = {
            'apple': {'mobile': 30, 'workstation': 15},
            'microsoft': {'workstation': 20, 'server': 10},
            'vmware': {'server': 35},
            'raspberry pi': {'iot': 40},
            'intel': {'workstation': 10, 'server': 10},
            'realtek': {'workstation': 15, 'router': 10}
        }

        for vendor_key, type_scores in vendor_specific_rules.items():
            if vendor_key in vendor_lower:
                for device_type, score in type_scores.items():
                    scores[device_type] = scores.get(device_type, 0) + score

        return scores

    def _analyze_os(self, os_name: str, os_family: str) -> Dict[str, float]:
        """Analizza informazioni OS per classificazione"""
        scores = {}

        os_text = f"{os_name} {os_family}".lower()

        if not os_text.strip():
            return scores

        # Pattern OS specifici
        os_patterns = {
            'server': [
                'server', 'centos', 'rhel', 'ubuntu server', 'debian',
                'freebsd', 'vmware', 'esxi', 'proxmox', 'hyper-v'
            ],
            'workstation': [
                'windows 10', 'windows 11', 'macos', 'ubuntu', 'fedora',
                'mint', 'arch', 'manjaro'
            ],
            'router': [
                'ios', 'junos', 'routeros', 'openwrt', 'dd-wrt',
                'pfsense', 'vyos', 'cisco'
            ],
            'mobile': [
                'android', 'ios', 'iphone', 'ipad'
            ],
            'printer': [
                'printer', 'jetdirect', 'postscript'
            ]
        }

        for device_type, patterns in os_patterns.items():
            for pattern in patterns:
                if pattern in os_text:
                    scores[device_type] = scores.get(device_type, 0) + 30
                    break

        # Regole specifiche
        if 'windows' in os_text:
            if 'server' in os_text:
                scores['server'] = scores.get('server', 0) + 35
            else:
                scores['workstation'] = scores.get('workstation', 0) + 25

        if 'linux' in os_text:
            scores['server'] = scores.get('server', 0) + 15
            scores['workstation'] = scores.get('workstation', 0) + 10

        return scores

    def _analyze_ports_services(self, scan_data: Dict[str, Any]) -> Dict[str, float]:
        """Analizza porte e servizi per classificazione"""
        scores = {}

        open_ports = []
        services = []

        # Estrai porte e servizi
        for port_data in scan_data.get('ports', []):
            if port_data.get('state', {}).get('state') == 'open':
                port_num = port_data.get('portid')
                if port_num:
                    open_ports.append(port_num)

                service_info = port_data.get('service', {})
                service_name = service_info.get('name')
                if service_name:
                    services.append(service_name.lower())

        # Analizza porte
        for device_type, signature_ports in self.port_signatures.items():
            matches = len(set(open_ports) & set(signature_ports))
            if matches > 0:
                scores[device_type] = scores.get(device_type, 0) + (matches * 8)

        # Analizza servizi
        for device_type, signature_services in self.service_signatures.items():
            matches = len(set(services) & set(signature_services))
            if matches > 0:
                scores[device_type] = scores.get(device_type, 0) + (matches * 10)

        # Regole specifiche per combinazioni
        self._apply_port_service_rules(open_ports, services, scores)

        return scores

    def _apply_port_service_rules(self, open_ports: List[int], services: List[str], scores: Dict[str, float]):
        """Applica regole specifiche basate su combinazioni porte/servizi"""

        # Web server detection
        if any(port in open_ports for port in [80, 443, 8080, 8443]):
            web_services = ['http', 'https', 'apache', 'nginx', 'iis']
            if any(service in services for service in web_services):
                scores['web_server'] = scores.get('web_server', 0) + 20

        # Database server
        db_ports = [1433, 3306, 5432, 1521, 27017]
        db_services = ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb']
        if any(port in open_ports for port in db_ports) or any(service in services for service in db_services):
            scores['database'] = scores.get('database', 0) + 25

        # Mail server
        mail_ports = [25, 110, 143, 465, 587, 993, 995]
        mail_services = ['smtp', 'pop3', 'imap', 'exchange']
        if any(port in open_ports for port in mail_ports) or any(service in services for service in mail_services):
            scores['mail_server'] = scores.get('mail_server', 0) + 25

        # Printer específico
        if 9100 in open_ports or 'jetdirect' in services:
            scores['printer'] = scores.get('printer', 0) + 30

        # VoIP phone
        if 5060 in open_ports or 'sip' in services:
            scores['voip'] = scores.get('voip', 0) + 30

        # Network equipment
        if 161 in open_ports and ('snmp' in services):
            scores['router'] = scores.get('router', 0) + 15
            scores['switch'] = scores.get('switch', 0) + 15

        # Remote access
        if 3389 in open_ports or 'rdp' in services:
            scores['server'] = scores.get('server', 0) + 10
            scores['workstation'] = scores.get('workstation', 0) + 15

        # SSH indicates server/network device
        if 22 in open_ports or 'ssh' in services:
            scores['server'] = scores.get('server', 0) + 8
            scores['router'] = scores.get('router', 0) + 5

        # SMB/CIFS indicates Windows
        if any(port in open_ports for port in [139, 445]) or 'smb' in services:
            scores['workstation'] = scores.get('workstation', 0) + 12
            scores['server'] = scores.get('server', 0) + 8

    def _analyze_hostname(self, hostname: str) -> Dict[str, float]:
        """Analizza hostname per classificazione"""
        scores = {}

        if not hostname:
            return scores

        hostname_lower = hostname.lower()

        # Pattern hostname comuni
        hostname_patterns = {
            'router': ['router', 'gw', 'gateway', 'fw', 'firewall', 'pfsense'],
            'switch': ['switch', 'sw', 'core', 'access'],
            'server': ['server', 'srv', 'db', 'web', 'mail', 'dns', 'dc', 'ad'],
            'workstation': ['pc', 'desktop', 'ws', 'workstation', 'laptop'],
            'printer': ['printer', 'print', 'hp', 'canon', 'epson'],
            'camera': ['cam', 'camera', 'ipcam', 'cctv'],
            'voip': ['phone', 'voip', 'sip', 'pbx'],
            'ap': ['ap', 'wifi', 'wireless', 'wlan']
        }

        for device_type, patterns in hostname_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    scores[device_type] = scores.get(device_type, 0) + 20
                    break

        # Pattern numerici (spesso workstation)
        if re.match(r'^[a-zA-Z]+-\d+$', hostname):
            scores['workstation'] = scores.get('workstation', 0) + 10

        return scores

    def get_device_confidence(self, classification_result: str, all_scores: Dict[str, float]) -> float:
        """Calcola il livello di confidenza della classificazione"""
        if not all_scores or classification_result not in all_scores:
            return 0.0

        best_score = all_scores[classification_result]
        total_score = sum(all_scores.values())

        if total_score == 0:
            return 0.0

        # Confidenza basata su score relativo
        confidence = best_score / total_score

        # Bonus per score alto
        if best_score >= 50:
            confidence += 0.2
        elif best_score >= 30:
            confidence += 0.1

        return min(confidence, 1.0)

    def classify_with_confidence(self, host_info: Dict[str, Any], scan_data: Dict[str, Any]) -> Tuple[str, float]:
        """Classifica device e restituisce anche il livello di confidenza"""
        # Modifica temporanea del metodo classify_device per restituire anche i scores
        original_classify = self.classify_device

        def classify_with_scores(host_info, scan_data):
            scores = {}

            # [Stesso codice del classify_device ma memorizzando tutti i scores]
            vendor_scores = self._analyze_vendor(host_info.get('vendor', ''), host_info.get('mac_address', ''))
            for device_type, score in vendor_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            os_scores = self._analyze_os(host_info.get('os_name', ''), host_info.get('os_family', ''))
            for device_type, score in os_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            ports_services_scores = self._analyze_ports_services(scan_data)
            for device_type, score in ports_services_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            hostname_scores = self._analyze_hostname(host_info.get('hostname', ''))
            for device_type, score in hostname_scores.items():
                scores[device_type] = scores.get(device_type, 0) + score

            if scores:
                best_type = max(scores, key=scores.get)
                best_score = scores[best_type]

                if best_score >= 10:
                    return best_type, scores

            return 'unknown', scores

        device_type, all_scores = classify_with_scores(host_info, scan_data)
        confidence = self.get_device_confidence(device_type, all_scores)

        return device_type, confidence

    def get_classification_details(self, host_info: Dict[str, Any], scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restituisce dettagli completi della classificazione"""
        device_type, confidence = self.classify_with_confidence(host_info, scan_data)

        return {
            'device_type': device_type,
            'confidence': confidence,
            'confidence_level': self._get_confidence_level(confidence),
            'classification_factors': {
                'vendor': host_info.get('vendor'),
                'os': host_info.get('os_name'),
                'hostname': host_info.get('hostname'),
                'open_ports': len([p for p in scan_data.get('ports', [])
                                   if p.get('state', {}).get('state') == 'open']),
                'services': [p.get('service', {}).get('name') for p in scan_data.get('ports', [])
                             if p.get('service', {}).get('name')]
            }
        }

    def _get_confidence_level(self, confidence: float) -> str:
        """Converte confidence numerica in livello testuale"""
        if confidence >= 0.8:
            return 'high'
        elif confidence >= 0.6:
            return 'medium'
        elif confidence >= 0.3:
            return 'low'
        else:
            return 'very_low'

    def add_custom_rule(self, device_type: str, rule_type: str, pattern: str, score: int = 10):
        """Aggiunge una regola di classificazione personalizzata"""
        if rule_type == 'vendor':
            if device_type not in self.vendor_patterns:
                self.vendor_patterns[device_type] = []
            self.vendor_patterns[device_type].append(pattern.lower())

        elif rule_type == 'service':
            if device_type not in self.service_signatures:
                self.service_signatures[device_type] = []
            self.service_signatures[device_type].append(pattern.lower())

        elif rule_type == 'port':
            try:
                port_num = int(pattern)
                if device_type not in self.port_signatures:
                    self.port_signatures[device_type] = []
                self.port_signatures[device_type].append(port_num)
            except ValueError:
                logger.error(f"Invalid port number: {pattern}")

        logger.info(f"Added custom rule: {device_type} - {rule_type} - {pattern}")

    def export_rules(self) -> Dict[str, Any]:
        """Esporta tutte le regole di classificazione"""
        return {
            'vendor_patterns': self.vendor_patterns,
            'service_signatures': self.service_signatures,
            'port_signatures': self.port_signatures,
            'os_signatures': self.os_signatures
        }

    def import_rules(self, rules: Dict[str, Any]):
        """Importa regole di classificazione"""
        if 'vendor_patterns' in rules:
            self.vendor_patterns.update(rules['vendor_patterns'])

        if 'service_signatures' in rules:
            self.service_signatures.update(rules['service_signatures'])

        if 'port_signatures' in rules:
            self.port_signatures.update(rules['port_signatures'])

        if 'os_signatures' in rules:
            self.os_signatures.update(rules['os_signatures'])

        logger.info("Classification rules imported successfully")


class DeviceTypeManager:
    """Gestore per i tipi di device e le loro caratteristiche"""

    def __init__(self):
        self.device_types = {
            'router': {
                'category': 'network',
                'description': 'Router di rete',
                'typical_ports': [22, 23, 80, 443, 161],
                'typical_services': ['ssh', 'telnet', 'http', 'https', 'snmp'],
                'risk_level': 'high'
            },
            'switch': {
                'category': 'network',
                'description': 'Switch di rete',
                'typical_ports': [22, 23, 80, 443, 161],
                'typical_services': ['ssh', 'telnet', 'http', 'https', 'snmp'],
                'risk_level': 'medium'
            },
            'server': {
                'category': 'compute',
                'description': 'Server',
                'typical_ports': [22, 80, 443, 3389],
                'typical_services': ['ssh', 'http', 'https', 'rdp'],
                'risk_level': 'high'
            },
            'workstation': {
                'category': 'compute',
                'description': 'Workstation/PC',
                'typical_ports': [3389, 5900, 445],
                'typical_services': ['rdp', 'vnc', 'smb'],
                'risk_level': 'medium'
            },
            'printer': {
                'category': 'peripheral',
                'description': 'Stampante di rete',
                'typical_ports': [80, 443, 515, 631, 9100],
                'typical_services': ['http', 'https', 'lpd', 'ipp', 'jetdirect'],
                'risk_level': 'low'
            },
            'voip': {
                'category': 'communication',
                'description': 'Telefono VoIP',
                'typical_ports': [5060, 5061, 1720],
                'typical_services': ['sip', 'h323'],
                'risk_level': 'medium'
            },
            'mobile': {
                'category': 'endpoint',
                'description': 'Dispositivo mobile',
                'typical_ports': [80, 443],
                'typical_services': ['http', 'https'],
                'risk_level': 'low'
            },
            'iot': {
                'category': 'iot',
                'description': 'Dispositivo IoT',
                'typical_ports': [80, 443, 1883],
                'typical_services': ['http', 'https', 'mqtt'],
                'risk_level': 'high'
            },
            'camera': {
                'category': 'security',
                'description': 'Telecamera IP',
                'typical_ports': [80, 443, 554, 8080],
                'typical_services': ['http', 'https', 'rtsp'],
                'risk_level': 'high'
            },
            'nas': {
                'category': 'storage',
                'description': 'Network Attached Storage',
                'typical_ports': [21, 22, 80, 139, 445, 2049],
                'typical_services': ['ftp', 'ssh', 'http', 'smb', 'nfs'],
                'risk_level': 'high'
            },
            'database': {
                'category': 'service',
                'description': 'Database Server',
                'typical_ports': [1433, 3306, 5432, 1521, 27017],
                'typical_services': ['mssql', 'mysql', 'postgresql', 'oracle', 'mongodb'],
                'risk_level': 'critical'
            },
            'web_server': {
                'category': 'service',
                'description': 'Web Server',
                'typical_ports': [80, 443, 8080, 8443],
                'typical_services': ['http', 'https', 'apache', 'nginx', 'iis'],
                'risk_level': 'high'
            },
            'mail_server': {
                'category': 'service',
                'description': 'Mail Server',
                'typical_ports': [25, 110, 143, 465, 587, 993, 995],
                'typical_services': ['smtp', 'pop3', 'imap'],
                'risk_level': 'high'
            },
            'access_point': {
                'category': 'network',
                'description': 'Access Point WiFi',
                'typical_ports': [22, 23, 80, 443, 161],
                'typical_services': ['ssh', 'telnet', 'http', 'https', 'snmp'],
                'risk_level': 'medium'
            },
            'firewall': {
                'category': 'security',
                'description': 'Firewall',
                'typical_ports': [22, 443, 161],
                'typical_services': ['ssh', 'https', 'snmp'],
                'risk_level': 'critical'
            },
            'ups': {
                'category': 'infrastructure',
                'description': 'Uninterruptible Power Supply',
                'typical_ports': [161, 3052],
                'typical_services': ['snmp', 'ups'],
                'risk_level': 'low'
            },
            'unknown': {
                'category': 'unknown',
                'description': 'Dispositivo non classificato',
                'typical_ports': [],
                'typical_services': [],
                'risk_level': 'medium'
            }
        }

    def get_device_info(self, device_type: str) -> Dict[str, Any]:
        """Restituisce informazioni su un tipo di dispositivo"""
        return self.device_types.get(device_type, self.device_types['unknown'])

    def get_risk_level(self, device_type: str) -> str:
        """Restituisce il livello di rischio per un tipo di dispositivo"""
        return self.get_device_info(device_type).get('risk_level', 'medium')

    def get_devices_by_category(self, category: str) -> List[str]:
        """Restituisce tutti i dispositivi di una categoria"""
        return [dtype for dtype, info in self.device_types.items()
                if info.get('category') == category]

    def get_all_categories(self) -> List[str]:
        """Restituisce tutte le categorie disponibili"""
        return list(set(info.get('category') for info in self.device_types.values()))

    def is_critical_device(self, device_type: str) -> bool:
        """Verifica se un dispositivo è considerato critico"""
        risk_level = self.get_risk_level(device_type)
        return risk_level in ['critical', 'high']

    def get_security_recommendations(self, device_type: str) -> List[str]:
        """Restituisce raccomandazioni di sicurezza per un tipo di dispositivo"""
        recommendations = {
            'router': [
                'Cambiare password di default',
                'Disabilitare servizi non necessari',
                'Aggiornare firmware regolarmente',
                'Configurare logging',
                'Limitare accesso amministrativo'
            ],
            'server': [
                'Installare aggiornamenti di sicurezza',
                'Configurare firewall locale',
                'Implementare monitoring',
                'Backup regolari',
                'Hardening del sistema operativo'
            ],
            'printer': [
                'Cambiare password amministratore',
                'Disabilitare protocolli non sicuri',
                'Aggiornare firmware',
                'Limitare accesso di rete'
            ],
            'iot': [
                'Cambiare credenziali di default',
                'Isolare in VLAN dedicata',
                'Monitorare traffico di rete',
                'Disabilitare funzioni non necessarie'
            ],
            'camera': [
                'Cambiare password di default',
                'Aggiornare firmware',
                'Configurare crittografia',
                'Limitare accesso remoto'
            ]
        }

        return recommendations.get(device_type, [
            'Verificare configurazioni di sicurezza',
            'Monitorare per attività anomale',
            'Mantenere aggiornato il software'
        ])


class NetworkTopologyAnalyzer:
    """Analizzatore per dedurre la topologia di rete dai dispositivi scansionati"""

    def __init__(self, db_manager):
        self.db = db_manager
        self.device_manager = DeviceTypeManager()

    def analyze_network_topology(self) -> Dict[str, Any]:
        """Analizza la topologia di rete basandosi sui dispositivi trovati"""
        hosts = self.db.get_all_hosts(active_only=True)

        analysis = {
            'total_devices': len(hosts),
            'device_distribution': {},
            'network_segments': {},
            'critical_devices': [],
            'potential_issues': [],
            'security_score': 0.0,
            'recommendations': []
        }

        # Analizza distribuzione per tipo
        for host in hosts:
            device_type = host.get('device_type', 'unknown')
            analysis['device_distribution'][device_type] = \
                analysis['device_distribution'].get(device_type, 0) + 1

        # Identifica dispositivi critici
        for host in hosts:
            device_type = host.get('device_type', 'unknown')
            if self.device_manager.is_critical_device(device_type):
                analysis['critical_devices'].append({
                    'ip': host.get('ip_address'),
                    'hostname': host.get('hostname'),
                    'type': device_type,
                    'risk_level': self.device_manager.get_risk_level(device_type)
                })

        # Analizza segmenti di rete
        analysis['network_segments'] = self._analyze_network_segments(hosts)

        # Identifica potenziali problemi
        analysis['potential_issues'] = self._identify_potential_issues(hosts)

        # Calcola security score
        analysis['security_score'] = self._calculate_security_score(hosts)

        # Genera raccomandazioni
        analysis['recommendations'] = self._generate_network_recommendations(analysis)

        return analysis

    def _analyze_network_segments(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analizza i segmenti di rete"""
        segments = {}

        for host in hosts:
            ip = host.get('ip_address', '')
            if not ip:
                continue

            # Estrai subnet /24
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                subnet = f"{'.'.join(ip_parts[:3])}.0/24"

                if subnet not in segments:
                    segments[subnet] = {
                        'hosts': [],
                        'device_types': {},
                        'risk_level': 'low'
                    }

                segments[subnet]['hosts'].append(host)
                device_type = host.get('device_type', 'unknown')
                segments[subnet]['device_types'][device_type] = \
                    segments[subnet]['device_types'].get(device_type, 0) + 1

                # Aggiorna risk level del segmento
                host_risk = self.device_manager.get_risk_level(device_type)
                if host_risk == 'critical':
                    segments[subnet]['risk_level'] = 'critical'
                elif host_risk == 'high' and segments[subnet]['risk_level'] != 'critical':
                    segments[subnet]['risk_level'] = 'high'

        return segments

    def _identify_potential_issues(self, hosts: List[Dict]) -> List[Dict[str, Any]]:
        """Identifica potenziali problemi di sicurezza"""
        issues = []

        # Controlla dispositivi senza classificazione
        unknown_devices = [h for h in hosts if h.get('device_type') == 'unknown']
        if unknown_devices:
            issues.append({
                'type': 'classification',
                'severity': 'medium',
                'description': f'{len(unknown_devices)} dispositivi non classificati',
                'affected_devices': [h.get('ip_address') for h in unknown_devices[:5]]
            })

        # Controlla dispositivi IoT non isolati
        iot_devices = [h for h in hosts if h.get('device_type') == 'iot']
        if len(iot_devices) > 0:
            issues.append({
                'type': 'iot_security',
                'severity': 'high',
                'description': f'{len(iot_devices)} dispositivi IoT rilevati - verificare isolamento',
                'affected_devices': [h.get('ip_address') for h in iot_devices]
            })

        # Controlla presenza di molti dispositivi critici
        critical_devices = [h for h in hosts
                            if self.device_manager.is_critical_device(h.get('device_type', 'unknown'))]
        if len(critical_devices) > 10:
            issues.append({
                'type': 'critical_density',
                'severity': 'medium',
                'description': f'{len(critical_devices)} dispositivi critici - implementare segmentazione',
                'affected_devices': []
            })

        # Controlla dispositivi con porte critiche aperte
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389]
        devices_with_risk_ports = []

        for host in hosts:
            host_ports = self.db.get_host_ports(host.get('id', 0))
            open_risk_ports = [p for p in host_ports
                               if p.get('port') in high_risk_ports and p.get('state') == 'open']
            if open_risk_ports:
                devices_with_risk_ports.append({
                    'ip': host.get('ip_address'),
                    'ports': [p.get('port') for p in open_risk_ports]
                })

        if devices_with_risk_ports:
            issues.append({
                'type': 'high_risk_ports',
                'severity': 'high',
                'description': f'{len(devices_with_risk_ports)} dispositivi con porte ad alto rischio aperte',
                'affected_devices': [d['ip'] for d in devices_with_risk_ports[:5]]
            })

        return issues

    def _calculate_security_score(self, hosts: List[Dict]) -> float:
        """Calcola uno score di sicurezza della rete"""
        if not hosts:
            return 0.0

        score = 100.0

        # Penalità per dispositivi non classificati
        unknown_count = len([h for h in hosts if h.get('device_type') == 'unknown'])
        score -= (unknown_count / len(hosts)) * 30

        # Penalità per dispositivi IoT
        iot_count = len([h for h in hosts if h.get('device_type') == 'iot'])
        score -= (iot_count / len(hosts)) * 20

        # Penalità per dispositivi con vulnerabilità
        vuln_count = 0
        for host in hosts:
            host_vulns = self.db.get_host_vulnerabilities(host.get('id', 0))
            vuln_count += len(host_vulns)

        if vuln_count > 0:
            vuln_ratio = vuln_count / len(hosts)
            score -= min(vuln_ratio * 25, 40)

        # Bonus per diversità di dispositivi (indica rete ben strutturata)
        device_types = set(h.get('device_type', 'unknown') for h in hosts)
        if len(device_types) > 5:
            score += 10

        # Penalità per troppi dispositivi critici non segmentati
        critical_count = len([h for h in hosts
                              if self.device_manager.is_critical_device(h.get('device_type', 'unknown'))])
        if critical_count > len(hosts) * 0.3:  # Più del 30% critici
            score -= 15

        return max(0.0, min(100.0, score))

    def _generate_network_recommendations(self, analysis: Dict) -> List[str]:
        """Genera raccomandazioni per la rete"""
        recommendations = []

        if analysis['device_distribution'].get('unknown', 0) > 0:
            recommendations.append(
                f"Classificare {analysis['device_distribution']['unknown']} dispositivi non identificati"
            )

        if len(analysis['critical_devices']) > 0:
            recommendations.append(
                f"Implementare monitoring avanzato per {len(analysis['critical_devices'])} dispositivi critici"
            )

        if analysis['device_distribution'].get('iot', 0) > 0:
            recommendations.append(
                "Considerare isolamento VLAN per dispositivi IoT"
            )

        if analysis['security_score'] < 70:
            recommendations.append(
                "Security score basso - implementare hardening dei dispositivi"
            )

        if len(analysis['network_segments']) > 3:
            recommendations.append(
                "Considerare implementazione di micro-segmentazione"
            )

        # Raccomandazioni specifiche per problemi identificati
        for issue in analysis['potential_issues']:
            if issue['type'] == 'high_risk_ports':
                recommendations.append(
                    "Chiudere o proteggere porte ad alto rischio (FTP, Telnet, RDP, SMB, SQL)"
                )
            elif issue['type'] == 'iot_security':
                recommendations.append(
                    "Isolare dispositivi IoT in VLAN separata con policy restrittive"
                )

        return recommendations

    def generate_network_map(self) -> Dict[str, Any]:
        """Genera una mappa della topologia di rete"""
        hosts = self.db.get_all_hosts(active_only=True)

        network_map = {
            'nodes': [],
            'edges': [],
            'subnets': {},
            'device_clusters': {},
            'critical_paths': []
        }

        # Crea nodi per ogni host
        for host in hosts:
            node = {
                'id': host.get('ip_address'),
                'label': host.get('hostname') or host.get('ip_address'),
                'type': host.get('device_type', 'unknown'),
                'risk_level': self.device_manager.get_risk_level(host.get('device_type', 'unknown')),
                'status': host.get('status', 'unknown'),
                'vendor': host.get('vendor'),
                'os': host.get('os_name')
            }
            network_map['nodes'].append(node)

        # Raggruppa per subnet
        for host in hosts:
            ip = host.get('ip_address', '')
            if ip:
                subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                if subnet not in network_map['subnets']:
                    network_map['subnets'][subnet] = []
                network_map['subnets'][subnet].append(ip)

        # Raggruppa per tipo di dispositivo
        for host in hosts:
            device_type = host.get('device_type', 'unknown')
            if device_type not in network_map['device_clusters']:
                network_map['device_clusters'][device_type] = []
            network_map['device_clusters'][device_type].append(host.get('ip_address'))

        # Identifica possibili connessioni logiche
        # (router/gateway presumibilmente .1, server su porte standard, etc.)
        for subnet, ips in network_map['subnets'].items():
            gateway_ip = subnet.replace('.0/24', '.1')
            if gateway_ip in ips:
                # Crea edge da gateway a tutti gli altri dispositivi del subnet
                for ip in ips:
                    if ip != gateway_ip:
                        edge = {
                            'from': gateway_ip,
                            'to': ip,
                            'type': 'subnet_connection',
                            'subnet': subnet
                        }
                        network_map['edges'].append(edge)

        return network_map

    def detect_network_anomalies(self) -> List[Dict[str, Any]]:
        """Rileva anomalie nella topologia di rete"""
        hosts = self.db.get_all_hosts(active_only=True)
        anomalies = []

        # Dispositivi con molte porte aperte (possibili honeypot o compromessi)
        for host in hosts:
            host_ports = self.db.get_host_ports(host.get('id', 0))
            open_ports = [p for p in host_ports if p.get('state') == 'open']

            if len(open_ports) > 20:
                anomalies.append({
                    'type': 'excessive_open_ports',
                    'severity': 'medium',
                    'host': host.get('ip_address'),
                    'description': f'Dispositivo con {len(open_ports)} porte aperte',
                    'details': {'open_ports_count': len(open_ports)}
                })

        # Dispositivi con servizi inusuali per il loro tipo
        for host in hosts:
            device_type = host.get('device_type', 'unknown')
            if device_type == 'unknown':
                continue

            expected_services = self.device_manager.get_device_info(device_type).get('typical_services', [])
            host_ports = self.db.get_host_ports(host.get('id', 0))
            host_services = [p.get('service_name') for p in host_ports if p.get('service_name')]

            unexpected_services = [s for s in host_services if s and s not in expected_services]
            if len(unexpected_services) > 3:
                anomalies.append({
                    'type': 'unexpected_services',
                    'severity': 'low',
                    'host': host.get('ip_address'),
                    'description': f'Servizi inaspettati per dispositivo {device_type}',
                    'details': {'unexpected_services': unexpected_services[:5]}
                })

        # Dispositivi con hostname sospetti
        suspicious_patterns = [
            'test', 'hack', 'exploit', 'backdoor', 'shell', 'root', 'admin123'
        ]

        for host in hosts:
            hostname = host.get('hostname', '').lower()
            if hostname and any(pattern in hostname for pattern in suspicious_patterns):
                anomalies.append({
                    'type': 'suspicious_hostname',
                    'severity': 'high',
                    'host': host.get('ip_address'),
                    'description': f'Hostname sospetto: {hostname}',
                    'details': {'hostname': hostname}
                })

        return anomalies


class DeviceFingerprinter:
    """Classe per fingerprinting avanzato dei dispositivi"""

    def __init__(self):
        self.fingerprints = self._load_fingerprint_database()

    def _load_fingerprint_database(self) -> Dict[str, Any]:
        """Carica database di fingerprint noti"""
        return {
            'web_servers': {
                'apache': {
                    'headers': ['Server: Apache'],
                    'responses': ['Apache HTTP Server'],
                    'ports': [80, 443, 8080]
                },
                'nginx': {
                    'headers': ['Server: nginx'],
                    'responses': ['nginx'],
                    'ports': [80, 443]
                },
                'iis': {
                    'headers': ['Server: Microsoft-IIS'],
                    'responses': ['Microsoft-IIS'],
                    'ports': [80, 443]
                }
            },
            'databases': {
                'mysql': {
                    'banners': ['MySQL'],
                    'ports': [3306],
                    'responses': ['mysql_native_password']
                },
                'postgresql': {
                    'banners': ['PostgreSQL'],
                    'ports': [5432]
                },
                'mssql': {
                    'banners': ['Microsoft SQL Server'],
                    'ports': [1433]
                }
            },
            'network_devices': {
                'cisco_ios': {
                    'banners': ['Cisco IOS'],
                    'ssh_versions': ['SSH-2.0-Cisco'],
                    'snmp_sysDescr': ['Cisco IOS Software']
                },
                'juniper_junos': {
                    'banners': ['JUNOS'],
                    'ssh_versions': ['SSH-2.0-OpenSSH_Juniper']
                }
            }
        }

    def enhanced_fingerprint(self, host_data: Dict[str, Any], nse_scripts: List[Dict]) -> Dict[str, Any]:
        """Esegue fingerprinting avanzato basato su banner e script NSE"""
        fingerprint_results = {
            'detected_software': [],
            'detected_versions': [],
            'confidence_scores': {},
            'additional_info': {}
        }

        # Analizza banner dei servizi
        for port in host_data.get('ports', []):
            service = port.get('service', {})
            if service.get('product'):
                software_info = {
                    'software': service.get('product'),
                    'version': service.get('version'),
                    'port': port.get('portid'),
                    'confidence': 'high' if service.get('version') else 'medium'
                }
                fingerprint_results['detected_software'].append(software_info)

        # Analizza script NSE per informazioni aggiuntive
        for script in nse_scripts:
            script_id = script.get('id', '')
            script_output = script.get('output', '')

            # HTTP headers analysis
            if script_id == 'http-server-header':
                server_header = script_output
                for category, servers in self.fingerprints.get('web_servers', {}).items():
                    for pattern in servers.get('headers', []):
                        if pattern.split(': ')[1] in server_header:
                            fingerprint_results['detected_software'].append({
                                'software': category,
                                'evidence': server_header,
                                'confidence': 'high'
                            })

            # SNMP system description
            elif script_id == 'snmp-sysdescr':
                sys_descr = script_output
                for category, devices in self.fingerprints.get('network_devices', {}).items():
                    for pattern in devices.get('snmp_sysDescr', []):
                        if pattern in sys_descr:
                            fingerprint_results['detected_software'].append({
                                'software': category,
                                'evidence': sys_descr,
                                'confidence': 'high'
                            })

        return fingerprint_results

    def detect_evasion_techniques(self, host_data: Dict[str, Any]) -> List[str]:
        """Rileva possibili tecniche di evasion"""
        evasion_indicators = []

        # Porte in ordine non standard
        open_ports = [p.get('portid') for p in host_data.get('ports', [])
                      if p.get('state', {}).get('state') == 'open']

        if open_ports:
            # Controlla porte ad alto numero (possibile port knocking)
            high_ports = [p for p in open_ports if p > 32768]
            if len(high_ports) > 5:
                evasion_indicators.append('multiple_high_ports')

            # Controlla sequenze di porte
            if len(open_ports) > 3:
                sorted_ports = sorted(open_ports)
                sequential = all(sorted_ports[i] == sorted_ports[i - 1] + 1
                                 for i in range(1, len(sorted_ports)))
                if sequential:
                    evasion_indicators.append('sequential_ports')

        # Servizi su porte non standard
        for port in host_data.get('ports', []):
            service = port.get('service', {})
            port_num = port.get('portid')
            service_name = service.get('name', '')

            # HTTP su porte non standard
            if service_name in ['http', 'https'] and port_num not in [80, 443, 8080, 8443]:
                evasion_indicators.append('non_standard_web_ports')

            # SSH su porte non standard
            if service_name == 'ssh' and port_num != 22:
                evasion_indicators.append('non_standard_ssh_port')

        return evasion_indicators

    def get_device_info(self, device_type: str) -> Dict[str, Any]:
        """Restituisce informazioni su un tipo di dispositivo"""
        return self.device_types.get(device_type, self.device_types['unknown'])

    def get_risk_level(self, device_type: str) -> str:
        """Restituisce il livello di rischio per un tipo di dispositivo"""
        return self.get_device_info(device_type).get('risk_level', 'medium')

    def get_devices_by_category(self, category: str) -> List[str]:
        """Restituisce tutti i dispositivi di una categoria"""
        return [dtype for dtype, info in self.device_types.items()
                if info.get('category') == category]

    def get_all_categories(self) -> List[str]:
        """Restituisce tutte le categorie disponibili"""
        return list(set(info.get('category') for info in self.device_types.values()))

    def is_critical_device(self, device_type: str) -> bool:
        """Verifica se un dispositivo è considerato critico"""
        risk_level = self.get_risk_level(device_type)
        return risk_level in ['critical', 'high']

    def get_security_recommendations(self, device_type: str) -> List[str]:
        """Restituisce raccomandazioni di sicurezza per un tipo di dispositivo"""
        recommendations = {
            'router': [
                'Cambiare password di default',
                'Disabilitare servizi non necessari',
                'Aggiornare firmware regolarmente',
                'Configurare logging',
                'Limitare accesso amministrativo'
            ],
            'server': [
                'Installare aggiornamenti di sicurezza',
                'Configurare firewall locale',
                'Implementare monitoring',
                'Backup regolari',
                'Hardening del sistema operativo'
            ],
            'printer': [
                'Cambiare password amministratore',
                'Disabilitare protocolli non sicuri',
                'Aggiornare firmware',
                'Limitare accesso di rete'
            ],
            'iot': [
                'Cambiare credenziali di default',
                'Isolare in VLAN dedicata',
                'Monitorare traffico di rete',
                'Disabilitare funzioni non necessarie'
            ],
            'camera': [
                'Cambiare password di default',
                'Aggiornare firmware',
                'Configurare crittografia',
                'Limitare accesso remoto'
            ]
        }

        return recommendations.get(device_type, [
            'Verificare configurazioni di sicurezza',
            'Monitorare per attività anomale',
            'Mantenere aggiornato il software'
        ])
