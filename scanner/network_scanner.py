"""
Network Scanner Module v2.0
Modulo principale per la scansione della rete aziendale - Versione migliorata
"""

import subprocess
import sqlite3
import json
import time
import logging
import threading
import ipaddress
import socket
import struct
import platform
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
import concurrent.futures
from enum import Enum

# Configurazione logging migliorata
def setup_logging(log_file: str = 'scanner/scanner.log', level=logging.INFO):
    """Configura il sistema di logging"""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# ==================== CONFIGURAZIONE ====================

class ScannerConfig:
    """Configurazione centralizzata dello scanner"""

    def __init__(self, config_dict: Dict = None):
        default_config = {
            'subnets': [
                '192.168.1.0/24',
                '192.168.20.0/24',
                '192.168.30.0/24',
            ],
            'scan_interval': 600,  # 10 minuti
            'port_timeout': 1,      # timeout per porta in secondi
            'max_threads': 10,      # thread per scansione parallela
            'database_path': 'scanner/network_scan.db',
            'common_ports': [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 9100
            ],
            'enable_os_detection': False,  # Disabilitato di default (richiede root)
            'enable_arp_scan': True,
            'enable_ping_scan': True,
            'ping_timeout': 1,
            'max_concurrent_hosts': 50,
        }

        if config_dict:
            default_config.update(config_dict)

        for key, value in default_config.items():
            setattr(self, key, value)

        # Crea directory necessarie
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)

# ==================== DATA CLASSES ====================

class DeviceStatus(Enum):
    """Stati possibili per un dispositivo"""
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"

class DeviceType(Enum):
    """Tipi di dispositivi riconosciuti"""
    ROUTER = "router"
    SWITCH = "switch"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    CAMERA = "camera"
    NAS = "nas"
    AP = "access_point"
    MOBILE = "mobile"
    IOT = "iot"
    VOIP = "voip"
    UNKNOWN = "unknown"

@dataclass
class Device:
    """Rappresenta un dispositivo nella rete"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = DeviceType.UNKNOWN.value
    os_family: Optional[str] = None
    os_details: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    status: str = DeviceStatus.UP.value
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    scan_count: int = 1
    confidence: int = 0
    notes: Optional[str] = None
    location: Optional[str] = None
    subnet: Optional[str] = None
    response_time: Optional[float] = None  # ms

    def to_dict(self) -> Dict:
        """Converte l'oggetto in dizionario"""
        data = asdict(self)
        data['last_seen'] = self.last_seen.isoformat()
        data['first_seen'] = self.first_seen.isoformat()
        data['open_ports'] = json.dumps(self.open_ports)
        data['services'] = json.dumps(self.services)
        return data

# ==================== PORT SCANNER ====================

class PortScanner:
    """Scanner di porte TCP semplice e veloce"""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan_port(self, host: str, port: int) -> bool:
        """Scansiona una singola porta TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.gaierror:
            return False
        except Exception as e:
            logger.debug(f"Errore scansione porta {host}:{port}: {e}")
            return False

    def scan_ports(self, host: str, ports: List[int], max_workers: int = 10) -> List[int]:
        """Scansiona multiple porte in parallelo"""
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Errore durante scansione porta {port}: {e}")

        return sorted(open_ports)

# ==================== SERVICE DETECTOR ====================

class ServiceDetector:
    """Identifica i servizi in base alle porte"""

    WELL_KNOWN_PORTS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        123: "NTP",
        135: "MS-RPC",
        137: "NetBIOS-NS",
        138: "NetBIOS-DGM",
        139: "NetBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        515: "LPD",
        548: "AFP",
        554: "RTSP",
        587: "SMTP",
        631: "IPP",
        636: "LDAPS",
        873: "Rsync",
        902: "VMware",
        993: "IMAPS",
        995: "POP3S",
        1433: "MS-SQL",
        1521: "Oracle",
        1723: "PPTP",
        1883: "MQTT",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5060: "SIP",
        5432: "PostgreSQL",
        5900: "VNC",
        5984: "CouchDB",
        6379: "Redis",
        7001: "WebLogic",
        8000: "HTTP-Alt",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        8883: "MQTT-SSL",
        9000: "SonarQube",
        9100: "JetDirect",
        9200: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
    }

    def identify_service(self, port: int) -> str:
        """Identifica il servizio basandosi sulla porta"""
        return self.WELL_KNOWN_PORTS.get(port, f"Unknown-{port}")

    def identify_services(self, ports: List[int]) -> Dict[int, str]:
        """Identifica multipli servizi"""
        return {port: self.identify_service(port) for port in ports}

# ==================== DEVICE TYPE DETECTOR ====================

class DeviceTypeDetector:
    """Rileva il tipo di dispositivo basandosi su vari indicatori"""

    DEVICE_SIGNATURES = {
        DeviceType.ROUTER: {
            'ports': {23, 80, 443, 8080, 8443, 161},
            'required_ports': {80, 443},
            'keywords': ['router', 'gateway', 'cisco', 'mikrotik', 'ubiquiti'],
            'weight': 1.0
        },
        DeviceType.SWITCH: {
            'ports': {22, 23, 161, 443},
            'required_ports': {161},
            'keywords': ['switch', 'catalyst'],
            'weight': 0.9
        },
        DeviceType.SERVER: {
            'ports': {22, 80, 443, 3306, 5432, 1433, 3389},
            'required_ports': set(),
            'keywords': ['server', 'ubuntu', 'centos', 'debian', 'windows server'],
            'weight': 0.8
        },
        DeviceType.WORKSTATION: {
            'ports': {135, 139, 445, 3389},
            'required_ports': {135, 445},
            'keywords': ['windows', 'workstation', 'desktop'],
            'weight': 0.7
        },
        DeviceType.PRINTER: {
            'ports': {515, 631, 9100, 9101, 9102, 80},
            'required_ports': {9100},
            'keywords': ['printer', 'print', 'cups', 'jetdirect'],
            'weight': 0.95
        },
        DeviceType.CAMERA: {
            'ports': {554, 8000, 8080, 80},
            'required_ports': {554},
            'keywords': ['camera', 'ipcam', 'hikvision', 'dahua'],
            'weight': 0.9
        },
        DeviceType.NAS: {
            'ports': {139, 445, 548, 2049, 80, 443},
            'required_ports': {445},
            'keywords': ['nas', 'synology', 'qnap'],
            'weight': 0.85
        },
        DeviceType.AP: {
            'ports': {22, 80, 443},
            'required_ports': set(),
            'keywords': ['ap', 'access point', 'wifi', 'wireless'],
            'weight': 0.6
        },
        DeviceType.VOIP: {
            'ports': {5060, 5061, 4569},
            'required_ports': {5060},
            'keywords': ['voip', 'phone', 'polycom', 'yealink'],
            'weight': 0.9
        },
    }

    def detect_type(self, device: Device) -> Tuple[str, int]:
        """
        Determina il tipo di dispositivo e la confidenza

        Returns:
            Tuple[device_type, confidence]
        """
        scores = {}
        open_ports_set = set(device.open_ports)

        for device_type, signature in self.DEVICE_SIGNATURES.items():
            score = 0.0

            # Controlla porte richieste
            if signature['required_ports']:
                if signature['required_ports'].issubset(open_ports_set):
                    score += 50
                else:
                    continue  # Skip se mancano porte richieste

            # Calcola match delle porte
            port_matches = len(open_ports_set.intersection(signature['ports']))
            if port_matches > 0:
                score += (port_matches / len(signature['ports'])) * 30

            # Controlla hostname
            if device.hostname:
                hostname_lower = device.hostname.lower()
                for keyword in signature['keywords']:
                    if keyword in hostname_lower:
                        score += 20
                        break

            # Applica peso
            score *= signature['weight']

            if score > 0:
                scores[device_type] = score

        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(int(scores[best_type]), 100)
            return best_type.value, confidence

        return DeviceType.UNKNOWN.value, 0

# ==================== HOST DISCOVERY ====================

class HostDiscovery:
    """Metodi per scoprire host attivi nella rete"""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.system = platform.system().lower()

    def ping_host(self, ip: str) -> Tuple[bool, Optional[float]]:
        """
        Esegue ping su un host

        Returns:
            Tuple[is_alive, response_time_ms]
        """
        try:
            if self.system == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(int(self.timeout * 1000)), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(int(self.timeout)), ip]

            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1
            )
            response_time = (time.time() - start_time) * 1000  # in ms

            if result.returncode == 0:
                return True, response_time
            return False, None

        except subprocess.TimeoutExpired:
            return False, None
        except Exception as e:
            logger.debug(f"Errore ping {ip}: {e}")
            return False, None

    def arp_scan(self, subnet: str) -> List[Tuple[str, str]]:
        """
        Esegue ARP scan sulla subnet (richiede privilegi su Linux/Mac)

        Returns:
            List[(ip, mac)]
        """
        results = []

        try:
            if self.system == 'windows':
                # Su Windows usa arp -a
                cmd = ['arp', '-a']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1]
                            # Valida IP
                            try:
                                ipaddress.ip_address(ip)
                                # Verifica se IP è nella subnet
                                if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                                    results.append((ip, mac))
                            except:
                                continue
            else:
                # Su Linux/Mac prova con arp-scan (se disponibile)
                cmd = ['arp-scan', '--local', '--interface=eth0', subnet]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            try:
                                ip = parts[0]
                                mac = parts[1]
                                ipaddress.ip_address(ip)  # Valida IP
                                results.append((ip, mac))
                            except:
                                continue
        except FileNotFoundError:
            logger.debug("arp-scan non disponibile, uso metodo alternativo")
        except Exception as e:
            logger.debug(f"Errore ARP scan: {e}")

        return results

    def discover_hosts(self, subnet: str, use_arp: bool = True, use_ping: bool = True) -> List[str]:
        """
        Scopre host attivi nella subnet

        Returns:
            Lista di IP attivi
        """
        active_hosts = set()

        # Prova ARP scan
        if use_arp:
            arp_results = self.arp_scan(subnet)
            for ip, mac in arp_results:
                active_hosts.add(ip)
                logger.debug(f"Host trovato via ARP: {ip} ({mac})")

        # Ping scan
        if use_ping:
            network = ipaddress.ip_network(subnet)

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {
                    executor.submit(self.ping_host, str(ip)): str(ip)
                    for ip in network.hosts()
                }

                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        is_alive, response_time = future.result()
                        if is_alive:
                            active_hosts.add(ip)
                            logger.debug(f"Host trovato via ping: {ip} ({response_time:.1f}ms)")
                    except Exception as e:
                        logger.debug(f"Errore ping {ip}: {e}")

        return list(active_hosts)

# ==================== DATABASE MANAGER ====================

class DatabaseManager:
    """Gestisce il database SQLite per lo scanner"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inizializza le tabelle del database"""
        with sqlite3.connect(self.db_path) as conn:
            # Tabella dispositivi
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    os_family TEXT,
                    os_details TEXT,
                    open_ports TEXT,
                    services TEXT,
                    status TEXT DEFAULT 'up',
                    confidence INTEGER DEFAULT 0,
                    response_time REAL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1,
                    notes TEXT,
                    location TEXT,
                    subnet TEXT
                )
            """)

            # Indici
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON devices(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON devices(device_type)")

            # Tabella storico scansioni
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    subnet TEXT,
                    hosts_scanned INTEGER DEFAULT 0,
                    hosts_up INTEGER DEFAULT 0,
                    new_devices INTEGER DEFAULT 0,
                    duration_seconds REAL,
                    status TEXT DEFAULT 'running',
                    error_message TEXT
                )
            """)

            # Tabella cambiamenti
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            """)

            # Tabella alert
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    alert_type TEXT,
                    severity TEXT,
                    message TEXT,
                    details TEXT,
                    resolved BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            """)

            conn.commit()

    def save_device(self, device: Device) -> int:
        """Salva o aggiorna un dispositivo"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Controlla se esiste
            cursor.execute("SELECT id, status, open_ports FROM devices WHERE ip_address = ?",
                          (device.ip_address,))
            existing = cursor.fetchone()

            device_dict = device.to_dict()

            if existing:
                device_id = existing[0]
                old_status = existing[1]
                old_ports = existing[2]

                # Aggiorna
                cursor.execute("""
                    UPDATE devices SET
                        mac_address = ?, hostname = ?, vendor = ?,
                        device_type = ?, os_family = ?, os_details = ?,
                        open_ports = ?, services = ?, status = ?,
                        confidence = ?, response_time = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        scan_count = scan_count + 1,
                        subnet = ?
                    WHERE id = ?
                """, (
                    device_dict['mac_address'], device_dict['hostname'],
                    device_dict['vendor'], device_dict['device_type'],
                    device_dict['os_family'], device_dict['os_details'],
                    device_dict['open_ports'], device_dict['services'],
                    device_dict['status'], device_dict['confidence'],
                    device_dict['response_time'], device_dict['subnet'],
                    device_id
                ))

                # Registra cambiamenti
                if old_status != device_dict['status']:
                    self._record_change(cursor, device_id, 'status', old_status, device_dict['status'])

                    if device_dict['status'] == DeviceStatus.DOWN.value:
                        self._create_alert(cursor, device_id, 'device_offline', 'warning',
                                         f"Device {device.ip_address} is now offline")

                if old_ports != device_dict['open_ports']:
                    self._record_change(cursor, device_id, 'ports', old_ports, device_dict['open_ports'])

                    # Controlla nuove porte aperte
                    try:
                        old_ports_list = json.loads(old_ports) if old_ports else []
                        new_ports_list = device.open_ports
                        new_ports = set(new_ports_list) - set(old_ports_list)

                        if new_ports:
                            self._create_alert(cursor, device_id, 'new_ports', 'info',
                                             f"New ports opened: {', '.join(map(str, new_ports))}")
                    except:
                        pass
            else:
                # Inserisci nuovo
                cursor.execute("""
                    INSERT INTO devices (
                        ip_address, mac_address, hostname, vendor, device_type,
                        os_family, os_details, open_ports, services, status,
                        confidence, response_time, subnet, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_dict['ip_address'], device_dict['mac_address'],
                    device_dict['hostname'], device_dict['vendor'],
                    device_dict['device_type'], device_dict['os_family'],
                    device_dict['os_details'], device_dict['open_ports'],
                    device_dict['services'], device_dict['status'],
                    device_dict['confidence'], device_dict['response_time'],
                    device_dict['subnet'], device_dict['first_seen'],
                    device_dict['last_seen']
                ))

                device_id = cursor.lastrowid

                # Alert nuovo dispositivo
                self._create_alert(cursor, device_id, 'new_device', 'info',
                                 f"New device discovered: {device.ip_address} ({device.device_type})")

            conn.commit()
            return device_id

    def _record_change(self, cursor, device_id: int, change_type: str, old_value, new_value):
        """Registra un cambiamento"""
        cursor.execute("""
            INSERT INTO device_changes (device_id, change_type, old_value, new_value)
            VALUES (?, ?, ?, ?)
        """, (device_id, change_type, str(old_value), str(new_value)))

    def _create_alert(self, cursor, device_id: int, alert_type: str, severity: str, message: str, details: str = None):
        """Crea un alert"""
        cursor.execute("""
            INSERT INTO alerts (device_id, alert_type, severity, message, details)
            VALUES (?, ?, ?, ?, ?)
        """, (device_id, alert_type, severity, message, details))

    def mark_devices_offline(self, subnet: str, online_ips: List[str]):
        """Marca come offline i dispositivi non trovati"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            if online_ips:
                placeholders = ','.join('?' * len(online_ips))
                cursor.execute(f"""
                    UPDATE devices SET status = 'down'
                    WHERE subnet = ? AND status = 'up'
                    AND ip_address NOT IN ({placeholders})
                """, [subnet] + online_ips)
            else:
                cursor.execute("""
                    UPDATE devices SET status = 'down'
                    WHERE subnet = ? AND status = 'up'
                """, (subnet,))

            conn.commit()

    def get_statistics(self) -> Dict:
        """Recupera statistiche"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            stats = {}

            cursor.execute("SELECT COUNT(*) FROM devices")
            stats['total_devices'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'up'")
            stats['online_devices'] = cursor.fetchone()[0]

            cursor.execute("""
                SELECT device_type, COUNT(*) FROM devices 
                GROUP BY device_type
            """)
            stats['by_type'] = dict(cursor.fetchall())

            cursor.execute("""
                SELECT subnet, COUNT(*) FROM devices 
                WHERE status = 'up' 
                GROUP BY subnet
            """)
            stats['by_subnet'] = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE resolved = 0")
            stats['unresolved_alerts'] = cursor.fetchone()[0]

            return stats

# ==================== MAIN SCANNER ====================

class NetworkScanner:
    """Scanner principale della rete - Versione 2.0"""

    def __init__(self, config: ScannerConfig = None):
        self.config = config or ScannerConfig()
        self.db_manager = DatabaseManager(self.config.database_path)
        self.port_scanner = PortScanner(timeout=self.config.port_timeout)
        self.service_detector = ServiceDetector()
        self.device_detector = DeviceTypeDetector()
        self.host_discovery = HostDiscovery(timeout=self.config.ping_timeout)
        self.scanning = False
        self.scan_thread = None

        logger.info("Network Scanner v2.0 inizializzato")

    def scan_host(self, ip: str) -> Optional[Device]:
        """Scansiona un singolo host"""
        try:
            # Verifica se l'host è attivo
            is_alive, response_time = self.host_discovery.ping_host(ip)

            if not is_alive:
                return None

            logger.debug(f"Scansione host {ip}")

            # Crea device base
            device = Device(
                ip_address=ip,
                status=DeviceStatus.UP.value,
                response_time=response_time
            )

            # Risoluzione hostname
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                device.hostname = hostname
            except:
                pass

            # Scansione porte
            device.open_ports = self.port_scanner.scan_ports(
                ip,
                self.config.common_ports,
                max_workers=5
            )

            # Identifica servizi
            if device.open_ports:
                device.services = self.service_detector.identify_services(device.open_ports)

            # Rileva tipo dispositivo
            device.device_type, device.confidence = self.device_detector.detect_type(device)

            # Determina subnet
            for subnet in self.config.subnets:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                    device.subnet = subnet
                    break

            return device

        except Exception as e:
            logger.error(f"Errore scansione host {ip}: {e}")
            return None

    def scan_subnet(self, subnet: str) -> List[Device]:
        """Scansiona una subnet completa"""
        logger.info(f"Inizio scansione subnet {subnet}")
        devices = []
        start_time = time.time()

        try:
            # Scopri host attivi
            active_hosts = self.host_discovery.discover_hosts(
                subnet,
                use_arp=self.config.enable_arp_scan,
                use_ping=self.config.enable_ping_scan
            )

            logger.info(f"Trovati {len(active_hosts)} host attivi in {subnet}")

            # Scansiona ogni host in parallelo
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                future_to_ip = {
                    executor.submit(self.scan_host, ip): ip
                    for ip in active_hosts[:self.config.max_concurrent_hosts]  # Limita concurrent
                }

                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        device = future.result()
                        if device:
                            devices.append(device)
                            logger.debug(f"Host scansionato: {ip} - {device.device_type}")
                    except Exception as e:
                        logger.error(f"Errore scansione {ip}: {e}")

            # Scansiona host rimanenti se ce ne sono
            if len(active_hosts) > self.config.max_concurrent_hosts:
                remaining = active_hosts[self.config.max_concurrent_hosts:]
                logger.info(f"Scansione {len(remaining)} host rimanenti...")

                for ip in remaining:
                    device = self.scan_host(ip)
                    if device:
                        devices.append(device)

        except Exception as e:
            logger.error(f"Errore scansione subnet {subnet}: {e}")

        duration = time.time() - start_time
        logger.info(f"Subnet {subnet} scansionata in {duration:.1f}s: {len(devices)} dispositivi")

        return devices

    def run_full_scan(self):
        """Esegue una scansione completa"""
        logger.info("=== Inizio scansione completa ===")
        total_start = time.time()

        # Registra inizio scansione nel DB
        with sqlite3.connect(self.config.database_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history (status) VALUES ('running')
            """)
            scan_id = cursor.lastrowid
            conn.commit()

        total_devices = 0

        try:
            for subnet in self.config.subnets:
                # Scansiona subnet
                devices = self.scan_subnet(subnet)
                total_devices += len(devices)

                # Salva dispositivi
                online_ips = []
                for device in devices:
                    self.db_manager.save_device(device)
                    online_ips.append(device.ip_address)

                # Marca offline i dispositivi non trovati
                self.db_manager.mark_devices_offline(subnet, online_ips)

            # Aggiorna storico scansione
            duration = time.time() - total_start

            with sqlite3.connect(self.config.database_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_history SET
                        end_time = CURRENT_TIMESTAMP,
                        hosts_up = ?,
                        duration_seconds = ?,
                        status = 'completed'
                    WHERE id = ?
                """, (total_devices, duration, scan_id))
                conn.commit()

            # Statistiche
            stats = self.db_manager.get_statistics()
            logger.info(f"=== Scansione completata in {duration:.1f}s ===")
            logger.info(f"Dispositivi online: {stats['online_devices']}/{stats['total_devices']}")
            logger.info(f"Per tipo: {stats['by_type']}")

        except Exception as e:
            logger.error(f"Errore durante scansione completa: {e}")

            with sqlite3.connect(self.config.database_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_history SET
                        end_time = CURRENT_TIMESTAMP,
                        status = 'error',
                        error_message = ?
                    WHERE id = ?
                """, (str(e), scan_id))
                conn.commit()

    def start_periodic_scan(self):
        """Avvia scansione periodica"""
        self.scanning = True

        def scan_loop():
            while self.scanning:
                try:
                    self.run_full_scan()
                except Exception as e:
                    logger.error(f"Errore nel ciclo di scansione: {e}")

                if self.scanning:
                    logger.info(f"Prossima scansione tra {self.config.scan_interval} secondi")
                    time.sleep(self.config.scan_interval)

        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        logger.info("Scanner periodico avviato")

    def stop_periodic_scan(self):
        """Ferma scansione periodica"""
        logger.info("Arresto scanner...")
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        logger.info("Scanner arrestato")

# ==================== TEST E MAIN ====================

def test_scanner():
    """Funzione di test dello scanner"""
    logger.info("=== TEST NETWORK SCANNER v2.0 ===")

    # Configurazione di test (usa subnet locale)
    config = ScannerConfig({
        'subnets': ['192.168.1.0/24'],  # Modifica con la tua subnet
        'scan_interval': 300,  # 5 minuti per test
        'common_ports': [22, 80, 443, 445, 3389, 8080],  # Porte comuni per test veloce
        'max_threads': 5,
        'max_concurrent_hosts': 10,
    })

    scanner = NetworkScanner(config)

    # Test scansione singola
    logger.info("Test scansione singola...")
    scanner.run_full_scan()

    # Mostra statistiche
    stats = scanner.db_manager.get_statistics()
    logger.info(f"Statistiche finali: {stats}")

    return scanner

if __name__ == "__main__":
    import sys

    # Modalità di esecuzione
    mode = sys.argv[1] if len(sys.argv) > 1 else 'daemon'  # DEFAULT: daemon

    if mode == 'test':
        # Modalità test - scansione singola per verifica
        logger.info("=== MODALITÀ TEST ===")
        scanner = test_scanner()

    elif mode == 'daemon' or mode == 'start':
        # Modalità daemon - DEFAULT
        logger.info("=== AVVIO NETWORK SCANNER DAEMON ===")

        # Carica configurazione
        config_file = 'scanner/config.json'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config_dict = json.load(f)
                    config = ScannerConfig(config_dict)
                    logger.info(f"Configurazione caricata da {config_file}")
            except Exception as e:
                logger.warning(f"Errore caricamento config: {e}, uso default")
                config = ScannerConfig()
        else:
            logger.info("File config non trovato, uso configurazione default")
            config = ScannerConfig()

        # Crea e avvia scanner
        scanner = NetworkScanner(config)

        # Registra signal handlers per shutdown pulito
        import signal

        def signal_handler(signum, frame):
            logger.info(f"Ricevuto segnale {signum}, arresto scanner...")
            scanner.stop_periodic_scan()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Esegui prima scansione immediata
            logger.info("Esecuzione prima scansione...")
            scanner.run_full_scan()

            # Avvia scansione periodica
            scanner.start_periodic_scan()

            logger.info("=" * 60)
            logger.info("SCANNER DAEMON ATTIVO")
            logger.info(f"Subnet monitorate: {', '.join(config.subnets)}")
            logger.info(f"Intervallo scansione: {config.scan_interval} secondi")
            logger.info(f"Database: {config.database_path}")
            logger.info("Premi Ctrl+C per fermare")
            logger.info("=" * 60)

            # Loop principale con report periodico
            while True:
                time.sleep(60)  # Report ogni minuto
                stats = scanner.db_manager.get_statistics()
                logger.info(f"📊 Status: {stats['online_devices']}/{stats['total_devices']} online | "
                          f"Alert: {stats['unresolved_alerts']} | "
                          f"Tipi: {stats.get('by_type', {})}")

        except KeyboardInterrupt:
            logger.info("Interruzione richiesta dall'utente")
            scanner.stop_periodic_scan()

        except Exception as e:
            logger.error(f"Errore fatale: {e}")
            scanner.stop_periodic_scan()
            sys.exit(1)

    elif mode == 'stop':
        # Modalità stop (per future implementazioni con PID file)
        logger.info("Stop non implementato in questa versione")
        print("Per fermare il daemon usa Ctrl+C o killa il processo")

    elif mode == 'status':
        # Mostra stato corrente dal database
        try:
            config = ScannerConfig()
            from network_scanner_v2 import DatabaseManager
            db = DatabaseManager(config.database_path)
            stats = db.get_statistics()

            print("=" * 60)
            print("NETWORK SCANNER STATUS")
            print("=" * 60)
            print(f"Dispositivi totali: {stats['total_devices']}")
            print(f"Dispositivi online: {stats['online_devices']}")
            print(f"Alert non risolti: {stats['unresolved_alerts']}")
            print(f"Per tipo: {stats.get('by_type', {})}")
            print(f"Per subnet: {stats.get('by_subnet', {})}")
            print("=" * 60)

        except Exception as e:
            print(f"Errore lettura status: {e}")

    elif mode == 'once':
        # Esegui una singola scansione e esci
        logger.info("=== SCANSIONE SINGOLA ===")
        config = ScannerConfig()
        scanner = NetworkScanner(config)
        scanner.run_full_scan()

        stats = scanner.db_manager.get_statistics()
        logger.info(f"Scansione completata: {stats['online_devices']} dispositivi online")

    elif mode == 'help' or mode == '--help' or mode == '-h':
        print("Network Scanner v2.0 - Utilizzo:")
        print()
        print("  python network_scanner.py [comando]")
        print()
        print("Comandi:")
        print("  daemon    - Avvia come daemon (DEFAULT)")
        print("  start     - Alias per daemon")
        print("  once      - Esegui una scansione e esci")
        print("  test      - Modalità test (subnet locale)")
        print("  status    - Mostra stato corrente")
        print("  help      - Mostra questo messaggio")
        print()
        print("Se non viene specificato nessun comando, parte in modalità daemon.")

    else:
        print(f"Comando sconosciuto: {mode}")
        print("Usa 'python network_scanner.py help' per vedere i comandi disponibili")
        print("Avvio in modalità daemon di default...")

        # Avvia comunque in modalità daemon
        os.execv(sys.executable, [sys.executable] + [sys.argv[0], 'daemon'])