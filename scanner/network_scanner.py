"""
Network Scanner Module
Modulo principale per la scansione della rete aziendale
"""

import nmap
import sqlite3
import json
import time
import logging
import threading
import ipaddress
import re
import subprocess
import platform
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
import requests
import os
from pathlib import Path

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURAZIONE ====================

SCANNER_CONFIG = {
    'subnets': [
        '192.168.20.0/24',
        '192.168.30.0/24',
        '192.168.40.0/24',
        '192.168.50.0/24',
    ],
    'scan_interval': 600,  # 10 minuti in secondi
    'nmap_timeout': 300,    # 5 minuti timeout per scansione
    'oui_update_days': 7,   # Aggiorna OUI ogni 7 giorni
    'database_path': 'scanner/network_scan.db',
    'oui_database_path': 'scanner/oui_cache.db',
    'oui_url': 'https://standards-oui.ieee.org/oui/oui.txt'
}

# ==================== DATA CLASSES ====================

@dataclass
class Device:
    """Rappresenta un dispositivo nella rete"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_family: Optional[str] = None
    os_details: Optional[str] = None
    open_ports: Optional[str] = None
    status: str = 'up'
    last_seen: datetime = None
    first_seen: datetime = None
    scan_count: int = 1
    services: Optional[str] = None
    confidence: int = 0
    notes: Optional[str] = None
    location: Optional[str] = None
    subnet: Optional[str] = None

    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()
        if self.first_seen is None:
            self.first_seen = datetime.now()

    def to_dict(self):
        data = asdict(self)
        data['last_seen'] = self.last_seen.isoformat() if self.last_seen else None
        data['first_seen'] = self.first_seen.isoformat() if self.first_seen else None
        return data

@dataclass
class ScanResult:
    """Risultato di una scansione"""
    scan_id: Optional[int] = None
    start_time: datetime = None
    end_time: datetime = None
    subnet: str = None
    devices_found: int = 0
    new_devices: int = 0
    status: str = 'running'
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()

# ==================== DEVICE TYPE DETECTOR ====================

class DeviceTypeDetector:
    """Classe per identificare il tipo di dispositivo basandosi su vari indicatori"""

    # Pattern per identificare dispositivi dai servizi/porte
    DEVICE_PATTERNS = {
        'router': {
            'ports': [23, 80, 443, 8080, 8443],
            'services': ['telnet', 'http', 'https'],
            'keywords': ['router', 'gateway', 'mikrotik', 'cisco', 'juniper', 'ubiquiti'],
            'vendors': ['Cisco', 'Juniper', 'MikroTik', 'Ubiquiti', 'TP-Link', 'Netgear']
        },
        'switch': {
            'ports': [23, 22, 161],
            'services': ['telnet', 'ssh', 'snmp'],
            'keywords': ['switch', 'catalyst'],
            'vendors': ['Cisco', 'HP', 'Dell', 'Aruba']
        },
        'printer': {
            'ports': [515, 631, 9100, 9101, 9102],
            'services': ['lpd', 'ipp', 'jetdirect'],
            'keywords': ['printer', 'print', 'cups', 'jetdirect'],
            'vendors': ['HP', 'Canon', 'Epson', 'Brother', 'Xerox', 'Lexmark']
        },
        'nas': {
            'ports': [139, 445, 548, 2049],
            'services': ['netbios', 'microsoft-ds', 'afp', 'nfs'],
            'keywords': ['nas', 'synology', 'qnap', 'freenas'],
            'vendors': ['Synology', 'QNAP', 'Western Digital', 'Buffalo']
        },
        'camera': {
            'ports': [554, 8000, 8080],
            'services': ['rtsp', 'http'],
            'keywords': ['camera', 'ipcam', 'dvr', 'nvr', 'hikvision', 'dahua'],
            'vendors': ['Hikvision', 'Dahua', 'Axis', 'Ubiquiti']
        },
        'ap': {
            'ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https'],
            'keywords': ['access point', 'ap', 'wifi', 'wireless'],
            'vendors': ['Ubiquiti', 'Cisco', 'Aruba', 'Ruckus', 'TP-Link']
        },
        'server': {
            'ports': [22, 80, 443, 3306, 5432, 1433, 3389],
            'services': ['ssh', 'http', 'https', 'mysql', 'postgresql', 'ms-sql', 'rdp'],
            'keywords': ['server', 'ubuntu', 'centos', 'windows server', 'debian'],
            'os_hints': ['Linux', 'Windows Server', 'Unix']
        },
        'workstation': {
            'ports': [135, 139, 445, 3389],
            'services': ['msrpc', 'netbios', 'microsoft-ds', 'ms-wbt-server'],
            'keywords': ['windows', 'workstation', 'desktop'],
            'os_hints': ['Windows 10', 'Windows 11', 'Windows 7']
        },
        'mobile': {
            'ports': [],
            'services': [],
            'keywords': ['android', 'ios', 'iphone', 'ipad', 'mobile'],
            'vendors': ['Apple', 'Samsung', 'Xiaomi', 'Huawei']
        },
        'iot': {
            'ports': [1883, 8883, 5683],
            'services': ['mqtt', 'coap'],
            'keywords': ['iot', 'smart', 'alexa', 'google home', 'sonos'],
            'vendors': ['Amazon', 'Google', 'Sonos', 'Philips']
        },
        'voip': {
            'ports': [5060, 5061, 4569],
            'services': ['sip', 'iax'],
            'keywords': ['voip', 'phone', 'polycom', 'yealink', 'grandstream'],
            'vendors': ['Polycom', 'Yealink', 'Grandstream', 'Cisco']
        }
    }

    def detect_type(self, device: Device, nmap_data: dict = None) -> Tuple[str, int]:
        """
        Determina il tipo di dispositivo e la confidenza della rilevazione

        Returns:
            Tuple[device_type, confidence]
        """
        scores = {}

        # Analizza porte aperte
        if device.open_ports:
            try:
                ports = json.loads(device.open_ports) if isinstance(device.open_ports, str) else device.open_ports
                for dev_type, patterns in self.DEVICE_PATTERNS.items():
                    score = 0
                    for port in ports:
                        if port in patterns['ports']:
                            score += 20
                    if score > 0:
                        scores[dev_type] = scores.get(dev_type, 0) + score
            except:
                pass

        # Analizza servizi
        if device.services:
            services_lower = device.services.lower()
            for dev_type, patterns in self.DEVICE_PATTERNS.items():
                for service in patterns['services']:
                    if service in services_lower:
                        scores[dev_type] = scores.get(dev_type, 0) + 25

        # Analizza vendor
        if device.vendor:
            vendor_lower = device.vendor.lower()
            for dev_type, patterns in self.DEVICE_PATTERNS.items():
                for vendor in patterns.get('vendors', []):
                    if vendor.lower() in vendor_lower:
                        scores[dev_type] = scores.get(dev_type, 0) + 30

        # Analizza OS
        if device.os_family or device.os_details:
            os_info = f"{device.os_family or ''} {device.os_details or ''}".lower()
            for dev_type, patterns in self.DEVICE_PATTERNS.items():
                for keyword in patterns['keywords']:
                    if keyword in os_info:
                        scores[dev_type] = scores.get(dev_type, 0) + 20

                # Check OS hints
                if 'os_hints' in patterns:
                    for hint in patterns['os_hints']:
                        if hint.lower() in os_info:
                            scores[dev_type] = scores.get(dev_type, 0) + 25

        # Analizza hostname
        if device.hostname:
            hostname_lower = device.hostname.lower()
            for dev_type, patterns in self.DEVICE_PATTERNS.items():
                for keyword in patterns['keywords']:
                    if keyword in hostname_lower:
                        scores[dev_type] = scores.get(dev_type, 0) + 15

        # Determina il tipo con score più alto
        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(scores[best_type], 100)
            return best_type, confidence

        return 'unknown', 0

# ==================== OUI MANAGER ====================

class OUIManager:
    """Gestisce il database OUI per la risoluzione dei vendor dai MAC address"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inizializza il database OUI"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oui_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    oui TEXT UNIQUE NOT NULL,
                    vendor TEXT NOT NULL,
                    vendor_full TEXT,
                    address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Crea indice separatamente
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oui ON oui_entries(oui)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS oui_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def needs_update(self) -> bool:
        """Verifica se il database OUI necessita di aggiornamento"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT value, updated_at FROM oui_metadata 
                WHERE key = 'last_update'
            """)
            row = cursor.fetchone()

            if not row:
                return True

            last_update = datetime.fromisoformat(row[1])
            days_old = (datetime.now() - last_update).days

            return days_old >= SCANNER_CONFIG['oui_update_days']

    def update_database(self):
        """Scarica e aggiorna il database OUI"""
        logger.info("Aggiornamento database OUI...")

        try:
            # Scarica il file OUI
            response = requests.get(SCANNER_CONFIG['oui_url'], timeout=30)
            response.raise_for_status()

            # Parse del file OUI
            entries = []
            lines = response.text.split('\n')

            for line in lines:
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    if len(parts) == 2:
                        oui = parts[0].strip().replace('-', ':').lower()
                        vendor = parts[1].strip()

                        # Estrai vendor name principale
                        vendor_short = vendor.split('\t')[0] if '\t' in vendor else vendor

                        entries.append((oui, vendor_short, vendor))

            # Aggiorna il database
            with sqlite3.connect(self.db_path) as conn:
                # Usa INSERT OR REPLACE per evitare errori di duplicati
                conn.executemany("""
                    INSERT OR REPLACE INTO oui_entries (oui, vendor, vendor_full)
                    VALUES (?, ?, ?)
                """, entries)

                # Aggiorna metadata
                conn.execute("""
                    INSERT OR REPLACE INTO oui_metadata (key, value, updated_at)
                    VALUES ('last_update', ?, CURRENT_TIMESTAMP)
                """, (datetime.now().isoformat(),))

                conn.execute("""
                    INSERT OR REPLACE INTO oui_metadata (key, value, updated_at)
                    VALUES ('entry_count', ?, CURRENT_TIMESTAMP)
                """, (len(entries),))

                conn.commit()

            logger.info(f"Database OUI aggiornato con {len(entries)} entries")

        except Exception as e:
            logger.error(f"Errore aggiornamento OUI: {e}")

    def get_vendor(self, mac_address: str) -> Optional[str]:
        """Ottiene il vendor dal MAC address"""
        if not mac_address:
            return None

        # Normalizza MAC address
        mac = mac_address.upper().replace('-', ':')
        oui = ':'.join(mac.split(':')[:3]).lower()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT vendor FROM oui_entries
                WHERE oui = ?
            """, (oui,))
            row = cursor.fetchone()

            return row[0] if row else None

# ==================== NETWORK SCANNER ====================

class NetworkScanner:
    """Scanner principale della rete"""

    def __init__(self, config: dict):
        self.config = config
        self.nm = nmap.PortScanner()
        self.oui_manager = OUIManager(config['oui_database_path'])
        self.device_detector = DeviceTypeDetector()
        self.init_database()
        self.scanning = False
        self.scan_thread = None

        # Aggiorna OUI se necessario
        if self.oui_manager.needs_update():
            self.oui_manager.update_database()

    def init_database(self):
        """Inizializza il database principale"""
        os.makedirs(os.path.dirname(self.config['database_path']), exist_ok=True)

        with sqlite3.connect(self.config['database_path']) as conn:
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
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1,
                    notes TEXT,
                    location TEXT,
                    subnet TEXT
                )
            """)

            # Crea indici separatamente
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mac ON devices(mac_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON devices(device_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subnet ON devices(subnet)")

            # Tabella storico scansioni
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    subnet TEXT,
                    devices_found INTEGER DEFAULT 0,
                    new_devices INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running',
                    error_message TEXT
                )
            """)

            # Tabella storico cambiamenti
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
                    resolved BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            """)

            conn.commit()

    def scan_host(self, ip: str) -> Optional[Device]:
        """Scansiona un singolo host"""
        try:
            # Scansione con OS detection e service detection
            # Su Windows, potrebbe richiedere privilegi di amministratore
            try:
                self.nm.scan(ip, arguments='-O -sV --osscan-guess')
            except nmap.PortScannerError:
                # Se fallisce OS detection, prova scansione base
                logger.warning(f"OS detection fallito per {ip}, uso scansione base")
                self.nm.scan(ip, arguments='-sV')

            if ip in self.nm.all_hosts():
                host_data = self.nm[ip]

                # Estrai informazioni base
                device = Device(
                    ip_address=ip,
                    hostname=host_data.hostname() or None,
                    status=host_data.state()
                )

                # MAC address e vendor
                if 'addresses' in host_data and 'mac' in host_data['addresses']:
                    device.mac_address = host_data['addresses']['mac']
                    device.vendor = self.oui_manager.get_vendor(device.mac_address)

                # OS detection
                if 'osmatch' in host_data and host_data['osmatch']:
                    best_match = host_data['osmatch'][0]
                    device.os_details = best_match.get('name', '')
                    device.confidence = int(best_match.get('accuracy', 0))

                    # Estrai OS family
                    if 'osclass' in best_match and best_match['osclass']:
                        os_class = best_match['osclass'][0]
                        device.os_family = os_class.get('osfamily', '')

                # Porte e servizi
                open_ports = []
                services = []

                for proto in host_data.all_protocols():
                    ports = host_data[proto].keys()
                    for port in ports:
                        port_info = host_data[proto][port]
                        if port_info['state'] == 'open':
                            open_ports.append(port)

                            service_name = port_info.get('name', '')
                            service_product = port_info.get('product', '')
                            service_version = port_info.get('version', '')

                            service_str = service_name
                            if service_product:
                                service_str += f" ({service_product}"
                                if service_version:
                                    service_str += f" {service_version}"
                                service_str += ")"

                            services.append(f"{port}/{proto}: {service_str}")

                device.open_ports = json.dumps(open_ports)
                device.services = ', '.join(services)

                # Rileva tipo di dispositivo
                device_type, confidence = self.device_detector.detect_type(device, host_data)
                device.device_type = device_type
                device.confidence = max(device.confidence, confidence)

                # Determina subnet
                for subnet in self.config['subnets']:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                        device.subnet = subnet
                        break

                return device

        except nmap.PortScannerError as e:
            logger.error(f"Errore nmap per host {ip}: {e}")
            # Crea entry base se il ping ha successo
            return Device(
                ip_address=ip,
                status='up',
                device_type='unknown'
            )
        except Exception as e:
            logger.error(f"Errore scansione host {ip}: {e}")
            return None

    def scan_subnet(self, subnet: str) -> List[Device]:
        """Scansiona una subnet completa"""
        logger.info(f"Inizio scansione subnet {subnet}")
        devices = []

        try:
            # Prima fai un ping sweep veloce
            self.nm.scan(subnet, arguments='-sn')
            hosts = self.nm.all_hosts()

            logger.info(f"Trovati {len(hosts)} host attivi in {subnet}")

            # Poi scansiona ogni host in dettaglio
            for ip in hosts:
                device = self.scan_host(ip)
                if device:
                    devices.append(device)
                    logger.debug(f"Scansionato: {ip} - {device.device_type}")

        except nmap.PortScannerError as e:
            logger.error(f"Errore nmap per subnet {subnet}: {e}")
            # Prova con un approccio alternativo se nmap fallisce
            try:
                # Prova a fare ping su singoli IP
                import ipaddress
                network = ipaddress.ip_network(subnet)
                for ip in network.hosts():
                    # Limita a primi 10 IP per test
                    if len(devices) >= 10:
                        break

                    # Prova ping semplice
                    import platform
                    param = '-n' if platform.system().lower() == 'windows' else '-c'
                    cmd = f"ping {param} 1 -w 1 {str(ip)}"

                    try:
                        result = subprocess.run(cmd.split(), capture_output=True, timeout=1)
                        if result.returncode == 0:
                            # Host risponde al ping
                            device = Device(
                                ip_address=str(ip),
                                status='up',
                                device_type='unknown',
                                subnet=subnet
                            )
                            devices.append(device)
                            logger.info(f"Host trovato via ping: {ip}")
                    except:
                        pass

            except Exception as e2:
                logger.error(f"Errore anche con metodo alternativo: {e2}")

        except Exception as e:
            logger.error(f"Errore scansione subnet {subnet}: {e}")

        return devices

    def save_device(self, device: Device):
        """Salva o aggiorna un dispositivo nel database"""
        with sqlite3.connect(self.config['database_path']) as conn:
            cursor = conn.cursor()

            # Verifica se il dispositivo esiste già
            cursor.execute("""
                SELECT id, device_type, status, open_ports, services
                FROM devices WHERE ip_address = ?
            """, (device.ip_address,))
            existing = cursor.fetchone()

            if existing:
                device_id = existing[0]
                old_type = existing[1]
                old_status = existing[2]
                old_ports = existing[3]
                old_services = existing[4]

                # Aggiorna dispositivo esistente
                cursor.execute("""
                    UPDATE devices SET
                        mac_address = ?,
                        hostname = ?,
                        vendor = ?,
                        device_type = ?,
                        os_family = ?,
                        os_details = ?,
                        open_ports = ?,
                        services = ?,
                        status = ?,
                        confidence = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        scan_count = scan_count + 1,
                        subnet = ?
                    WHERE id = ?
                """, (
                    device.mac_address,
                    device.hostname,
                    device.vendor,
                    device.device_type,
                    device.os_family,
                    device.os_details,
                    device.open_ports,
                    device.services,
                    device.status,
                    device.confidence,
                    device.subnet,
                    device_id
                ))

                # Registra cambiamenti significativi
                if old_type != device.device_type:
                    cursor.execute("""
                        INSERT INTO device_changes (device_id, change_type, old_value, new_value)
                        VALUES (?, 'device_type', ?, ?)
                    """, (device_id, old_type, device.device_type))

                if old_status != device.status:
                    cursor.execute("""
                        INSERT INTO device_changes (device_id, change_type, old_value, new_value)
                        VALUES (?, 'status', ?, ?)
                    """, (device_id, old_status, device.status))

                if old_ports != device.open_ports:
                    cursor.execute("""
                        INSERT INTO device_changes (device_id, change_type, old_value, new_value)
                        VALUES (?, 'ports', ?, ?)
                    """, (device_id, old_ports, device.open_ports))

            else:
                # Inserisci nuovo dispositivo
                cursor.execute("""
                    INSERT INTO devices (
                        ip_address, mac_address, hostname, vendor, device_type,
                        os_family, os_details, open_ports, services, status,
                        confidence, subnet
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device.ip_address,
                    device.mac_address,
                    device.hostname,
                    device.vendor,
                    device.device_type,
                    device.os_family,
                    device.os_details,
                    device.open_ports,
                    device.services,
                    device.status,
                    device.confidence,
                    device.subnet
                ))

                device_id = cursor.lastrowid

                # Crea alert per nuovo dispositivo
                cursor.execute("""
                    INSERT INTO alerts (device_id, alert_type, severity, message)
                    VALUES (?, 'new_device', 'info', ?)
                """, (device_id, f"Nuovo dispositivo rilevato: {device.ip_address} ({device.device_type})"))

            conn.commit()

    def mark_devices_offline(self, subnet: str, online_ips: List[str]):
        """Marca come offline i dispositivi non trovati nella scansione"""
        with sqlite3.connect(self.config['database_path']) as conn:
            cursor = conn.cursor()

            # Trova dispositivi che erano online ma non sono nella lista corrente
            placeholders = ','.join('?' * len(online_ips))
            cursor.execute(f"""
                SELECT id, ip_address FROM devices
                WHERE subnet = ? AND status = 'up'
                AND ip_address NOT IN ({placeholders})
            """, [subnet] + online_ips)

            offline_devices = cursor.fetchall()

            for device_id, ip in offline_devices:
                cursor.execute("""
                    UPDATE devices SET status = 'down', last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (device_id,))

                cursor.execute("""
                    INSERT INTO device_changes (device_id, change_type, old_value, new_value)
                    VALUES (?, 'status', 'up', 'down')
                """, (device_id,))

                cursor.execute("""
                    INSERT INTO alerts (device_id, alert_type, severity, message)
                    VALUES (?, 'device_offline', 'warning', ?)
                """, (device_id, f"Dispositivo {ip} è andato offline"))

            conn.commit()

    def run_full_scan(self):
        """Esegue una scansione completa di tutte le subnet"""
        for subnet in self.config['subnets']:
            scan_result = ScanResult(subnet=subnet)

            try:
                # Salva inizio scansione
                with sqlite3.connect(self.config['database_path']) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO scan_history (subnet, status)
                        VALUES (?, 'running')
                    """, (subnet,))
                    scan_result.scan_id = cursor.lastrowid
                    conn.commit()

                # Esegui scansione
                devices = self.scan_subnet(subnet)
                online_ips = []

                # Salva dispositivi
                for device in devices:
                    self.save_device(device)
                    online_ips.append(device.ip_address)

                # Marca dispositivi offline
                self.mark_devices_offline(subnet, online_ips)

                # Aggiorna risultato scansione
                scan_result.end_time = datetime.now()
                scan_result.devices_found = len(devices)
                scan_result.status = 'completed'

                with sqlite3.connect(self.config['database_path']) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE scan_history SET
                            end_time = CURRENT_TIMESTAMP,
                            devices_found = ?,
                            status = ?
                        WHERE id = ?
                    """, (scan_result.devices_found, scan_result.status, scan_result.scan_id))
                    conn.commit()

                logger.info(f"Scansione {subnet} completata: {len(devices)} dispositivi trovati")

            except Exception as e:
                logger.error(f"Errore durante scansione {subnet}: {e}")
                scan_result.status = 'error'
                scan_result.error_message = str(e)

                with sqlite3.connect(self.config['database_path']) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE scan_history SET
                            end_time = CURRENT_TIMESTAMP,
                            status = 'error',
                            error_message = ?
                        WHERE id = ?
                    """, (scan_result.error_message, scan_result.scan_id))
                    conn.commit()

    def start_periodic_scan(self):
        """Avvia la scansione periodica"""
        self.scanning = True

        def scan_loop():
            while self.scanning:
                logger.info("Inizio ciclo di scansione...")
                self.run_full_scan()
                logger.info(f"Scansione completata. Prossima tra {self.config['scan_interval']} secondi")

                # Attendi l'intervallo specificato
                for _ in range(self.config['scan_interval']):
                    if not self.scanning:
                        break
                    time.sleep(1)

        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        logger.info("Scanner avviato")

    def stop_periodic_scan(self):
        """Ferma la scansione periodica"""
        self.scanning = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        logger.info("Scanner fermato")

    def get_all_devices(self) -> List[Dict]:
        """Recupera tutti i dispositivi dal database"""
        with sqlite3.connect(self.config['database_path']) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM devices
                ORDER BY subnet, ip_address
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_device_by_ip(self, ip: str) -> Optional[Dict]:
        """Recupera un dispositivo specifico"""
        with sqlite3.connect(self.config['database_path']) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_statistics(self) -> Dict:
        """Recupera statistiche sulla rete"""
        with sqlite3.connect(self.config['database_path']) as conn:
            cursor = conn.cursor()

            stats = {}

            # Totale dispositivi
            cursor.execute("SELECT COUNT(*) FROM devices")
            stats['total_devices'] = cursor.fetchone()[0]

            # Dispositivi online
            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'up'")
            stats['online_devices'] = cursor.fetchone()[0]

            # Per tipo
            cursor.execute("""
                SELECT device_type, COUNT(*) as count
                FROM devices
                GROUP BY device_type
            """)
            stats['by_type'] = {row[0]: row[1] for row in cursor.fetchall()}

            # Per subnet
            cursor.execute("""
                SELECT subnet, COUNT(*) as count
                FROM devices
                GROUP BY subnet
            """)
            stats['by_subnet'] = {row[0]: row[1] for row in cursor.fetchall()}

            # Ultima scansione
            cursor.execute("""
                SELECT MAX(end_time) FROM scan_history
                WHERE status = 'completed'
            """)
            last_scan = cursor.fetchone()[0]
            stats['last_scan'] = last_scan

            # Alert non risolti
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE resolved = 0")
            stats['unresolved_alerts'] = cursor.fetchone()[0]

            return stats


# ==================== MAIN ====================

if __name__ == "__main__":
    # Test dello scanner
    scanner = NetworkScanner(SCANNER_CONFIG)

    # Avvia scansione periodica
    scanner.start_periodic_scan()

    try:
        # Mantieni il programma in esecuzione
        while True:
            time.sleep(60)

            # Stampa statistiche ogni minuto
            stats = scanner.get_statistics()
            logger.info(f"Statistiche: {stats}")

    except KeyboardInterrupt:
        logger.info("Interruzione richiesta...")
        scanner.stop_periodic_scan()