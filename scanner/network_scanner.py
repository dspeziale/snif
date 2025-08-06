"""
Network Scanner System with NMAP for Windows
Sistema completo di scansione rete con NMAP per inventario dispositivi
"""

import sqlite3
import subprocess
import json
import xml.etree.ElementTree as ET
import threading
import time
import re
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from queue import Queue, Empty
import ipaddress
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from pathlib import Path

# ==================== CONFIGURAZIONE ====================

SCANNER_CONFIG = {
    'nmap_path': r'C:\Program Files (x86)\Nmap\nmap.exe',  # Path NMAP Windows
    'db_path': '../data/network_inventory.db',
    'oui_cache_path': '../data/oui_cache.txt',
    'oui_url': 'https://standards-oui.ieee.org/oui/oui.txt',
    'log_path': '../logs/scanner.log',

    # Reti da scansionare (192.168.20.0/24 - 192.168.70.0/24, solo decine)
    'subnets': [f'192.168.{i}.0/24' for i in range(20, 71, 10)],

    # Timing configurazioni
    'quick_scan_interval': 600,  # 10 minuti
    'full_scan_after_detections': 5,  # Dopo 5 rilevamenti
    'oui_update_interval': 86400 * 7,  # 1 settimana

    # Thread pool
    'max_workers': 20,
    'scan_timeout': 300,  # 5 minuti per scansione

    # SNMP
    'snmp_community': 'public',
    'snmp_timeout': 2,
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(SCANNER_CONFIG['log_path']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== DATABASE SCHEMA ====================

DATABASE_SCHEMA = """
-- Tabella principale dispositivi
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    os_family TEXT,
    os_version TEXT,
    status TEXT DEFAULT 'unknown',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_full_scan TIMESTAMP,
    detection_count INTEGER DEFAULT 0,
    notes TEXT,
    location TEXT,
    asset_tag TEXT,
    UNIQUE(ip_address, mac_address)
);

-- Storico scansioni
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    scan_type TEXT, -- 'quick', 'full', 'vuln'
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scan_duration REAL,
    scan_result TEXT,
    raw_output TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Porte aperte
CREATE TABLE IF NOT EXISTS open_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    version TEXT,
    state TEXT,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    UNIQUE(device_id, port, protocol)
);

-- Vulnerabilità
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    vuln_id TEXT,
    title TEXT,
    severity TEXT, -- 'critical', 'high', 'medium', 'low'
    description TEXT,
    solution TEXT,
    cve_ids TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved BOOLEAN DEFAULT 0,
    resolved_at TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Informazioni SNMP
CREATE TABLE IF NOT EXISTS snmp_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    sys_name TEXT,
    sys_descr TEXT,
    sys_contact TEXT,
    sys_location TEXT,
    sys_uptime TEXT,
    interfaces TEXT, -- JSON
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    UNIQUE(device_id)
);

-- Servizi rilevati
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    port INTEGER,
    service_name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    fingerprint TEXT,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Alert e notifiche
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    alert_type TEXT, -- 'new_device', 'port_change', 'vulnerability', 'offline'
    severity TEXT,
    message TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT 0,
    acknowledged_at TIMESTAMP,
    acknowledged_by TEXT,
    resolved BOOLEAN DEFAULT 0,
    resolved_at TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Cache OUI
CREATE TABLE IF NOT EXISTS oui_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_prefix TEXT UNIQUE,
    vendor TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Statistiche scansioni
CREATE TABLE IF NOT EXISTS scan_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date DATE,
    subnet TEXT,
    devices_found INTEGER,
    new_devices INTEGER,
    offline_devices INTEGER,
    scan_duration REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indici per performance
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_device ON scan_history(device_id);
CREATE INDEX IF NOT EXISTS idx_open_ports_device ON open_ports(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
"""


# ==================== DATA CLASSES ====================

@dataclass
class Device:
    """Rappresenta un dispositivo di rete"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    status: str = 'unknown'
    open_ports: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    snmp_info: Optional[Dict] = None
    detection_count: int = 0
    last_seen: Optional[datetime] = None
    last_full_scan: Optional[datetime] = None


@dataclass
class ScanResult:
    """Risultato di una scansione"""
    scan_type: str
    device: Device
    raw_output: str
    duration: float
    success: bool
    error: Optional[str] = None


# ==================== OUI MANAGER ====================

class OUIManager:
    """Gestisce la cache OUI per identificare i vendor dai MAC address"""

    def __init__(self, cache_path: str, db_path: str):
        self.cache_path = cache_path
        self.db_path = db_path
        self.oui_dict = {}
        self.load_cache()

    def load_cache(self):
        """Carica la cache OUI dal database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT mac_prefix, vendor FROM oui_cache")
                for row in cursor.fetchall():
                    self.oui_dict[row[0]] = row[1]
                logger.info(f"Caricati {len(self.oui_dict)} vendor OUI dalla cache")
        except Exception as e:
            logger.error(f"Errore caricamento cache OUI: {e}")

    def update_cache(self):
        """Scarica e aggiorna la cache OUI"""
        try:
            logger.info("Aggiornamento cache OUI...")
            response = requests.get(SCANNER_CONFIG['oui_url'], timeout=30)

            if response.status_code == 200:
                # Salva il file
                with open(self.cache_path, 'wb') as f:
                    f.write(response.content)

                # Parse e aggiorna database
                self._parse_oui_file()
                logger.info("Cache OUI aggiornata con successo")
            else:
                logger.error(f"Errore download OUI: HTTP {response.status_code}")

        except Exception as e:
            logger.error(f"Errore aggiornamento OUI: {e}")

    def _parse_oui_file(self):
        """Parse del file OUI e aggiornamento database"""
        if not os.path.exists(self.cache_path):
            return

        new_entries = {}
        try:
            with open(self.cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '(hex)' in line:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            mac_prefix = parts[0].split()[0].replace('-', ':').upper()
                            vendor = parts[-1].strip()
                            new_entries[mac_prefix] = vendor

            # Aggiorna database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM oui_cache")

                for prefix, vendor in new_entries.items():
                    cursor.execute("""
                        INSERT INTO oui_cache (mac_prefix, vendor) 
                        VALUES (?, ?)
                    """, (prefix, vendor))

                conn.commit()
                self.oui_dict = new_entries
                logger.info(f"Aggiornati {len(new_entries)} vendor OUI nel database")

        except Exception as e:
            logger.error(f"Errore parsing OUI: {e}")

    def get_vendor(self, mac_address: str) -> Optional[str]:
        """Ottiene il vendor dal MAC address"""
        if not mac_address:
            return None

        # Normalizza MAC address
        mac_clean = mac_address.upper().replace('-', ':')
        mac_prefix = ':'.join(mac_clean.split(':')[:3])

        return self.oui_dict.get(mac_prefix)

    def identify_device_type(self, vendor: str, hostname: str = None,
                             services: List[Dict] = None) -> str:
        """Identifica il tipo di dispositivo basandosi su vendor e servizi"""
        if not vendor:
            return 'unknown'

        vendor_lower = vendor.lower()
        hostname_lower = (hostname or '').lower()

        # Router/Switch patterns
        router_vendors = ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'tp-link',
                          'netgear', 'd-link', 'asus', 'linksys']
        if any(v in vendor_lower for v in router_vendors):
            if 'switch' in hostname_lower:
                return 'switch'
            return 'router'

        # Printer patterns
        printer_vendors = ['hp', 'canon', 'epson', 'brother', 'xerox', 'ricoh']
        if any(v in vendor_lower for v in printer_vendors):
            return 'printer'

        # Camera patterns
        camera_vendors = ['hikvision', 'dahua', 'axis', 'vivotek', 'hanwha']
        if any(v in vendor_lower for v in camera_vendors):
            return 'camera'

        # Server patterns
        server_vendors = ['dell', 'hewlett packard', 'ibm', 'supermicro']
        if any(v in vendor_lower for v in server_vendors):
            if services:
                server_ports = [22, 3389, 445, 139]
                if any(s.get('port') in server_ports for s in services):
                    return 'server'

        # Access Point
        if 'access point' in hostname_lower or 'ap-' in hostname_lower:
            return 'ap'

        # NAS
        nas_vendors = ['synology', 'qnap', 'buffalo', 'netapp']
        if any(v in vendor_lower for v in nas_vendors):
            return 'nas'

        # Mobile devices
        mobile_vendors = ['apple', 'samsung', 'huawei', 'xiaomi', 'oneplus']
        if any(v in vendor_lower for v in mobile_vendors):
            return 'mobile'

        # IoT devices
        iot_vendors = ['sonoff', 'tuya', 'shelly', 'amazon', 'google']
        if any(v in vendor_lower for v in iot_vendors):
            return 'iot'

        # VoIP
        voip_vendors = ['polycom', 'yealink', 'grandstream', 'fanvil']
        if any(v in vendor_lower for v in voip_vendors):
            return 'voip'

        # Default to workstation if has common OS
        if services:
            workstation_ports = [445, 139, 3389, 5900]  # SMB, RDP, VNC
            if any(s.get('port') in workstation_ports for s in services):
                return 'workstation'

        return 'unknown'


# ==================== NMAP SCANNER ====================

class NmapScanner:
    """Wrapper per eseguire scansioni NMAP"""

    def __init__(self, nmap_path: str):
        self.nmap_path = nmap_path
        if not os.path.exists(nmap_path):
            raise FileNotFoundError(f"NMAP non trovato in: {nmap_path}")

    def _run_nmap(self, args: List[str], timeout: int = 300) -> Tuple[str, bool]:
        """Esegue comando NMAP e ritorna output"""
        try:
            cmd = [self.nmap_path] + args + ['-oX', '-']  # Output XML to stdout
            logger.debug(f"Eseguendo: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                return result.stdout, True
            else:
                logger.error(f"NMAP error: {result.stderr}")
                return result.stderr, False

        except subprocess.TimeoutExpired:
            logger.error(f"NMAP timeout dopo {timeout} secondi")
            return "Timeout", False
        except Exception as e:
            logger.error(f"Errore esecuzione NMAP: {e}")
            return str(e), False

    def quick_scan(self, subnet: str) -> List[Device]:
        """Scansione veloce per trovare host attivi"""
        args = ['-T4', '-sn', subnet]
        output, success = self._run_nmap(args)

        if not success:
            return []

        devices = []
        try:
            root = ET.fromstring(output)

            for host in root.findall('.//host'):
                if host.find(".//status[@state='up']") is not None:
                    device = Device(ip_address='')

                    # IP Address
                    addr = host.find(".//address[@addrtype='ipv4']")
                    if addr is not None:
                        device.ip_address = addr.get('addr')

                    # MAC Address
                    mac = host.find(".//address[@addrtype='mac']")
                    if mac is not None:
                        device.mac_address = mac.get('addr')
                        device.vendor = mac.get('vendor')

                    # Hostname
                    hostname = host.find(".//hostname")
                    if hostname is not None:
                        device.hostname = hostname.get('name')

                    device.status = 'online'

                    if device.ip_address:
                        devices.append(device)

        except ET.ParseError as e:
            logger.error(f"Errore parsing XML: {e}")

        return devices

    def full_scan(self, ip: str) -> Device:
        """Scansione completa di un singolo host"""
        # Prima scansione: servizi e OS
        args = ['-sS', '-sV', '-O', '-T4', '--osscan-guess', ip]
        output1, success1 = self._run_nmap(args, timeout=600)

        device = Device(ip_address=ip)

        if success1:
            self._parse_full_scan(output1, device)

        # Seconda scansione: vulnerabilità
        args = ['-sV', '--script', 'vuln', '-T4', ip]
        output2, success2 = self._run_nmap(args, timeout=600)

        if success2:
            self._parse_vuln_scan(output2, device)

        # SNMP scan se porta 161 è aperta
        if any(p.get('port') == 161 for p in device.open_ports):
            self._scan_snmp(ip, device)

        return device

    def _parse_full_scan(self, xml_output: str, device: Device):
        """Parse output scansione completa"""
        try:
            root = ET.fromstring(xml_output)
            host = root.find('.//host')

            if host is None:
                return

            # Status
            status = host.find(".//status")
            if status is not None:
                device.status = 'online' if status.get('state') == 'up' else 'offline'

            # MAC e Vendor
            mac = host.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr')
                device.vendor = mac.get('vendor')

            # Hostname
            hostname = host.find(".//hostname")
            if hostname is not None:
                device.hostname = hostname.get('name')

            # OS Detection
            os_match = host.find(".//osmatch")
            if os_match is not None:
                device.os_family = os_match.get('name', '')
                device.os_version = os_match.get('accuracy', '')

                # Parse OS class per maggiori dettagli
                os_class = os_match.find(".//osclass")
                if os_class is not None:
                    device.os_family = os_class.get('osfamily', device.os_family)

            # Porte e Servizi
            for port in host.findall(".//port"):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol')

                state = port.find(".//state")
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': port_id,
                        'protocol': protocol,
                        'state': 'open'
                    }

                    # Servizio
                    service = port.find(".//service")
                    if service is not None:
                        service_info = {
                            'port': port_id,
                            'service_name': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version'),
                            'extra_info': service.get('extrainfo')
                        }

                        port_info['service'] = service.get('name')
                        port_info['version'] = service.get('version')

                        device.services.append(service_info)

                    device.open_ports.append(port_info)

        except ET.ParseError as e:
            logger.error(f"Errore parsing full scan XML: {e}")

    def _parse_vuln_scan(self, xml_output: str, device: Device):
        """Parse output scansione vulnerabilità"""
        try:
            root = ET.fromstring(xml_output)
            host = root.find('.//host')

            if host is None:
                return

            # Cerca script output per vulnerabilità
            for script in host.findall(".//script"):
                script_id = script.get('id')
                output = script.get('output', '')

                if 'vuln' in script_id or 'CVE' in output:
                    # Estrai CVE IDs
                    cve_pattern = r'CVE-\d{4}-\d{4,}'
                    cves = re.findall(cve_pattern, output)

                    vuln = {
                        'vuln_id': script_id,
                        'title': script_id.replace('-', ' ').title(),
                        'description': output[:500],  # Limita lunghezza
                        'cve_ids': ','.join(cves) if cves else None,
                        'severity': self._determine_severity(script_id, output)
                    }

                    device.vulnerabilities.append(vuln)

        except ET.ParseError as e:
            logger.error(f"Errore parsing vuln scan XML: {e}")

    def _scan_snmp(self, ip: str, device: Device):
        """Scansione SNMP per raccogliere informazioni aggiuntive"""
        try:
            args = ['--script', 'snmp-info,snmp-interfaces,snmp-sysdescr',
                    '-sU', '-p', '161', '--script-args',
                    f'snmpcommunity={SCANNER_CONFIG["snmp_community"]}', ip]

            output, success = self._run_nmap(args, timeout=60)

            if success:
                # Parse SNMP output
                root = ET.fromstring(output)
                snmp_info = {}

                for script in root.findall(".//script"):
                    script_id = script.get('id')
                    output_text = script.get('output', '')

                    if 'snmp-sysdescr' in script_id:
                        snmp_info['sys_descr'] = output_text
                    elif 'snmp-info' in script_id:
                        # Parse SNMP info output
                        lines = output_text.split('\n')
                        for line in lines:
                            if 'System Name:' in line:
                                snmp_info['sys_name'] = line.split(':', 1)[1].strip()
                            elif 'System Contact:' in line:
                                snmp_info['sys_contact'] = line.split(':', 1)[1].strip()
                            elif 'System Location:' in line:
                                snmp_info['sys_location'] = line.split(':', 1)[1].strip()
                            elif 'System Uptime:' in line:
                                snmp_info['sys_uptime'] = line.split(':', 1)[1].strip()
                    elif 'snmp-interfaces' in script_id:
                        snmp_info['interfaces'] = output_text

                if snmp_info:
                    device.snmp_info = snmp_info

        except Exception as e:
            logger.error(f"Errore SNMP scan per {ip}: {e}")

    def _determine_severity(self, script_id: str, output: str) -> str:
        """Determina la severità di una vulnerabilità"""
        output_lower = output.lower()

        if 'critical' in output_lower or 'rce' in output_lower:
            return 'critical'
        elif 'high' in output_lower or 'dos' in output_lower:
            return 'high'
        elif 'medium' in output_lower or 'xss' in output_lower:
            return 'medium'
        else:
            return 'low'


# ==================== DATABASE MANAGER ====================

class DatabaseManager:
    """Gestisce tutte le operazioni del database"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inizializza il database con lo schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DATABASE_SCHEMA)
            conn.commit()
            logger.info("Database inizializzato")

    def save_device(self, device: Device) -> int:
        """Salva o aggiorna un dispositivo nel database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Controlla se il device esiste già
            cursor.execute("""
                SELECT id, detection_count FROM devices 
                WHERE ip_address = ? AND (mac_address = ? OR mac_address IS NULL)
            """, (device.ip_address, device.mac_address))

            existing = cursor.fetchone()

            if existing:
                device_id = existing[0]
                detection_count = existing[1] + 1

                # Aggiorna device esistente
                cursor.execute("""
                    UPDATE devices SET
                        mac_address = COALESCE(?, mac_address),
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor),
                        device_type = COALESCE(?, device_type),
                        os_family = COALESCE(?, os_family),
                        os_version = COALESCE(?, os_version),
                        status = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        detection_count = ?,
                        last_full_scan = COALESCE(?, last_full_scan)
                    WHERE id = ?
                """, (device.mac_address, device.hostname, device.vendor,
                      device.device_type, device.os_family, device.os_version,
                      device.status, detection_count, device.last_full_scan,
                      device_id))
            else:
                # Inserisci nuovo device
                cursor.execute("""
                    INSERT INTO devices (
                        ip_address, mac_address, hostname, vendor, device_type,
                        os_family, os_version, status, detection_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (device.ip_address, device.mac_address, device.hostname,
                      device.vendor, device.device_type, device.os_family,
                      device.os_version, device.status))

                device_id = cursor.lastrowid

                # Crea alert per nuovo device
                self.create_alert(device_id, 'new_device', 'info',
                                  f'Nuovo dispositivo rilevato: {device.ip_address}')

            # Salva porte aperte
            if device.open_ports:
                self._save_open_ports(cursor, device_id, device.open_ports)

            # Salva servizi
            if device.services:
                self._save_services(cursor, device_id, device.services)

            # Salva vulnerabilità
            if device.vulnerabilities:
                self._save_vulnerabilities(cursor, device_id, device.vulnerabilities)

            # Salva info SNMP
            if device.snmp_info:
                self._save_snmp_info(cursor, device_id, device.snmp_info)

            conn.commit()
            return device_id

    def _save_open_ports(self, cursor, device_id: int, ports: List[Dict]):
        """Salva le porte aperte"""
        for port in ports:
            cursor.execute("""
                INSERT OR REPLACE INTO open_ports 
                (device_id, port, protocol, service, version, state, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (device_id, port.get('port'), port.get('protocol'),
                  port.get('service'), port.get('version'), port.get('state')))

    def _save_services(self, cursor, device_id: int, services: List[Dict]):
        """Salva i servizi rilevati"""
        for service in services:
            cursor.execute("""
                INSERT OR REPLACE INTO services
                (device_id, port, service_name, product, version, extra_info, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (device_id, service.get('port'), service.get('service_name'),
                  service.get('product'), service.get('version'),
                  service.get('extra_info')))

    def _save_vulnerabilities(self, cursor, device_id: int, vulnerabilities: List[Dict]):
        """Salva le vulnerabilità"""
        for vuln in vulnerabilities:
            # Controlla se la vulnerabilità esiste già
            cursor.execute("""
                SELECT id FROM vulnerabilities
                WHERE device_id = ? AND vuln_id = ? AND resolved = 0
            """, (device_id, vuln.get('vuln_id')))

            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO vulnerabilities
                    (device_id, vuln_id, title, severity, description, cve_ids)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (device_id, vuln.get('vuln_id'), vuln.get('title'),
                      vuln.get('severity'), vuln.get('description'),
                      vuln.get('cve_ids')))

                # Crea alert per vulnerabilità critiche
                if vuln.get('severity') in ['critical', 'high']:
                    self.create_alert(device_id, 'vulnerability', vuln.get('severity'),
                                      f"Vulnerabilità {vuln.get('severity')}: {vuln.get('title')}")

    def _save_snmp_info(self, cursor, device_id: int, snmp_info: Dict):
        """Salva informazioni SNMP"""
        cursor.execute("""
            INSERT OR REPLACE INTO snmp_info
            (device_id, sys_name, sys_descr, sys_contact, sys_location, 
             sys_uptime, interfaces, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (device_id, snmp_info.get('sys_name'), snmp_info.get('sys_descr'),
              snmp_info.get('sys_contact'), snmp_info.get('sys_location'),
              snmp_info.get('sys_uptime'), json.dumps(snmp_info.get('interfaces', {}))))

    def save_scan_history(self, device_id: int, scan_result: ScanResult):
        """Salva lo storico della scansione"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history 
                (device_id, scan_type, scan_duration, scan_result, raw_output)
                VALUES (?, ?, ?, ?, ?)
            """, (device_id, scan_result.scan_type, scan_result.duration,
                  'success' if scan_result.success else 'failed',
                  scan_result.raw_output[:10000]))  # Limita output
            conn.commit()

    def get_devices_for_full_scan(self, threshold: int = 5) -> List[Tuple[int, str]]:
        """Ottiene i device pronti per scansione completa"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip_address FROM devices
                WHERE detection_count >= ? 
                AND status = 'online'
                AND (last_full_scan IS NULL 
                     OR datetime(last_full_scan) < datetime('now', '-1 day'))
                ORDER BY detection_count DESC
            """, (threshold,))
            return cursor.fetchall()

    def update_device_scan_time(self, device_id: int):
        """Aggiorna il timestamp dell'ultima scansione completa"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE devices 
                SET last_full_scan = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (device_id,))
            conn.commit()

    def mark_devices_offline(self, subnet: str, online_ips: List[str]):
        """Marca come offline i device non trovati nella scansione"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Ottieni range IP della subnet
            network = ipaddress.ip_network(subnet)
            subnet_ips = [str(ip) for ip in network.hosts()]

            # Marca offline i device non trovati
            placeholders = ','.join('?' * len(online_ips))
            cursor.execute(f"""
                UPDATE devices 
                SET status = 'offline' 
                WHERE ip_address IN (
                    SELECT ip_address FROM devices 
                    WHERE ip_address LIKE ? 
                    AND ip_address NOT IN ({placeholders})
                    AND status = 'online'
                )
            """, (subnet.replace('/24', '.%'),) + tuple(online_ips))

            affected = cursor.rowcount
            if affected > 0:
                logger.info(f"{affected} dispositivi marcati come offline in {subnet}")

            conn.commit()

    def create_alert(self, device_id: int, alert_type: str, severity: str, message: str):
        """Crea un nuovo alert"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (device_id, alert_type, severity, message)
                VALUES (?, ?, ?, ?)
            """, (device_id, alert_type, severity, message))
            conn.commit()
            logger.info(f"Alert creato: {alert_type} - {message}")

    def save_scan_statistics(self, subnet: str, devices_found: int,
                             new_devices: int, duration: float):
        """Salva statistiche della scansione"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_statistics 
                (scan_date, subnet, devices_found, new_devices, scan_duration)
                VALUES (DATE('now'), ?, ?, ?, ?)
            """, (subnet, devices_found, new_devices, duration))
            conn.commit()


# ==================== MAIN SCANNER ENGINE ====================

class NetworkScanner:
    """Motore principale di scansione della rete"""

    def __init__(self, config: Dict):
        self.config = config
        self.db_manager = DatabaseManager(config['db_path'])
        self.oui_manager = OUIManager(config['oui_cache_path'], config['db_path'])
        self.nmap_scanner = NmapScanner(config['nmap_path'])

        self.scan_queue = Queue()
        self.full_scan_queue = Queue()
        self.executor = ThreadPoolExecutor(max_workers=config['max_workers'])

        self.running = False
        self.last_oui_update = None

        # Aggiorna OUI cache se necessario
        self._check_oui_update()

    def _check_oui_update(self):
        """Controlla e aggiorna cache OUI se necessario"""
        if not os.path.exists(self.config['oui_cache_path']):
            logger.info("Cache OUI non trovata, download in corso...")
            self.oui_manager.update_cache()
            self.last_oui_update = datetime.now()
        else:
            # Controlla età del file
            file_age = time.time() - os.path.getmtime(self.config['oui_cache_path'])
            if file_age > self.config['oui_update_interval']:
                logger.info("Cache OUI obsoleta, aggiornamento...")
                self.oui_manager.update_cache()
                self.last_oui_update = datetime.now()

    def start_periodic_scan(self):
        """Avvia il ciclo di scansione periodica"""
        self.running = True
        logger.info("Scanner avviato")

        # Thread per scansioni rapide
        quick_scan_thread = threading.Thread(target=self._quick_scan_worker)
        quick_scan_thread.daemon = True
        quick_scan_thread.start()

        # Thread per scansioni complete
        full_scan_thread = threading.Thread(target=self._full_scan_worker)
        full_scan_thread.daemon = True
        full_scan_thread.start()

        # Thread principale scheduler
        while self.running:
            try:
                # Aggiungi subnet da scansionare
                for subnet in self.config['subnets']:
                    self.scan_queue.put(subnet)
                    logger.info(f"Subnet {subnet} aggiunta alla coda")

                # Attendi intervallo
                time.sleep(self.config['quick_scan_interval'])

                # Aggiorna OUI periodicamente
                if self.last_oui_update:
                    if (datetime.now() - self.last_oui_update).total_seconds() > self.config['oui_update_interval']:
                        self.oui_manager.update_cache()
                        self.last_oui_update = datetime.now()

            except KeyboardInterrupt:
                logger.info("Interruzione richiesta")
                self.stop()
                break
            except Exception as e:
                logger.error(f"Errore nel loop principale: {e}")

    def _quick_scan_worker(self):
        """Worker per scansioni rapide"""
        while self.running:
            try:
                subnet = self.scan_queue.get(timeout=1)
                self._scan_subnet(subnet)
                self.scan_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Errore quick scan worker: {e}")

    def _full_scan_worker(self):
        """Worker per scansioni complete"""
        while self.running:
            try:
                # Controlla device da scansionare
                devices = self.db_manager.get_devices_for_full_scan(
                    self.config['full_scan_after_detections']
                )

                for device_id, ip in devices:
                    if not self.running:
                        break

                    logger.info(f"Avvio scansione completa per {ip}")
                    start_time = time.time()

                    try:
                        device = self.nmap_scanner.full_scan(ip)

                        # Aggiungi vendor e tipo device
                        if device.mac_address:
                            device.vendor = self.oui_manager.get_vendor(device.mac_address)
                            device.device_type = self.oui_manager.identify_device_type(
                                device.vendor, device.hostname, device.services
                            )

                        device.last_full_scan = datetime.now()

                        # Salva risultati
                        self.db_manager.save_device(device)
                        self.db_manager.update_device_scan_time(device_id)

                        # Salva storico
                        scan_result = ScanResult(
                            scan_type='full',
                            device=device,
                            raw_output='',
                            duration=time.time() - start_time,
                            success=True
                        )
                        self.db_manager.save_scan_history(device_id, scan_result)

                        logger.info(f"Scansione completa completata per {ip}")

                    except Exception as e:
                        logger.error(f"Errore scansione completa {ip}: {e}")

                # Attendi prima del prossimo ciclo
                time.sleep(30)

            except Exception as e:
                logger.error(f"Errore full scan worker: {e}")
                time.sleep(60)

    def _scan_subnet(self, subnet: str):
        """Scansiona una subnet"""
        logger.info(f"Scansione subnet {subnet}")
        start_time = time.time()

        try:
            # Scansione rapida
            devices = self.nmap_scanner.quick_scan(subnet)

            online_ips = []
            new_devices = 0

            for device in devices:
                # Aggiungi vendor info
                if device.mac_address:
                    device.vendor = self.oui_manager.get_vendor(device.mac_address)
                    device.device_type = self.oui_manager.identify_device_type(
                        device.vendor, device.hostname
                    )

                # Controlla se è nuovo
                device_id = self.db_manager.save_device(device)
                if device_id:
                    online_ips.append(device.ip_address)

                    # Se è la prima volta, conta come nuovo
                    if not device.last_seen:
                        new_devices += 1

            # Marca offline i device non trovati
            self.db_manager.mark_devices_offline(subnet, online_ips)

            # Salva statistiche
            duration = time.time() - start_time
            self.db_manager.save_scan_statistics(
                subnet, len(devices), new_devices, duration
            )

            logger.info(f"Subnet {subnet} scansionata: {len(devices)} device trovati in {duration:.2f}s")

        except Exception as e:
            logger.error(f"Errore scansione subnet {subnet}: {e}")

    def run_full_scan(self):
        """Esegue una scansione completa immediata di tutti i device online"""
        logger.info("Avvio scansione completa manuale")

        with sqlite3.connect(self.config['db_path']) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip_address FROM devices 
                WHERE status = 'online'
            """)
            devices = cursor.fetchall()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []

            for device_id, ip in devices:
                future = executor.submit(self._scan_single_device, device_id, ip)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Errore in scansione device: {e}")

        logger.info("Scansione completa manuale completata")

    def _scan_single_device(self, device_id: int, ip: str):
        """Scansiona un singolo device"""
        try:
            device = self.nmap_scanner.full_scan(ip)

            if device.mac_address:
                device.vendor = self.oui_manager.get_vendor(device.mac_address)
                device.device_type = self.oui_manager.identify_device_type(
                    device.vendor, device.hostname, device.services
                )

            device.last_full_scan = datetime.now()

            self.db_manager.save_device(device)
            self.db_manager.update_device_scan_time(device_id)

            logger.info(f"Device {ip} scansionato con successo")

        except Exception as e:
            logger.error(f"Errore scansione device {ip}: {e}")

    def stop(self):
        """Ferma lo scanner"""
        logger.info("Arresto scanner...")
        self.running = False
        self.executor.shutdown(wait=True)
        logger.info("Scanner arrestato")


# ==================== MAIN ====================

if __name__ == "__main__":
    # Test dello scanner
    scanner = NetworkScanner(SCANNER_CONFIG)

    try:
        # Avvia scansione periodica
        scanner.start_periodic_scan()
    except KeyboardInterrupt:
        scanner.stop()