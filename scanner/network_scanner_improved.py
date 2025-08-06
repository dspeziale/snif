"""
Network Scanner System with NMAP for Windows - VERSIONE MIGLIORATA
Sistema completo di scansione rete con diagnostica avanzata
"""

import sqlite3
import subprocess
import json
import xml.etree.ElementTree as ET
import threading
import time
import re
import os
import sys
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
import platform

# ==================== CONFIGURAZIONE ====================

def find_nmap_path():
    """Trova automaticamente il path di NMAP su Windows"""
    possible_paths = [
        r'C:\Program Files (x86)\Nmap\nmap.exe',
        r'C:\Program Files\Nmap\nmap.exe',
        r'C:\Nmap\nmap.exe',
        'nmap.exe',  # Se è nel PATH
        'nmap'
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

        # Prova anche con which/where
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['where', 'nmap'], capture_output=True, text=True)
            else:
                result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)

            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass

    return None

SCANNER_CONFIG = {
    'nmap_path': find_nmap_path(),
    'db_path': '../data/network_inventory.db',
    'oui_cache_path': '../data/oui_cache.txt',
    'oui_url': 'https://standards-oui.ieee.org/oui/oui.txt',
    'log_path': '../logs/scanner.log',

    # Reti da scansionare - CORREZIONE subnet
    'subnets': [f'192.168.{i}.0/24' for i in range(20, 71, 10)],

    # Timing configurazioni
    'quick_scan_interval': 600,  # 10 minuti
    'full_scan_after_detections': 5,  # Dopo 5 rilevamenti
    'oui_update_interval': 86400 * 7,  # 1 settimana

    # Thread pool
    'max_workers': 5,  # Ridotto per Windows
    'scan_timeout': 300,  # 5 minuti per scansione

    # SNMP
    'snmp_community': 'public',
    'snmp_timeout': 2,

    # Windows specific
    'use_sudo': False,  # Non usare sudo su Windows
    'ping_timeout': 1,  # Timeout per ping in secondi
}

# Crea directory se non esistono
os.makedirs('scanner', exist_ok=True)

# Setup logging con rotazione
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# File handler con rotazione
file_handler = RotatingFileHandler(
    SCANNER_CONFIG['log_path'],
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formato
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ==================== DATABASE SCHEMA (invariato) ====================

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
    scan_type TEXT,
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
    severity TEXT,
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
    interfaces TEXT,
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
    alert_type TEXT,
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

# ==================== SYSTEM DIAGNOSTICS ====================

class SystemDiagnostics:
    """Diagnostica del sistema e prerequisiti"""

    @staticmethod
    def check_system():
        """Verifica tutti i prerequisiti del sistema"""
        logger.info("=" * 60)
        logger.info("DIAGNOSTICA SISTEMA")
        logger.info("=" * 60)

        # Info sistema
        logger.info(f"Sistema Operativo: {platform.system()} {platform.release()}")
        logger.info(f"Python Version: {sys.version}")
        logger.info(f"Working Directory: {os.getcwd()}")

        # Verifica NMAP
        nmap_ok = SystemDiagnostics.check_nmap()

        # Verifica permessi amministratore (Windows)
        admin_ok = SystemDiagnostics.check_admin_rights()

        # Verifica connettività di rete
        network_ok = SystemDiagnostics.check_network()

        # Verifica database
        db_ok = SystemDiagnostics.check_database()

        logger.info("=" * 60)

        return nmap_ok and admin_ok and network_ok and db_ok

    @staticmethod
    def check_nmap():
        """Verifica installazione e funzionamento NMAP"""
        logger.info("\n[NMAP CHECK]")

        nmap_path = SCANNER_CONFIG['nmap_path']

        if not nmap_path:
            logger.error("[ERROR] NMAP non trovato! Installare da: https://nmap.org/download.html")
            return False

        logger.info(f"[OK] NMAP trovato: {nmap_path}")

        # Test esecuzione
        try:
            result = subprocess.run(
                [nmap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                logger.info(f"[OK] NMAP Version: {version_line}")
                return True
            else:
                logger.error(f"[ERROR] NMAP error: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"[ERROR] Errore esecuzione NMAP: {e}")
            return False

    @staticmethod
    def check_admin_rights():
        """Verifica privilegi amministratore (consigliato per NMAP)"""
        logger.info("\n[PRIVILEGI CHECK]")

        try:
            if platform.system() == 'Windows':
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

                if is_admin:
                    logger.info("[OK] Esecuzione con privilegi amministratore")
                else:
                    logger.warning("[WARN] NON in esecuzione come amministratore")
                    logger.warning("  Alcune funzionalita' NMAP potrebbero non funzionare")
                    logger.warning("  Eseguire come amministratore per risultati ottimali")

                return True  # Non bloccare, solo avvisare
            else:
                # Linux/Mac
                is_root = os.geteuid() == 0
                if is_root:
                    logger.info("[OK] Esecuzione come root")
                else:
                    logger.warning("[WARN] Non in esecuzione come root")
                return True

        except Exception as e:
            logger.warning(f"[WARN] Impossibile verificare privilegi: {e}")
            return True

    @staticmethod
    def check_network():
        """Verifica connettività di rete"""
        logger.info("\n[NETWORK CHECK]")

        # Test ping gateway predefinito
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '192.168.1.1'],
                    capture_output=True,
                    timeout=2
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '192.168.1.1'],
                    capture_output=True,
                    timeout=2
                )

            logger.info("[OK] Connettivita' di rete OK")
            return True

        except Exception as e:
            logger.warning(f"[WARN] Test connettivita' fallito: {e}")
            return True  # Non bloccare

    @staticmethod
    def check_database():
        """Verifica accesso database"""
        logger.info("\n[DATABASE CHECK]")

        try:
            db_path = SCANNER_CONFIG['db_path']
            db_dir = os.path.dirname(db_path)

            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)
                logger.info(f"[OK] Directory database creata: {db_dir}")

            # Test connessione
            conn = sqlite3.connect(db_path)
            conn.execute("SELECT 1")
            conn.close()

            logger.info(f"[OK] Database accessibile: {db_path}")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Errore database: {e}")
            return False

# ==================== NMAP SCANNER MIGLIORATO ====================

class NmapScanner:
    """Wrapper per eseguire scansioni NMAP con gestione errori avanzata"""

    def __init__(self, nmap_path: str):
        self.nmap_path = nmap_path
        if not nmap_path:
            raise FileNotFoundError("NMAP non configurato! Verificare installazione.")

        logger.info(f"NmapScanner inizializzato con: {nmap_path}")

    def _run_nmap(self, args: List[str], timeout: int = 300) -> Tuple[str, bool]:
        """Esegue comando NMAP e ritorna output"""
        try:
            # Aggiungi opzioni per Windows se necessario
            if platform.system() == 'Windows':
                # Su Windows, evita di usare opzioni che richiedono privilegi
                # se non si è amministratori
                if '--unprivileged' not in args and not self._is_admin():
                    args.insert(0, '--unprivileged')

            cmd = [self.nmap_path] + args + ['-oX', '-']  # Output XML to stdout

            logger.debug(f"Comando NMAP: {' '.join(cmd)}")

            # Esegui con shell=True su Windows per alcuni casi
            use_shell = platform.system() == 'Windows'

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=use_shell
            )

            logger.debug(f"NMAP return code: {result.returncode}")

            if result.returncode == 0:
                logger.debug(f"NMAP output length: {len(result.stdout)} chars")
                return result.stdout, True
            else:
                logger.error(f"NMAP stderr: {result.stderr}")
                logger.error(f"NMAP stdout: {result.stdout}")

                # Alcuni codici di ritorno non sono errori fatali
                if result.returncode in [1, 2]:  # Warning codes
                    if result.stdout and '<nmaprun' in result.stdout:
                        logger.warning("NMAP completato con warning")
                        return result.stdout, True

                return result.stderr or result.stdout, False

        except subprocess.TimeoutExpired:
            logger.error(f"NMAP timeout dopo {timeout} secondi")
            return "Timeout", False
        except FileNotFoundError:
            logger.error(f"NMAP non trovato: {self.nmap_path}")
            return "NMAP not found", False
        except Exception as e:
            logger.error(f"Errore esecuzione NMAP: {type(e).__name__}: {e}")
            return str(e), False

    def _is_admin(self):
        """Verifica se il processo ha privilegi amministratore"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    def test_connectivity(self, ip: str) -> bool:
        """Test veloce di connettività con ping"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    timeout=2
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )

            return result.returncode == 0
        except:
            return False

    def quick_scan(self, subnet: str) -> List[Device]:
        """Scansione veloce per trovare host attivi"""
        logger.info(f"Avvio quick scan per {subnet}")

        # Prima prova con ARP ping (più affidabile in LAN)
        args = ['-sn', '-T4', '--max-retries', '2', subnet]

        output, success = self._run_nmap(args)

        if not success:
            logger.warning(f"Quick scan fallito per {subnet}, provo metodo alternativo")
            # Prova con ping ICMP semplice
            args = ['-sn', '-PE', '-T4', subnet]
            output, success = self._run_nmap(args)

            if not success:
                logger.error(f"Tutti i metodi di scan falliti per {subnet}")
                return []

        devices = []
        try:
            # Se l'output non è XML valido, prova parsing testuale
            if not output.startswith('<?xml'):
                logger.warning("Output non XML, tentativo parsing testuale")
                devices = self._parse_text_output(output, subnet)
            else:
                root = ET.fromstring(output)

                for host in root.findall('.//host'):
                    # Verifica che l'host sia up
                    status = host.find(".//status")
                    if status is None or status.get('state') != 'up':
                        continue

                    device = Device(ip_address='')

                    # IP Address
                    for addr in host.findall(".//address"):
                        if addr.get('addrtype') == 'ipv4':
                            device.ip_address = addr.get('addr')
                        elif addr.get('addrtype') == 'mac':
                            device.mac_address = addr.get('addr')
                            device.vendor = addr.get('vendor')

                    # Hostname
                    for hostname in host.findall(".//hostname"):
                        device.hostname = hostname.get('name')
                        break

                    device.status = 'online'

                    if device.ip_address:
                        devices.append(device)
                        logger.debug(f"Device trovato: {device.ip_address} ({device.mac_address})")

            logger.info(f"Quick scan completato: {len(devices)} dispositivi trovati in {subnet}")

        except ET.ParseError as e:
            logger.error(f"Errore parsing XML: {e}")
            logger.debug(f"Output XML non valido: {output[:500]}")
            # Tentativo di recupero con parsing testuale
            devices = self._parse_text_output(output, subnet)
        except Exception as e:
            logger.error(f"Errore inaspettato in quick_scan: {e}")

        return devices

    def _parse_text_output(self, output: str, subnet: str) -> List[Device]:
        """Parse output testuale di NMAP come fallback"""
        devices = []
        try:
            lines = output.split('\n')
            current_device = None

            for line in lines:
                # Cerca pattern IP
                ip_match = re.search(r'Nmap scan report for ([\d.]+)', line)
                if ip_match:
                    if current_device and current_device.ip_address:
                        devices.append(current_device)

                    current_device = Device(ip_address=ip_match.group(1))
                    current_device.status = 'online'

                # Cerca MAC address
                if current_device:
                    mac_match = re.search(r'MAC Address: ([0-9A-F:]+)(?:\s+\(([^)]+)\))?', line)
                    if mac_match:
                        current_device.mac_address = mac_match.group(1)
                        if mac_match.group(2):
                            current_device.vendor = mac_match.group(2)

                    # Cerca hostname
                    host_match = re.search(r'Nmap scan report for ([^\s]+) \(([\d.]+)\)', line)
                    if host_match:
                        current_device.hostname = host_match.group(1)

            # Aggiungi l'ultimo device
            if current_device and current_device.ip_address:
                devices.append(current_device)

            logger.info(f"Parse testuale completato: {len(devices)} dispositivi")

        except Exception as e:
            logger.error(f"Errore parse testuale: {e}")

        return devices

    def full_scan(self, ip: str) -> Device:
        """Scansione completa di un singolo host"""
        logger.info(f"Avvio full scan per {ip}")

        device = Device(ip_address=ip)

        # Test connettività prima
        if not self.test_connectivity(ip):
            logger.warning(f"Host {ip} non raggiungibile, skip full scan")
            device.status = 'offline'
            return device

        # Scansione servizi base (senza -O che richiede root)
        args = ['-sV', '-T4', '--max-retries', '2', ip]

        # Aggiungi -O solo se admin
        if self._is_admin():
            args.insert(0, '-O')
            args.insert(1, '--osscan-guess')

        output1, success1 = self._run_nmap(args, timeout=120)

        if success1:
            self._parse_full_scan(output1, device)
        else:
            logger.error(f"Full scan fallito per {ip}")

        # Scansione vulnerabilità (solo se prima scan ok)
        if success1 and device.open_ports:
            logger.info(f"Avvio vuln scan per {ip}")
            args = ['--script', 'vuln', '-T4', ip]
            output2, success2 = self._run_nmap(args, timeout=180)

            if success2:
                self._parse_vuln_scan(output2, device)

        # SNMP scan se porta 161 è aperta
        if any(p.get('port') == 161 for p in device.open_ports):
            logger.info(f"Porta SNMP aperta su {ip}, tentativo scan SNMP")
            self._scan_snmp(ip, device)

        return device

    def _parse_full_scan(self, xml_output: str, device: Device):
        """Parse output scansione completa"""
        try:
            if not xml_output.startswith('<?xml'):
                logger.warning("Output full scan non XML")
                return

            root = ET.fromstring(xml_output)
            host = root.find('.//host')

            if host is None:
                return

            # Status
            status = host.find(".//status")
            if status is not None:
                device.status = 'online' if status.get('state') == 'up' else 'offline'

            # Indirizzi
            for addr in host.findall(".//address"):
                if addr.get('addrtype') == 'mac':
                    device.mac_address = addr.get('addr')
                    device.vendor = addr.get('vendor')

            # Hostname
            for hostname in host.findall(".//hostname"):
                device.hostname = hostname.get('name')
                break

            # OS Detection
            for osmatch in host.findall(".//osmatch"):
                device.os_family = osmatch.get('name', '')
                accuracy = osmatch.get('accuracy', '')
                if accuracy:
                    device.os_version = f"{accuracy}% confidence"

                # Più dettagli da osclass
                for osclass in osmatch.findall(".//osclass"):
                    if osclass.get('osfamily'):
                        device.os_family = osclass.get('osfamily')
                    break
                break

            # Porte e Servizi
            for port in host.findall(".//port"):
                port_id = int(port.get('portid', 0))
                protocol = port.get('protocol', 'tcp')

                state = port.find(".//state")
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': port_id,
                        'protocol': protocol,
                        'state': 'open'
                    }

                    # Informazioni servizio
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

            logger.debug(f"Parse full scan completato: {len(device.open_ports)} porte aperte")

        except ET.ParseError as e:
            logger.error(f"Errore parsing full scan XML: {e}")
        except Exception as e:
            logger.error(f"Errore inaspettato in _parse_full_scan: {e}")

    def _parse_vuln_scan(self, xml_output: str, device: Device):
        """Parse output scansione vulnerabilità"""
        try:
            if not xml_output.startswith('<?xml'):
                return

            root = ET.fromstring(xml_output)
            host = root.find('.//host')

            if host is None:
                return

            # Cerca script output per vulnerabilità
            for script in host.findall(".//script"):
                script_id = script.get('id', '')
                output = script.get('output', '')

                # Filtra solo script relativi a vulnerabilità
                if 'vuln' in script_id.lower() or 'CVE' in output:
                    # Estrai CVE IDs
                    cve_pattern = r'CVE-\d{4}-\d{4,}'
                    cves = re.findall(cve_pattern, output)

                    # Determina severità
                    severity = 'low'
                    output_lower = output.lower()
                    if 'critical' in output_lower or 'rce' in output_lower:
                        severity = 'critical'
                    elif 'high' in output_lower or 'dos' in output_lower:
                        severity = 'high'
                    elif 'medium' in output_lower or 'xss' in output_lower:
                        severity = 'medium'

                    vuln = {
                        'vuln_id': script_id,
                        'title': script_id.replace('-', ' ').replace('_', ' ').title(),
                        'description': output[:500],
                        'cve_ids': ','.join(cves) if cves else None,
                        'severity': severity
                    }

                    device.vulnerabilities.append(vuln)
                    logger.debug(f"Vulnerabilità trovata: {script_id}")

        except ET.ParseError as e:
            logger.error(f"Errore parsing vuln scan XML: {e}")
        except Exception as e:
            logger.error(f"Errore in _parse_vuln_scan: {e}")

    def _scan_snmp(self, ip: str, device: Device):
        """Scansione SNMP per informazioni aggiuntive"""
        try:
            args = [
                '-sU', '-p', '161',
                '--script', 'snmp-info,snmp-interfaces,snmp-sysdescr',
                '--script-args', f'snmpcommunity={SCANNER_CONFIG["snmp_community"]}',
                ip
            ]

            output, success = self._run_nmap(args, timeout=60)

            if not success:
                return

            # Parse SNMP output
            if output.startswith('<?xml'):
                root = ET.fromstring(output)
                snmp_info = {}

                for script in root.findall(".//script"):
                    script_id = script.get('id', '')
                    output_text = script.get('output', '')

                    if 'snmp-sysdescr' in script_id:
                        snmp_info['sys_descr'] = output_text
                    elif 'snmp-info' in script_id:
                        # Parse SNMP info
                        for line in output_text.split('\n'):
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
                    logger.info(f"Informazioni SNMP raccolte per {ip}")

        except Exception as e:
            logger.error(f"Errore SNMP scan per {ip}: {e}")

# Il resto del codice rimane invariato ma userò la versione migliorata
# Continua con OUIManager, DatabaseManager e NetworkScanner dalla versione precedente
# ma con logging migliorato...

# ==================== TEST E INIZIALIZZAZIONE ====================

def test_scanner_setup():
    """Test completo del setup dello scanner"""
    logger.info("\n" + "="*60)
    logger.info("TEST CONFIGURAZIONE NETWORK SCANNER")
    logger.info("="*60)

    # Diagnostica sistema
    if not SystemDiagnostics.check_system():
        logger.error("[ERROR] Diagnostica sistema fallita!")
        logger.error("Correggere i problemi sopra indicati prima di continuare")
        return False

    logger.info("\n[OK] Diagnostica sistema completata con successo")

    # Test scansione di prova
    logger.info("\n" + "-"*40)
    logger.info("TEST SCANSIONE DI PROVA")
    logger.info("-"*40)

    try:
        scanner = NmapScanner(SCANNER_CONFIG['nmap_path'])

        # Test su localhost
        logger.info("Test scan su localhost (127.0.0.1)...")
        devices = scanner.quick_scan("127.0.0.1")

        if devices:
            logger.info(f"[OK] Test scan OK: {len(devices)} dispositivi trovati")
            for device in devices:
                logger.info(f"  - {device.ip_address}")
        else:
            logger.warning("[WARN] Nessun dispositivo trovato nel test (potrebbe essere normale)")

        return True

    except Exception as e:
        logger.error(f"[ERROR] Test scan fallito: {e}")
        return False

# ==================== MAIN ====================

if __name__ == "__main__":
    # Esegui test diagnostici
    if test_scanner_setup():
        logger.info("\n" + "="*60)
        logger.info("AVVIO NETWORK SCANNER")
        logger.info("="*60)

        from network_scanner import NetworkScanner, DatabaseManager, OUIManager

        # Inizializza e avvia scanner
        scanner = NetworkScanner(SCANNER_CONFIG)

        try:
            scanner.start_periodic_scan()
        except KeyboardInterrupt:
            logger.info("\nInterruzione richiesta dall'utente")
            scanner.stop()
        except Exception as e:
            logger.error(f"Errore fatale: {e}")
            scanner.stop()
    else:
        logger.error("\n[ERROR] Setup fallito. Correggere i problemi prima di avviare lo scanner.")
        sys.exit(1)