"""
Database models per il sistema di network inventory
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import logging
import os

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path: str = "instance/network_inventory.db"):
        self.db_path = db_path
        # Crea la directory se non esiste
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_database()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_database(self):
        """Inizializza il database con tutte le tabelle necessarie"""
        with self.get_connection() as conn:
            # Tabella hosts principali
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    os_name TEXT,
                    os_family TEXT,
                    os_version TEXT,
                    os_accuracy INTEGER,
                    status TEXT DEFAULT 'up',
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_scan DATETIME,
                    confidence_score REAL DEFAULT 0.0,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Tabella scansioni
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    nmap_command TEXT,
                    xml_output TEXT,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    duration_seconds INTEGER,
                    hosts_found INTEGER DEFAULT 0,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Tabella porte e servizi
            conn.execute("""
                CREATE TABLE IF NOT EXISTS host_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    scan_id INTEGER,
                    protocol TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    service_name TEXT,
                    service_product TEXT,
                    service_version TEXT,
                    service_extrainfo TEXT,
                    service_ostype TEXT,
                    service_method TEXT,
                    service_conf INTEGER,
                    service_fingerprint TEXT,
                    cpe_list TEXT,
                    banner TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans (id),
                    UNIQUE(host_id, protocol, port)
                )
            """)

            # Tabella vulnerabilità
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_id INTEGER,
                    cve_id TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    description TEXT,
                    exploit_available BOOLEAN DEFAULT FALSE,
                    detection_method TEXT,
                    first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'open',
                    remediation TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                    FOREIGN KEY (port_id) REFERENCES host_ports (id) ON DELETE CASCADE
                )
            """)

            # Tabella script NSE
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nse_scripts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    port_id INTEGER,
                    scan_id INTEGER,
                    script_id TEXT NOT NULL,
                    script_output TEXT,
                    script_data TEXT,
                    execution_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                    FOREIGN KEY (port_id) REFERENCES host_ports (id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)

            # Tabella OUI (MAC address vendors)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oui_vendors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    oui TEXT UNIQUE NOT NULL,
                    vendor_name TEXT NOT NULL,
                    vendor_address TEXT,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Tabella CVE database
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_database (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT,
                    cvss_v2_score REAL,
                    cvss_v2_vector TEXT,
                    cvss_v3_score REAL,
                    cvss_v3_vector TEXT,
                    severity TEXT,
                    published_date DATETIME,
                    modified_date DATETIME,
                    cpe_list TEXT,
                    [references] TEXT,
                    exploit_available BOOLEAN DEFAULT FALSE,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Tabella cronologia device
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    field_changed TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_id INTEGER,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)

            # Tabella alerting
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    host_id INTEGER,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    alert_data TEXT,
                    status TEXT DEFAULT 'new',
                    acknowledged BOOLEAN DEFAULT FALSE,
                    acknowledged_by TEXT,
                    acknowledged_at DATETIME,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                )
            """)

            # Tabella configurazioni scanning
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_name TEXT UNIQUE NOT NULL,
                    scan_type TEXT NOT NULL,
                    target_range TEXT,
                    nmap_options TEXT,
                    schedule_enabled BOOLEAN DEFAULT TRUE,
                    schedule_interval INTEGER,
                    last_run DATETIME,
                    next_run DATETIME,
                    active BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Indici per performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_host_port ON host_ports(host_id, port)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_type_time ON scans(scan_type, start_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oui_lookup ON oui_vendors(oui)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_lookup ON cve_database(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)")

            # Inserisci configurazioni di scan di default
            self._insert_default_scan_configs(conn)

            conn.commit()
            logger.info("Database inizializzato correttamente")

    def _insert_default_scan_configs(self, conn):
        """Inserisce le configurazioni di scan di default"""
        default_configs = [
            ("discovery", "discovery", "192.168.30.0/24",
             "-sn -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 --source-port 53", True, 60),
            ("quick_scan", "tcp_connect", "192.168.30.0/24", "-sS --top-ports 1000 -T4", True, 240),
            ("full_scan", "comprehensive", "192.168.30.0/24", "-sS -sU -O -sV -sC --top-ports 1000 -T4", True, 1440),
            ("vuln_scan", "vulnerability", "192.168.30.0/24", "-sV --script vuln,exploit -T4", True, 4320),
            ("snmp_scan", "snmp", "192.168.30.0/24", "-sU -p 161 --script snmp-*", True, 720)
        ]

        for config in default_configs:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO scan_configs 
                    (config_name, scan_type, target_range, nmap_options, schedule_enabled, schedule_interval)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, config)
            except sqlite3.IntegrityError:
                pass  # Config già esistente

    def get_host_by_ip(self, ip_address: str) -> Optional[Dict]:
        """Recupera un host dal database tramite IP"""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM hosts WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_host_by_id(self, host_id: int) -> Optional[Dict]:
        """Recupera un host dal database tramite ID"""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def insert_or_update_host(self, host_data: Dict) -> int:
        """Inserisce o aggiorna un host nel database"""
        with self.get_connection() as conn:
            existing_host = self.get_host_by_ip(host_data['ip_address'])

            if existing_host:
                # Aggiorna host esistente
                host_id = existing_host['id']
                self._track_host_changes(conn, host_id, existing_host, host_data)

                conn.execute("""
                    UPDATE hosts SET 
                        mac_address = COALESCE(?, mac_address),
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor),
                        device_type = COALESCE(?, device_type),
                        os_name = COALESCE(?, os_name),
                        os_family = COALESCE(?, os_family),
                        os_version = COALESCE(?, os_version),
                        os_accuracy = COALESCE(?, os_accuracy),
                        status = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        last_scan = CURRENT_TIMESTAMP,
                        confidence_score = COALESCE(?, confidence_score),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (
                    host_data.get('mac_address'),
                    host_data.get('hostname'),
                    host_data.get('vendor'),
                    host_data.get('device_type'),
                    host_data.get('os_name'),
                    host_data.get('os_family'),
                    host_data.get('os_version'),
                    host_data.get('os_accuracy'),
                    host_data.get('status', 'up'),
                    host_data.get('confidence_score'),
                    host_id
                ))
            else:
                # Inserisci nuovo host
                cursor = conn.execute("""
                    INSERT INTO hosts (
                        ip_address, mac_address, hostname, vendor, device_type,
                        os_name, os_family, os_version, os_accuracy, status,
                        confidence_score, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    host_data['ip_address'],
                    host_data.get('mac_address'),
                    host_data.get('hostname'),
                    host_data.get('vendor'),
                    host_data.get('device_type'),
                    host_data.get('os_name'),
                    host_data.get('os_family'),
                    host_data.get('os_version'),
                    host_data.get('os_accuracy'),
                    host_data.get('status', 'up'),
                    host_data.get('confidence_score', 0.0),
                    host_data.get('notes')
                ))
                host_id = cursor.lastrowid

                # Crea alert per nuovo device
                self._create_new_device_alert(conn, host_id, host_data)

            conn.commit()
            return host_id

    def _track_host_changes(self, conn, host_id: int, old_data: Dict, new_data: Dict):
        """Traccia i cambiamenti nei dati dell'host"""
        fields_to_track = ['hostname', 'vendor', 'device_type', 'os_name', 'status']

        for field in fields_to_track:
            old_value = old_data.get(field)
            new_value = new_data.get(field)

            if new_value and old_value != new_value:
                conn.execute("""
                    INSERT INTO device_history (host_id, change_type, old_value, new_value, field_changed)
                    VALUES (?, 'field_change', ?, ?, ?)
                """, (host_id, str(old_value), str(new_value), field))

    def _create_new_device_alert(self, conn, host_id: int, host_data: Dict):
        """Crea un alert per un nuovo device scoperto"""
        conn.execute("""
            INSERT INTO alerts (alert_type, host_id, severity, title, description, alert_data)
            VALUES ('new_device', ?, 'info', 'Nuovo device scoperto', 
                    'È stato scoperto un nuovo device nella rete', ?)
        """, (host_id, json.dumps(host_data)))

    def insert_scan_record(self, scan_data: Dict) -> int:
        """Inserisce un record di scansione"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scans (scan_type, target, status, nmap_command, xml_output, 
                                 start_time, end_time, duration_seconds, hosts_found, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data['scan_type'],
                scan_data['target'],
                scan_data.get('status', 'completed'),
                scan_data.get('nmap_command'),
                scan_data.get('xml_output'),
                scan_data.get('start_time'),
                scan_data.get('end_time'),
                scan_data.get('duration_seconds'),
                scan_data.get('hosts_found', 0),
                scan_data.get('error_message')
            ))
            scan_id = cursor.lastrowid
            conn.commit()
            return scan_id

    def get_vendor_by_mac(self, mac_address: str) -> Optional[str]:
        """Recupera il vendor dal MAC address usando il database OUI"""
        if not mac_address or len(mac_address) < 8:
            return None

        oui = mac_address.upper().replace(':', '').replace('-', '')[:6]

        with self.get_connection() as conn:
            cursor = conn.execute("SELECT vendor_name FROM oui_vendors WHERE oui = ?", (oui,))
            row = cursor.fetchone()
            return row['vendor_name'] if row else None

    def get_all_hosts(self, active_only: bool = True) -> List[Dict]:
        """Recupera tutti gli host dal database"""
        with self.get_connection() as conn:
            query = "SELECT * FROM hosts"
            if active_only:
                query += " WHERE status = 'up'"
            query += " ORDER BY ip_address"

            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def get_host_ports(self, host_id: int) -> List[Dict]:
        """Recupera tutte le porte di un host"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM host_ports 
                WHERE host_id = ? AND state = 'open'
                ORDER BY protocol, port
            """, (host_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_host_vulnerabilities(self, host_id: int) -> List[Dict]:
        """Recupera tutte le vulnerabilità di un host"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                SELECT v.*, c.description as cve_description, c.cvss_v3_score
                FROM vulnerabilities v
                LEFT JOIN cve_database c ON v.cve_id = c.cve_id
                WHERE v.host_id = ? AND v.status = 'open'
                ORDER BY v.cvss_score DESC
            """, (host_id,))
            return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_data(self, days: int = 90):
        """Pulisce i dati vecchi dal database"""
        cutoff_date = datetime.now() - timedelta(days=days)

        with self.get_connection() as conn:
            # Rimuovi scansioni vecchie
            conn.execute("DELETE FROM scans WHERE start_time < ? AND status != 'running'",
                         (cutoff_date,))

            # Rimuovi host non visti da molto tempo
            conn.execute("UPDATE hosts SET status = 'inactive' WHERE last_seen < ?",
                         (cutoff_date,))

            # Rimuovi alert vecchi risolti
            conn.execute("DELETE FROM alerts WHERE resolved = 1 AND resolved_at < ?",
                         (cutoff_date,))

            conn.commit()
            logger.info(f"Cleanup completato per dati più vecchi di {days} giorni")

# Classe per gestire le operazioni sui port
class PortManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def insert_or_update_port(self, host_id: int, port_data: Dict, scan_id: Optional[int] = None):
        """Inserisce o aggiorna informazioni su una porta"""
        with self.db.get_connection() as conn:
            # Cerca porta esistente
            cursor = conn.execute("""
                SELECT id FROM host_ports 
                WHERE host_id = ? AND protocol = ? AND port = ?
            """, (host_id, port_data['protocol'], port_data['port']))

            existing_port = cursor.fetchone()

            if existing_port:
                # Aggiorna porta esistente
                conn.execute("""
                    UPDATE host_ports SET
                        state = ?, service_name = ?, service_product = ?,
                        service_version = ?, service_extrainfo = ?, service_ostype = ?,
                        service_method = ?, service_conf = ?, service_fingerprint = ?,
                        cpe_list = ?, banner = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (
                    port_data['state'],
                    port_data.get('service_name'),
                    port_data.get('service_product'),
                    port_data.get('service_version'),
                    port_data.get('service_extrainfo'),
                    port_data.get('service_ostype'),
                    port_data.get('service_method'),
                    port_data.get('service_conf'),
                    port_data.get('service_fingerprint'),
                    json.dumps(port_data.get('cpe_list', [])),
                    port_data.get('banner'),
                    existing_port['id']
                ))
                port_id = existing_port['id']
            else:
                # Inserisci nuova porta
                cursor = conn.execute("""
                    INSERT INTO host_ports (
                        host_id, scan_id, protocol, port, state, service_name,
                        service_product, service_version, service_extrainfo, service_ostype,
                        service_method, service_conf, service_fingerprint, cpe_list, banner
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    host_id, scan_id, port_data['protocol'], port_data['port'],
                    port_data['state'], port_data.get('service_name'),
                    port_data.get('service_product'), port_data.get('service_version'),
                    port_data.get('service_extrainfo'), port_data.get('service_ostype'),
                    port_data.get('service_method'), port_data.get('service_conf'),
                    port_data.get('service_fingerprint'),
                    json.dumps(port_data.get('cpe_list', [])),
                    port_data.get('banner')
                ))
                port_id = cursor.lastrowid

            conn.commit()
            return port_id

# Classe per gestire le vulnerabilità
class VulnerabilityManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def insert_vulnerability(self, vuln_data: Dict):
        """Inserisce una vulnerabilità nel database"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities (
                    host_id, port_id, cve_id, vuln_type, severity, cvss_score,
                    cvss_vector, description, exploit_available, detection_method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_data['host_id'],
                vuln_data.get('port_id'),
                vuln_data.get('cve_id'),
                vuln_data.get('vuln_type'),
                vuln_data.get('severity'),
                vuln_data.get('cvss_score'),
                vuln_data.get('cvss_vector'),
                vuln_data.get('description'),
                vuln_data.get('exploit_available', False),
                vuln_data.get('detection_method')
            ))

            vuln_id = cursor.lastrowid

            # Crea alert se la vulnerabilità è critica
            if vuln_data.get('cvss_score', 0) >= 7.0:
                self._create_vulnerability_alert(conn, vuln_data)

            conn.commit()
            return vuln_id

    def _create_vulnerability_alert(self, conn, vuln_data: Dict):
        """Crea un alert per una vulnerabilità critica"""
        conn.execute("""
            INSERT INTO alerts (alert_type, host_id, severity, title, description, alert_data)
            VALUES ('vulnerability', ?, 'high', 'Vulnerabilità critica rilevata', ?, ?)
        """, (
            vuln_data['host_id'],
            f"CVE: {vuln_data.get('cve_id', 'N/A')} - CVSS: {vuln_data.get('cvss_score', 'N/A')}",
            json.dumps(vuln_data)
        ))