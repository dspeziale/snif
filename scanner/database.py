import sqlite3
import os
from datetime import datetime, timedelta
import json
import logging


class DatabaseManager:
    """Gestisce il database SQLite per lo scanner"""

    def __init__(self, db_path='data/network_scanner.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def get_connection(self):
        """Ottiene connessione al database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """Inizializza il database con tutte le tabelle"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Tabella dispositivi
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT,
                os_name TEXT,
                os_version TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                notes TEXT
            )
        ''')

        # Tabella servizi
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                version TEXT,
                state TEXT,
                first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (device_id) REFERENCES devices (id),
                UNIQUE(device_id, port, protocol)
            )
        ''')

        # Tabella vulnerabilità
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                cve_id TEXT,
                severity TEXT,
                score REAL,
                description TEXT,
                solution TEXT,
                first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_verified DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # Tabella SNMP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                community_string TEXT,
                version TEXT,
                system_descr TEXT,
                system_name TEXT,
                system_location TEXT,
                system_contact TEXT,
                uptime INTEGER,
                interfaces_count INTEGER,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')

        # Tabella interfacce SNMP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snmp_info_id INTEGER,
                interface_index INTEGER,
                interface_name TEXT,
                interface_type TEXT,
                mac_address TEXT,
                ip_address TEXT,
                status TEXT,
                speed BIGINT,
                mtu INTEGER,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (snmp_info_id) REFERENCES snmp_info (id)
            )
        ''')

        # Tabella scansioni
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                status TEXT,
                devices_found INTEGER DEFAULT 0,
                xml_file TEXT,
                notes TEXT
            )
        ''')

        # Tabella cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_type TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                cache_value TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                UNIQUE(cache_type, cache_key)
            )
        ''')

        conn.commit()
        conn.close()

    def add_device(self, ip, mac=None, hostname=None, vendor=None):
        """Aggiunge o aggiorna un dispositivo"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Controlla se il dispositivo esiste già
        cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip,))
        existing = cursor.fetchone()

        if existing:
            # Aggiorna dispositivo esistente
            cursor.execute('''
                UPDATE devices 
                SET mac_address = COALESCE(?, mac_address),
                    hostname = COALESCE(?, hostname),
                    vendor = COALESCE(?, vendor),
                    last_seen = CURRENT_TIMESTAMP,
                    is_active = 1
                WHERE ip_address = ?
            ''', (mac, hostname, vendor, ip))
            device_id = existing['id']
        else:
            # Crea nuovo dispositivo
            cursor.execute('''
                INSERT INTO devices (ip_address, mac_address, hostname, vendor)
                VALUES (?, ?, ?, ?)
            ''', (ip, mac, hostname, vendor))
            device_id = cursor.lastrowid

        conn.commit()
        conn.close()
        return device_id

    def add_service(self, device_id, port, protocol, service_name=None, version=None, state='open'):
        """Aggiunge o aggiorna un servizio"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO services 
            (device_id, port, protocol, service_name, version, state, last_detected)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (device_id, port, protocol, service_name, version, state))

        conn.commit()
        conn.close()

    def add_vulnerability(self, device_id, cve_id, severity, score=None, description=None):
        """Aggiunge una vulnerabilità"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR IGNORE INTO vulnerabilities 
            (device_id, cve_id, severity, score, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, cve_id, severity, score, description))

        conn.commit()
        conn.close()

    def add_snmp_info(self, device_id, community, version, sys_descr=None, sys_name=None):
        """Aggiunge informazioni SNMP"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO snmp_info 
            (device_id, community_string, version, system_descr, system_name, last_updated)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (device_id, community, version, sys_descr, sys_name))

        snmp_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return snmp_id

    def get_all_devices(self):
        """Ottiene tutti i dispositivi attivi"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT d.*, 
                   COUNT(s.id) as services_count,
                   COUNT(v.id) as vulnerabilities_count,
                   CASE WHEN sn.id IS NOT NULL THEN 1 ELSE 0 END as has_snmp
            FROM devices d
            LEFT JOIN services s ON d.id = s.device_id AND s.is_active = 1
            LEFT JOIN vulnerabilities v ON d.id = v.device_id AND v.is_active = 1
            LEFT JOIN snmp_info sn ON d.id = sn.device_id
            WHERE d.is_active = 1
            GROUP BY d.id
            ORDER BY d.last_seen DESC
        ''')

        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return devices

    def get_device_details(self, device_id):
        """Ottiene dettagli completi di un dispositivo"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Dispositivo base
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        device = dict(cursor.fetchone()) if cursor.fetchone() else None

        if not device:
            conn.close()
            return None

        # Servizi
        cursor.execute('''
            SELECT * FROM services 
            WHERE device_id = ? AND is_active = 1 
            ORDER BY port
        ''', (device_id,))
        device['services'] = [dict(row) for row in cursor.fetchall()]

        # Vulnerabilità
        cursor.execute('''
            SELECT * FROM vulnerabilities 
            WHERE device_id = ? AND is_active = 1 
            ORDER BY score DESC
        ''', (device_id,))
        device['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]

        # SNMP
        cursor.execute('SELECT * FROM snmp_info WHERE device_id = ?', (device_id,))
        snmp_info = cursor.fetchone()
        if snmp_info:
            device['snmp'] = dict(snmp_info)

            # Interfacce SNMP
            cursor.execute('''
                SELECT * FROM snmp_interfaces 
                WHERE snmp_info_id = ? 
                ORDER BY interface_index
            ''', (snmp_info['id'],))
            device['snmp']['interfaces'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return device

    def get_dashboard_stats(self):
        """Ottiene statistiche per la dashboard"""
        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {}

        # Dispositivi totali
        cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_active = 1')
        stats['total_devices'] = cursor.fetchone()['count']

        # Dispositivi visti nelle ultime 24 ore
        cursor.execute('''
            SELECT COUNT(*) as count FROM devices 
            WHERE is_active = 1 AND last_seen > datetime('now', '-1 day')
        ''')
        stats['devices_24h'] = cursor.fetchone()['count']

        # Servizi totali
        cursor.execute('SELECT COUNT(*) as count FROM services WHERE is_active = 1')
        stats['total_services'] = cursor.fetchone()['count']

        # Vulnerabilità attive
        cursor.execute('SELECT COUNT(*) as count FROM vulnerabilities WHERE is_active = 1')
        stats['total_vulnerabilities'] = cursor.fetchone()['count']

        # Dispositivi con SNMP
        cursor.execute('SELECT COUNT(DISTINCT device_id) as count FROM snmp_info')
        stats['snmp_devices'] = cursor.fetchone()['count']

        # Ultima scansione
        cursor.execute('''
            SELECT scan_type, start_time, status 
            FROM scan_history 
            ORDER BY start_time DESC 
            LIMIT 1
        ''')
        last_scan = cursor.fetchone()
        stats['last_scan'] = dict(last_scan) if last_scan else None

        conn.close()
        return stats

    def add_scan_record(self, scan_type, target, xml_file=None):
        """Aggiunge record di scansione"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scan_history (scan_type, target, xml_file, status)
            VALUES (?, ?, ?, 'running')
        ''', (scan_type, target, xml_file))

        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def update_scan_record(self, scan_id, status, devices_found=0, notes=None):
        """Aggiorna record di scansione"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE scan_history 
            SET status = ?, end_time = CURRENT_TIMESTAMP, 
                devices_found = ?, notes = ?
            WHERE id = ?
        ''', (status, devices_found, notes, scan_id))

        conn.commit()
        conn.close()