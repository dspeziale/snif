#!/usr/bin/env python3
"""
Database Manager - Gestisce tutte le operazioni del database SQLite
"""

import sqlite3
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def adapt_datetime(dt):
    """Converte datetime in stringa ISO per SQLite"""
    return dt.isoformat()


def convert_datetime(s):
    """Converte stringa ISO da SQLite in datetime"""
    return datetime.fromisoformat(s.decode())


# Registra gli adapter per datetime
sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)


class DatabaseManager:
    """Gestisce tutte le operazioni del database SQLite"""

    def __init__(self, db_path: str = "../data/snmp_scan_results.db"):
        """Inizializza il manager del database"""
        os.makedirs("../data", exist_ok=True)
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def connect(self):
        """Connette al database SQLite"""
        try:
            self.conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            self.cursor = self.conn.cursor()
            logger.info(f"Connesso al database: {self.db_path}")
        except Exception as e:
            logger.error(f"Errore connessione database: {e}")
            raise

    def close(self):
        """Chiude la connessione al database"""
        if self.conn:
            self.conn.close()
            logger.info("Connessione database chiusa")

    def create_tables(self):
        """Crea tutte le tabelle necessarie per il database normalizzato"""

        # Tabella informazioni scansione
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_info (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                elapsed_time REAL,
                nmap_version TEXT,
                command_line TEXT,
                scan_args TEXT,
                total_hosts INTEGER,
                up_hosts INTEGER,
                down_hosts INTEGER,
                xml_file_name TEXT
            )
        ''')

        # Tabella principale degli host (chiave: IP address)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                vendor TEXT,
                status TEXT,
                status_reason TEXT,
                hostname TEXT,
                fqdn TEXT,
                scan_id INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scan_info(scan_id)
            )
        ''')

        # Tabella delle porte
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                state TEXT,
                reason TEXT,
                reason_ttl INTEGER,
                UNIQUE(ip_address, port_number, protocol),
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella dei servizi
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                service_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                service_name TEXT,
                service_product TEXT,
                service_version TEXT,
                service_info TEXT,
                service_method TEXT,
                service_conf INTEGER,
                UNIQUE(ip_address, port_number, protocol),
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella degli script NSE
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS nse_scripts (
                script_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                script_name TEXT,
                script_output TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle vulnerabilità
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port_number INTEGER,
                protocol TEXT,
                vuln_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                vuln_references TEXT,
                cvss_score REAL,
                cve_id TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella del software installato
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS installed_software (
                software_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                software_name TEXT,
                install_date TIMESTAMP,
                version TEXT,
                publisher TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella dei processi in esecuzione
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS running_processes (
                process_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                process_params TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle informazioni OS
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS os_info (
                ip_address TEXT PRIMARY KEY,
                os_name TEXT,
                os_version TEXT,
                os_family TEXT,
                os_generation TEXT,
                os_type TEXT,
                os_vendor TEXT,
                accuracy INTEGER,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella degli hostname e domini
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS hostnames (
                hostname_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                hostname TEXT,
                hostname_type TEXT,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Tabella delle traceroute
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS traceroute (
                trace_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                hop_number INTEGER,
                hop_ip TEXT,
                hop_hostname TEXT,
                rtt REAL,
                FOREIGN KEY (ip_address) REFERENCES hosts(ip_address)
            )
        ''')

        # Indici per performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_ip ON vulnerabilities(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_software_ip ON installed_software(ip_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_processes_ip ON running_processes(ip_address)')

        self.conn.commit()
        logger.info("Tabelle create con successo")

    def insert_scan_info(self, scan_info: Dict) -> int:
        """Inserisce informazioni della scansione e restituisce l'ID"""
        try:
            self.cursor.execute('''
                INSERT INTO scan_info 
                (start_time, end_time, elapsed_time, nmap_version, command_line, 
                 scan_args, total_hosts, up_hosts, down_hosts, xml_file_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_info.get('start_time'),
                scan_info.get('end_time'),
                scan_info.get('elapsed_time'),
                scan_info.get('nmap_version'),
                scan_info.get('command_line'),
                scan_info.get('scan_args'),
                scan_info.get('total_hosts'),
                scan_info.get('up_hosts'),
                scan_info.get('down_hosts'),
                scan_info.get('xml_file_name')
            ))
            return self.cursor.lastrowid
        except Exception as e:
            logger.error(f"Errore inserimento scan_info: {e}")
            return None

    def insert_host(self, host_data: Dict):
        """Inserisce o aggiorna un host"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO hosts 
                (ip_address, mac_address, vendor, status, status_reason, hostname, fqdn, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                host_data['ip_address'],
                host_data.get('mac_address'),
                host_data.get('vendor'),
                host_data.get('status'),
                host_data.get('status_reason'),
                host_data.get('hostname'),
                host_data.get('fqdn'),
                host_data.get('scan_id')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento host {host_data.get('ip_address')}: {e}")

    def insert_port(self, port_data: Dict):
        """Inserisce una porta"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO ports 
                (ip_address, port_number, protocol, state, reason, reason_ttl)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                port_data['ip_address'],
                port_data['port_number'],
                port_data['protocol'],
                port_data.get('state'),
                port_data.get('reason'),
                port_data.get('reason_ttl')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento porta: {e}")

    def insert_service(self, service_data: Dict):
        """Inserisce un servizio"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO services 
                (ip_address, port_number, protocol, service_name, service_product, 
                 service_version, service_info, service_method, service_conf)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                service_data['ip_address'],
                service_data['port_number'],
                service_data['protocol'],
                service_data.get('service_name'),
                service_data.get('service_product'),
                service_data.get('service_version'),
                service_data.get('service_info'),
                service_data.get('service_method'),
                service_data.get('service_conf')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento servizio: {e}")

    def insert_nse_script(self, script_data: Dict):
        """Inserisce risultato script NSE"""
        try:
            self.cursor.execute('''
                INSERT INTO nse_scripts 
                (ip_address, port_number, protocol, script_name, script_output)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                script_data['ip_address'],
                script_data.get('port_number'),
                script_data.get('protocol'),
                script_data['script_name'],
                script_data['script_output']
            ))
        except Exception as e:
            logger.error(f"Errore inserimento script NSE: {e}")

    def insert_vulnerability(self, vuln_data: Dict):
        """Inserisce una vulnerabilità"""
        try:
            self.cursor.execute('''
                INSERT INTO vulnerabilities 
                (ip_address, port_number, protocol, vuln_type, severity, title, 
                 description, vuln_references, cvss_score, cve_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_data['ip_address'],
                vuln_data.get('port_number'),
                vuln_data.get('protocol'),
                vuln_data.get('vuln_type'),
                vuln_data.get('severity'),
                vuln_data.get('title'),
                vuln_data.get('description'),
                vuln_data.get('vuln_references'),
                vuln_data.get('cvss_score'),
                vuln_data.get('cve_id')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento vulnerabilità: {e}")

    def insert_software(self, software_data: Dict):
        """Inserisce software installato"""
        try:
            self.cursor.execute('''
                INSERT INTO installed_software 
                (ip_address, software_name, install_date, version, publisher)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                software_data['ip_address'],
                software_data['software_name'],
                software_data.get('install_date'),
                software_data.get('version'),
                software_data.get('publisher')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento software: {e}")

    def insert_process(self, process_data: Dict):
        """Inserisce processo in esecuzione"""
        try:
            self.cursor.execute('''
                INSERT INTO running_processes 
                (ip_address, pid, process_name, process_path, process_params)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                process_data['ip_address'],
                process_data.get('pid'),
                process_data['process_name'],
                process_data.get('process_path'),
                process_data.get('process_params')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento processo: {e}")

    def insert_os_info(self, os_data: Dict):
        """Inserisce informazioni OS"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO os_info 
                (ip_address, os_name, os_version, os_family, os_generation, 
                 os_type, os_vendor, accuracy)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                os_data['ip_address'],
                os_data.get('os_name'),
                os_data.get('os_version'),
                os_data.get('os_family'),
                os_data.get('os_generation'),
                os_data.get('os_type'),
                os_data.get('os_vendor'),
                os_data.get('accuracy')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento OS info: {e}")

    def insert_hostname(self, hostname_data: Dict):
        """Inserisce hostname"""
        try:
            self.cursor.execute('''
                INSERT INTO hostnames 
                (ip_address, hostname, hostname_type)
                VALUES (?, ?, ?)
            ''', (
                hostname_data['ip_address'],
                hostname_data['hostname'],
                hostname_data.get('hostname_type', 'discovered')
            ))
        except Exception as e:
            logger.error(f"Errore inserimento hostname: {e}")

    def update_host_hostname(self, ip_address: str, hostname: str, source: str):
        """Aggiorna hostname di un host"""
        try:
            self.cursor.execute('''
                UPDATE hosts SET hostname = ? WHERE ip_address = ?
            ''', (hostname, ip_address))

            # Inserisce anche nella tabella hostnames
            self.insert_hostname({
                'ip_address': ip_address,
                'hostname': hostname,
                'hostname_type': source
            })
        except Exception as e:
            logger.error(f"Errore aggiornamento hostname: {e}")

    def commit(self):
        """Commit delle transazioni"""
        if self.conn:
            self.conn.commit()

    def rollback(self):
        """Rollback delle transazioni"""
        if self.conn:
            self.conn.rollback()

    def generate_summary_report(self) -> Dict:
        """Genera un report riassuntivo dei dati nel database"""
        report = {}

        try:
            # Conteggio host
            self.cursor.execute('SELECT COUNT(*) FROM hosts')
            report['total_hosts'] = self.cursor.fetchone()[0]

            # Host attivi
            self.cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'")
            report['active_hosts'] = self.cursor.fetchone()[0]

            # Host con hostname
            self.cursor.execute("SELECT COUNT(*) FROM hosts WHERE hostname IS NOT NULL AND hostname != ''")
            report['hosts_with_hostname'] = self.cursor.fetchone()[0]

            # Host con hostname multipli
            self.cursor.execute('''
                SELECT COUNT(DISTINCT ip_address) FROM hostnames 
                WHERE ip_address IN (
                    SELECT ip_address FROM hostnames 
                    GROUP BY ip_address HAVING COUNT(*) > 1
                )
            ''')
            report['hosts_with_multiple_hostnames'] = self.cursor.fetchone()[0]

            # Porte aperte
            self.cursor.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'")
            report['open_ports'] = self.cursor.fetchone()[0]

            # Vulnerabilità
            self.cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            report['vulnerabilities'] = self.cursor.fetchone()[0]

            # Software
            self.cursor.execute('SELECT COUNT(*) FROM installed_software')
            report['installed_software'] = self.cursor.fetchone()[0]

            # Processi
            self.cursor.execute('SELECT COUNT(*) FROM running_processes')
            report['running_processes'] = self.cursor.fetchone()[0]

            # Top 5 porte più comuni
            self.cursor.execute('''
                SELECT port_number, COUNT(*) as count 
                FROM ports WHERE state = 'open' 
                GROUP BY port_number 
                ORDER BY count DESC LIMIT 5
            ''')
            report['top_ports'] = self.cursor.fetchall()

            # Vendor più comuni
            self.cursor.execute('''
                SELECT vendor, COUNT(*) as count 
                FROM hosts WHERE vendor IS NOT NULL 
                GROUP BY vendor 
                ORDER BY count DESC LIMIT 5
            ''')
            report['vendors'] = self.cursor.fetchall()

        except Exception as e:
            logger.error(f"Errore generazione report: {e}")

        return report