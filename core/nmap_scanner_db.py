#!/usr/bin/env python3
"""
Nmap Scanner Database Schema - VERSIONE COMPLETA FINALE
Comprehensive SQLite database for storing Nmap XML scan results with full SNMP support
"""

import sqlite3
import os
import logging
from datetime import datetime
from typing import Optional, List, Dict


class NmapScannerDB:
    """Database handler for Nmap scan results with complete SNMP support"""

    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        """Initialize the database connection and create all tables"""

        # Setup logging FIRST
        self.logger = self._setup_logger()

        # Ensure instance directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")

        # Create all tables with complete schema
        self.create_tables()

    def _setup_logger(self):
        """Setup logger for this instance"""
        os.makedirs("logs", exist_ok=True)

        logger = logging.getLogger(f"{__name__}_{id(self)}")

        if not logger.handlers:
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler('logs/nmap_scanner.log')
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def create_tables(self):
        """Create ALL necessary tables including SNMP tables"""

        # =====================================================
        # TABELLE PRINCIPALI NMAP
        # =====================================================

        # Main scan runs table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanner VARCHAR(50),
            version VARCHAR(20),
            xml_output_version VARCHAR(10),
            args TEXT,
            start_time INTEGER,
            start_time_str VARCHAR(50),
            end_time INTEGER,
            end_time_str VARCHAR(50),
            filename VARCHAR(255),
            file_hash VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # Scan info table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            scan_type VARCHAR(50),
            protocol VARCHAR(10),
            num_services INTEGER,
            services TEXT,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Host hints table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS host_hints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            status_state VARCHAR(20),
            status_reason VARCHAR(50),
            status_reason_ttl INTEGER,
            ip_address VARCHAR(45),
            mac_address VARCHAR(17),
            vendor VARCHAR(100),
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Main hosts table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            start_time INTEGER,
            end_time INTEGER,
            status_state VARCHAR(20),
            status_reason VARCHAR(50),
            status_reason_ttl INTEGER,
            ip_address VARCHAR(45),
            mac_address VARCHAR(17),
            vendor VARCHAR(100),
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Host hostnames table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS hostnames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            hostname VARCHAR(255),
            hostname_type VARCHAR(50),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # Ports table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            protocol VARCHAR(10),
            port_id INTEGER,
            state VARCHAR(20),
            reason VARCHAR(50),
            reason_ttl INTEGER,
            service_name VARCHAR(100),
            service_product VARCHAR(200),
            service_version VARCHAR(100),
            service_extra_info TEXT,
            service_os_type VARCHAR(100),
            service_method VARCHAR(50),
            service_conf INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # CPE (Common Platform Enumeration) table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS cpe_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            cpe_string VARCHAR(500),
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
        )
        """)

        # Scripts table (NSE script results)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            script_id VARCHAR(100),
            script_output TEXT,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
        )
        """)

        # Script elements table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS script_elements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id INTEGER,
            elem_key VARCHAR(200),
            elem_value TEXT,
            parent_table_key VARCHAR(200),
            FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE
        )
        """)

        # Script tables
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS script_tables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id INTEGER,
            parent_table_id INTEGER,
            table_key VARCHAR(200),
            FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_table_id) REFERENCES script_tables(id) ON DELETE CASCADE
        )
        """)

        # Extra ports table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS extra_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            state VARCHAR(20),
            count INTEGER,
            reason VARCHAR(50),
            reason_count INTEGER,
            protocol VARCHAR(10),
            ports_range VARCHAR(500),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # OS detection table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS os_detection (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            port_used_state VARCHAR(20),
            port_used_proto VARCHAR(10),
            port_used_port_id INTEGER,
            port_used_portid INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # OS matches table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS os_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_detection_id INTEGER,
            match_name VARCHAR(300),
            match_accuracy INTEGER,
            match_line INTEGER,
            os_name VARCHAR(200),
            accuracy INTEGER,
            line INTEGER,
            FOREIGN KEY (os_detection_id) REFERENCES os_detection(id) ON DELETE CASCADE
        )
        """)

        # OS classes table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS os_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_match_id INTEGER,
            os_class_type VARCHAR(100),
            vendor VARCHAR(100),
            os_family VARCHAR(100),
            os_gen VARCHAR(50),
            accuracy INTEGER,
            cpe TEXT,
            os_type VARCHAR(100),
            FOREIGN KEY (os_match_id) REFERENCES os_matches(id) ON DELETE CASCADE
        )
        """)

        # Task progress table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS task_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            task_name VARCHAR(100),
            task_begin INTEGER,
            task_end INTEGER,
            task_time INTEGER,
            task_extrainfo TEXT,
            percent REAL,
            remaining INTEGER,
            etc INTEGER,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Runtime stats table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS runtime_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER UNIQUE,
            finished_time INTEGER,
            finished_time_str VARCHAR(50),
            elapsed_time TEXT,
            summary TEXT,
            exit_status VARCHAR(20),
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Vulnerabilities table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            port_id INTEGER,
            script_id INTEGER,
            vuln_id VARCHAR(100),
            title VARCHAR(500),
            description TEXT,
            severity VARCHAR(20),
            cvss_score REAL,
            state VARCHAR(20),
            risk_factor VARCHAR(20),
            disclosure_date TEXT,
            exploit_available BOOLEAN,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE,
            FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE
        )
        """)

        # Vulnerability references table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER,
            reference_type VARCHAR(50),
            reference_id VARCHAR(100),
            reference_url TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        )
        """)

        # =====================================================
        # TABELLE SNMP - COMPLETE E CORRETTE
        # =====================================================

        # SNMP Services (servizi Windows/Unix)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            startup_type TEXT DEFAULT 'unknown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, service_name)
        )
        """)

        # SNMP Processes (processi attivi)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            process_id INTEGER,
            process_name TEXT NOT NULL,
            process_path TEXT,
            memory_usage INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )
        """)

        # SNMP Software (software installato)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            software_name TEXT NOT NULL,
            version TEXT,
            install_date TEXT,
            vendor TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, software_name, version, install_date)
        )
        """)

        # SNMP Users (utenti di sistema)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            full_name TEXT,
            description TEXT,
            status TEXT DEFAULT 'unknown',
            last_logon TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, username)
        )
        """)

        # SNMP Network Interfaces
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            interface_index INTEGER,
            ip_address TEXT,
            netmask TEXT,
            interface_type TEXT,
            mac_address TEXT,
            status TEXT DEFAULT 'unknown',
            speed INTEGER,
            mtu INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )
        """)

        # SNMP Network Connections
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            local_address TEXT NOT NULL,
            local_port INTEGER,
            remote_address TEXT,
            remote_port INTEGER,
            state TEXT DEFAULT 'unknown',
            pid INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )
        """)

        # SNMP System Information
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_system_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL UNIQUE,
            system_description TEXT,
            hardware_info TEXT,
            software_info TEXT,
            system_uptime TEXT,
            system_contact TEXT,
            system_location TEXT,
            system_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )
        """)

        # SNMP Shares (condivisioni di rete)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            share_name TEXT NOT NULL,
            share_path TEXT,
            share_type TEXT DEFAULT 'unknown',
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, share_name)
        )
        """)

        # =====================================================
        # TABELLE SICUREZZA AGGIUNTIVE
        # =====================================================

        # SSL Certificates
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            subject TEXT,
            issuer TEXT,
            not_before TEXT,
            not_after TEXT,
            serial TEXT,
            signature_algorithm TEXT,
            key_length INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # SSH Host Keys
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ssh_hostkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            key_type TEXT NOT NULL,
            key_size INTEGER,
            fingerprint TEXT,
            key_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # HTTP Information
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS http_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            title TEXT,
            server_header TEXT,
            content_type TEXT,
            status_code INTEGER,
            redirect_url TEXT,
            methods TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # SMB Information
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS smb_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            computer_name TEXT,
            domain_name TEXT,
            workgroup TEXT,
            os_version TEXT,
            smb_version TEXT,
            signing_enabled BOOLEAN,
            signing_required BOOLEAN,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # Create indexes for performance
        self._create_indexes()

        # Commit all changes
        self.conn.commit()
        self.logger.info("Database tables created successfully")

    def _create_indexes(self):
        """Create indexes for better performance"""
        indexes = [
            # Main table indexes
            "CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_hosts_scan_run ON hosts(scan_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_scripts_port ON scripts(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_filename ON scan_runs(filename)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_hash ON scan_runs(file_hash)",

            # SNMP table indexes
            "CREATE INDEX IF NOT EXISTS idx_snmp_services_host ON snmp_services(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_processes_host ON snmp_processes(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_processes_name ON snmp_processes(process_name)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_software_host ON snmp_software(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_software_name ON snmp_software(software_name)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_users_host ON snmp_users(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_host ON snmp_interfaces(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_connections_host ON snmp_network_connections(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_system_host ON snmp_system_info(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_shares_host ON snmp_shares(host_id)",

            # Security table indexes
            "CREATE INDEX IF NOT EXISTS idx_ssl_certs_host ON ssl_certificates(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssh_keys_host ON ssh_hostkeys(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_script ON vulnerabilities(script_id)"
        ]

        for index_sql in indexes:
            try:
                self.conn.execute(index_sql)
            except Exception as e:
                self.logger.warning(f"Index creation failed: {e}")

    def get_scan_by_hash(self, file_hash: str) -> Optional[int]:
        """Check if a scan with the given hash already exists"""
        cursor = self.conn.execute(
            "SELECT id FROM scan_runs WHERE file_hash = ?",
            (file_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_scan_by_filename(self, filename: str) -> Optional[int]:
        """Get scan ID by filename"""
        cursor = self.conn.execute(
            "SELECT id FROM scan_runs WHERE filename = ?",
            (filename,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_all_scans(self) -> List[Dict]:
        """Get all scan runs with basic info"""
        cursor = self.conn.execute("""
        SELECT id, filename, start_time_str, end_time_str, args 
        FROM scan_runs 
        ORDER BY created_at DESC
        """)

        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'filename': row[1],
                'start_time': row[2],
                'end_time': row[3],
                'args': row[4]
            })
        return scans

    def get_hosts_for_scan(self, scan_run_id: int) -> List[Dict]:
        """Get all hosts for a specific scan"""
        cursor = self.conn.execute("""
        SELECT id, ip_address, status_state, mac_address, vendor
        FROM hosts 
        WHERE scan_run_id = ?
        ORDER BY ip_address
        """, (scan_run_id,))

        hosts = []
        for row in cursor.fetchall():
            hosts.append({
                'id': row[0],
                'ip_address': row[1],
                'status': row[2],
                'mac_address': row[3],
                'vendor': row[4]
            })
        return hosts

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute a custom query and return results as list of dicts"""
        cursor = self.conn.execute(query, params)
        columns = [description[0] for description in cursor.description]

        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def get_database_stats(self):
        """Get comprehensive database statistics"""
        stats = {}

        # Database file size
        stats['database_size_mb'] = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)

        # Get all table names
        cursor = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        # Count records in each table
        for table in tables:
            try:
                cursor = self.conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                stats[f"{table}_count"] = count
            except Exception as e:
                self.logger.warning(f"Could not count {table}: {e}")
                stats[f"{table}_count"] = 0

        return stats

    def cleanup_old_scans(self, keep_last_n: int = 10):
        """Remove old scan runs, keeping only the most recent N"""
        cursor = self.conn.execute("""
        SELECT id FROM scan_runs 
        ORDER BY created_at DESC 
        LIMIT -1 OFFSET ?
        """, (keep_last_n,))

        old_scan_ids = [row[0] for row in cursor.fetchall()]

        if old_scan_ids:
            placeholders = ','.join('?' * len(old_scan_ids))
            self.conn.execute(f"""
            DELETE FROM scan_runs WHERE id IN ({placeholders})
            """, old_scan_ids)

            self.conn.commit()
            self.logger.info(f"Cleaned up {len(old_scan_ids)} old scans")
            return len(old_scan_ids)

        return 0

    def vacuum_database(self):
        """Vacuum the database to reclaim space"""
        self.conn.execute("VACUUM")
        self.logger.info("Database vacuumed successfully")

    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Test function
def test_database_creation():
    """Test database creation with all tables"""
    test_db_path = "test_complete_db.db"

    # Remove existing test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("🧪 Testing complete database creation...")

    with NmapScannerDB(test_db_path) as db:
        stats = db.get_database_stats()

        print(f"✅ Database created successfully")
        print(f"📊 Database size: {stats['database_size_mb']} MB")

        # Count different types of tables
        main_tables = [k for k in stats.keys() if k.endswith('_count') and
                       not k.startswith('snmp_') and not k.startswith('ssl_') and
                       not k.startswith('ssh_') and not k.startswith('http_') and
                       not k.startswith('smb_')]

        snmp_tables = [k for k in stats.keys() if k.startswith('snmp_') and k.endswith('_count')]
        security_tables = [k for k in stats.keys() if k.endswith('_count') and
                           (k.startswith('ssl_') or k.startswith('ssh_') or
                            k.startswith('http_') or k.startswith('smb_'))]

        print(f"📋 Tables created:")
        print(f"   • {len(main_tables)} tabelle Nmap principali")
        print(f"   • {len(snmp_tables)} tabelle SNMP")
        print(f"   • {len(security_tables)} tabelle sicurezza")
        print(f"   • {len(main_tables) + len(snmp_tables) + len(security_tables)} tabelle totali")

        # Test SNMP tables specifically
        snmp_table_names = [
            'snmp_services', 'snmp_processes', 'snmp_software', 'snmp_users',
            'snmp_interfaces', 'snmp_network_connections', 'snmp_system_info', 'snmp_shares'
        ]

        print(f"\n🔍 Verifica tabelle SNMP:")
        all_snmp_present = True
        for table in snmp_table_names:
            if f"{table}_count" in stats:
                print(f"   ✅ {table}")
            else:
                print(f"   ❌ {table} MANCANTE!")
                all_snmp_present = False

        if all_snmp_present:
            print(f"\n🎉 TUTTI I COMPONENTI CREATI CORRETTAMENTE!")
            print(f"   Database pronto per il parsing SNMP")
        else:
            print(f"\n🚨 Alcune tabelle SNMP mancanti!")

    # Clean up test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    return all_snmp_present


if __name__ == "__main__":
    success = test_database_creation()
    if success:
        print("\n🚀 Database schema completo e pronto!")
    else:
        print("\n❌ Problemi con lo schema database")