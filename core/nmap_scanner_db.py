"""
Nmap Scanner Database Schema - Versione Completa
Comprehensive SQLite database for storing Nmap XML scan results with SNMP support
"""

import sqlite3
import os
import logging
from datetime import datetime
from typing import Optional

class NmapScannerDB:
    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        """Initialize the database connection and create tables if they don't exist"""
        # Setup logging FIRST before anything else
        self.logger = self._setup_logger()

        # Ensure instance directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_tables()

    def _setup_logger(self):
        """Setup logger for this instance"""
        # Ensure logs directory exists
        os.makedirs("logs", exist_ok=True)

        # Create logger
        logger = logging.getLogger(f"{__name__}_{id(self)}")

        # Only add handler if not already added
        if not logger.handlers:
            logger.setLevel(logging.INFO)

            # Create file handler
            handler = logging.FileHandler('logs/nmap_scanner.log')
            handler.setLevel(logging.INFO)

            # Create formatter
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)

            # Add handler to logger
            logger.addHandler(handler)

        return logger

    def create_tables(self):
        """Create all necessary tables for storing Nmap scan data"""

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

        # Scan info table (different scan types)
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

        # Host hints table (for discovered hosts before detailed scanning)
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

        # Script elements table (structured script data)
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

        # Script tables (nested script data structures)
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
            port_used_portid INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # OS matches table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS os_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_detection_id INTEGER,
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
            os_type VARCHAR(100),
            vendor VARCHAR(100),
            os_family VARCHAR(100),
            os_gen VARCHAR(100),
            accuracy INTEGER,
            FOREIGN KEY (os_match_id) REFERENCES os_matches(id) ON DELETE CASCADE
        )
        """)

        # Task progress table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS task_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            task VARCHAR(50),
            time INTEGER,
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
            scan_run_id INTEGER,
            finished_time INTEGER,
            finished_time_str VARCHAR(50),
            elapsed REAL,
            summary TEXT,
            exit_status VARCHAR(20),
            hosts_up INTEGER,
            hosts_down INTEGER,
            hosts_total INTEGER,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Vulnerabilities table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id INTEGER,
            host_id INTEGER,
            port_id INTEGER,
            vuln_id VARCHAR(50),
            title VARCHAR(200),
            state VARCHAR(20),
            risk_factor VARCHAR(20),
            cvss_score REAL,
            description TEXT,
            disclosure_date VARCHAR(20),
            exploit_available BOOLEAN,
            FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
        )
        """)

        # Vulnerability references table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER,
            reference_url TEXT,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        )
        """)

        # =====================================================
        # TABELLE SNMP SPECIALIZZATE
        # =====================================================

        # SNMP Services (servizi Windows/Linux)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            startup_type TEXT DEFAULT 'unknown',
            description TEXT,
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
            process_args TEXT,
            memory_usage INTEGER,
            cpu_usage REAL,
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
            install_location TEXT,
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

        # SNMP Network Interfaces (interfacce di rete)
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

        # SNMP Network Connections (connessioni di rete attive)
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

        # SNMP System Information (informazioni di sistema)
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
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )
        """)

        # SNMP Shares (condivisioni di rete)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            share_name TEXT NOT NULL,
            share_path TEXT NOT NULL,
            share_type TEXT,
            description TEXT,
            max_users INTEGER,
            current_users INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, share_name)
        )
        """)

        # =====================================================
        # TABELLE AGGIUNTIVE PER SICUREZZA
        # =====================================================

        # SSL Certificates (certificati SSL)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            subject TEXT,
            issuer TEXT,
            not_before TEXT,
            not_after TEXT,
            serial_number TEXT,
            signature_algorithm TEXT,
            key_size INTEGER,
            fingerprint_md5 TEXT,
            fingerprint_sha1 TEXT,
            fingerprint_sha256 TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # SSH Host Keys (chiavi host SSH)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS ssh_hostkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            key_type TEXT,
            key_size TEXT,
            fingerprint TEXT,
            key_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )
        """)

        # HTTP Information (informazioni HTTP)
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

        # SMB Information (informazioni SMB/CIFS)
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

        # Create indexes for better performance
        self._create_indexes()

        self.conn.commit()
        self.logger.info("Database tables created successfully")

    def _create_indexes(self):
        """Create indexes for better query performance"""
        indexes = [
            # Indexes principali
            "CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_hosts_scan_run ON hosts(scan_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_scripts_port ON scripts(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_filename ON scan_runs(filename)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_hash ON scan_runs(file_hash)",

            # Indexes per vulnerabilità
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_script ON vulnerabilities(script_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON vulnerabilities(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vuln_id ON vulnerabilities(vuln_id)",

            # Indexes SNMP
            "CREATE INDEX IF NOT EXISTS idx_snmp_services_host ON snmp_services(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_services_name ON snmp_services(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_processes_host ON snmp_processes(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_processes_name ON snmp_processes(process_name)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_processes_pid ON snmp_processes(process_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_software_host ON snmp_software(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_software_name ON snmp_software(software_name)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_users_host ON snmp_users(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_users_username ON snmp_users(username)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_host ON snmp_interfaces(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_ip ON snmp_interfaces(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_connections_host ON snmp_network_connections(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_connections_local ON snmp_network_connections(local_address)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_system_host ON snmp_system_info(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_snmp_shares_host ON snmp_shares(host_id)",

            # Indexes per sicurezza
            "CREATE INDEX IF NOT EXISTS idx_ssl_certs_host ON ssl_certificates(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssl_certs_port ON ssl_certificates(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssh_keys_host ON ssh_hostkeys(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ssh_keys_port ON ssh_hostkeys(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_http_info_host ON http_info(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_smb_info_host ON smb_info(host_id)"
        ]

        for index in indexes:
            try:
                self.conn.execute(index)
            except Exception as e:
                self.logger.error(f"Error creating index: {e}")

    def get_scan_by_hash(self, file_hash: str) -> Optional[int]:
        """Check if a scan with this hash already exists"""
        cursor = self.conn.execute(
            "SELECT id FROM scan_runs WHERE file_hash = ?", (file_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_database_stats(self) -> dict:
        """Get statistics about the database"""
        stats = {}

        # Get table counts
        cursor = self.conn.execute("""
        SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
        """)
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor = self.conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                stats[f'{table}_count'] = count
            except Exception as e:
                stats[f'{table}_count'] = f"Error: {e}"

        # Get total database size
        cursor = self.conn.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0]
        stats['database_size_bytes'] = db_size
        stats['database_size_mb'] = round(db_size / (1024 * 1024), 2)

        return stats

    def cleanup_old_scans(self, keep_last_n: int = 10):
        """Remove old scan data, keeping only the last N scans"""
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
        """Vacuum the database to reclaim space and optimize performance"""
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

# Utility functions per testare il database
def test_database_creation():
    """Test function to verify database creation"""
    test_db_path = "test_nmap_scans.db"

    # Remove existing test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("🧪 Testing database creation...")

    with NmapScannerDB(test_db_path) as db:
        stats = db.get_database_stats()

        print(f"✅ Database created successfully")
        print(f"📊 Database size: {stats['database_size_mb']} MB")

        # Count tables by category
        nmap_tables = sum(1 for k in stats.keys() if k.endswith('_count') and
                         not k.startswith('snmp_') and not k.startswith('ssl_') and
                         not k.startswith('ssh_') and not k.startswith('http_') and
                         not k.startswith('smb_'))

        snmp_tables = sum(1 for k in stats.keys() if k.startswith('snmp_') and k.endswith('_count'))
        security_tables = sum(1 for k in stats.keys() if k.endswith('_count') and
                            (k.startswith('ssl_') or k.startswith('ssh_') or k.startswith('http_') or k.startswith('smb_')))

        print(f"📋 Tables created:")
        print(f"   • {nmap_tables} tabelle Nmap principali")
        print(f"   • {snmp_tables} tabelle SNMP")
        print(f"   • {security_tables} tabelle sicurezza aggiuntive")

        total_tables = nmap_tables + snmp_tables + security_tables
        print(f"   • {total_tables} tabelle totali")

    # Clean up test database
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

    print("🎉 Test completato con successo!")

if __name__ == "__main__":
    test_database_creation()