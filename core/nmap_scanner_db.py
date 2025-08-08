"""
Nmap Scanner Database Schema
Comprehensive SQLite database for storing Nmap XML scan results
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
            ports_range TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # OS detection results
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

        # OS matches
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

        # OS classes
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS os_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_match_id INTEGER,
            os_type VARCHAR(100),
            vendor VARCHAR(100),
            os_family VARCHAR(100),
            os_gen VARCHAR(50),
            accuracy INTEGER,
            cpe TEXT,
            FOREIGN KEY (os_match_id) REFERENCES os_matches(id) ON DELETE CASCADE
        )
        """)

        # Task progress table
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS task_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            task_name VARCHAR(100),
            task_time INTEGER,
            percent REAL,
            remaining INTEGER,
            etc INTEGER,
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Runtime statistics
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS runtime_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER,
            finished_time INTEGER,
            finished_time_str VARCHAR(50),
            elapsed_time REAL,
            summary TEXT,
            exit_status VARCHAR(20),
            FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)

        # Vulnerability information (from vuln scripts)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id INTEGER,
            vuln_id VARCHAR(50),
            title TEXT,
            state VARCHAR(50),
            risk_factor VARCHAR(50),
            cvss_score REAL,
            description TEXT,
            disclosure_date DATE,
            exploit_available BOOLEAN,
            FOREIGN KEY (script_id) REFERENCES scripts(id) ON DELETE CASCADE
        )
        """)

        # Vulnerability references
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS vuln_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER,
            reference_url TEXT,
            reference_type VARCHAR(50),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        )
        """)

        # SNMP information (for SNMP scans)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS snmp_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            community_string VARCHAR(100),
            system_description TEXT,
            system_uptime INTEGER,
            system_contact VARCHAR(200),
            system_name VARCHAR(200),
            system_location VARCHAR(200),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # Process information (from SNMP process enumeration)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            process_id INTEGER,
            process_name VARCHAR(200),
            process_path TEXT,
            process_args TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # Network connections (from SNMP netstat)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            protocol VARCHAR(10),
            local_address VARCHAR(50),
            local_port INTEGER,
            remote_address VARCHAR(50),
            remote_port INTEGER,
            state VARCHAR(50),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        """)

        # Create indexes for better performance
        self._create_indexes()

        self.conn.commit()
        self.logger.info("Database tables created successfully")

    def _create_indexes(self):
        """Create indexes for better query performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_hosts_scan_run ON hosts(scan_run_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service_name)",
            "CREATE INDEX IF NOT EXISTS idx_scripts_port ON scripts(port_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_filename ON scan_runs(filename)",
            "CREATE INDEX IF NOT EXISTS idx_scan_runs_hash ON scan_runs(file_hash)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_script ON vulnerabilities(script_id)",
            "CREATE INDEX IF NOT EXISTS idx_processes_host ON processes(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_connections_host ON network_connections(host_id)"
        ]

        for index in indexes:
            self.conn.execute(index)

    def get_scan_by_hash(self, file_hash: str) -> Optional[int]:
        """Check if a scan with this hash already exists"""
        cursor = self.conn.execute(
            "SELECT id FROM scan_runs WHERE file_hash = ?", (file_hash,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()