#!/usr/bin/env python3
"""
Script di test e debug per il database dello scanner
Verifica e risolve problemi di scrittura sul database
"""

import sqlite3
import os
import json
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_database_connection(db_path='scanner/network_scan.db'):
    """Testa la connessione al database"""
    logger.info(f"Testing database at: {os.path.abspath(db_path)}")

    # Verifica se la directory esiste
    db_dir = os.path.dirname(db_path)
    if not os.path.exists(db_dir):
        logger.warning(f"Directory {db_dir} non esiste, la creo...")
        os.makedirs(db_dir, exist_ok=True)

    # Verifica se il file database esiste
    if os.path.exists(db_path):
        logger.info(f"Database esiste: {db_path}")
        logger.info(f"Dimensione file: {os.path.getsize(db_path)} bytes")
    else:
        logger.warning("Database non esiste, verrà creato")

    try:
        # Test connessione
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verifica tabelle
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            ORDER BY name
        """)
        tables = cursor.fetchall()
        logger.info(f"Tabelle nel database: {[t[0] for t in tables]}")

        # Conta record nella tabella devices
        try:
            cursor.execute("SELECT COUNT(*) FROM devices")
            count = cursor.fetchone()[0]
            logger.info(f"Numero di dispositivi nel database: {count}")

            if count > 0:
                cursor.execute("SELECT * FROM devices LIMIT 5")
                rows = cursor.fetchall()
                logger.info("Primi 5 dispositivi:")
                for row in rows:
                    logger.info(f"  {row}")
        except sqlite3.OperationalError as e:
            logger.error(f"Errore lettura tabella devices: {e}")

        conn.close()
        return True

    except Exception as e:
        logger.error(f"Errore connessione database: {e}")
        return False


def create_database_schema(db_path='scanner/network_scan.db'):
    """Crea o ricrea lo schema del database"""
    logger.info("Creazione schema database...")

    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Drop delle tabelle esistenti (opzionale)
    # cursor.execute("DROP TABLE IF EXISTS devices")
    # cursor.execute("DROP TABLE IF EXISTS scan_history")

    # Crea tabella devices
    cursor.execute("""
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
            subnet TEXT,
            response_time REAL
        )
    """)

    # Crea indici
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON devices(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_subnet ON devices(subnet)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON devices(status)")

    # Crea tabella scan_history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            subnet TEXT,
            devices_found INTEGER DEFAULT 0,
            new_devices INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running',
            error_message TEXT,
            scan_method TEXT
        )
    """)

    # Crea tabella alerts
    cursor.execute("""
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

    # Crea tabella device_changes
    cursor.execute("""
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

    conn.commit()
    conn.close()

    logger.info("Schema database creato con successo")


def test_insert_device(db_path='scanner/network_scan.db'):
    """Test inserimento di un dispositivo di prova"""
    logger.info("Test inserimento dispositivo...")

    test_device = {
        'ip_address': '192.168.20.99',
        'hostname': 'test-device',
        'device_type': 'test',
        'open_ports': json.dumps([80, 443]),
        'services': 'http, https',
        'status': 'up',
        'subnet': '192.168.20.0/24',
        'response_time': 12.5
    }

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Prima verifica se esiste già
        cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (test_device['ip_address'],))
        existing = cursor.fetchone()

        if existing:
            logger.info(f"Dispositivo test già esiste con ID: {existing[0]}")
            # Update
            cursor.execute("""
                UPDATE devices SET
                    hostname = ?,
                    device_type = ?,
                    open_ports = ?,
                    services = ?,
                    status = ?,
                    last_seen = CURRENT_TIMESTAMP,
                    scan_count = scan_count + 1,
                    subnet = ?,
                    response_time = ?
                WHERE ip_address = ?
            """, (
                test_device['hostname'],
                test_device['device_type'],
                test_device['open_ports'],
                test_device['services'],
                test_device['status'],
                test_device['subnet'],
                test_device['response_time'],
                test_device['ip_address']
            ))
            logger.info("Dispositivo aggiornato")
        else:
            # Insert
            cursor.execute("""
                INSERT INTO devices (
                    ip_address, hostname, device_type, open_ports, 
                    services, status, subnet, response_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                test_device['ip_address'],
                test_device['hostname'],
                test_device['device_type'],
                test_device['open_ports'],
                test_device['services'],
                test_device['status'],
                test_device['subnet'],
                test_device['response_time']
            ))
            logger.info(f"Nuovo dispositivo inserito con ID: {cursor.lastrowid}")

        conn.commit()

        # Verifica che sia stato salvato
        cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (test_device['ip_address'],))
        saved = cursor.fetchone()
        if saved:
            logger.info(f"Dispositivo salvato correttamente: {dict(zip([d[0] for d in cursor.description], saved))}")
        else:
            logger.error("Dispositivo non trovato dopo il salvataggio!")

        conn.close()
        return True

    except Exception as e:
        logger.error(f"Errore durante inserimento: {e}")
        import traceback
        traceback.print_exc()
        return False


def insert_detected_devices(devices_data, db_path='scanner/network_scan.db'):
    """Inserisce i dispositivi rilevati nel database"""
    logger.info(f"Inserimento di {len(devices_data)} dispositivi nel database...")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        inserted = 0
        updated = 0

        for device in devices_data:
            # Verifica se esiste
            cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (device['ip'],))
            existing = cursor.fetchone()

            if existing:
                # Update
                cursor.execute("""
                    UPDATE devices SET
                        hostname = ?,
                        status = 'up',
                        last_seen = CURRENT_TIMESTAMP,
                        scan_count = scan_count + 1,
                        subnet = ?
                    WHERE ip_address = ?
                """, (
                    device.get('hostname'),
                    device.get('subnet'),
                    device['ip']
                ))
                updated += 1
                logger.debug(f"Aggiornato: {device['ip']}")
            else:
                # Insert
                cursor.execute("""
                    INSERT INTO devices (
                        ip_address, hostname, status, subnet, device_type
                    ) VALUES (?, ?, 'up', ?, 'unknown')
                """, (
                    device['ip'],
                    device.get('hostname'),
                    device.get('subnet')
                ))
                inserted += 1
                logger.debug(f"Inserito: {device['ip']}")

        conn.commit()
        conn.close()

        logger.info(f"Operazione completata: {inserted} inseriti, {updated} aggiornati")
        return True

    except Exception as e:
        logger.error(f"Errore durante inserimento batch: {e}")
        import traceback
        traceback.print_exc()
        return False


def fix_scanner_database():
    """Funzione principale per fixare il database dello scanner"""
    logger.info("=== INIZIO FIX DATABASE SCANNER ===")

    db_path = 'scanner/network_scan.db'

    # 1. Test connessione
    if not test_database_connection(db_path):
        logger.warning("Problemi con il database, provo a ricreare lo schema...")
        create_database_schema(db_path)

    # 2. Test inserimento
    if not test_insert_device(db_path):
        logger.error("Impossibile inserire dati nel database!")
        return False

    # 3. Inserisci i dispositivi rilevati dai log
    devices_from_logs = [
        {'ip': '192.168.20.1', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.3', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.4', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.7', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.9', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.11', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.12', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.15', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.16', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.20.17', 'subnet': '192.168.20.0/24'},
        {'ip': '192.168.30.1', 'subnet': '192.168.30.0/24'},
        {'ip': '192.168.30.2', 'subnet': '192.168.30.0/24'},
    ]

    logger.info("Inserimento dispositivi rilevati dai log...")
    insert_detected_devices(devices_from_logs, db_path)

    # 4. Verifica finale
    logger.info("\n=== VERIFICA FINALE ===")
    test_database_connection(db_path)

    logger.info("\n=== FIX COMPLETATO ===")
    return True


if __name__ == "__main__":
    fix_scanner_database()