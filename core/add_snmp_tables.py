#!/usr/bin/env python3
"""
Script per aggiungere le tabelle SNMP mancanti al database esistente
"""

import sqlite3
import os
import sys


def add_snmp_tables(db_path="instance/nmap_scans.db"):
    """Aggiunge le tabelle SNMP necessarie al database esistente"""

    # Controlla se il file database esiste
    if not os.path.exists(db_path):
        print(f"❌ Database non trovato: {db_path}")
        print("💡 Esegui prima il sistema principale per creare il database base")
        return False

    print(f"📂 Collegamento al database: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Verifica tabelle esistenti
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = [row[0] for row in cursor.fetchall()]
    print(f"📊 Trovate {len(existing_tables)} tabelle esistenti")

    # Definisci le tabelle SNMP da creare
    snmp_tables = {
        'snmp_services': '''
        CREATE TABLE IF NOT EXISTS snmp_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            service_name TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            startup_type TEXT DEFAULT 'unknown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, service_name)
        )''',

        'snmp_processes': '''
        CREATE TABLE IF NOT EXISTS snmp_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            process_id INTEGER,
            process_name TEXT NOT NULL,
            process_path TEXT,
            memory_usage INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )''',

        'snmp_software': '''
        CREATE TABLE IF NOT EXISTS snmp_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            software_name TEXT NOT NULL,
            version TEXT,
            install_date TEXT,
            vendor TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, software_name, install_date)
        )''',

        'snmp_users': '''
        CREATE TABLE IF NOT EXISTS snmp_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            full_name TEXT,
            description TEXT,
            status TEXT DEFAULT 'unknown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, username)
        )''',

        'snmp_interfaces': '''
        CREATE TABLE IF NOT EXISTS snmp_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            interface_name TEXT NOT NULL,
            ip_address TEXT,
            netmask TEXT,
            interface_type TEXT,
            status TEXT DEFAULT 'unknown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )''',

        'snmp_network_connections': '''
        CREATE TABLE IF NOT EXISTS snmp_network_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            local_address TEXT NOT NULL,
            remote_address TEXT,
            state TEXT DEFAULT 'unknown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )''',

        'snmp_system_info': '''
        CREATE TABLE IF NOT EXISTS snmp_system_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL UNIQUE,
            hardware_info TEXT,
            software_info TEXT,
            system_uptime TEXT,
            contact TEXT,
            location TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
        )''',

        'snmp_shares': '''
        CREATE TABLE IF NOT EXISTS snmp_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            share_name TEXT NOT NULL,
            share_path TEXT NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            UNIQUE(host_id, share_name)
        )''',

        # Tabelle aggiuntive per supportare altri tipi di vulnerabilità
        'ssl_certificates': '''
        CREATE TABLE IF NOT EXISTS ssl_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            subject TEXT,
            issuer TEXT,
            not_before TEXT,
            not_after TEXT,
            serial TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )''',

        'ssh_hostkeys': '''
        CREATE TABLE IF NOT EXISTS ssh_hostkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_id INTEGER NOT NULL,
            key_type TEXT,
            key_size TEXT,
            fingerprint TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE CASCADE
        )'''
    }

    # Crea le tabelle
    tables_created = 0
    tables_existing = 0

    for table_name, create_sql in snmp_tables.items():
        try:
            if table_name in existing_tables:
                print(f"✅ {table_name} - già esistente")
                tables_existing += 1
            else:
                cursor.execute(create_sql)
                print(f"🆕 {table_name} - creata")
                tables_created += 1
        except Exception as e:
            print(f"❌ Errore creando {table_name}: {e}")

    # Crea indici per le tabelle SNMP
    snmp_indexes = [
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
        "CREATE INDEX IF NOT EXISTS idx_ssl_certs_host ON ssl_certificates(host_id)",
        "CREATE INDEX IF NOT EXISTS idx_ssh_keys_host ON ssh_hostkeys(host_id)"
    ]

    print(f"\n🔧 Creando indici...")
    for index_sql in snmp_indexes:
        try:
            cursor.execute(index_sql)
        except Exception as e:
            print(f"⚠️  Errore creando indice: {e}")

    # Commit delle modifiche
    conn.commit()

    print(f"\n📈 Riassunto:")
    print(f"   • {tables_existing} tabelle già esistenti")
    print(f"   • {tables_created} tabelle create")
    print(f"   • {len(snmp_indexes)} indici aggiunti")

    # Verifica finale
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'snmp_%';")
    snmp_tables_final = [row[0] for row in cursor.fetchall()]

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ssl_certificates', 'ssh_hostkeys');")
    other_tables = [row[0] for row in cursor.fetchall()]

    print(f"\n✅ Verifica finale:")
    print(f"   • {len(snmp_tables_final)} tabelle SNMP presenti")
    print(f"   • {len(other_tables)} tabelle aggiuntive presenti")

    conn.close()

    if tables_created > 0:
        print(f"\n🎉 Database aggiornato con successo!")
        print(f"🚀 Ora puoi usare il nuovo parser SNMP")
    else:
        print(f"\n✨ Database già aggiornato, pronto all'uso!")

    return True


def show_table_counts(db_path="instance/nmap_scans.db"):
    """Mostra il conteggio dei record nelle tabelle"""

    if not os.path.exists(db_path):
        print(f"❌ Database non trovato: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print(f"\n📊 Stato attuale del database:")
    print("=" * 50)

    # Tabelle principali
    main_tables = ['scan_runs', 'hosts', 'ports', 'scripts']
    for table in main_tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"{table:20} : {count:>8} record")
        except:
            print(f"{table:20} : {'NON TROVATA':>15}")

    print("-" * 50)

    # Tabelle SNMP
    snmp_tables = [
        'snmp_services', 'snmp_processes', 'snmp_software', 'snmp_users',
        'snmp_interfaces', 'snmp_network_connections', 'snmp_system_info', 'snmp_shares'
    ]

    for table in snmp_tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            status = "✅" if count > 0 else "⚪"
            print(f"{status} {table:18} : {count:>8} record")
        except:
            print(f"❌ {table:18} : {'NON TROVATA':>15}")

    conn.close()


def main():
    """Main function"""
    print("🗄️  Aggiornamento Database SNMP")
    print("=" * 40)

    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    else:
        db_path = "instance/nmap_scans.db"

    # Aggiungi le tabelle
    success = add_snmp_tables(db_path)

    if success:
        # Mostra lo stato attuale
        show_table_counts(db_path)

        print(f"\n🎯 Prossimi passi:")
        print("1. Testa il nuovo parser:")
        print("   python core/advanced_nmap_parser.py")
        print("\n2. Parsa i tuoi file XML:")
        print(
            "   python -c \"from core.advanced_nmap_parser import AdvancedNmapParser; p=AdvancedNmapParser(); print('Parser pronto!')\"")
        print("\n3. Verifica i dati importati:")
        print(f"   python {sys.argv[0]} {db_path}")


if __name__ == "__main__":
    main()