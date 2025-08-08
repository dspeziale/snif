#!/usr/bin/env python3
"""
Script di verifica e correzione del database Nmap Scanner
Questo script verifica la struttura del database e corregge eventuali problemi
"""

import sqlite3
import os
import sys


def check_database_structure(db_path):
    """Verifica la struttura del database e identifica problemi"""

    print(f"🔍 Verificando database: {db_path}")

    if not os.path.exists(db_path):
        print(f"❌ Database non trovato: {db_path}")
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Ottieni tutte le tabelle
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]

        print(f"📊 Trovate {len(tables)} tabelle:")
        for table in tables:
            print(f"   • {table}")

        # Verifica struttura tabella ports
        print(f"\n🔍 Verifica struttura tabella 'ports':")
        cursor.execute("PRAGMA table_info(ports)")
        columns = cursor.fetchall()

        port_columns = [col[1] for col in columns]
        print(f"   Colonne trovate: {port_columns}")

        # Verifica presenza delle colonne critiche
        required_columns = ['service_name', 'state', 'host_id', 'port_id']
        missing_columns = []

        for col in required_columns:
            if col not in port_columns:
                missing_columns.append(col)

        if missing_columns:
            print(f"❌ Colonne mancanti in 'ports': {missing_columns}")
        else:
            print(f"✅ Tutte le colonne richieste sono presenti")

        # Verifica struttura tabella hosts
        print(f"\n🔍 Verifica struttura tabella 'hosts':")
        cursor.execute("PRAGMA table_info(hosts)")
        columns = cursor.fetchall()

        host_columns = [col[1] for col in columns]
        print(f"   Colonne trovate: {host_columns}")

        # Verifica presenza delle colonne critiche per hosts
        required_host_columns = ['status_state', 'ip_address', 'id']
        missing_host_columns = []

        for col in required_host_columns:
            if col not in host_columns:
                missing_host_columns.append(col)

        if missing_host_columns:
            print(f"❌ Colonne mancanti in 'hosts': {missing_host_columns}")
        else:
            print(f"✅ Tutte le colonne richieste sono presenti")

        # Verifica dati di esempio
        print(f"\n📈 Statistiche database:")

        cursor.execute("SELECT COUNT(*) FROM hosts")
        host_count = cursor.fetchone()[0]
        print(f"   • {host_count} host")

        cursor.execute("SELECT COUNT(*) FROM ports")
        port_count = cursor.fetchone()[0]
        print(f"   • {port_count} porte")

        if 'vulnerabilities' in tables:
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            print(f"   • {vuln_count} vulnerabilità")

        # Test query problematiche
        print(f"\n🧪 Test query dashboard:")

        try:
            # Test query servizi
            cursor.execute("""
                SELECT service_name, COUNT(*) as count
                FROM ports
                WHERE service_name IS NOT NULL AND service_name != ''
                GROUP BY service_name
                ORDER BY count DESC
                LIMIT 5
            """)
            services = cursor.fetchall()
            print(f"   ✅ Query servizi OK - {len(services)} servizi trovati")

            # Test query host attivi
            cursor.execute("""
                SELECT COUNT(*) as count FROM hosts WHERE status_state = 'up'
            """)
            active_hosts = cursor.fetchone()[0]
            print(f"   ✅ Query host attivi OK - {active_hosts} host attivi")

            # Test query porte aperte
            cursor.execute("""
                SELECT COUNT(*) as count FROM ports WHERE state = 'open'
            """)
            open_ports = cursor.fetchone()[0]
            print(f"   ✅ Query porte aperte OK - {open_ports} porte aperte")

        except Exception as e:
            print(f"   ❌ Errore test query: {e}")
            return False

        conn.close()
        print(f"\n✅ Verifica database completata con successo!")
        return True

    except Exception as e:
        print(f"❌ Errore durante verifica: {e}")
        return False


def create_missing_columns(db_path):
    """Crea colonne mancanti se necessario"""

    print(f"\n🔧 Tentativo correzione database...")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Backup del database
        backup_path = f"{db_path}.backup"
        print(f"📦 Creando backup: {backup_path}")

        with open(backup_path, 'w') as f:
            for line in conn.iterdump():
                f.write('%s\n' % line)

        # Qui potresti aggiungere logic per aggiungere colonne mancanti
        # Per ora solo notifichiamo
        print(f"⚠️  Correzioni automatiche non implementate")
        print(f"💡 Suggerimento: Ricrea il database dal parser XML")

        conn.close()

    except Exception as e:
        print(f"❌ Errore durante correzione: {e}")


def main():
    """Funzione principale"""

    print("🚀 Nmap Scanner Database Checker")
    print("=" * 50)

    # Path del database
    db_paths = [
        "instance/nmap_scans.db",
        "nmap_scans.db",
        "../instance/nmap_scans.db"
    ]

    db_path = None
    for path in db_paths:
        if os.path.exists(path):
            db_path = path
            break

    if not db_path:
        print(f"❌ Nessun database trovato nei percorsi:")
        for path in db_paths:
            print(f"   • {path}")

        # Chiedi all'utente il percorso
        custom_path = input("\n📝 Inserisci il percorso del database (o premi Invio per uscire): ").strip()
        if custom_path and os.path.exists(custom_path):
            db_path = custom_path
        else:
            print("👋 Uscita.")
            return

    # Verifica il database
    success = check_database_structure(db_path)

    if not success:
        print(f"\n🛠️  Vuoi tentare una correzione automatica? (y/n): ", end="")
        response = input().lower().strip()

        if response == 'y':
            create_missing_columns(db_path)

    print(f"\n" + "=" * 50)
    print(f"🏁 Verifica completata!")


if __name__ == "__main__":
    main()