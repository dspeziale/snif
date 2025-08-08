#!/usr/bin/env python3
"""
Setup Clean System - Ricrea tutto da zero con supporto SNMP completo
"""

import os
import shutil
import sqlite3
import sys


def clean_everything():
    """Pulisce tutto il sistema"""
    print("🧹 PULIZIA COMPLETA DEL SISTEMA")
    print("=" * 40)

    items_to_remove = [
        'instance',
        'logs',
        '*.db',
        'test_*.db',
        '__pycache__',
        'core/__pycache__'
    ]

    removed_count = 0

    for item in items_to_remove:
        if '*' in item:
            # Handle wildcards
            import glob
            matching_files = glob.glob(item)
            for file in matching_files:
                try:
                    if os.path.isfile(file):
                        os.remove(file)
                        print(f"🗑️ Rimosso file: {file}")
                        removed_count += 1
                    elif os.path.isdir(file):
                        shutil.rmtree(file)
                        print(f"🗑️ Rimossa directory: {file}")
                        removed_count += 1
                except Exception as e:
                    print(f"⚠️ Errore rimuovendo {file}: {e}")
        else:
            # Handle regular files/directories
            if os.path.exists(item):
                try:
                    if os.path.isfile(item):
                        os.remove(item)
                        print(f"🗑️ Rimosso file: {item}")
                        removed_count += 1
                    elif os.path.isdir(item):
                        shutil.rmtree(item)
                        print(f"🗑️ Rimossa directory: {item}")
                        removed_count += 1
                except Exception as e:
                    print(f"⚠️ Errore rimuovendo {item}: {e}")

    print(f"✅ Pulizia completata: {removed_count} elementi rimossi")


def create_directory_structure():
    """Crea la struttura delle directory"""
    print("\n📁 CREAZIONE STRUTTURA DIRECTORY")
    print("=" * 40)

    directories = [
        'instance',
        'logs',
        'core',
        'scans',
        'reports',
        'backups'
    ]

    created_count = 0
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"📂 Directory creata: {directory}")
            created_count += 1
        except Exception as e:
            print(f"❌ Errore creando {directory}: {e}")

    print(f"✅ {created_count} directory create")


def setup_core_files():
    """Setup dei file core"""
    print("\n📋 SETUP FILE CORE")
    print("=" * 40)

    # Copy the new database schema
    print("🔧 Copiando nmap_scanner_db.py...")
    try:
        shutil.copy2('nmap_scanner_db.py', 'core/nmap_scanner_db.py')
        print("✅ nmap_scanner_db.py copiato")
    except Exception as e:
        print(f"❌ Errore copiando nmap_scanner_db.py: {e}")

    # Copy the advanced parser
    print("🔧 Copiando advanced_nmap_parser.py...")
    try:
        shutil.copy2('advanced_nmap_parser.py', 'core/advanced_nmap_parser.py')
        print("✅ advanced_nmap_parser.py copiato")
    except Exception as e:
        print(f"❌ Errore copiando advanced_nmap_parser.py: {e}")


def test_database_creation():
    """Testa la creazione del database"""
    print("\n🧪 TEST CREAZIONE DATABASE")
    print("=" * 40)

    try:
        sys.path.insert(0, 'core')
        from nmap_scanner_db import NmapScannerDB

        # Test database creation
        with NmapScannerDB() as db:
            stats = db.get_database_stats()

            print("✅ Database creato con successo")
            print(f"📊 Dimensione: {stats['database_size_mb']} MB")

            # Count table types
            main_tables = [k for k in stats.keys() if k.endswith('_count') and
                           not k.startswith(('snmp_', 'ssl_', 'ssh_', 'http_', 'smb_'))]
            snmp_tables = [k for k in stats.keys() if k.startswith('snmp_') and k.endswith('_count')]
            security_tables = [k for k in stats.keys() if k.endswith('_count') and
                               k.startswith(('ssl_', 'ssh_', 'http_', 'smb_'))]

            print(f"📋 Tabelle create:")
            print(f"   • {len(main_tables)} tabelle Nmap principali")
            print(f"   • {len(snmp_tables)} tabelle SNMP")
            print(f"   • {len(security_tables)} tabelle sicurezza")
            print(f"   • {len(main_tables) + len(snmp_tables) + len(security_tables)} totali")

            # Verify SNMP tables specifically
            required_snmp_tables = [
                'snmp_services_count', 'snmp_processes_count', 'snmp_software_count',
                'snmp_users_count', 'snmp_interfaces_count', 'snmp_network_connections_count',
                'snmp_system_info_count', 'snmp_shares_count'
            ]

            missing_snmp = [t for t in required_snmp_tables if t not in stats]
            if missing_snmp:
                print(f"❌ Tabelle SNMP mancanti: {missing_snmp}")
                return False
            else:
                print("✅ Tutte le tabelle SNMP presenti")
                return True

    except Exception as e:
        print(f"❌ Test database fallito: {e}")
        return False


def test_advanced_parser():
    """Testa il parser avanzato"""
    print("\n🧪 TEST PARSER AVANZATO")
    print("=" * 40)

    try:
        sys.path.insert(0, 'core')
        from advanced_nmap_parser import AdvancedNmapParser

        # Create parser instance
        parser = AdvancedNmapParser()
        print("✅ AdvancedNmapParser creato")

        # Check SNMP handlers
        snmp_handlers = [k for k in parser.script_handlers.keys() if k.startswith('snmp-')]
        print(f"✅ {len(snmp_handlers)} handler SNMP registrati:")

        for handler in snmp_handlers:
            print(f"    📋 {handler}")

        if len(snmp_handlers) == 8:  # Expected number of SNMP handlers
            print("✅ Tutti gli handler SNMP presenti")
            return True
        else:
            print(f"❌ Handler SNMP incompleti: {len(snmp_handlers)}/8")
            return False

    except Exception as e:
        print(f"❌ Test parser fallito: {e}")
        return False


def check_xml_files():
    """Controlla i file XML disponibili"""
    print("\n📁 CONTROLLO FILE XML")
    print("=" * 40)

    scan_dirs = ['scans', '.']
    xml_files = []

    for scan_dir in scan_dirs:
        if os.path.exists(scan_dir):
            for file in os.listdir(scan_dir):
                if file.lower().endswith('.xml'):
                    xml_files.append(os.path.join(scan_dir, file))

    print(f"📄 Trovati {len(xml_files)} file XML:")

    good_files = 0
    snmp_files = 0

    for xml_file in xml_files:
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()

            if root.tag == 'nmaprun':
                # Count SNMP scripts
                snmp_scripts = [s for s in root.findall('.//script')
                                if s.get('id', '').startswith('snmp-')]

                if snmp_scripts:
                    print(f"✅ {xml_file}: {len(snmp_scripts)} script SNMP")
                    snmp_files += 1
                else:
                    print(f"⚪ {xml_file}: nessuno script SNMP")

                good_files += 1
            else:
                print(f"❌ {xml_file}: non è un file Nmap XML")

        except ET.ParseError:
            print(f"❌ {xml_file}: XML corrotto")
        except Exception as e:
            print(f"❌ {xml_file}: errore - {e}")

    print(f"\n📊 Riepilogo file:")
    print(f"   File XML validi: {good_files}")
    print(f"   File con SNMP: {snmp_files}")

    return good_files, snmp_files


def create_test_script():
    """Crea uno script di test completo"""
    print("\n📝 CREAZIONE SCRIPT DI TEST")
    print("=" * 40)

    test_script = '''#!/usr/bin/env python3
"""
Test completo del sistema SNMP
"""

import os
import sys
import sqlite3

def test_full_system():
    """Test completo del sistema"""
    print("🧪 TEST COMPLETO SISTEMA SNMP")
    print("=" * 50)

    # Test 1: Database
    print("\\n1. Test Database...")
    sys.path.insert(0, 'core')

    try:
        from nmap_scanner_db import NmapScannerDB
        with NmapScannerDB() as db:
            stats = db.get_database_stats()
            snmp_tables = [k for k in stats.keys() if k.startswith('snmp_')]
            print(f"✅ Database OK - {len(snmp_tables)} tabelle SNMP")
    except Exception as e:
        print(f"❌ Database ERRORE: {e}")
        return False

    # Test 2: Parser
    print("\\n2. Test Parser...")
    try:
        from advanced_nmap_parser import AdvancedNmapParser
        parser = AdvancedNmapParser()
        snmp_handlers = [k for k in parser.script_handlers.keys() if k.startswith('snmp-')]
        print(f"✅ Parser OK - {len(snmp_handlers)} handler SNMP")
    except Exception as e:
        print(f"❌ Parser ERRORE: {e}")
        return False

    # Test 3: File XML
    print("\\n3. Test File XML...")
    xml_files = []
    if os.path.exists('scans'):
        xml_files = [f for f in os.listdir('scans') if f.endswith('.xml')]

    if xml_files:
        print(f"✅ Trovati {len(xml_files)} file XML")

        # Test parsing di un file
        test_file = os.path.join('scans', xml_files[0])
        try:
            success = parser.parse_file(test_file)
            if success:
                print(f"✅ Parsing di {xml_files[0]} riuscito")

                # Check SNMP data
                with NmapScannerDB() as db:
                    stats = db.get_database_stats()
                    snmp_records = sum(v for k, v in stats.items() 
                                     if k.startswith('snmp_') and k.endswith('_count'))

                    if snmp_records > 0:
                        print(f"🎉 TROVATI {snmp_records} RECORD SNMP!")
                        return True
                    else:
                        print("⚠️ Nessun record SNMP trovato (normale se il file non contiene dati SNMP)")
                        return True
            else:
                print(f"❌ Parsing fallito")
                return False
        except Exception as e:
            print(f"❌ Errore parsing: {e}")
            return False
    else:
        print("⚠️ Nessun file XML trovato")
        return True

if __name__ == "__main__":
    success = test_full_system()
    if success:
        print("\\n🎉 SISTEMA COMPLETO E FUNZIONANTE!")
    else:
        print("\\n❌ SISTEMA NON FUNZIONANTE!")
'''

    try:
        with open('test_complete_system.py', 'w') as f:
            f.write(test_script)
        print("✅ Script di test creato: test_complete_system.py")
        return True
    except Exception as e:
        print(f"❌ Errore creando script: {e}")
        return False


def main():
    """Funzione principale"""
    print("🚀 SETUP SISTEMA SNMP COMPLETO")
    print("=" * 50)

    # Step 1: Clean everything
    clean_everything()

    # Step 2: Create directory structure
    create_directory_structure()

    # Step 3: Setup core files
    setup_core_files()

    # Step 4: Test database
    db_ok = test_database_creation()

    # Step 5: Test parser
    parser_ok = test_advanced_parser()

    # Step 6: Check XML files
    good_files, snmp_files = check_xml_files()

    # Step 7: Create test script
    test_script_ok = create_test_script()

    # Final summary
    print("\n" + "=" * 50)
    print("📊 RIEPILOGO SETUP")
    print("=" * 50)
    print(f"Database:       {'✅ OK' if db_ok else '❌ ERRORE'}")
    print(f"Parser:         {'✅ OK' if parser_ok else '❌ ERRORE'}")
    print(f"File XML:       ✅ {good_files} trovati ({snmp_files} con SNMP)")
    print(f"Test Script:    {'✅ OK' if test_script_ok else '❌ ERRORE'}")

    if db_ok and parser_ok:
        print("\n🎉 SETUP COMPLETATO CON SUCCESSO!")
        print("\n🚀 PROSSIMI PASSI:")
        print("1. Esegui il test completo:")
        print("   python test_complete_system.py")
        print("\n2. Parsa i tuoi file XML:")
        print(
            "   python -c \"from core.advanced_nmap_parser import AdvancedNmapParser; p=AdvancedNmapParser(); p.parse_file('scans/nomefile.xml')\"")
        print("\n3. Controlla i dati SNMP:")
        print("   sqlite3 instance/nmap_scans.db \"SELECT COUNT(*) FROM snmp_services;\"")

        return True
    else:
        print("\n❌ SETUP FALLITO!")
        print("Controlla gli errori sopra e riprova")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)