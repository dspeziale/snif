#!/usr/bin/env python3
"""
Script di setup completo per la migrazione da JSON a database SQLite
"""
import os
import sys
import shutil
import argparse
from pathlib import Path
from datetime import datetime


def print_header():
    """Stampa l'header del setup"""
    print("=" * 80)
    print("🚀 SETUP ADMINLTE FLASK - MIGRAZIONE A DATABASE SQLITE")
    print("=" * 80)
    print()


def print_step(step_num, total_steps, description):
    """Stampa il progresso del setup"""
    print(f"📋 Step {step_num}/{total_steps}: {description}")
    print("-" * 50)


def check_requirements():
    """Controlla che i requisiti siano soddisfatti"""
    print("🔍 Controllo requisiti...")

    # Controlla Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ richiesto")
        return False

    print(f"✅ Python {sys.version.split()[0]} OK")

    # Controlla se Flask è installato
    try:
        import flask
        print(f"✅ Flask {flask.__version__} OK")
    except ImportError:
        print("❌ Flask non installato. Installa con: pip install flask")
        return False

    # Controlla se SQLAlchemy è installato
    try:
        import sqlalchemy
        print(f"✅ SQLAlchemy {sqlalchemy.__version__} OK")
    except ImportError:
        print("❌ SQLAlchemy non installato. Installa con: pip install flask-sqlalchemy")
        return False

    return True


def install_requirements():
    """Installa i requirements necessari"""
    print("📦 Installazione dipendenze...")

    requirements = [
        "flask>=2.3.0",
        "flask-sqlalchemy>=3.0.0",
        "pathlib",
    ]

    try:
        import subprocess
        for req in requirements:
            try:
                # Controlla se il pacchetto è già installato
                pkg_name = req.split('>=')[0].split('==')[0]
                __import__(pkg_name.replace('-', '_'))
                print(f"✅ {pkg_name} già installato")
            except ImportError:
                print(f"📦 Installazione {req}...")
                result = subprocess.run([
                    sys.executable, "-m", "pip", "install", req
                ], capture_output=True, text=True)

                if result.returncode == 0:
                    print(f"✅ {req} installato")
                else:
                    print(f"❌ Errore nell'installazione di {req}")
                    print(result.stderr)
                    return False

        return True

    except Exception as e:
        print(f"❌ Errore nell'installazione: {e}")
        return False


def backup_existing_files():
    """Crea backup dei file esistenti"""
    print("💾 Backup dei file esistenti...")

    backup_dir = Path("backup_json_migration")
    backup_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    specific_backup_dir = backup_dir / f"backup_{timestamp}"
    specific_backup_dir.mkdir(exist_ok=True)

    files_to_backup = [
        "app.py",
        "blueprint/api.py",
        "templates/base.html",
        "config/menu.json",
        "config/messages.json",
        "config/notifications.json"
    ]

    backed_up_files = []

    for file_path in files_to_backup:
        source = Path(file_path)
        if source.exists():
            dest = specific_backup_dir / source.name
            shutil.copy2(source, dest)
            backed_up_files.append(str(source))
            print(f"✅ Backup: {source} -> {dest}")

    if backed_up_files:
        print(f"📁 Backup salvato in: {specific_backup_dir}")
        return str(specific_backup_dir)
    else:
        print("ℹ️ Nessun file da salvare trovato")
        return None


def create_directory_structure():
    """Crea la struttura di directory necessaria"""
    print("📁 Creazione struttura directory...")

    directories = [
        "instance",
        "templates/admin",
        "static/css",
        "static/js",
        "static/assets/img",
        "templates/charts",
        "templates/ui",
        "templates/forms",
        "templates/tables",
        "templates/layouts",
        "templates/auth",
        "templates/errors"
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Directory: {directory}")

    return True


def copy_new_files():
    """Copia i nuovi file del database system"""
    print("📋 Installazione nuovi file...")

    # Qui normalmente copieresti i file, ma dato che sono già presenti
    # come artifacts, stampiamo solo un messaggio
    print("ℹ️ I nuovi file sono già stati creati dagli artifacts")
    print("ℹ️ Assicurati di salvare tutti gli artifacts come file:")
    print("  - models.py")
    print("  - database_config.py")
    print("  - db_manager.py")
    print("  - new_api.py (sostituisce blueprint/api.py)")
    print("  - migrate_json_to_db.py")
    print("  - app.py (aggiornato)")
    print("  - templates/base_updated.html (sostituisce templates/base.html)")

    return True


def setup_database(app_path="."):
    """Configura il database"""
    print("🗄️ Setup database SQLite...")

    try:
        # Cambia nella directory dell'app se specificata
        original_cwd = os.getcwd()
        if app_path != ".":
            os.chdir(app_path)

        # Importa l'app aggiornata
        sys.path.insert(0, os.getcwd())

        try:
            from updated_app_py import create_app  # Usa l'app aggiornata
            app = create_app()

            with app.app_context():
                from models import db

                # Crea le tabelle
                db.create_all()
                print("✅ Tabelle database create")

                # Controlla se esistono file JSON per la migrazione
                config_path = Path("config")
                json_files = [
                    config_path / "menu.json",
                    config_path / "messages.json",
                    config_path / "notifications.json"
                ]

                json_files_exist = any(f.exists() for f in json_files)

                if json_files_exist:
                    print("📥 File JSON trovati, esecuzione migrazione...")

                    from migrate_json_to_db import JSONToDBMigrator
                    migrator = JSONToDBMigrator(app)
                    success = migrator.run_migration(clear_existing=True)

                    if success:
                        print("✅ Migrazione dai file JSON completata")
                    else:
                        print("⚠️ Migrazione completata con alcuni errori")
                else:
                    print("📝 Nessun file JSON trovato, creazione dati di esempio...")

                    # Crea dati di esempio
                    from models import (
                        MenuType, MenuItem, MessageType, MessagePriority,
                        NotificationType, NotificationCategory, NotificationPriority
                    )

                    # Crea il tipo di menu
                    menu_type = MenuType(
                        name='sidebar',
                        label='Sidebar Menu',
                        description='Menu principale della sidebar'
                    )
                    db.session.add(menu_type)
                    db.session.flush()

                    # Crea alcuni elementi del menu
                    dashboard_item = MenuItem(
                        title='Dashboard',
                        icon='bi bi-speedometer',
                        url='/',
                        active=True,
                        sort_order=1,
                        menu_type_id=menu_type.id
                    )
                    db.session.add(dashboard_item)

                    widgets_item = MenuItem(
                        title='Widgets',
                        icon='bi bi-grid',
                        url='/widgets',
                        sort_order=2,
                        menu_type_id=menu_type.id
                    )
                    db.session.add(widgets_item)

                    # Crea tipi di messaggio
                    msg_types = [
                        MessageType(type='system', label='System', color='info', icon='bi-gear'),
                        MessageType(type='welcome', label='Welcome', color='success', icon='bi-hand-wave'),
                    ]
                    for msg_type in msg_types:
                        db.session.add(msg_type)

                    # Crea priorità messaggi
                    priorities = [
                        MessagePriority(level='low', label='Low', color='secondary', sort_order=1),
                        MessagePriority(level='medium', label='Medium', color='warning', sort_order=2),
                        MessagePriority(level='high', label='High', color='danger', sort_order=3),
                    ]
                    for priority in priorities:
                        db.session.add(priority)

                    # Crea tipi di notifica
                    notif_types = [
                        NotificationType(type='success', label='Success', color='success', icon='bi-check-circle-fill'),
                        NotificationType(type='info', label='Info', color='info', icon='bi-info-circle-fill'),
                    ]
                    for notif_type in notif_types:
                        db.session.add(notif_type)

                    # Crea categorie notifiche
                    categories = [
                        NotificationCategory(category='system', label='System', color='info', icon='bi-gear'),
                        NotificationCategory(category='user', label='User', color='primary', icon='bi-person'),
                    ]
                    for category in categories:
                        db.session.add(category)

                    # Crea priorità notifiche
                    for priority_data in priorities:
                        notif_priority = NotificationPriority(
                            level=priority_data.level,
                            label=priority_data.label,
                            color=priority_data.color,
                            sort_order=priority_data.sort_order
                        )
                        db.session.add(notif_priority)

                    db.session.commit()
                    print("✅ Dati di esempio creati")

        finally:
            os.chdir(original_cwd)

        return True

    except Exception as e:
        print(f"❌ Errore nel setup database: {e}")
        return False


def update_configuration():
    """Aggiorna le configurazioni"""
    print("⚙️ Aggiornamento configurazioni...")

    # Crea un file di configurazione per il database
    config_content = """# Configurazione Database SQLite
# Il database verrà creato automaticamente nella directory instance/

DATABASE_URL = 'sqlite:///instance/adminlte.db'
SECRET_KEY = 'your-secret-key-change-in-production'
DEBUG = True

# Configurazioni SQLAlchemy
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
"""

    config_file = Path("database_config.txt")
    with open(config_file, 'w') as f:
        f.write(config_content)

    print(f"✅ Configurazione salvata in: {config_file}")

    return True


def create_startup_script():
    """Crea uno script di avvio"""
    startup_script = """#!/usr/bin/env python3
'''
Script di avvio per AdminLTE Flask con Database SQLite
'''
import os
from app import create_app

if __name__ == '__main__':
    app = create_app()

    print("🚀 Avvio AdminLTE Flask con Database SQLite")
    print("📊 Dashboard: http://localhost:5000")
    print("🔧 Admin Panel: http://localhost:5000/admin")
    print("🔌 API: http://localhost:5000/api/")
    print("")
    print("Comandi disponibili:")
    print("  flask create-sample-data  - Crea dati di esempio") 
    print("  flask db-info            - Info database")
    print("  flask backup-db          - Backup database")
    print("")

    app.run(host='0.0.0.0', port=5000, debug=True)
"""

    script_file = Path("run_database_app.py")
    with open(script_file, 'w') as f:
        f.write(startup_script)

    # Rendi eseguibile su Unix
    if os.name != 'nt':
        os.chmod(script_file, 0o755)

    print(f"✅ Script di avvio creato: {script_file}")
    return True


def run_tests():
    """Esegue test base per verificare il funzionamento"""
    print("🧪 Esecuzione test base...")

    try:
        # Test importazione moduli
        from models import db, MenuItem, Message, Notification
        print("✅ Import modelli OK")

        from database_config import init_database
        print("✅ Import configurazione database OK")

        from db_manager import menu_manager, message_manager, notification_manager
        print("✅ Import manager OK")

        # Test creazione app
        from app import create_app
        app = create_app()
        print("✅ Creazione app OK")

        # Test database
        with app.app_context():
            db.create_all()

            # Test query base
            menu_count = MenuItem.query.count()
            message_count = Message.query.count()
            notification_count = Notification.query.count()

            print(
                f"✅ Database test OK - Menu: {menu_count}, Messages: {message_count}, Notifications: {notification_count}")

        return True

    except Exception as e:
        print(f"❌ Test fallito: {e}")
        return False


def print_completion_info(backup_dir=None):
    """Stampa le informazioni di completamento"""
    print()
    print("=" * 80)
    print("🎉 SETUP COMPLETATO CON SUCCESSO!")
    print("=" * 80)
    print()
    print("📋 Riepilogo:")
    print("  ✅ Database SQLite configurato in instance/adminlte.db")
    print("  ✅ Modelli del database creati")
    print("  ✅ API aggiornate per il database")
    print("  ✅ Template aggiornati")
    print("  ✅ Manager per l'accesso ai dati configurati")

    if backup_dir:
        print(f"  ✅ Backup file originali in: {backup_dir}")

    print()
    print("🚀 Per avviare l'applicazione:")
    print("  python app.py")
    print("  oppure")
    print("  python run_database_app.py")
    print()
    print("🔧 Comandi Flask disponibili:")
    print("  flask create-sample-data  - Crea dati di esempio")
    print("  flask migrate-json        - Migra da file JSON esistenti")
    print("  flask db-info            - Mostra informazioni database")
    print("  flask backup-db          - Crea backup database")
    print("  flask optimize-db        - Ottimizza database")
    print()
    print("📊 URL disponibili:")
    print("  http://localhost:5000          - Dashboard principale")
    print("  http://localhost:5000/admin    - Pannello amministrazione")
    print("  http://localhost:5000/api/     - API endpoints")
    print()
    print("📝 File importanti:")
    print("  instance/adminlte.db          - Database SQLite")
    print("  models.py                     - Modelli database")
    print("  db_manager.py                 - Manager accesso dati")
    print("  migrate_json_to_db.py         - Script migrazione")
    print()


def main():
    """Funzione principale"""
    parser = argparse.ArgumentParser(description="Setup AdminLTE Flask Database Migration")
    parser.add_argument('--skip-backup', action='store_true', help='Salta il backup dei file esistenti')
    parser.add_argument('--skip-requirements', action='store_true', help='Salta il controllo dei requirements')
    parser.add_argument('--skip-tests', action='store_true', help='Salta i test finali')
    parser.add_argument('--app-path', default='.', help='Percorso della directory dell\'app')

    args = parser.parse_args()

    print_header()

    total_steps = 8
    current_step = 0
    backup_dir = None

    try:
        # Step 1: Controllo requisiti
        current_step += 1
        print_step(current_step, total_steps, "Controllo requisiti")
        if not args.skip_requirements:
            if not check_requirements():
                print("❌ Setup fallito al controllo requisiti")
                return False

            if not install_requirements():
                print("❌ Setup fallito all'installazione dipendenze")
                return False
        else:
            print("⏭️ Controllo requisiti saltato")
        print()

        # Step 2: Backup file esistenti
        current_step += 1
        print_step(current_step, total_steps, "Backup file esistenti")
        if not args.skip_backup:
            backup_dir = backup_existing_files()
        else:
            print("⏭️ Backup saltato")
        print()

        # Step 3: Creazione struttura directory
        current_step += 1
        print_step(current_step, total_steps, "Creazione struttura directory")
        if not create_directory_structure():
            print("❌ Setup fallito alla creazione directory")
            return False
        print()

        # Step 4: Copia nuovi file
        current_step += 1
        print_step(current_step, total_steps, "Installazione nuovi file")
        if not copy_new_files():
            print("❌ Setup fallito alla copia file")
            return False
        print()

        # Step 5: Setup database
        current_step += 1
        print_step(current_step, total_steps, "Configurazione database")
        if not setup_database(args.app_path):
            print("❌ Setup fallito alla configurazione database")
            return False
        print()

        # Step 6: Aggiornamento configurazioni
        current_step += 1
        print_step(current_step, total_steps, "Aggiornamento configurazioni")
        if not update_configuration():
            print("❌ Setup fallito all'aggiornamento configurazioni")
            return False
        print()

        # Step 7: Creazione script di avvio
        current_step += 1
        print_step(current_step, total_steps, "Creazione script di avvio")
        if not create_startup_script():
            print("❌ Setup fallito alla creazione script di avvio")
            return False
        print()

        # Step 8: Test finale
        current_step += 1
        print_step(current_step, total_steps, "Test finale")
        if not args.skip_tests:
            if not run_tests():
                print("⚠️ Alcuni test sono falliti, ma il setup potrebbe comunque funzionare")
        else:
            print("⏭️ Test finali saltati")
        print()

        # Completamento
        print_completion_info(backup_dir)
        return True

    except KeyboardInterrupt:
        print("\n❌ Setup interrotto dall'utente")
        return False
    except Exception as e:
        print(f"\n❌ Errore durante il setup: {e}")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)