"""
Setup Script per Network Scanner
Configura, testa e avvia il sistema di scansione
"""

import os
import sys
import subprocess
import platform
import sqlite3
import json
from pathlib import Path


def print_header(text):
    """Stampa header formattato"""
    print("\n" + "=" * 60)
    print(text.center(60))
    print("=" * 60)


def print_status(status, message):
    """Stampa stato con simbolo"""
    symbols = {
        'ok': '✓',
        'error': '❌',
        'warning': '⚠',
        'info': 'ℹ'
    }
    symbol = symbols.get(status, '•')
    print(f"{symbol} {message}")


def check_python_version():
    """Verifica versione Python"""
    print_header("VERIFICA PYTHON")

    version = sys.version_info
    if version.major == 3 and version.minor >= 7:
        print_status('ok', f"Python {version.major}.{version.minor}.{version.micro} OK")
        return True
    else:
        print_status('error', f"Python 3.7+ richiesto (trovato {version.major}.{version.minor})")
        return False


def install_requirements():
    """Installa dipendenze Python"""
    print_header("INSTALLAZIONE DIPENDENZE")

    requirements = [
        'requests',
        'flask',
        'python-dateutil'
    ]

    for package in requirements:
        try:
            __import__(package.replace('-', '_'))
            print_status('ok', f"{package} già installato")
        except ImportError:
            print_status('info', f"Installazione {package}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print_status('ok', f"{package} installato")
            except:
                print_status('error', f"Errore installazione {package}")
                return False

    return True


def find_nmap():
    """Trova NMAP nel sistema"""
    print_header("RICERCA NMAP")

    # Possibili path di NMAP
    if platform.system() == 'Windows':
        paths = [
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe',
            r'C:\Nmap\nmap.exe',
        ]
    else:
        paths = [
            '/usr/bin/nmap',
            '/usr/local/bin/nmap',
            '/opt/local/bin/nmap'
        ]

    # Cerca in PATH
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['where', 'nmap'], capture_output=True, text=True)
        else:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)

        if result.returncode == 0:
            nmap_path = result.stdout.strip().split('\n')[0]
            print_status('ok', f"NMAP trovato in PATH: {nmap_path}")
            return nmap_path
    except:
        pass

    # Cerca nei path comuni
    for path in paths:
        if os.path.exists(path):
            print_status('ok', f"NMAP trovato: {path}")
            return path

    print_status('error', "NMAP non trovato!")
    print("\nInstallare NMAP da: https://nmap.org/download.html")

    if platform.system() == 'Windows':
        print("\nSu Windows:")
        print("1. Scarica il setup da https://nmap.org/download.html#windows")
        print("2. Installa con le opzioni predefinite")
        print("3. Riavvia questo script")

    return None


def test_nmap(nmap_path):
    """Testa funzionamento NMAP"""
    print_header("TEST NMAP")

    try:
        # Test versione
        result = subprocess.run(
            [nmap_path, '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            print_status('ok', f"NMAP funzionante: {version}")

            # Test scan base
            print_status('info', "Test scan localhost...")
            result = subprocess.run(
                [nmap_path, '-sn', '127.0.0.1'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                print_status('ok', "Test scan completato")
                return True
            else:
                print_status('warning', "Test scan fallito (potrebbe richiedere privilegi admin)")
                return True  # Non fatale
        else:
            print_status('error', "NMAP non funzionante")
            return False

    except Exception as e:
        print_status('error', f"Errore test NMAP: {e}")
        return False


def check_admin():
    """Verifica privilegi amministratore"""
    print_header("VERIFICA PRIVILEGI")

    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0

        if is_admin:
            print_status('ok', "Esecuzione con privilegi amministratore")
        else:
            print_status('warning', "NON in esecuzione come amministratore")
            print("\nAlcune funzionalità potrebbero non funzionare correttamente.")
            print("Consigliato: eseguire come amministratore per risultati ottimali.")

            if platform.system() == 'Windows':
                print("\nSu Windows:")
                print("- Click destro su 'Command Prompt' o 'PowerShell'")
                print("- Seleziona 'Esegui come amministratore'")
                print("- Naviga alla directory del progetto ed esegui nuovamente")

        return True  # Non bloccare

    except Exception as e:
        print_status('warning', f"Impossibile verificare privilegi: {e}")
        return True


def setup_database():
    """Inizializza database"""
    print_header("SETUP DATABASE")

    db_dir = Path('scanner')
    db_path = db_dir / 'network_inventory.db'

    # Crea directory
    if not db_dir.exists():
        db_dir.mkdir(parents=True)
        print_status('ok', f"Directory creata: {db_dir}")

    # Test connessione
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("SELECT 1")
        conn.close()
        print_status('ok', f"Database accessibile: {db_path}")
        return True
    except Exception as e:
        print_status('error', f"Errore database: {e}")
        return False


def create_config(nmap_path):
    """Crea file di configurazione"""
    print_header("CREAZIONE CONFIGURAZIONE")

    config = {
        'nmap_path': nmap_path,
        'subnets': [f'192.168.{i}.0/24' for i in range(20, 71, 10)],
        'quick_scan_interval': 600,
        'full_scan_after_detections': 5,
        'max_workers': 5
    }

    config_path = Path('scanner') / 'config.json'

    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print_status('ok', f"Configurazione salvata: {config_path}")
        print("\nSubnet configurate:")
        for subnet in config['subnets']:
            print(f"  - {subnet}")

        return True
    except Exception as e:
        print_status('error', f"Errore salvataggio config: {e}")
        return False


def test_network():
    """Test connettività di rete"""
    print_header("TEST RETE")

    test_ips = [
        ('Gateway', '192.168.1.1'),
        ('DNS Google', '8.8.8.8'),
        ('Localhost', '127.0.0.1')
    ]

    for name, ip in test_ips:
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    timeout=2
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )

            if result.returncode == 0:
                print_status('ok', f"{name} ({ip}) raggiungibile")
            else:
                print_status('warning', f"{name} ({ip}) non raggiungibile")

        except Exception as e:
            print_status('warning', f"Test {name} fallito: {e}")

    return True


def main():
    """Main setup procedure"""
    print_header("NETWORK SCANNER SETUP")
    print("Sistema di inventario dispositivi di rete con NMAP\n")

    # Lista check
    checks = [
        ("Python", check_python_version),
        ("Dipendenze", install_requirements),
        ("Database", setup_database),
        ("Privilegi", check_admin),
        ("Rete", test_network)
    ]

    all_ok = True
    for name, func in checks:
        if not func():
            all_ok = False
            if name in ["Python", "Database"]:
                print_status('error', f"{name} check fallito - setup interrotto")
                return False

    # NMAP check speciale
    nmap_path = find_nmap()
    if not nmap_path:
        print_status('error', "NMAP non trovato - setup interrotto")
        return False

    if not test_nmap(nmap_path):
        print_status('error', "NMAP non funzionante - setup interrotto")
        return False

    # Crea configurazione
    if not create_config(nmap_path):
        return False

    # Riepilogo finale
    print_header("SETUP COMPLETATO")

    if all_ok:
        print_status('ok', "Sistema pronto per l'avvio!")
        print("\nPer avviare lo scanner:")
        print(f"  python scanner/network_scanner_improved.py")
        print("\nPer avviare l'interfaccia web:")
        print(f"  python app.py")
        print("\nAccedi a: http://localhost:5000/scanner")
    else:
        print_status('warning', "Setup completato con avvertimenti")
        print("Il sistema potrebbe funzionare con limitazioni")

    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup interrotto dall'utente")
        sys.exit(1)
    except Exception as e:
        print(f"\nErrore inaspettato: {e}")
        sys.exit(1)