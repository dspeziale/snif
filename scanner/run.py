# ===================================================================
# scanner/run.py - Script per avviare l'applicazione
# !/usr/bin/env python3
"""
Network Scanner Application Launcher
"""
import os
import sys
from pathlib import Path

# Aggiungi il percorso corrente al Python path
sys.path.insert(0, str(Path(__file__).parent))

from app import app, setup_directories, db_manager


def main():
    """Funzione principale"""
    print("=" * 60)
    print("Network Scanner - Avvio applicazione")
    print("=" * 60)

    # Verifica prerequisiti
    if not check_requirements():
        sys.exit(1)

    # Setup directories
    print("Creazione directory...")
    setup_directories()

    # Inizializza database
    print("Inizializzazione database...")
    db_manager.init_database()

    print("Applicazione pronta!")
    print("Dashboard disponibile su: http://localhost:5000")
    print("Premere Ctrl+C per fermare")
    print("=" * 60)

    try:
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\nArresto applicazione...")


def check_requirements():
    """Verifica prerequisiti"""
    # Verifica Nmap
    try:
        import subprocess
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print("ERRORE: Nmap non trovato!")
            print("Installare Nmap da: https://nmap.org/download.html")
            return False
        else:
            print(f"✓ Nmap trovato: {result.stdout.split()[1]}")
    except FileNotFoundError:
        print("ERRORE: Nmap non trovato nel PATH!")
        return False

    # Verifica Python modules
    required_modules = ['flask', 'pysnmp', 'requests']
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module} disponibile")
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        print(f"ERRORE: Moduli Python mancanti: {', '.join(missing_modules)}")
        print("Installare con: pip install -r requirements.txt")
        return False

    return True


if __name__ == '__main__':
    main()