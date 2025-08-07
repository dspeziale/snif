# ===================================================================
# scanner/install_dependencies.py - Script installazione dipendenze
# !/usr/bin/env python3
"""
Script per installare e verificare dipendenze del Network Scanner
"""
import subprocess
import sys
import os
import platform


def check_python_version():
    """Verifica versione Python"""
    if sys.version_info < (3, 7):
        print("ERRORE: Python 3.7+ richiesto")
        return False
    print(f"✓ Python {sys.version.split()[0]}")
    return True


def install_python_packages():
    """Installa pacchetti Python necessari"""
    packages = [
        'flask>=3.0.0',
        'pysnmp>=4.4.12',
        'requests>=2.31.0',
        'python-nmap>=0.7.1'
    ]

    print("Installazione pacchetti Python...")

    for package in packages:
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', package
            ])
            print(f"✓ {package}")
        except subprocess.CalledProcessError:
            print(f"✗ Errore installazione {package}")
            return False

    return True


def check_nmap():
    """Verifica installazione Nmap"""
    try:
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            print(f"✓ {version}")
            return True
    except FileNotFoundError:
        pass

    print("✗ Nmap non trovato")
    print("Scaricare da: https://nmap.org/download.html")
    return False


def setup_directories():
    """Crea directory necessarie"""
    dirs = [
        'scanner/xml',
        'scanner/log',
        'scanner/reports',
        'data',
        'scanner/templates'
    ]

    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Directory {directory}")


def create_service_file():
    """Crea file di servizio per Windows/Linux"""
    system = platform.system().lower()

    if system == 'windows':
        # Crea batch file per Windows
        batch_content = f"""@echo off
cd /d "{os.getcwd()}"
python scanner/run.py
pause
"""
        with open('start_scanner.bat', 'w') as f:
            f.write(batch_content)
        print("✓ File start_scanner.bat creato")

    else:
        # Crea shell script per Linux
        script_content = f"""#!/bin/bash
cd "{os.getcwd()}"
python3 scanner/run.py
"""
        with open('start_scanner.sh', 'w') as f:
            f.write(script_content)
        os.chmod('start_scanner.sh', 0o755)
        print("✓ File start_scanner.sh creato")


def main():
    """Funzione principale installazione"""
    print("=" * 60)
    print("Network Scanner - Setup e Installazione")
    print("=" * 60)

    # Verifica Python
    if not check_python_version():
        return False

    # Installa pacchetti Python
    if not install_python_packages():
        return False

    # Verifica Nmap
    nmap_ok = check_nmap()

    # Setup directory
    setup_directories()

    # Crea file di avvio
    create_service_file()

    print("\n" + "=" * 60)
    if nmap_ok:
        print("✓ Installazione completata con successo!")
        print("Avviare con: python scanner/run.py")
    else:
        print("⚠ Installazione parzialmente completata")
        print("IMPORTANTE: Installare Nmap per funzionamento completo")
    print("=" * 60)

    return True


if __name__ == '__main__':
    main()