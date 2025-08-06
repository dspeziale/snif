#!/usr/bin/env python3
"""
Network Scanner Service
Servizio standalone per eseguire lo scanner in background
"""

import sys
import os
import signal
import logging
import argparse
from pathlib import Path
import daemon
import daemon.pidfile
from network_scanner import NetworkScanner, SCANNER_CONFIG

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner/scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ScannerService:
    """Servizio per eseguire lo scanner come demone"""

    def __init__(self, config=None):
        self.config = config or SCANNER_CONFIG
        self.scanner = None
        self.running = False

    def start(self):
        """Avvia il servizio scanner"""
        logger.info("Avvio servizio scanner...")

        try:
            self.scanner = NetworkScanner(self.config)
            self.running = True

            # Registra signal handlers
            signal.signal(signal.SIGTERM, self.handle_signal)
            signal.signal(signal.SIGINT, self.handle_signal)

            # Avvia scanner
            self.scanner.start_periodic_scan()

            # Mantieni il servizio attivo
            while self.running:
                signal.pause()

        except Exception as e:
            logger.error(f"Errore nel servizio: {e}")
            self.stop()

    def stop(self):
        """Ferma il servizio scanner"""
        logger.info("Arresto servizio scanner...")
        self.running = False

        if self.scanner:
            self.scanner.stop_periodic_scan()

        logger.info("Servizio scanner arrestato")

    def handle_signal(self, signum, frame):
        """Gestisce i segnali di sistema"""
        logger.info(f"Ricevuto segnale {signum}")
        self.stop()
        sys.exit(0)


def main():
    """Main function per il servizio"""
    parser = argparse.ArgumentParser(description='Network Scanner Service')
    parser.add_argument('action', choices=['start', 'stop', 'restart', 'status'],
                        help='Azione da eseguire')
    parser.add_argument('--daemon', action='store_true',
                        help='Esegui come demone')
    parser.add_argument('--pidfile', default='/var/run/network_scanner.pid',
                        help='Path del PID file')
    parser.add_argument('--config', help='Path del file di configurazione')

    args = parser.parse_args()

    # Crea directory per i log se non esiste
    os.makedirs('scanner', exist_ok=True)

    if args.action == 'start':
        if args.daemon:
            # Esegui come demone
            pidfile = daemon.pidfile.PIDLockFile(args.pidfile)

            with daemon.DaemonContext(
                    working_directory=os.getcwd(),
                    pidfile=pidfile,
                    preserve_files=[
                        logging.getLogger().handlers[0].stream.fileno()
                    ]
            ):
                service = ScannerService()
                service.start()
        else:
            # Esegui in foreground
            service = ScannerService()
            service.start()

    elif args.action == 'stop':
        # Invia segnale SIGTERM al processo
        pidfile_path = Path(args.pidfile)
        if pidfile_path.exists():
            with open(pidfile_path, 'r') as f:
                pid = int(f.read())
                os.kill(pid, signal.SIGTERM)
                print(f"Inviato segnale di stop al processo {pid}")
        else:
            print("Servizio non in esecuzione")

    elif args.action == 'restart':
        # Stop e poi start
        os.system(f"{sys.argv[0]} stop --pidfile {args.pidfile}")
        os.system(f"{sys.argv[0]} start --daemon --pidfile {args.pidfile}")

    elif args.action == 'status':
        pidfile_path = Path(args.pidfile)
        if pidfile_path.exists():
            with open(pidfile_path, 'r') as f:
                pid = int(f.read())
                try:
                    os.kill(pid, 0)
                    print(f"Servizio in esecuzione (PID: {pid})")
                except OSError:
                    print("Servizio non in esecuzione (PID file obsoleto)")
        else:
            print("Servizio non in esecuzione")


if __name__ == '__main__':
    main()