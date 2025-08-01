#!/usr/bin/env python3
"""
Modulo principale per il sistema di Network Scanning e Inventory
Gestisce l'avvio, l'integrazione con Flask e la coordinazione dei componenti
"""
import os
import sys
import signal
import logging
import threading
import time
from pathlib import Path

# Aggiungi il percorso dei moduli
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'moduli'))

from moduli.network_scanner import NetworkScanManager, check_nmap_availability
from moduli.scanner_api import scanner_bp, init_scanner_api

logger = logging.getLogger(__name__)


class ScannerApplication:
    """Applicazione principale per il sistema di scanning"""

    def __init__(self, config_file: str = 'scan_config.json'):
        self.config_file = config_file
        self.scan_manager = None
        self.running = False
        self.shutdown_event = threading.Event()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Verifica prerequisiti
        self._check_prerequisites()

    def _signal_handler(self, signum, frame):
        """Gestisce segnali di shutdown"""
        logger.info(f"Ricevuto segnale {signum}, avvio shutdown...")
        self.shutdown()

    def _check_prerequisites(self):
        """Verifica prerequisiti del sistema"""
        logger.info("Verifica prerequisiti sistema...")

        # Crea directory necessarie
        os.makedirs('instance', exist_ok=True)
        os.makedirs('instance/logs', exist_ok=True)

        # Verifica NMAP
        nmap_status = check_nmap_availability()
        if not nmap_status['available']:
            logger.error(f"NMAP non disponibile: {nmap_status.get('error', 'Motivo sconosciuto')}")
            sys.exit(1)

        logger.info(f"NMAP versione {nmap_status['version']} disponibile")

        if not nmap_status['can_run_as_root']:
            logger.warning("NMAP non può eseguire scansioni SYN (privilegi root richiesti)")

        if not nmap_status['scripts_available']:
            logger.warning("Script NSE non disponibili")

        # Verifica file configurazione
        if not os.path.exists(self.config_file):
            logger.warning(f"File configurazione {self.config_file} non trovato, verrà usata configurazione di default")

    def initialize(self):
        """Inizializza il sistema"""
        logger.info("Inizializzazione NetworkScanManager...")

        try:
            self.scan_manager = NetworkScanManager(self.config_file)
            self.scan_manager.start()

            # Inizializza API
            init_scanner_api(self.scan_manager)

            self.running = True
            logger.info("Sistema inizializzato con successo")

        except Exception as e:
            logger.error(f"Errore inizializzazione: {e}")
            raise

    def run_standalone(self):
        """Esegue il sistema in modalità standalone (senza Flask)"""
        logger.info("Avvio in modalità standalone")

        try:
            self.initialize()

            logger.info("Sistema avviato. Premi Ctrl+C per fermare.")

            # Mantieni il processo attivo
            while self.running and not self.shutdown_event.is_set():
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Interruzione da tastiera ricevuta")
        except Exception as e:
            logger.error(f"Errore durante esecuzione: {e}")
        finally:
            self.shutdown()

    def integrate_with_flask(self, app):
        """Integra il sistema con un'applicazione Flask esistente"""
        logger.info("Integrazione con Flask")

        try:
            self.initialize()

            # Registra blueprint
            app.register_blueprint(scanner_bp)

            # Aggiungi contesto per template
            @app.context_processor
            def inject_scanner_status():
                if self.scan_manager:
                    try:
                        status = self.scan_manager.get_system_status()
                        return {'scanner_status': status}
                    except Exception:
                        pass
                return {'scanner_status': None}

            # Shutdown handler per Flask
            @app.teardown_appcontext
            def shutdown_scanner(exception):
                if exception:
                    logger.error(f"Errore applicazione Flask: {exception}")

            logger.info("Integrazione Flask completata")

        except Exception as e:
            logger.error(f"Errore integrazione Flask: {e}")
            raise

    def shutdown(self):
        """Shutdown graceful del sistema"""
        if not self.running:
            return

        logger.info("Avvio shutdown sistema...")
        self.running = False
        self.shutdown_event.set()

        if self.scan_manager:
            try:
                self.scan_manager.stop()
                logger.info("NetworkScanManager fermato")
            except Exception as e:
                logger.error(f"Errore shutdown NetworkScanManager: {e}")

        logger.info("Shutdown completato")

    def get_manager(self):
        """Restituisce il manager per accesso esterno"""
        return self.scan_manager


def setup_logging():
    """Configura logging di base"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def create_flask_app():
    """Crea e configura l'applicazione Flask con scanner integrato"""
    from flask import Flask, render_template, redirect, url_for

    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

    # Inizializza scanner
    scanner_app = ScannerApplication()
    scanner_app.integrate_with_flask(app)

    # Route base
    @app.route('/')
    def index():
        """Dashboard principale"""
        try:
            status = scanner_app.get_manager().get_system_status()
            return render_template('dashboard.html', status=status)
        except Exception as e:
            logger.error(f"Errore dashboard: {e}")
            return render_template('error.html', error=str(e)), 500

    @app.route('/inventory')
    def inventory():
        """Pagina inventario"""
        return render_template('inventory.html')

    @app.route('/scans')
    def scans():
        """Pagina scansioni"""
        return render_template('scans.html')

    @app.route('/vulnerabilities')
    def vulnerabilities():
        """Pagina vulnerabilità"""
        return render_template('vulnerabilities.html')

    @app.route('/reports')
    def reports():
        """Pagina report"""
        return render_template('reports.html')

    @app.route('/settings')
    def settings():
        """Pagina impostazioni"""
        return render_template('settings.html')

    # Health check
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            if scanner_app.get_manager():
                status = scanner_app.get_manager().get_system_status()
                return {
                    'status': 'healthy',
                    'active_scans': status.get('active_scans', 0),
                    'total_hosts': status.get('database_stats', {}).get('total_hosts', 0)
                }
            else:
                return {'status': 'initializing'}, 503
        except Exception as e:
            return {'status': 'error', 'error': str(e)}, 500

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html',
                               error="Pagina non trovata",
                               error_code=404), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html',
                               error="Errore interno del server",
                               error_code=500), 500

    # Shutdown handler
    import atexit
    atexit.register(lambda: scanner_app.shutdown())

    return app, scanner_app


def main():
    """Funzione principale"""
    setup_logging()

    import argparse
    parser = argparse.ArgumentParser(description='Network Scanner and Inventory System')
    parser.add_argument('--mode', default="standalone", choices=['standalone', 'flask'],                         help='Modalità di esecuzione (default: flask)')
    parser.add_argument('--config', default='scan_config.json',
                        help='File di configurazione (default: scan_config.json)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host per Flask (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000,
                        help='Porta per Flask (default: 5000)')
    parser.add_argument('--debug', action='store_true',
                        help='Abilita debug mode per Flask')

    args = parser.parse_args()

    if args.mode == 'standalone':
        # Modalità standalone
        scanner_app = ScannerApplication(args.config)
        scanner_app.run_standalone()

    else:
        # Modalità Flask
        app, scanner_app = create_flask_app()

        logger.info(f"Avvio server Flask su {args.host}:{args.port}")

        try:
            app.run(
                host=args.host,
                port=args.port,
                debug=args.debug,
                threaded=True
            )
        except KeyboardInterrupt:
            logger.info("Interruzione da tastiera")
        finally:
            scanner_app.shutdown()


if __name__ == '__main__':
    main()