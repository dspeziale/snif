# ===================================================================
# scanner/main_app_extended.py - Applicazione principale estesa
from flask import Flask
import threading
import time
from pathlib import Path

# Import componenti
from config_manager import ConfigManager
from database import DatabaseManager
from cache_manager import CacheManager
from scanner_core import NetworkScanner
from advanced_scanner import AdvancedScanner
from snmp_scanner import SNMPScanner
from mac_resolver import MacResolver
from vulnerability_scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from scheduler import ScanScheduler
from api_extensions import create_api_blueprint


def create_extended_app():
    """Crea applicazione Flask estesa"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-extended-secret-key'

    # Inizializza componenti
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    cache_manager = CacheManager(db_manager)

    # Scanner componenti
    base_scanner = NetworkScanner(config_manager, db_manager, cache_manager)
    snmp_scanner = SNMPScanner(config_manager)
    mac_resolver = MacResolver()
    vuln_scanner = VulnerabilityScanner(cache_manager)

    # Advanced scanner
    advanced_scanner = AdvancedScanner(config_manager, db_manager, cache_manager, base_scanner)

    # Report generator
    report_generator = ReportGenerator(db_manager)

    # Scheduler
    scheduler = ScanScheduler(base_scanner, db_manager)

    # Registra API estese
    api_bp = create_api_blueprint(base_scanner, db_manager, report_generator, scheduler)
    app.register_blueprint(api_bp)

    # Route principali
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'components': {
                'database': 'ok',
                'scanner': 'ok',
                'scheduler': 'running' if scheduler.running else 'stopped'
            }
        })

    # Avvia componenti
    def start_background_services():
        """Avvia servizi in background"""
        try:
            # Database
            db_manager.init_database()

            # Advanced scanner
            advanced_scanner.start()

            # Scheduler
            scheduler.start()
            scheduler.auto_schedule_maintenance()

            print("Servizi in background avviati")

        except Exception as e:
            print(f"Errore avvio servizi: {e}")

    # Avvia servizi in thread separato
    services_thread = threading.Thread(target=start_background_services, daemon=True)
    services_thread.start()

    return app