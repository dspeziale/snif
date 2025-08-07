from flask import Flask, render_template, jsonify, request
import threading
import time
from datetime import datetime
import os
from pathlib import Path

# Import dei moduli personalizzati
from scanner_core import NetworkScanner
from database import DatabaseManager
from config_manager import ConfigManager
from cache_manager import CacheManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-for-scanner'

# Inizializzazione componenti
config_manager = ConfigManager()
db_manager = DatabaseManager()
cache_manager = CacheManager()
scanner = NetworkScanner(config_manager, db_manager, cache_manager)

# Thread di scansione
scanning_thread = None
scanner_running = False


def scanner_daemon():
    """Daemon per le scansioni automatiche"""
    global scanner_running
    scanner_running = True

    while scanner_running:
        try:
            # Scansione discovery ogni 10 minuti
            scanner.run_discovery_scan()

            # Aspetta 10 minuti (600 secondi)
            for i in range(600):
                if not scanner_running:
                    break
                time.sleep(1)

        except Exception as e:
            print(f"Errore nel daemon scanner: {e}")
            time.sleep(60)  # Aspetta 1 minuto in caso di errore


@app.route('/')
def index():
    """Dashboard principale"""
    stats = db_manager.get_dashboard_stats()
    return render_template('index.html', stats=stats)


@app.route('/api/devices')
def api_devices():
    """API per ottenere tutti i dispositivi"""
    devices = db_manager.get_all_devices()
    return jsonify(devices)


@app.route('/api/device/<device_id>')
def api_device_details(device_id):
    """API per ottenere dettagli di un dispositivo"""
    device = db_manager.get_device_details(device_id)
    return jsonify(device)


@app.route('/api/scan/discovery')
def api_scan_discovery():
    """API per avviare scansione discovery manuale"""
    try:
        result = scanner.run_discovery_scan()
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/scan/services/<device_id>')
def api_scan_services(device_id):
    """API per scansione servizi su dispositivo specifico"""
    try:
        result = scanner.run_services_scan(device_id)
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/scan/os/<device_id>')
def api_scan_os(device_id):
    """API per scansione OS su dispositivo specifico"""
    try:
        result = scanner.run_os_scan(device_id)
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/scan/vulnerabilities/<device_id>')
def api_scan_vulnerabilities(device_id):
    """API per scansione vulnerabilità su dispositivo specifico"""
    try:
        result = scanner.run_vulnerability_scan(device_id)
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/scan/snmp/<device_id>')
def api_scan_snmp(device_id):
    """API per scansione SNMP su dispositivo specifico"""
    try:
        result = scanner.run_snmp_scan(device_id)
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/cache/update')
def api_cache_update():
    """API per aggiornamento cache manuale"""
    try:
        cache_manager.force_update_all()
        return jsonify({'status': 'success', 'message': 'Cache aggiornata'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/stats')
def api_stats():
    """API per statistiche dashboard"""
    stats = db_manager.get_dashboard_stats()
    return jsonify(stats)


def setup_directories():
    """Crea le directory necessarie"""
    directories = [
        'scanner/xml',
        'scanner/log',
        'data'
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


if __name__ == '__main__':
    # Setup iniziale
    setup_directories()

    # Inizializza database
    db_manager.init_database()

    # Avvia thread scanner
    scanning_thread = threading.Thread(target=scanner_daemon, daemon=True)
    scanning_thread.start()

    # Avvia Flask
    app.run(debug=True, host='0.0.0.0', port=5000)