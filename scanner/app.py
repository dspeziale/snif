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
cache_manager = CacheManager(db_manager)
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
            # Scansione discovery ogni 10 minuti su tutti i range
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

    # Aggiungi informazioni sui range di rete
    ranges_info = scanner.get_scan_ranges_info()
    stats['network_ranges'] = ranges_info
    stats['total_ranges'] = len(ranges_info)
    stats['valid_ranges'] = len([r for r in ranges_info if r.get('valid', True)])

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


@app.route('/api/network/ranges')
def api_network_ranges():
    """API per ottenere informazioni sui range di rete"""
    ranges_info = scanner.get_scan_ranges_info()
    return jsonify({
        'ranges': ranges_info,
        'total_count': len(ranges_info),
        'valid_count': len([r for r in ranges_info if r.get('valid', True)])
    })


@app.route('/api/network/detect')
def api_detect_networks():
    """API per rilevare automaticamente le reti locali"""
    try:
        # Forza il rilevamento delle reti locali
        original_auto_detect = config_manager.get('network.auto_detect_local_networks')
        config_manager.set('network.auto_detect_local_networks', True)

        # Ottieni i range aggiornati
        ranges_info = scanner.get_scan_ranges_info()

        # Ripristina impostazione originale
        config_manager.set('network.auto_detect_local_networks', original_auto_detect)

        return jsonify({
            'status': 'success',
            'ranges': ranges_info,
            'message': f'Rilevate {len(ranges_info)} reti'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })


@app.route('/api/scan/discovery')
def api_scan_discovery():
    """API per avviare scansione discovery manuale su tutti i range"""
    try:
        result = scanner.run_discovery_scan()
        return jsonify({'status': 'success', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/scan/discovery/<path:network_range>')
def api_scan_discovery_range(network_range):
    """API per avviare scansione discovery su un range specifico"""
    try:
        # Decodifica il range (sostituisce _ con . e - con /)
        decoded_range = network_range.replace('_', '.').replace('-', '/')
        result = scanner._run_single_discovery(decoded_range)
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

    # Aggiungi statistiche sui range di rete
    ranges_info = scanner.get_scan_ranges_info()
    stats['network_ranges'] = ranges_info
    stats['total_ranges'] = len(ranges_info)
    stats['valid_ranges'] = len([r for r in ranges_info if r.get('valid', True)])

    return jsonify(stats)


# Aggiungi al file app.py - endpoint per monitorare lo stato delle scansioni

@app.route('/api/scan/status')
def api_scan_status():
    """API per ottenere stato delle scansioni"""
    try:
        # Ottieni ultime scansioni
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        # Scansioni recenti (ultime 24 ore)
        cursor.execute('''
            SELECT scan_type, target, start_time, end_time, status, devices_found, notes
            FROM scan_history 
            WHERE start_time > datetime('now', '-1 day')
            ORDER BY start_time DESC
            LIMIT 20
        ''')
        recent_scans = [dict(row) for row in cursor.fetchall()]

        # Statistiche scansioni
        cursor.execute('''
            SELECT 
                scan_type,
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
                AVG(devices_found) as avg_devices_found
            FROM scan_history 
            WHERE start_time > datetime('now', '-7 days')
            GROUP BY scan_type
        ''')
        scan_stats = [dict(row) for row in cursor.fetchall()]

        # Scansioni attive
        cursor.execute('''
            SELECT scan_type, target, start_time
            FROM scan_history 
            WHERE status = 'running'
            ORDER BY start_time DESC
        ''')
        active_scans = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify({
            'recent_scans': recent_scans,
            'scan_statistics': scan_stats,
            'active_scans': active_scans,
            'total_active': len(active_scans)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network/summary')
def api_network_summary():
    """Riepilogo della rete scoperta"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        # Statistiche per subnet
        cursor.execute('''
            SELECT 
                SUBSTR(ip_address, 1, INSTR(ip_address||'.', '.', -1, 2)-1) as subnet,
                COUNT(*) as device_count,
                COUNT(CASE WHEN device_type IS NOT NULL THEN 1 END) as typed_devices,
                COUNT(CASE WHEN hostname IS NOT NULL THEN 1 END) as named_devices,
                COUNT(CASE WHEN mac_address IS NOT NULL THEN 1 END) as mac_known,
                MAX(last_seen) as last_activity
            FROM devices 
            WHERE is_active = 1
            GROUP BY subnet
            ORDER BY device_count DESC
        ''')
        subnet_stats = [dict(row) for row in cursor.fetchall()]

        # Dispositivi per tipo
        cursor.execute('''
            SELECT 
                COALESCE(device_type, 'unknown') as type,
                COUNT(*) as count
            FROM devices 
            WHERE is_active = 1
            GROUP BY device_type
            ORDER BY count DESC
        ''')
        device_types = [dict(row) for row in cursor.fetchall()]

        # Vendor distribution
        cursor.execute('''
            SELECT 
                COALESCE(vendor, 'Unknown') as vendor,
                COUNT(*) as count
            FROM devices 
            WHERE is_active = 1
            GROUP BY vendor
            ORDER BY count DESC
            LIMIT 10
        ''')
        vendor_stats = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify({
            'subnet_statistics': subnet_stats,
            'device_types': device_types,
            'vendor_distribution': vendor_stats
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/ranges', methods=['GET', 'POST'])
def api_config_ranges():
    """API per gestire configurazione range di rete"""
    if request.method == 'GET':
        # Ottieni configurazione attuale
        current_ranges = config_manager.get('network.scan_ranges', [])
        auto_detect = config_manager.get('network.auto_detect_local_networks', False)

        return jsonify({
            'scan_ranges': current_ranges,
            'auto_detect_local_networks': auto_detect,
            'parallel_scans': config_manager.get('network.parallel_scans', True),
            'max_concurrent_ranges': config_manager.get('network.max_concurrent_ranges', 3)
        })

    elif request.method == 'POST':
        # Aggiorna configurazione
        try:
            data = request.get_json()

            if 'scan_ranges' in data:
                config_manager.set('network.scan_ranges', data['scan_ranges'])

            if 'auto_detect_local_networks' in data:
                config_manager.set('network.auto_detect_local_networks',
                                   data['auto_detect_local_networks'])

            if 'parallel_scans' in data:
                config_manager.set('network.parallel_scans', data['parallel_scans'])

            if 'max_concurrent_ranges' in data:
                config_manager.set('network.max_concurrent_ranges',
                                   data['max_concurrent_ranges'])

            return jsonify({
                'status': 'success',
                'message': 'Configurazione aggiornata'
            })

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            })


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

    # Log informazioni sui range configurati
    ranges_info = scanner.get_scan_ranges_info()
    print(f"Range di rete configurati: {len(ranges_info)}")
    for range_info in ranges_info:
        if range_info.get('valid', True):
            print(f"  - {range_info['range']}: {range_info.get('num_hosts', 0)} host possibili")
        else:
            print(f"  - {range_info['range']}: ERRORE - {range_info.get('error', 'Sconosciuto')}")

    # Avvia Flask
    app.run(debug=True, host='0.0.0.0', port=5000)

