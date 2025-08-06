"""
Scanner API Module
Fornisce endpoint API per interagire con lo scanner di rete
"""

from flask import Blueprint, jsonify, request, render_template
from datetime import datetime, timedelta
import sqlite3
import json
from typing import Dict, List, Optional
import os

# Crea il blueprint
scanner_bp = Blueprint('scanner', __name__, url_prefix='/scanner')

# Configurazione database
SCANNER_DB = 'scanner/network_scan.db'
OUI_DB = 'scanner/oui_cache.db'


# ==================== HELPER FUNCTIONS ====================

def get_db_connection(db_path: str = SCANNER_DB):
    """Crea una connessione al database"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def dict_from_row(row):
    """Converte una riga SQLite in dizionario"""
    return dict(row) if row else None


# ==================== API ENDPOINTS ====================

@scanner_bp.route('/api/devices')
def api_get_devices():
    """Recupera tutti i dispositivi"""
    try:
        filters = {}

        # Applica filtri dalla query string
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('device_type'):
            filters['device_type'] = request.args.get('device_type')
        if request.args.get('subnet'):
            filters['subnet'] = request.args.get('subnet')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Costruisci query con filtri
        query = "SELECT * FROM devices WHERE 1=1"
        params = []

        for key, value in filters.items():
            query += f" AND {key} = ?"
            params.append(value)

        query += " ORDER BY subnet, ip_address"

        cursor.execute(query, params)
        devices = [dict_from_row(row) for row in cursor.fetchall()]
        conn.close()

        # Processa i dati per la visualizzazione
        for device in devices:
            # Parse delle porte aperte
            if device['open_ports']:
                try:
                    device['open_ports'] = json.loads(device['open_ports'])
                except:
                    device['open_ports'] = []

            # Formatta date
            if device['last_seen']:
                device['last_seen_formatted'] = datetime.fromisoformat(
                    device['last_seen'].replace(' ', 'T')
                ).strftime('%d/%m/%Y %H:%M')

            if device['first_seen']:
                device['first_seen_formatted'] = datetime.fromisoformat(
                    device['first_seen'].replace(' ', 'T')
                ).strftime('%d/%m/%Y %H:%M')

        return jsonify({
            'success': True,
            'devices': devices,
            'count': len(devices)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/api/device/<ip>')
def api_get_device(ip):
    """Recupera un singolo dispositivo"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip,))
        device = dict_from_row(cursor.fetchone())

        if not device:
            conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        # Recupera storico cambiamenti
        cursor.execute("""
            SELECT * FROM device_changes 
            WHERE device_id = ?
            ORDER BY changed_at DESC
            LIMIT 20
        """, (device['id'],))
        changes = [dict_from_row(row) for row in cursor.fetchall()]

        # Recupera alert
        cursor.execute("""
            SELECT * FROM alerts
            WHERE device_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        """, (device['id'],))
        alerts = [dict_from_row(row) for row in cursor.fetchall()]

        conn.close()

        # Parse dei dati
        if device['open_ports']:
            try:
                device['open_ports'] = json.loads(device['open_ports'])
            except:
                device['open_ports'] = []

        return jsonify({
            'success': True,
            'device': device,
            'changes': changes,
            'alerts': alerts
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/statistics')
def api_get_statistics():
    """Recupera statistiche della rete"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        stats = {}

        # Totale dispositivi
        cursor.execute("SELECT COUNT(*) FROM devices")
        stats['total_devices'] = cursor.fetchone()[0]

        # Dispositivi online/offline
        cursor.execute("SELECT status, COUNT(*) FROM devices GROUP BY status")
        status_counts = {row[0]: row[1] for row in cursor.fetchall()}
        stats['online_devices'] = status_counts.get('up', 0)
        stats['offline_devices'] = status_counts.get('down', 0)

        # Per tipo di dispositivo
        cursor.execute("""
            SELECT device_type, COUNT(*) as count
            FROM devices
            GROUP BY device_type
            ORDER BY count DESC
        """)
        stats['by_type'] = [
            {'type': row[0] or 'unknown', 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # Per subnet
        cursor.execute("""
            SELECT subnet, COUNT(*) as total,
                   SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as online
            FROM devices
            GROUP BY subnet
        """)
        stats['by_subnet'] = [
            {
                'subnet': row[0],
                'total': row[1],
                'online': row[2],
                'offline': row[1] - row[2]
            }
            for row in cursor.fetchall()
        ]

        # Per vendor (top 10)
        cursor.execute("""
            SELECT vendor, COUNT(*) as count
            FROM devices
            WHERE vendor IS NOT NULL
            GROUP BY vendor
            ORDER BY count DESC
            LIMIT 10
        """)
        stats['top_vendors'] = [
            {'vendor': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # Ultima scansione
        cursor.execute("""
            SELECT * FROM scan_history
            WHERE status = 'completed'
            ORDER BY end_time DESC
            LIMIT 1
        """)
        last_scan = dict_from_row(cursor.fetchone())
        if last_scan:
            stats['last_scan'] = {
                'time': last_scan['end_time'],
                'subnet': last_scan['subnet'],
                'devices_found': last_scan['devices_found']
            }

        # Alert non risolti
        cursor.execute("""
            SELECT alert_type, COUNT(*) as count
            FROM alerts
            WHERE resolved = 0
            GROUP BY alert_type
        """)
        stats['unresolved_alerts'] = [
            {'type': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # Nuovi dispositivi (ultimi 7 giorni)
        cursor.execute("""
            SELECT COUNT(*) FROM devices
            WHERE first_seen > datetime('now', '-7 days')
        """)
        stats['new_devices_week'] = cursor.fetchone()[0]

        conn.close()

        return jsonify({
            'success': True,
            'statistics': stats
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/scan/history')
def api_scan_history():
    """Recupera lo storico delle scansioni"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        limit = request.args.get('limit', 50, type=int)

        cursor.execute("""
            SELECT * FROM scan_history
            ORDER BY start_time DESC
            LIMIT ?
        """, (limit,))

        history = [dict_from_row(row) for row in cursor.fetchall()]
        conn.close()

        # Formatta le date
        for scan in history:
            if scan['start_time']:
                scan['start_time_formatted'] = datetime.fromisoformat(
                    scan['start_time'].replace(' ', 'T')
                ).strftime('%d/%m/%Y %H:%M')
            if scan['end_time']:
                scan['end_time_formatted'] = datetime.fromisoformat(
                    scan['end_time'].replace(' ', 'T')
                ).strftime('%d/%m/%Y %H:%M')

                # Calcola durata
                start = datetime.fromisoformat(scan['start_time'].replace(' ', 'T'))
                end = datetime.fromisoformat(scan['end_time'].replace(' ', 'T'))
                duration = (end - start).total_seconds()
                scan['duration_seconds'] = duration
                scan['duration_formatted'] = f"{int(duration // 60)}m {int(duration % 60)}s"

        return jsonify({
            'success': True,
            'history': history
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/alerts')
def api_get_alerts():
    """Recupera gli alert"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Filtri
        resolved = request.args.get('resolved')
        severity = request.args.get('severity')
        limit = request.args.get('limit', 100, type=int)

        query = """
            SELECT a.*, d.ip_address, d.hostname, d.device_type
            FROM alerts a
            JOIN devices d ON a.device_id = d.id
            WHERE 1=1
        """
        params = []

        if resolved is not None:
            query += " AND a.resolved = ?"
            params.append(1 if resolved == 'true' else 0)

        if severity:
            query += " AND a.severity = ?"
            params.append(severity)

        query += " ORDER BY a.created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        alerts = [dict_from_row(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify({
            'success': True,
            'alerts': alerts
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert(alert_id):
    """Risolve un alert"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE alerts
            SET resolved = 1, resolved_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (alert_id,))

        conn.commit()
        conn.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/device/<ip>/update', methods=['POST'])
def api_update_device(ip):
    """Aggiorna informazioni manuale di un dispositivo"""
    try:
        data = request.json

        conn = get_db_connection()
        cursor = conn.cursor()

        # Campi aggiornabili manualmente
        updateable_fields = ['notes', 'location', 'device_type']

        updates = []
        params = []

        for field in updateable_fields:
            if field in data:
                updates.append(f"{field} = ?")
                params.append(data[field])

        if not updates:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400

        params.append(ip)
        query = f"UPDATE devices SET {', '.join(updates)} WHERE ip_address = ?"

        cursor.execute(query, params)

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        conn.commit()
        conn.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@scanner_bp.route('/api/scan/trigger', methods=['POST'])
def api_trigger_scan():
    """Trigger una scansione manuale"""
    try:
        # Importa lo scanner
        from scanner.network_scanner import NetworkScanner, SCANNER_CONFIG
        import threading

        subnet = request.json.get('subnet')

        def run_scan():
            scanner = NetworkScanner(SCANNER_CONFIG)
            if subnet:
                devices = scanner.scan_subnet(subnet)
                for device in devices:
                    scanner.save_device(device)
            else:
                scanner.run_full_scan()

        # Avvia in thread separato
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Scan triggered successfully'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== WEB INTERFACE ROUTES ====================

@scanner_bp.route('/')
@scanner_bp.route('/dashboard')
def scanner_dashboard():
    """Dashboard principale dello scanner"""
    return render_template('scanner/dashboard.html',
                           page_title='Network Scanner Dashboard')


@scanner_bp.route('/devices')
def scanner_devices():
    """Lista dispositivi"""
    return render_template('scanner/devices.html',
                           page_title='Dispositivi di Rete')


@scanner_bp.route('/device/<ip>')
def scanner_device_detail(ip):
    """Dettaglio dispositivo"""
    return render_template('scanner/device_detail.html',
                           ip_address=ip,
                           page_title=f'Dispositivo {ip}')


@scanner_bp.route('/alerts')
def scanner_alerts():
    """Pagina alert"""
    return render_template('scanner/alerts.html',
                           page_title='Alert di Rete')


@scanner_bp.route('/scan-history')
def scanner_history():
    """Storico scansioni"""
    return render_template('scanner/scan_history.html',
                           page_title='Storico Scansioni')


@scanner_bp.route('/network-map')
def scanner_network_map():
    """Mappa della rete"""
    return render_template('scanner/network_map.html',
                           page_title='Mappa della Rete')