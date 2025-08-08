from flask import Flask, render_template, request, jsonify, g, flash, redirect, url_for
import os
import sqlite3
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any

# Import dei moduli core
from core.nmap_scanner_db import NmapScannerDB
from core.nmap_scanner import NmapScannerSystem

# Crea l'applicazione Flask
app = Flask(__name__)

# Configurazione
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['DATABASE_PATH'] = 'instance/nmap_scans.db'

# Importa e registra la blueprint del menu dopo aver creato l'app
from menu import menu_bp

app.register_blueprint(menu_bp)

# Registra la blueprint network
from network import network_bp

app.register_blueprint(network_bp)


def get_db():
    """Ottiene una connessione al database"""
    return NmapScannerDB(app.config['DATABASE_PATH'])


def format_datetime(value):
    """Formatta datetime per i template"""
    if value is None:
        return 'N/A'
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value
    return value.strftime('%d/%m/%Y %H:%M:%S')


def format_timestamp(value):
    """Formatta timestamp Unix per i template"""
    if value is None:
        return 'N/A'
    try:
        dt = datetime.fromtimestamp(float(value))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except:
        return str(value)


# Registra i filtri per i template
app.jinja_env.filters['datetime'] = format_datetime
app.jinja_env.filters['timestamp'] = format_timestamp


@app.route('/')
def index():
    """Homepage con dashboard principale"""
    return redirect(url_for('network.dashboard'))


@app.route('/widgets')
def widgets():
    """Pagina widgets - Statistiche e grafici avanzati"""
    try:
        with get_db() as db:
            # Dati per grafici

            # Trend scansioni per mese
            scan_trend = db.execute_query("""
                SELECT strftime('%Y-%m', datetime(start_time, 'unixepoch')) as month,
                       COUNT(*) as count
                FROM scan_runs
                WHERE start_time IS NOT NULL
                GROUP BY month
                ORDER BY month DESC
                LIMIT 12
            """)

            # Distribuzione porte per stato
            port_distribution = db.execute_query("""
                SELECT state, COUNT(*) as count
                FROM ports
                GROUP BY state
                ORDER BY count DESC
            """)

            # Top 10 servizi
            service_stats = db.execute_query("""
                SELECT service, COUNT(*) as count
                FROM ports
                WHERE service IS NOT NULL AND service != ''
                GROUP BY service
                ORDER BY count DESC
                LIMIT 10
            """)

            # Distribuzione OS
            os_stats = db.execute_query("""
                SELECT name, accuracy, COUNT(*) as count
                FROM os_matches
                GROUP BY name
                ORDER BY count DESC
                LIMIT 10
            """)

            # Vulnerabilità per severità
            vuln_severity = db.execute_query("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE severity IS NOT NULL
                GROUP BY severity
                ORDER BY count DESC
            """)

            return render_template('widgets.html',
                                   scan_trend=scan_trend,
                                   port_distribution=port_distribution,
                                   service_stats=service_stats,
                                   os_stats=os_stats,
                                   vuln_severity=vuln_severity)

    except Exception as e:
        flash(f'Errore nel caricamento widgets: {str(e)}', 'error')
        return render_template('widgets.html')


@app.route('/forms')
def forms():
    """Pagina forms - Test e configurazione sistema"""
    try:
        # Test connessione database
        with get_db() as db:
            db_status = "Connessione OK"
            tables = db.execute_query("SELECT name FROM sqlite_master WHERE type='table'")
            table_count = len(tables)

        # Test scanner system
        try:
            scanner = NmapScannerSystem()
            scanner_status = "Scanner OK"
        except Exception as e:
            scanner_status = f"Errore: {str(e)}"

        return render_template('forms.html',
                               db_status=db_status,
                               table_count=table_count,
                               scanner_status=scanner_status)

    except Exception as e:
        flash(f'Errore: {str(e)}', 'error')
        return render_template('forms.html',
                               db_status="Errore connessione",
                               table_count=0,
                               scanner_status="Non disponibile")


@app.route('/tables')
def tables():
    """Pagina tables - Vista dati tabellari"""
    try:
        with get_db() as db:
            # Ottieni tutti gli scan
            scans = db.execute_query("""
                SELECT sr.id, sr.scanner, sr.version, sr.args, 
                       sr.start_time, sr.end_time, sr.filename,
                       COUNT(h.id) as host_count
                FROM scan_runs sr
                LEFT JOIN hosts h ON sr.id = h.scan_run_id
                GROUP BY sr.id
                ORDER BY sr.created_at DESC
                LIMIT 50
            """)

            # Ottieni tutti gli host - CORREZIONE: h.status -> h.status_state
            hosts = db.execute_query("""
                SELECT h.id, h.ip_address, h.status_state as status, h.mac_address, h.vendor,
                       sr.filename, sr.start_time,
                       COUNT(p.id) as port_count
                FROM hosts h
                JOIN scan_runs sr ON h.scan_run_id = sr.id
                LEFT JOIN ports p ON h.id = p.host_id
                GROUP BY h.id
                ORDER BY sr.start_time DESC
                LIMIT 100
            """)

            return render_template('tables.html', scans=scans, hosts=hosts)

    except Exception as e:
        flash(f'Errore nel caricamento tabelle: {str(e)}', 'error')
        return render_template('tables.html', scans=[], hosts=[])


@app.route('/about')
def about():
    """Pagina about"""
    return render_template('about.html')


# API Endpoints per AJAX
@app.route('/api/scan/<int:scan_id>')
def api_scan_details(scan_id):
    """API per dettagli scan"""
    try:
        with get_db() as db:
            # Dettagli scan
            scan = db.execute_query("""
                SELECT * FROM scan_runs WHERE id = ?
            """, (scan_id,))

            if not scan:
                return jsonify({'error': 'Scan non trovato'}), 404

            # Host del scan - CORREZIONE: h.status -> h.status_state
            hosts = db.execute_query("""
                SELECT h.*, h.status_state as status, COUNT(p.id) as port_count
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_run_id = ?
                GROUP BY h.id
            """, (scan_id,))

            return jsonify({
                'scan': scan[0],
                'hosts': hosts
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/host/<int:host_id>')
def api_host_details(host_id):
    """API per dettagli host"""
    try:
        with get_db() as db:
            # Dettagli host - CORREZIONE: Aggiunto alias per status_state
            host = db.execute_query("""
                SELECT h.*, h.status_state as status, sr.filename, sr.start_time as scan_time
                FROM hosts h
                JOIN scan_runs sr ON h.scan_run_id = sr.id
                WHERE h.id = ?
            """, (host_id,))

            if not host:
                return jsonify({'error': 'Host non trovato'}), 404

            # Porte dell'host
            ports = db.execute_query("""
                SELECT * FROM ports WHERE host_id = ?
                ORDER BY port_number
            """, (host_id,))

            # Vulnerabilità dell'host
            vulns = db.execute_query("""
                SELECT * FROM vulnerabilities WHERE host_id = ?
                ORDER BY cvss_score DESC
            """, (host_id,))

            # Info SNMP se disponibili
            snmp_info = db.execute_query("""
                SELECT * FROM snmp_system_info WHERE host_id = ?
            """, (host_id,))

            return jsonify({
                'host': host[0],
                'ports': ports,
                'vulnerabilities': vulns,
                'snmp_info': snmp_info[0] if snmp_info else None
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/search')
def api_search():
    """API per ricerca avanzata"""
    try:
        # Parametri di ricerca
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))

        offset = (page - 1) * per_page

        results = []
        total = 0

        with get_db() as db:
            if search_type == 'hosts' or search_type == 'all':
                # Ricerca negli host - CORREZIONE: h.status -> h.status_state
                host_query = """
                    SELECT 'host' as type, h.id, h.ip_address as title, 
                           h.status_state as description, sr.filename as context
                    FROM hosts h
                    JOIN scan_runs sr ON h.scan_run_id = sr.id
                    WHERE h.ip_address LIKE ? OR h.vendor LIKE ?
                    ORDER BY h.ip_address
                    LIMIT ? OFFSET ?
                """
                search_term = f'%{query}%'
                host_results = db.execute_query(host_query,
                                                (search_term, search_term, per_page, offset))
                results.extend(host_results)

            if search_type == 'services' or search_type == 'all':
                # Ricerca nei servizi
                service_query = """
                    SELECT 'service' as type, p.id, p.service as title,
                           (p.port_number || '/' || p.protocol) as description,
                           h.ip_address as context
                    FROM ports p
                    JOIN hosts h ON p.host_id = h.id
                    WHERE p.service LIKE ? OR p.version LIKE ?
                    ORDER BY p.service
                    LIMIT ? OFFSET ?
                """
                service_results = db.execute_query(service_query,
                                                   (search_term, search_term, per_page, offset))
                results.extend(service_results)

        return jsonify({
            'results': results,
            'total': len(results),
            'page': page,
            'per_page': per_page,
            'query': query
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


# Context processor per rendere disponibili alcune variabili in tutti i template
@app.context_processor
def inject_template_vars():
    """Inietta variabili in tutti i template"""
    return {
        'current_endpoint': getattr(g, 'current_endpoint', None),
        'now': datetime.now()
    }


@app.before_request
def before_request():
    """Eseguito prima di ogni richiesta"""
    g.current_endpoint = request.endpoint


if __name__ == '__main__':
    # Assicurati che le cartelle necessarie esistano
    for directory in ['templates', 'templates/errors', 'templates/network',
                      'static', 'static/css', 'static/js', 'static/img', 'instance']:
        if not os.path.exists(directory):
            os.makedirs(directory)

    app.run(debug=True, host='0.0.0.0', port=8132)