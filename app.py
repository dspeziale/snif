from flask import Flask, render_template, request, jsonify, g, flash, redirect, url_for
import os
import sqlite3
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any

# Crea l'applicazione Flask
app = Flask(__name__)

# Configurazione
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['DATABASE_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'snmp_scan_results.db')

# ===========================
# IMPORT E REGISTRAZIONE BLUEPRINT
# ===========================

# Importa il menu blueprint (già esistente)
from menu import menu_bp

# Importa tutte le nuove blueprint
from routes.network import network_bp
from routes.security import security_bp
from routes.devices import devices_bp
from routes.system import system_bp
from routes.reports import reports_bp
from routes.analytics import analytics_bp
from routes.tools import tools_bp
from routes.admin import admin_bp
from routes.help import help_bp
from routes.about import about_bp

# Registra tutte le blueprint
app.register_blueprint(menu_bp)
app.register_blueprint(network_bp)
app.register_blueprint(security_bp)
app.register_blueprint(devices_bp)
app.register_blueprint(system_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(analytics_bp)
app.register_blueprint(tools_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(help_bp)
app.register_blueprint(about_bp)


# ===========================
# HELPER FUNCTIONS
# ===========================

def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row  # Per accesso come dizionario
    return g.db


def close_db(error=None):
    """Chiude la connessione al database"""
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


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


def get_dashboard_stats():
    """Ottiene statistiche per la dashboard principale"""
    db = get_db()

    try:
        stats = {
            'total_hosts': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'active_hosts': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
            'total_ports': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
            'open_ports': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0],
            'total_vulnerabilities': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
            'critical_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[
                0],
            'high_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH'").fetchone()[0],
            'total_software': db.execute('SELECT COUNT(*) FROM installed_software').fetchone()[0],
            'total_processes': db.execute('SELECT COUNT(*) FROM running_processes').fetchone()[0]
        }

        # Calcola percentuali
        if stats['total_hosts'] > 0:
            stats['active_hosts_percent'] = round((stats['active_hosts'] / stats['total_hosts']) * 100, 1)
        else:
            stats['active_hosts_percent'] = 0

        if stats['total_ports'] > 0:
            stats['open_ports_percent'] = round((stats['open_ports'] / stats['total_ports']) * 100, 1)
        else:
            stats['open_ports_percent'] = 0

        return stats
    except Exception as e:
        print(f"Errore nel recupero statistiche: {e}")
        return {
            'total_hosts': 0, 'active_hosts': 0, 'total_ports': 0, 'open_ports': 0,
            'total_vulnerabilities': 0, 'critical_vulns': 0, 'high_vulns': 0,
            'total_software': 0, 'total_processes': 0,
            'active_hosts_percent': 0, 'open_ports_percent': 0
        }


# ===========================
# REGISTRAZIONE FILTRI E CONTEXT PROCESSORS
# ===========================

# Registra i filtri per i template
app.jinja_env.filters['datetime'] = format_datetime
app.jinja_env.filters['timestamp'] = format_timestamp


# Context processor per rendere disponibili alcune variabili in tutti i template
@app.context_processor
def inject_template_vars():
    """Inietta variabili in tutti i template"""
    return {
        'current_endpoint': getattr(g, 'current_endpoint', None),
        'now': datetime.now()
    }


# ===========================
# EVENT HANDLERS
# ===========================

@app.before_request
def before_request():
    """Eseguito prima di ogni richiesta"""
    g.current_endpoint = request.endpoint


@app.teardown_appcontext
def close_db_connection(exception):
    """Chiude la connessione al database alla fine della richiesta"""
    close_db(exception)


# ===========================
# ROUTE PRINCIPALI
# ===========================

@app.route('/')
def index():
    """Homepage con dashboard principale"""
    stats = get_dashboard_stats()

    # Ottieni ultimi scan
    db = get_db()
    try:
        recent_scans = db.execute('''
            SELECT * FROM scan_info 
            ORDER BY start_time DESC 
            LIMIT 5
        ''').fetchall()

        # Top 5 host con più vulnerabilità
        vulnerable_hosts = db.execute('''
            SELECT v.ip_address, h.hostname, COUNT(*) as vuln_count,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            GROUP BY v.ip_address 
            ORDER BY vuln_count DESC 
            LIMIT 5
        ''').fetchall()

        # Top 5 porte più comuni
        top_ports = db.execute('''
            SELECT port_number, protocol, COUNT(*) as count 
            FROM ports WHERE state = 'open' 
            GROUP BY port_number, protocol 
            ORDER BY count DESC 
            LIMIT 5
        ''').fetchall()

        # Distribuzione per tipo di dispositivo
        device_types = db.execute('''
            SELECT device_type, COUNT(*) as count
            FROM device_classification 
            WHERE device_type IS NOT NULL
            GROUP BY device_type 
            ORDER BY count DESC
            LIMIT 5
        ''').fetchall()

    except Exception as e:
        print(f"Errore nel recupero dati dashboard: {e}")
        recent_scans = []
        vulnerable_hosts = []
        top_ports = []
        device_types = []

    return render_template('index.html',
                           stats=stats,
                           recent_scans=recent_scans,
                           vulnerable_hosts=vulnerable_hosts,
                           top_ports=top_ports,
                           device_types=device_types)


# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """Gestisce eccezioni generali"""
    # Log dell'errore
    app.logger.error(f"Errore non gestito: {str(e)}")

    # Se in debug mode, rilancia l'eccezione
    if app.debug:
        raise e

    # Altrimenti mostra pagina errore 500
    return render_template('errors/500.html'), 500


# ===========================
# API ENDPOINTS HELPER
# ===========================

@app.route('/api/stats')
def api_stats():
    """API endpoint per statistiche in formato JSON"""
    try:
        stats = get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    try:
        db = get_db()
        # Test connessione database
        db.execute('SELECT 1').fetchone()

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


# ===========================
# DEBUG ROUTES (solo in development)
# ===========================

@app.route('/debug/db-tables')
def debug_db_tables():
    """Debug: mostra tutte le tabelle del database"""
    if not app.debug:
        return "Debug mode not enabled", 403

    try:
        db = get_db()
        tables = db.execute('''
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            ORDER BY name
        ''').fetchall()

        table_info = {}
        for table in tables:
            table_name = table['name']
            count = db.execute(f'SELECT COUNT(*) FROM {table_name}').fetchone()[0]
            table_info[table_name] = count

        return jsonify(table_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/debug/endpoints')
def debug_endpoints():
    """Debug: mostra tutti gli endpoint registrati"""
    if not app.debug:
        return "Debug mode not enabled", 403

    endpoints = []
    for rule in app.url_map.iter_rules():
        endpoints.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': str(rule)
        })

    return jsonify(sorted(endpoints, key=lambda x: x['endpoint']))


# ===========================
# INIZIALIZZAZIONE
# ===========================

def init_app():
    """Inizializza l'applicazione"""
    # Assicurati che le cartelle necessarie esistano
    directories = [
        'templates', 'templates/errors', 'templates/network', 'templates/security',
        'templates/devices', 'templates/system', 'templates/reports', 'templates/analytics',
        'templates/tools', 'templates/admin', 'templates/help', 'templates/about',
        'static', 'static/css', 'static/js', 'static/img', 'static/data',
        'data', 'logs', 'reports', 'cache'
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Creata directory: {directory}")

    # Controlla se il database esiste
    if not os.path.exists(app.config['DATABASE_PATH']):
        print(f"⚠️  ATTENZIONE: Database non trovato in {app.config['DATABASE_PATH']}")
        print("   Assicurati di aver eseguito il parser per creare il database.")
    else:
        print(f"✅ Database trovato: {app.config['DATABASE_PATH']}")


if __name__ == '__main__':
    # Inizializza l'app
    init_app()

    # Configura logging se in produzione
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler

        if not os.path.exists('logs'):
            os.mkdir('logs')

        file_handler = RotatingFileHandler('logs/flask_app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Network Analysis Tool startup')

    # Avvia l'applicazione
    app.run(debug=True, host='0.0.0.0', port=8132)