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


# ===========================
# FILTRI JINJA2 PERSONALIZZATI
# ===========================

@app.template_filter('datetime')
def datetime_filter(value):
    """Filtro datetime per compatibilità con i template esistenti"""
    return format_datetime_filter(value)


@app.template_filter('format_datetime')
def format_datetime_filter(value):
    """Formatta datetime per i template"""
    if value is None:
        return 'N/A'
    if isinstance(value, str):
        try:
            # Prova diversi formati datetime
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%d/%m/%Y %H:%M:%S']:
                try:
                    value = datetime.strptime(value.replace('T', ' ').replace('Z', ''), fmt)
                    break
                except ValueError:
                    continue
            else:
                return value  # Se non riesce a parsare, restituisce la stringa originale
        except:
            return value

    if hasattr(value, 'strftime'):
        return value.strftime('%d/%m/%Y %H:%M:%S')

    return str(value)


@app.template_filter('format_datetime_obj')
def format_datetime_obj_filter(value):
    """Converte datetime string in oggetto datetime per calcoli"""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']:
                try:
                    return datetime.strptime(value.replace('T', ' ').replace('Z', ''), fmt)
                except ValueError:
                    continue
            return None
        except:
            return None

    if hasattr(value, 'strftime'):
        return value

    return None


@app.template_filter('filesizeformat')
def filesizeformat_filter(value):
    """Formatta dimensioni file"""
    if value is None:
        return 'N/A'

    try:
        value = float(value)
    except (TypeError, ValueError):
        return 'N/A'

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


@app.template_filter('format_duration')
def format_duration_filter(seconds):
    """Formatta durata in secondi in formato leggibile"""
    if seconds is None:
        return 'N/A'

    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return 'N/A'

    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


@app.template_filter('format_number')
def format_number_filter(value, decimals=0):
    """Formatta numeri con separatori delle migliaia"""
    if value is None:
        return 'N/A'
    try:
        if decimals == 0:
            return f"{int(value):,}"
        else:
            return f"{float(value):,.{decimals}f}"
    except (TypeError, ValueError):
        return str(value)


@app.template_filter('format_percentage')
def format_percentage_filter(value, total=None):
    """Calcola e formatta percentuale"""
    if value is None:
        return '0.0%'

    try:
        if total is not None and total != 0:
            percentage = (float(value) / float(total)) * 100
        else:
            percentage = float(value)
        return f"{percentage:.1f}%"
    except (TypeError, ValueError, ZeroDivisionError):
        return '0.0%'


@app.template_filter('timestamp')
def timestamp_filter(value):
    """Filtro timestamp per compatibilità"""
    return format_datetime_filter(value)


@app.template_filter('format_bytes')
def format_bytes_filter(value):
    """Alias per filesizeformat"""
    return filesizeformat_filter(value)


@app.template_filter('format_port')
def format_port_filter(value):
    """Formatta numero porta"""
    if not value:
        return 'N/A'

    try:
        port = int(value)
        if 1 <= port <= 65535:
            return str(port)
        else:
            return str(value)
    except (TypeError, ValueError):
        return str(value)


@app.template_filter('format_ip')
def format_ip_filter(value):
    """Formatta indirizzo IP"""
    if not value:
        return 'N/A'

    return str(value).strip()


@app.template_filter('format_cvss')
def format_cvss_filter(value):
    """Formatta score CVSS"""
    if not value:
        return 'N/A'

    try:
        score = float(value)
        return f"{score:.1f}"
    except (TypeError, ValueError):
        return str(value)


@app.template_filter('severity_class')
def severity_class_filter(severity):
    """Restituisce la classe CSS per il badge di severità"""
    if not severity:
        return 'bg-secondary'

    severity = str(severity).upper()

    if severity == 'CRITICAL':
        return 'bg-danger'
    elif severity == 'HIGH':
        return 'bg-warning'
    elif severity == 'MEDIUM':
        return 'bg-info'
    elif severity == 'LOW':
        return 'bg-success'
    else:
        return 'bg-secondary'


@app.template_filter('status_class')
def status_class_filter(status):
    """Restituisce la classe CSS per il badge di status"""
    if not status:
        return 'bg-secondary'

    status = str(status).lower()

    if status in ['completed', 'success', 'up', 'active', 'open']:
        return 'bg-success'
    elif status in ['running', 'in_progress', 'pending']:
        return 'bg-primary'
    elif status in ['failed', 'error', 'down', 'critical', 'closed']:
        return 'bg-danger'
    elif status in ['cancelled', 'stopped', 'inactive', 'filtered']:
        return 'bg-secondary'
    elif status in ['warning', 'partial']:
        return 'bg-warning'
    else:
        return 'bg-info'


# ===========================
# CONTEXT PROCESSORS
# ===========================

@app.context_processor
def inject_current_time():
    """Inietta il timestamp corrente e utility nei template"""
    return {
        'current_time': datetime.now(),
        'now': datetime.now()
    }


@app.context_processor
def utility_processor():
    """Aggiunge funzioni di utilità ai template"""

    def get_severity_class(severity):
        if not severity:
            return 'bg-secondary'

        severity = str(severity).upper()

        if severity == 'CRITICAL':
            return 'bg-danger'
        elif severity == 'HIGH':
            return 'bg-warning'
        elif severity == 'MEDIUM':
            return 'bg-info'
        elif severity == 'LOW':
            return 'bg-success'
        else:
            return 'bg-secondary'

    def get_cvss_class(score):
        if not score:
            return 'bg-secondary'

        try:
            score = float(score)
            if score >= 9.0:
                return 'bg-danger'
            elif score >= 7.0:
                return 'bg-warning'
            elif score >= 4.0:
                return 'bg-info'
            else:
                return 'bg-success'
        except (TypeError, ValueError):
            return 'bg-secondary'

    def get_status_class(status):
        if not status:
            return 'bg-secondary'

        status = str(status).lower()

        if status in ['completed', 'success', 'up', 'active']:
            return 'bg-success'
        elif status in ['running', 'in_progress', 'pending']:
            return 'bg-primary'
        elif status in ['failed', 'error', 'down', 'critical']:
            return 'bg-danger'
        elif status in ['cancelled', 'stopped', 'inactive']:
            return 'bg-secondary'
        elif status in ['warning', 'partial']:
            return 'bg-warning'
        else:
            return 'bg-info'

    return dict(
        get_severity_class=get_severity_class,
        get_cvss_class=get_cvss_class,
        get_status_class=get_status_class,
        format_datetime=format_datetime_filter,
        format_filesize=filesizeformat_filter,
        format_number=format_number_filter
    )


# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(404)
def not_found_error(error):
    """Gestisce errori 404"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Gestisce errori 500"""
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    """Gestisce errori 403"""
    return render_template('errors/403.html'), 403


# ===========================
# DATABASE TEARDOWN
# ===========================

@app.teardown_appcontext
def close_db_connection(exception):
    """Chiude la connessione al database al termine della richiesta"""
    close_db(exception)


# ===========================
# ROUTE PRINCIPALE
# ===========================

@app.route('/')
def index():
    """Home page principale"""
    try:
        db = get_db()

        # Statistiche base
        stats = {
            'total_hosts': 0,
            'total_ports': 0,
            'open_ports': 0,
            'total_vulnerabilities': 0,
            'critical_vulns': 0,
            'recent_scans': 0
        }

        try:
            # Conta hosts
            hosts_count = db.execute('SELECT COUNT(*) FROM hosts').fetchone()
            if hosts_count:
                stats['total_hosts'] = hosts_count[0]

            # Conta porte
            ports_count = db.execute('SELECT COUNT(*) FROM ports').fetchone()
            if ports_count:
                stats['total_ports'] = ports_count[0]

            # Conta porte aperte
            open_ports_count = db.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()
            if open_ports_count:
                stats['open_ports'] = open_ports_count[0]

            # Conta vulnerabilità
            vulns_count = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()
            if vulns_count:
                stats['total_vulnerabilities'] = vulns_count[0]

            # Conta vulnerabilità critiche
            critical_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()
            if critical_vulns:
                stats['critical_vulns'] = critical_vulns[0]

            # Conta scansioni recenti (ultima settimana)
            week_ago = datetime.now() - timedelta(days=7)
            recent_scans = db.execute(
                "SELECT COUNT(*) FROM scan_results WHERE start_time > ?",
                (week_ago.strftime('%Y-%m-%d %H:%M:%S'),)
            ).fetchone()
            if recent_scans:
                stats['recent_scans'] = recent_scans[0]

        except Exception as e:
            app.logger.error(f"Errore nel calcolo delle statistiche: {e}")
            # Mantieni le statistiche a 0 in caso di errore

        return render_template('index.html', stats=stats)

    except Exception as e:
        app.logger.error(f"Errore nella route index: {e}")
        flash('Errore nel caricamento della dashboard', 'error')
        return render_template('index.html', stats={
            'total_hosts': 0,
            'total_ports': 0,
            'open_ports': 0,
            'total_vulnerabilities': 0,
            'critical_vulns': 0,
            'recent_scans': 0
        })


# ===========================
# API ENDPOINTS BASE
# ===========================

@app.route('/api/stats')
def api_stats():
    """API endpoint per statistiche generali"""
    try:
        db = get_db()

        stats = {}

        # Statistiche hosts
        stats['hosts'] = {
            'total': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'up': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
            'down': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'down'").fetchone()[0]
        }

        # Statistiche porte
        stats['ports'] = {
            'total': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
            'open': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0],
            'closed': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'closed'").fetchone()[0],
            'filtered': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'filtered'").fetchone()[0]
        }

        # Statistiche vulnerabilità
        stats['vulnerabilities'] = {
            'total': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
            'critical': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[0],
            'high': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH'").fetchone()[0],
            'medium': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM'").fetchone()[0],
            'low': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'LOW'").fetchone()[0]
        }

        return jsonify(stats)

    except Exception as e:
        app.logger.error(f"Errore in api_stats: {e}")
        return jsonify({'error': 'Errore nel recupero delle statistiche'}), 500


@app.route('/api/health')
def api_health():
    """API endpoint per controllo salute sistema"""
    try:
        db = get_db()
        # Test connessione database
        db.execute('SELECT 1').fetchone()

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'version': '1.0.0'
        })

    except Exception as e:
        app.logger.error(f"Errore in health check: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'disconnected',
            'error': str(e)
        }), 500


# ===========================
# UTILITY ROUTES
# ===========================
# ===========================
# CONFIGURAZIONE SVILUPPO
# ===========================

if __name__ == '__main__':
    # Configurazione per sviluppo
    app.config['DEBUG'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # Crea la directory data se non esiste
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    # Avvia l'applicazione
    app.run(host='0.0.0.0', port=8132, debug=True)