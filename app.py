from flask import Flask, render_template, request, jsonify, g, flash, redirect, url_for
import os
import sqlite3
import builtins  # ← AGGIUNTO per risolvere problema ricorsione
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
            # Prova diversi formati
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']:
                try:
                    return datetime.strptime(value.replace('T', ' ').replace('Z', ''), fmt)
                except ValueError:
                    continue
            return None
        except:
            return None
    return value


@app.template_filter('truncate_words')
def truncate_words_filter(text, length=20, end='...'):
    """Tronca testo a un numero di parole"""
    if not text:
        return ''

    words = str(text).split()
    if len(words) <= length:
        return text

    return ' '.join(words[:length]) + end


@app.template_filter('filesizeformat')
def filesizeformat_filter(value):
    """Formatta dimensioni file in formato leggibile"""
    if value is None:
        return 'N/A'

    try:
        bytes_value = float(value)

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0

        return f"{bytes_value:.1f} PB"
    except (TypeError, ValueError):
        return str(value)


@app.template_filter('format_number')
def format_number_filter(value, decimals=0):
    """Formatta numero con separatori delle migliaia"""
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


@app.template_filter('confidence_class')
def confidence_class_filter(confidence):
    """Restituisce la classe CSS per il badge di confidenza"""
    if confidence is None:
        return 'bg-secondary'

    try:
        conf = float(confidence)
        if conf >= 0.8:
            return 'bg-success'
        elif conf >= 0.6:
            return 'bg-primary'
        elif conf >= 0.4:
            return 'bg-warning'
        else:
            return 'bg-danger'
    except (TypeError, ValueError):
        return 'bg-secondary'


@app.template_filter('status_class')
def status_class_filter(status):
    """Restituisce la classe CSS per il badge di status"""
    if not status:
        return 'bg-secondary'

    status = str(status).lower()

    if status == 'up':
        return 'bg-success'
    elif status == 'down':
        return 'bg-danger'
    elif status == 'filtered':
        return 'bg-warning'
    elif status == 'open':
        return 'bg-success'
    elif status == 'closed':
        return 'bg-danger'
    elif status == 'running':
        return 'bg-primary'
    elif status == 'stopped':
        return 'bg-secondary'
    else:
        return 'bg-info'


# ===========================
# FUNZIONI GLOBALI PER TEMPLATE (FIX RICORSIONE)
# ===========================

@app.context_processor
def inject_builtin_functions():
    """Inietta funzioni Python built-in nei template - VERSIONE SICURA"""

    def safe_max(*args):
        try:
            if not args:
                return 0
            # Filtra valori None e non numerici
            valid_args = []
            for arg in args:
                if arg is not None:
                    try:
                        # Prova a convertire in numero se è una stringa
                        if isinstance(arg, str) and arg.isdigit():
                            valid_args.append(int(arg))
                        else:
                            valid_args.append(arg)
                    except:
                        valid_args.append(arg)

            return builtins.max(valid_args) if valid_args else 0
        except:
            return 0

    def safe_min(*args):
        try:
            if not args:
                return 0
            # Filtra valori None e non numerici
            valid_args = []
            for arg in args:
                if arg is not None:
                    try:
                        # Prova a convertire in numero se è una stringa
                        if isinstance(arg, str) and arg.isdigit():
                            valid_args.append(int(arg))
                        else:
                            valid_args.append(arg)
                    except:
                        valid_args.append(arg)

            return builtins.min(valid_args) if valid_args else 0
        except:
            return 0

    def safe_len(obj):
        try:
            return builtins.len(obj) if obj is not None else 0
        except:
            return 0

    def safe_sum(iterable):
        try:
            return builtins.sum(iterable) if iterable else 0
        except:
            return 0

    def safe_round(value, ndigits=0):
        try:
            return builtins.round(float(value), ndigits) if value is not None else 0
        except:
            return 0

    return {
        'max': safe_max,
        'min': safe_min,
        'len': safe_len,
        'sum': safe_sum,
        'round': safe_round,
        'range': builtins.range,
        'enumerate': builtins.enumerate,
        'zip': builtins.zip,
        'abs': lambda x: builtins.abs(x) if x is not None else 0,
        'int': lambda x: builtins.int(x) if x is not None else 0,
        'float': lambda x: builtins.float(x) if x is not None else 0.0,
        'str': lambda x: builtins.str(x) if x is not None else '',
    }


# ===========================
# GESTIONE ERRORI
# ===========================

@app.errorhandler(404)
def not_found_error(error):
    """Gestisce errori 404"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Gestisce errori 500"""
    return render_template('errors/500.html'), 500


@app.teardown_appcontext
def close_db_connection(exception):
    """Chiude la connessione al database alla fine della richiesta"""
    close_db(exception)


# ===========================
# ROUTE PRINCIPALI
# ===========================

@app.route('/')
def index():
    """Pagina principale"""
    try:
        db = get_db()

        # Statistiche rapide per la dashboard
        stats = {
            'total_hosts': 0,
            'active_hosts': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'total_ports': 0,
            'open_ports': 0,
            'classified_devices': 0,
            'last_scan_date': None
        }

        try:
            # Statistiche host
            stats['total_hosts'] = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
            stats['active_hosts'] = db.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"').fetchone()[0]
        except:
            pass

        try:
            # Statistiche vulnerabilità
            stats['total_vulnerabilities'] = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
            stats['critical_vulnerabilities'] = \
            db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "CRITICAL"').fetchone()[0]
        except:
            pass

        try:
            # Statistiche porte
            stats['total_ports'] = db.execute('SELECT COUNT(*) FROM ports').fetchone()[0]
            stats['open_ports'] = db.execute('SELECT COUNT(*) FROM ports WHERE state = "open"').fetchone()[0]
        except:
            pass

        try:
            # Statistiche dispositivi classificati
            stats['classified_devices'] = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]
        except:
            pass

        try:
            # Data ultima scansione
            last_scan = db.execute('SELECT MAX(start_time) FROM scan_info').fetchone()[0]
            if last_scan:
                stats['last_scan_date'] = last_scan
        except:
            pass

        # Attività recenti (host scoperti di recente)
        recent_activity = []
        try:
            recent_hosts = db.execute('''
                SELECT ip_address, hostname, status, scan_id
                FROM hosts 
                ORDER BY scan_id DESC 
                LIMIT 10
            ''').fetchall()

            for host in recent_hosts:
                recent_activity.append({
                    'type': 'host_discovered',
                    'ip_address': host['ip_address'],
                    'hostname': host['hostname'],
                    'status': host['status'],
                    'timestamp': datetime.now()  # In realtà dovresti usare timestamp reale
                })
        except:
            pass

        return render_template('index.html',
                               stats=stats,
                               recent_activity=recent_activity)

    except Exception as e:
        app.logger.error(f"Errore nella pagina principale: {e}")
        return render_template('index.html',
                               stats={},
                               recent_activity=[],
                               error="Errore nel caricamento dei dati")


# ===========================
# API ENDPOINTS
# ===========================

@app.route('/api/stats')
def api_stats():
    """API endpoint per statistiche generali"""
    try:
        db = get_db()

        stats = {
            'hosts': {
                'total': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
                'active': db.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"').fetchone()[0],
                'inactive': db.execute('SELECT COUNT(*) FROM hosts WHERE status = "down"').fetchone()[0]
            },
            'ports': {
                'total': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
                'open': db.execute('SELECT COUNT(*) FROM ports WHERE state = "open"').fetchone()[0],
                'closed': db.execute('SELECT COUNT(*) FROM ports WHERE state = "closed"').fetchone()[0]
            },
            'vulnerabilities': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'devices': {
                'classified': 0,
                'unclassified': 0
            }
        }

        # Statistiche vulnerabilità (se la tabella esiste)
        try:
            stats['vulnerabilities']['total'] = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
            stats['vulnerabilities']['critical'] = \
            db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "CRITICAL"').fetchone()[0]
            stats['vulnerabilities']['high'] = \
            db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "HIGH"').fetchone()[0]
            stats['vulnerabilities']['medium'] = \
            db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "MEDIUM"').fetchone()[0]
            stats['vulnerabilities']['low'] = \
            db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "LOW"').fetchone()[0]
        except:
            pass

        # Statistiche dispositivi classificati (se la tabella esiste)
        try:
            stats['devices']['classified'] = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]
            stats['devices']['unclassified'] = stats['hosts']['total'] - stats['devices']['classified']
        except:
            pass

        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'data': stats
        })

    except Exception as e:
        app.logger.error(f"Errore nel recupero delle statistiche: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Errore nel recupero delle statistiche'
        }), 500


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
# ROUTE DI UTILITÀ
# ===========================

@app.route('/search')
def global_search():
    """Ricerca globale"""
    query = request.args.get('q', '').strip()

    if not query:
        return render_template('search_results.html', query='', results={})

    try:
        db = get_db()
        results = {
            'hosts': [],
            'vulnerabilities': [],
            'services': []
        }

        # Cerca negli host
        try:
            hosts = db.execute('''
                SELECT ip_address, hostname, status, vendor
                FROM hosts 
                WHERE ip_address LIKE ? OR hostname LIKE ? OR vendor LIKE ?
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
            results['hosts'] = [dict(host) for host in hosts]
        except:
            pass

        # Cerca nelle vulnerabilità
        try:
            vulns = db.execute('''
                SELECT ip_address, vuln_id, title, severity
                FROM vulnerabilities 
                WHERE title LIKE ? OR vuln_id LIKE ?
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%')).fetchall()
            results['vulnerabilities'] = [dict(vuln) for vuln in vulns]
        except:
            pass

        # Cerca nei servizi
        try:
            services = db.execute('''
                SELECT ip_address, port_number, service_name, service_product
                FROM services 
                WHERE service_name LIKE ? OR service_product LIKE ?
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%')).fetchall()
            results['services'] = [dict(service) for service in services]
        except:
            pass

        return render_template('search_results.html', query=query, results=results)

    except Exception as e:
        app.logger.error(f"Errore nella ricerca globale: {e}")
        return render_template('search_results.html',
                               query=query,
                               results={},
                               error=str(e))


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