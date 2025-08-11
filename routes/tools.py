# ===========================
# routes/reports.py - Reports Blueprint
# ===========================

from flask import Blueprint, render_template, request, jsonify, g, current_app, make_response
import sqlite3
from datetime import datetime
import json
import csv
import io

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


@reports_bp.route('/overview')
@reports_bp.route('/')
def overview():
    """Overview dei report disponibili"""
    return render_template('reports/overview.html')


@reports_bp.route('/executive-summary')
def executive_summary():
    """Executive summary report"""
    try:
        db = get_db()

        # Dati per il report executive
        summary_data = {
            'report_date': datetime.now(),
            'total_hosts': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'active_hosts': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
            'total_vulnerabilities': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
            'critical_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[
                0],
            'high_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH'").fetchone()[0],
            'medium_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'MEDIUM'").fetchone()[0],
            'low_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'LOW'").fetchone()[0]
        }

        # Risk assessment
        risk_score = (summary_data['critical_vulns'] * 10 +
                      summary_data['high_vulns'] * 7 +
                      summary_data['medium_vulns'] * 4 +
                      summary_data['low_vulns'] * 1)

        if summary_data['active_hosts'] > 0:
            summary_data['risk_score_per_host'] = risk_score / summary_data['active_hosts']
        else:
            summary_data['risk_score_per_host'] = 0

        return render_template('reports/executive_summary.html', data=summary_data)

    except Exception as e:
        current_app.logger.error(f"Errore in executive_summary: {e}")
        return render_template('reports/executive_summary.html', error=str(e))


@reports_bp.route('/export')
def export():
    """Pagina per export dati"""
    return render_template('reports/export.html')


@reports_bp.route('/export/csv')
def export_csv():
    """Export dati in formato CSV"""
    table = request.args.get('table', 'hosts')

    try:
        db = get_db()

        # Query basata sulla tabella richiesta
        if table == 'hosts':
            query = '''
                SELECT h.ip_address, h.hostname, h.status, h.vendor, h.mac_address,
                       COUNT(DISTINCT p.port_number) as open_ports,
                       COUNT(DISTINCT v.vuln_id) as vulnerabilities
                FROM hosts h
                LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
                LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
                GROUP BY h.ip_address
            '''
        elif table == 'vulnerabilities':
            query = '''
                SELECT v.ip_address, h.hostname, v.severity, v.title, v.vuln_type, v.cve_id
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
            '''
        elif table == 'ports':
            query = '''
                SELECT p.ip_address, h.hostname, p.port_number, p.protocol, p.state, s.service_name
                FROM ports p
                LEFT JOIN hosts h ON p.ip_address = h.ip_address
                LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
            '''
        else:
            return jsonify({'error': 'Invalid table'}), 400

        results = db.execute(query).fetchall()

        # Crea CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        if results:
            writer.writerow(results[0].keys())

            # Data
            for row in results:
                writer.writerow(row)

        # Prepara response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers[
            'Content-Disposition'] = f'attachment; filename={table}_{datetime.now().strftime("%Y%m%d")}.csv'

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================
# routes/analytics.py - Analytics Blueprint
# ===========================

analytics_bp = Blueprint('analytics', __name__, url_prefix='/analytics')


@analytics_bp.route('/overview')
@analytics_bp.route('/')
def overview():
    """Analytics overview"""
    return render_template('analytics/overview.html')


@analytics_bp.route('/network')
def network():
    """Network analytics"""
    try:
        db = get_db()

        # Trend analysis
        network_trends = {
            'hosts_over_time': [],  # Se hai timestamp nelle scansioni
            'ports_distribution': db.execute('''
                SELECT port_number, COUNT(*) as count
                FROM ports WHERE state = 'open'
                GROUP BY port_number
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall(),
            'service_popularity': db.execute('''
                SELECT service_name, COUNT(*) as count
                FROM services
                WHERE service_name IS NOT NULL
                GROUP BY service_name
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
        }

        return render_template('analytics/network.html', trends=network_trends)

    except Exception as e:
        return render_template('analytics/network.html', error=str(e))


# ===========================
# routes/tools.py - Tools Blueprint
# ===========================

tools_bp = Blueprint('tools', __name__, url_prefix='/tools')


@tools_bp.route('/database/status')
def database_status():
    """Status del database"""
    try:
        db = get_db()

        # Informazioni tabelle
        tables = db.execute('''
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            ORDER BY name
        ''').fetchall()

        table_stats = {}
        for table in tables:
            table_name = table['name']
            count = db.execute(f'SELECT COUNT(*) FROM {table_name}').fetchone()[0]
            table_stats[table_name] = count

        # Dimensione database
        db_size = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]

        status_info = {
            'tables': table_stats,
            'db_size_bytes': db_size,
            'db_size_mb': round(db_size / (1024 * 1024), 2)
        }

        return render_template('tools/database_status.html', status=status_info)

    except Exception as e:
        return render_template('tools/database_status.html', error=str(e))


@tools_bp.route('/search/global')
def global_search():
    """Ricerca globale"""
    query = request.args.get('q', '').strip()

    if not query:
        return render_template('tools/global_search.html')

    try:
        db = get_db()
        results = {}

        # Cerca negli host
        results['hosts'] = db.execute('''
            SELECT ip_address, hostname, status, vendor
            FROM hosts 
            WHERE ip_address LIKE ? OR hostname LIKE ? OR vendor LIKE ?
            LIMIT 10
        ''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()

        # Cerca nei servizi
        results['services'] = db.execute('''
            SELECT DISTINCT s.service_name, s.service_product, COUNT(*) as count
            FROM services s
            WHERE s.service_name LIKE ? OR s.service_product LIKE ?
            GROUP BY s.service_name, s.service_product
            LIMIT 10
        ''', (f'%{query}%', f'%{query}%')).fetchall()

        # Cerca nelle vulnerabilità
        results['vulnerabilities'] = db.execute('''
            SELECT title, cve_id, severity, COUNT(*) as count
            FROM vulnerabilities
            WHERE title LIKE ? OR cve_id LIKE ?
            GROUP BY title, cve_id, severity
            LIMIT 10
        ''', (f'%{query}%', f'%{query}%')).fetchall()

        return render_template('tools/global_search.html', query=query, results=results)

    except Exception as e:
        return render_template('tools/global_search.html', query=query, error=str(e))