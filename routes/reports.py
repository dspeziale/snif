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