# ===========================
# routes/reports.py - Complete Reports Blueprint
# ===========================

from flask import Blueprint, render_template, request, jsonify, g, current_app, make_response, redirect, url_for, flash
import sqlite3
from datetime import datetime, timedelta
import json
import csv
import io
import os
from werkzeug.utils import secure_filename

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


@reports_bp.route('/vulnerability')
def vulnerability_report():
    """Detailed vulnerability report"""
    try:
        db = get_db()

        # Get vulnerability data
        vuln_data = {
            'critical_vulns': [],
            'high_vulns': [],
            'medium_vulns': [],
            'low_vulns': [],
            'stats': {
                'total_vulns': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        }

        # Fetch critical vulnerabilities
        critical_vulns = db.execute('''
            SELECT v.*, h.ip_address, h.hostname 
            FROM vulnerabilities v 
            JOIN hosts h ON v.host_ip = h.ip_address 
            WHERE v.severity = 'CRITICAL' 
            ORDER BY v.discovery_date DESC
            LIMIT 10
        ''').fetchall()

        vuln_data['critical_vulns'] = [dict(vuln) for vuln in critical_vulns]

        # Get stats
        stats = db.execute('''
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY severity
        ''').fetchall()

        for stat in stats:
            severity = stat['severity'].lower()
            count = stat['count']
            vuln_data['stats'][f'{severity}_count'] = count
            vuln_data['stats']['total_vulns'] += count

        return render_template('reports/vulnerability.html', data=vuln_data)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerability_report: {e}")
        return render_template('reports/vulnerability.html', error=str(e))


@reports_bp.route('/export')
def export():
    """Pagina per export dati"""
    return render_template('reports/export.html')


@reports_bp.route('/history')
def history():
    """Report history page"""
    try:
        # In a real implementation, you would fetch from a reports table
        # For now, we'll return the template with mock data
        return render_template('reports/history.html')
    except Exception as e:
        current_app.logger.error(f"Errore in history: {e}")
        return render_template('reports/history.html', error=str(e))


@reports_bp.route('/export/csv')
def export_csv():
    """Export dati in formato CSV"""
    table = request.args.get('table', 'hosts')
    format_type = request.args.get('format', 'csv')

    try:
        db = get_db()

        # Query basata sulla tabella richiesta
        if table == 'hosts':
            query = '''
                SELECT h.ip_address, h.hostname, h.status, h.vendor, h.mac_address,
                       COUNT(DISTINCT p.port_number) as open_ports,
                       COUNT(DISTINCT v.vuln_id) as vulnerabilities
                FROM hosts h
                LEFT JOIN ports p ON h.ip_address = p.host_ip AND p.state = 'open'
                LEFT JOIN vulnerabilities v ON h.ip_address = v.host_ip
                GROUP BY h.ip_address
                ORDER BY h.ip_address
            '''
        elif table == 'vulnerabilities':
            query = '''
                SELECT v.vuln_id, v.host_ip, v.port, v.severity, v.description,
                       v.cve, v.discovery_date, h.hostname
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.host_ip = h.ip_address
                ORDER BY v.severity, v.discovery_date DESC
            '''
        elif table == 'ports':
            query = '''
                SELECT p.host_ip, p.port_number, p.protocol, p.state, p.service, p.version,
                       h.hostname
                FROM ports p
                LEFT JOIN hosts h ON p.host_ip = h.ip_address
                WHERE p.state = 'open'
                ORDER BY p.host_ip, p.port_number
            '''
        else:
            # Default to hosts
            query = '''
                SELECT h.ip_address, h.hostname, h.status, h.vendor, h.mac_address
                FROM hosts h
                ORDER BY h.ip_address
            '''

        results = db.execute(query).fetchall()

        if format_type == 'json':
            # Return JSON
            data = [dict(row) for row in results]
            response = make_response(json.dumps(data, indent=2, default=str))
            response.headers['Content-Type'] = 'application/json'
            response.headers[
                'Content-Disposition'] = f'attachment; filename="{table}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        else:
            # Return CSV
            output = io.StringIO()
            if results:
                fieldnames = results[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                for row in results:
                    writer.writerow(dict(row))

            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers[
                'Content-Disposition'] = f'attachment; filename="{table}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

        return response

    except Exception as e:
        current_app.logger.error(f"Errore in export_csv: {e}")
        flash(f'Errore durante l\'export: {str(e)}', 'error')
        return redirect(url_for('reports.export'))


@reports_bp.route('/export/<report_type>')
def export_report(report_type):
    """Export specific report type"""
    format_type = request.args.get('format', 'pdf')

    try:
        db = get_db()

        if report_type == 'executive':
            # Generate executive summary data
            data = {
                'report_date': datetime.now(),
                'total_hosts': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
                'active_hosts': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
                'total_vulnerabilities': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
            }
        elif report_type == 'vulnerability':
            # Generate vulnerability report data
            data = {
                'vulnerabilities': db.execute(
                    'SELECT * FROM vulnerabilities ORDER BY severity, discovery_date DESC').fetchall()
            }
        else:
            data = {}

        # In a real implementation, you would generate the actual file here
        # For now, we'll simulate the download
        if format_type == 'json':
            response = make_response(json.dumps(dict(data), default=str, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers[
                'Content-Disposition'] = f'attachment; filename="{report_type}_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        else:
            # Simulate PDF/other formats
            response = make_response(f"{report_type.title()} Report - Generated on {datetime.now()}")
            response.headers['Content-Type'] = 'text/plain'
            response.headers[
                'Content-Disposition'] = f'attachment; filename="{report_type}_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'

        return response

    except Exception as e:
        current_app.logger.error(f"Errore in export_report: {e}")
        flash(f'Errore durante l\'export del report: {str(e)}', 'error')
        return redirect(url_for('reports.overview'))


@reports_bp.route('/api/stats')
def api_stats():
    """API endpoint for report statistics"""
    try:
        db = get_db()

        stats = {
            'total_reports': 25,  # Mock data - in real app, query reports table
            'reports_today': 3,
            'reports_this_week': 12,
            'reports_this_month': 25,
            'most_popular_format': 'PDF',
            'total_exports': 128,
            'storage_used_mb': 2300,
            'storage_total_mb': 5000
        }

        return jsonify(stats)

    except Exception as e:
        current_app.logger.error(f"Errore in api_stats: {e}")
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/download/<report_id>')
def download_report(report_id):
    """Download a specific report by ID"""
    try:
        # In a real implementation, you would:
        # 1. Validate the report_id
        # 2. Check user permissions
        # 3. Fetch the report file path from database
        # 4. Return the actual file

        # For now, simulate download
        response = make_response(f"Report {report_id} content - Generated on {datetime.now()}")
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename="report_{report_id}.pdf"'

        return response

    except Exception as e:
        current_app.logger.error(f"Errore in download_report: {e}")
        flash(f'Errore nel download del report: {str(e)}', 'error')
        return redirect(url_for('reports.history'))


@reports_bp.route('/preview/<report_id>')
def preview_report(report_id):
    """Preview a report in browser"""
    try:
        # In a real implementation, you would fetch and display the actual report
        return f"<html><body><h1>Report {report_id} Preview</h1><p>Generated on {datetime.now()}</p></body></html>"

    except Exception as e:
        current_app.logger.error(f"Errore in preview_report: {e}")
        return f"<html><body><h1>Error</h1><p>{str(e)}</p></body></html>"


@reports_bp.route('/share/<report_id>')
def share_report(report_id):
    """Generate shareable link for report"""
    try:
        # In a real implementation, you would:
        # 1. Generate a secure token
        # 2. Set expiration
        # 3. Store in database
        # 4. Return the shareable URL

        share_token = f"token_{report_id}_{int(datetime.now().timestamp())}"
        share_url = url_for('reports.shared_report', token=share_token, _external=True)

        return jsonify({
            'success': True,
            'share_url': share_url,
            'expires': (datetime.now() + timedelta(days=7)).isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore in share_report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@reports_bp.route('/shared/<token>')
def shared_report(token):
    """View shared report via token"""
    try:
        # In a real implementation, you would validate the token
        # and return the appropriate report

        return f"<html><body><h1>Shared Report</h1><p>Token: {token}</p><p>This would display the actual shared report content.</p></body></html>"

    except Exception as e:
        current_app.logger.error(f"Errore in shared_report: {e}")
        return f"<html><body><h1>Error</h1><p>Invalid or expired share link</p></body></html>", 404


# Error handlers for the reports blueprint
@reports_bp.errorhandler(404)
def not_found(error):
    return render_template('reports/error.html',
                           error_code=404,
                           error_message="Report not found"), 404


@reports_bp.errorhandler(500)
def internal_error(error):
    return render_template('reports/error.html',
                           error_code=500,
                           error_message="Internal server error"), 500