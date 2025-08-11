from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
from datetime import datetime

# Blueprint per Security Analysis
security_bp = Blueprint('security', __name__, url_prefix='/security')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


# ===========================
# VULNERABILITIES OVERVIEW
# ===========================

@security_bp.route('/vulnerabilities/overview')
def vulnerabilities_overview():
    """Overview delle vulnerabilità con statistiche dettagliate"""
    try:
        db = get_db()

        # Statistiche generali
        total_vulns = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]

        # Statistiche per severità
        severity_stats = db.execute('''
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities 
            GROUP BY severity
            ORDER BY 
                CASE severity 
                    WHEN 'CRITICAL' THEN 1 
                    WHEN 'HIGH' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    WHEN 'LOW' THEN 4 
                    ELSE 5 
                END
        ''').fetchall()

        # Statistiche per tipo
        type_stats = db.execute('''
            SELECT vuln_type, COUNT(*) as count
            FROM vulnerabilities 
            GROUP BY vuln_type 
            ORDER BY count DESC
        ''').fetchall()

        # Host più vulnerabili
        vulnerable_hosts = db.execute('''
            SELECT v.ip_address, h.hostname, 
                   COUNT(*) as total_vulns,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) as low_count
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            GROUP BY v.ip_address, h.hostname 
            ORDER BY total_vulns DESC 
            LIMIT 10
        ''').fetchall()

        # CVE più comuni
        common_cves = db.execute('''
            SELECT cve_id, COUNT(*) as count, severity,
                   GROUP_CONCAT(DISTINCT vuln_type) as types
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL 
            GROUP BY cve_id, severity 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        # Vulnerabilità critiche recenti
        critical_vulns = db.execute('''
            SELECT v.*, h.hostname
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            WHERE v.severity = 'CRITICAL'
            ORDER BY v.vuln_id DESC
            LIMIT 5
        ''').fetchall()

        # Distribuzione per porta
        port_vulns = db.execute('''
            SELECT port_number, protocol, COUNT(*) as count
            FROM vulnerabilities 
            WHERE port_number IS NOT NULL
            GROUP BY port_number, protocol 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        # Calcola percentuali
        severity_percentages = {}
        if total_vulns > 0:
            for stat in severity_stats:
                severity_percentages[stat['severity']] = round((stat['count'] / total_vulns) * 100, 1)

        return render_template('security/vulnerabilities_overview.html',
                               total_vulns=total_vulns,
                               severity_stats=severity_stats,
                               severity_percentages=severity_percentages,
                               type_stats=type_stats,
                               vulnerable_hosts=vulnerable_hosts,
                               common_cves=common_cves,
                               critical_vulns=critical_vulns,
                               port_vulns=port_vulns)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerabilities_overview: {e}")
        return render_template('security/vulnerabilities_overview.html', error=str(e))


# ===========================
# VULNERABILITIES LIST
# ===========================

@security_bp.route('/vulnerabilities')
def vulnerabilities():
    """Lista vulnerabilità con filtri avanzati"""
    try:
        db = get_db()

        # Filtri dalla query string
        severity = request.args.get('severity')
        vuln_type = request.args.get('type')
        host_ip = request.args.get('host')
        cve_id = request.args.get('cve')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Query base
        query = '''
            SELECT v.*, h.hostname, h.vendor
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri
        if severity:
            conditions.append('v.severity = ?')
            params.append(severity.upper())

        if vuln_type:
            if vuln_type == 'web':
                conditions.append('v.vuln_type = "Web Application"')
            elif vuln_type == 'smb':
                conditions.append('v.vuln_type = "SMB"')
            elif vuln_type == 'ssl':
                conditions.append('v.vuln_type = "SSL/TLS"')
            else:
                conditions.append('v.vuln_type LIKE ?')
                params.append(f'%{vuln_type}%')

        if host_ip:
            conditions.append('v.ip_address = ?')
            params.append(host_ip)

        if cve_id:
            conditions.append('v.cve_id LIKE ?')
            params.append(f'%{cve_id}%')

        if search:
            conditions.append('''(
                v.title LIKE ? OR 
                v.description LIKE ? OR 
                v.cve_id LIKE ? OR
                h.hostname LIKE ?
            )''')
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += '''
            ORDER BY 
                CASE v.severity 
                    WHEN 'CRITICAL' THEN 1 
                    WHEN 'HIGH' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    WHEN 'LOW' THEN 4 
                    ELSE 5 
                END, v.ip_address, v.vuln_id
        '''

        # Conteggio totale
        count_query = query.replace('SELECT v.*, h.hostname, h.vendor', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        vulns_data = db.execute(paginated_query, params).fetchall()

        # Informazioni paginazione
        total_pages = (total_count + per_page - 1) // per_page
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }

        # Ottieni hosts disponibili per filtro
        hosts_with_vulns = db.execute('''
            SELECT DISTINCT v.ip_address, h.hostname
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            ORDER BY v.ip_address
        ''').fetchall()

        # Statistiche per i filtri attuali
        if conditions:
            filter_stats_query = count_query
            filter_stats = {
                'total_filtered': db.execute(filter_stats_query, params).fetchone()[0]
            }
        else:
            filter_stats = {'total_filtered': total_count}

        current_filters = {
            'severity': severity,
            'type': vuln_type,
            'host': host_ip,
            'cve': cve_id,
            'search': search
        }

        return render_template('security/vulnerabilities.html',
                               vulnerabilities=vulns_data,
                               pagination=pagination,
                               current_filters=current_filters,
                               hosts_with_vulns=hosts_with_vulns,
                               filter_stats=filter_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerabilities: {e}")
        return render_template('security/vulnerabilities.html',
                               vulnerabilities=[], pagination={}, error=str(e))


@security_bp.route('/vulnerabilities/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """Dettaglio singola vulnerabilità"""
    try:
        db = get_db()

        # Dettagli vulnerabilità
        vuln = db.execute('''
            SELECT v.*, h.hostname, h.vendor, h.status,
                   s.service_name, s.service_product, s.service_version
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            LEFT JOIN services s ON v.ip_address = s.ip_address AND v.port_number = s.port_number
            WHERE v.vuln_id = ?
        ''', (vuln_id,)).fetchone()

        if not vuln:
            return render_template('errors/404.html'), 404

        # Altre vulnerabilità dello stesso host
        related_vulns = db.execute('''
            SELECT * FROM vulnerabilities 
            WHERE ip_address = ? AND vuln_id != ?
            ORDER BY severity, vuln_id
            LIMIT 10
        ''', (vuln['ip_address'], vuln_id)).fetchall()

        # Altre occorrenze della stessa vulnerabilità
        similar_vulns = []
        if vuln['cve_id']:
            similar_vulns = db.execute('''
                SELECT v.*, h.hostname
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
                WHERE v.cve_id = ? AND v.vuln_id != ?
                ORDER BY v.ip_address
            ''', (vuln['cve_id'], vuln_id)).fetchall()

        return render_template('security/vulnerability_detail.html',
                               vulnerability=vuln,
                               related_vulns=related_vulns,
                               similar_vulns=similar_vulns)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerability_detail per {vuln_id}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# CVE DATABASE
# ===========================

@security_bp.route('/cve-database')
def cve_database():
    """Database CVE identificati"""
    try:
        db = get_db()

        search_cve = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = 30

        # Query per CVE con statistiche
        query = '''
            SELECT cve_id, 
                   COUNT(*) as occurrences,
                   COUNT(DISTINCT ip_address) as affected_hosts,
                   GROUP_CONCAT(DISTINCT severity) as severities,
                   GROUP_CONCAT(DISTINCT vuln_type) as types,
                   AVG(cvss_score) as avg_cvss,
                   MAX(cvss_score) as max_cvss
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL AND cve_id != ""
        '''

        params = []
        if search_cve:
            query += ' AND cve_id LIKE ?'
            params.append(f'%{search_cve}%')

        query += '''
            GROUP BY cve_id 
            ORDER BY occurrences DESC, max_cvss DESC
        '''

        # Conteggio totale
        count_query = f'''
            SELECT COUNT(DISTINCT cve_id) 
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL AND cve_id != ""
            {f" AND cve_id LIKE ?" if search_cve else ""}
        '''
        total_count = db.execute(count_query, params[:1] if search_cve else []).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        cves_data = db.execute(paginated_query, params).fetchall()

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page < (total_count + per_page - 1) // per_page
        }

        # Statistiche CVE
        cve_stats = {
            'total_unique_cves': total_count,
            'total_occurrences': db.execute('SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NOT NULL').fetchone()[
                0],
            'hosts_with_cves': db.execute(
                'SELECT COUNT(DISTINCT ip_address) FROM vulnerabilities WHERE cve_id IS NOT NULL').fetchone()[0]
        }

        # Top CVE per numero di host affetti
        top_cves_by_hosts = db.execute('''
            SELECT cve_id, COUNT(DISTINCT ip_address) as affected_hosts,
                   MAX(cvss_score) as max_cvss, GROUP_CONCAT(DISTINCT severity) as severities
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL 
            GROUP BY cve_id 
            ORDER BY affected_hosts DESC 
            LIMIT 10
        ''').fetchall()

        return render_template('security/cve_database.html',
                               cves_data=cves_data,
                               pagination=pagination,
                               current_search=search_cve,
                               cve_stats=cve_stats,
                               top_cves_by_hosts=top_cves_by_hosts)

    except Exception as e:
        current_app.logger.error(f"Errore in cve_database: {e}")
        return render_template('security/cve_database.html',
                               cves_data=[], pagination={}, error=str(e))


@security_bp.route('/cve/<cve_id>')
def cve_detail(cve_id):
    """Dettaglio specifico CVE"""
    try:
        db = get_db()

        # Tutte le occorrenze di questo CVE
        cve_occurrences = db.execute('''
            SELECT v.*, h.hostname, h.vendor
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            WHERE v.cve_id = ?
            ORDER BY v.severity, v.ip_address
        ''', (cve_id,)).fetchall()

        if not cve_occurrences:
            return render_template('errors/404.html'), 404

        # Statistiche per questo CVE
        cve_info = {
            'cve_id': cve_id,
            'total_occurrences': len(cve_occurrences),
            'affected_hosts': len(set(occ['ip_address'] for occ in cve_occurrences)),
            'severities': list(set(occ['severity'] for occ in cve_occurrences if occ['severity'])),
            'vuln_types': list(set(occ['vuln_type'] for occ in cve_occurrences if occ['vuln_type'])),
            'max_cvss': max((occ['cvss_score'] or 0) for occ in cve_occurrences),
            'avg_cvss': sum((occ['cvss_score'] or 0) for occ in cve_occurrences) / len(cve_occurrences)
        }

        # Raggruppa per host
        hosts_affected = {}
        for occ in cve_occurrences:
            host_ip = occ['ip_address']
            if host_ip not in hosts_affected:
                hosts_affected[host_ip] = {
                    'ip_address': host_ip,
                    'hostname': occ['hostname'],
                    'vendor': occ['vendor'],
                    'occurrences': []
                }
            hosts_affected[host_ip]['occurrences'].append(occ)

        return render_template('security/cve_detail.html',
                               cve_info=cve_info,
                               cve_occurrences=cve_occurrences,
                               hosts_affected=hosts_affected)

    except Exception as e:
        current_app.logger.error(f"Errore in cve_detail per {cve_id}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# SECURITY METRICS & REPORTING
# ===========================

@security_bp.route('/security-summary')
def security_summary():
    """Riassunto sicurezza completo"""
    try:
        db = get_db()

        # Risk Score per host (basato su vulnerabilità)
        risk_scores = db.execute('''
            SELECT v.ip_address, h.hostname,
                   SUM(CASE v.severity 
                       WHEN 'CRITICAL' THEN 10 
                       WHEN 'HIGH' THEN 7 
                       WHEN 'MEDIUM' THEN 4 
                       WHEN 'LOW' THEN 1 
                       ELSE 0 
                   END) as risk_score,
                   COUNT(*) as total_vulns,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            GROUP BY v.ip_address, h.hostname
            ORDER BY risk_score DESC
            LIMIT 20
        ''').fetchall()

        # Trend temporale (se ci sono timestamp)
        vuln_timeline = db.execute('''
            SELECT DATE(h.scan_id) as scan_date,
                   COUNT(*) as vulns_found
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            WHERE h.scan_id IS NOT NULL
            GROUP BY scan_date
            ORDER BY scan_date DESC
            LIMIT 30
        ''').fetchall()

        # Distribuzione per servizio
        service_vulns = db.execute('''
            SELECT s.service_name, COUNT(*) as vuln_count,
                   COUNT(DISTINCT v.ip_address) as hosts_affected
            FROM vulnerabilities v
            LEFT JOIN services s ON v.ip_address = s.ip_address AND v.port_number = s.port_number
            WHERE s.service_name IS NOT NULL
            GROUP BY s.service_name
            ORDER BY vuln_count DESC
            LIMIT 15
        ''').fetchall()

        # Compliance metrics (esempio)
        compliance_metrics = {
            'hosts_with_critical': db.execute('''
                SELECT COUNT(DISTINCT ip_address) 
                FROM vulnerabilities WHERE severity = 'CRITICAL'
            ''').fetchone()[0],
            'unpatched_systems': db.execute('''
                SELECT COUNT(DISTINCT ip_address) 
                FROM vulnerabilities WHERE cve_id IS NOT NULL
            ''').fetchone()[0],
            'exposed_services': db.execute('''
                SELECT COUNT(*) 
                FROM services s 
                JOIN ports p ON s.ip_address = p.ip_address AND s.port_number = p.port_number
                WHERE p.state = 'open'
            ''').fetchone()[0]
        }

        return render_template('security/security_summary.html',
                               risk_scores=risk_scores,
                               vuln_timeline=vuln_timeline,
                               service_vulns=service_vulns,
                               compliance_metrics=compliance_metrics)

    except Exception as e:
        current_app.logger.error(f"Errore in security_summary: {e}")
        return render_template('security/security_summary.html', error=str(e))


# ===========================
# API ENDPOINTS
# ===========================

@security_bp.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint per vulnerabilità in formato JSON"""
    try:
        db = get_db()

        # Parametri query
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 100))

        query = '''
            SELECT v.vuln_id, v.ip_address, v.port_number, v.protocol,
                   v.severity, v.title, v.vuln_type, v.cve_id, v.cvss_score,
                   h.hostname
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
        '''

        params = []
        if severity:
            query += ' WHERE v.severity = ?'
            params.append(severity.upper())

        query += ' ORDER BY v.severity, v.ip_address LIMIT ?'
        params.append(limit)

        vulns_data = db.execute(query, params).fetchall()

        # Converti in lista di dizionari
        vulns_list = []
        for vuln in vulns_data:
            vulns_list.append({
                'vuln_id': vuln['vuln_id'],
                'ip_address': vuln['ip_address'],
                'hostname': vuln['hostname'],
                'port': f"{vuln['port_number']}/{vuln['protocol']}" if vuln['port_number'] else None,
                'severity': vuln['severity'],
                'title': vuln['title'],
                'type': vuln['vuln_type'],
                'cve_id': vuln['cve_id'],
                'cvss_score': vuln['cvss_score']
            })

        return jsonify(vulns_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/api/security-stats')
def api_security_stats():
    """API endpoint per statistiche sicurezza"""
    try:
        db = get_db()

        stats = {
            'total_vulnerabilities': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0],
            'hosts_with_vulns': db.execute('SELECT COUNT(DISTINCT ip_address) FROM vulnerabilities').fetchone()[0],
            'critical_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[
                0],
            'high_vulns': db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH'").fetchone()[0],
            'unique_cves':
                db.execute('SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE cve_id IS NOT NULL').fetchone()[0]
        }

        # Distribuzione per severità
        severity_dist = db.execute('''
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities 
            GROUP BY severity
        ''').fetchall()

        stats['severity_distribution'] = {s['severity']: s['count'] for s in severity_dist}

        # Top CVE
        top_cves = db.execute('''
            SELECT cve_id, COUNT(*) as count
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL
            GROUP BY cve_id 
            ORDER BY count DESC 
            LIMIT 5
        ''').fetchall()

        stats['top_cves'] = [{'cve': c['cve_id'], 'count': c['count']} for c in top_cves]

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@security_bp.route('/api/risk-assessment')
def api_risk_assessment():
    """API endpoint per risk assessment"""
    try:
        db = get_db()

        # Calcola risk score per ogni host
        risk_data = db.execute('''
            SELECT v.ip_address, h.hostname,
                   COUNT(*) as total_vulns,
                   SUM(CASE v.severity 
                       WHEN 'CRITICAL' THEN 10 
                       WHEN 'HIGH' THEN 7 
                       WHEN 'MEDIUM' THEN 4 
                       WHEN 'LOW' THEN 1 
                       ELSE 0 
                   END) as risk_score,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            GROUP BY v.ip_address, h.hostname
            ORDER BY risk_score DESC
        ''').fetchall()

        # Categorizza risk levels
        risk_levels = []
        for host in risk_data:
            if host['risk_score'] >= 50:
                risk_level = 'Critical'
            elif host['risk_score'] >= 20:
                risk_level = 'High'
            elif host['risk_score'] >= 10:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'

            risk_levels.append({
                'ip_address': host['ip_address'],
                'hostname': host['hostname'],
                'risk_score': host['risk_score'],
                'risk_level': risk_level,
                'total_vulns': host['total_vulns'],
                'critical_count': host['critical_count'],
                'high_count': host['high_count']
            })

        return jsonify(risk_levels)

    except Exception as e:
        return jsonify({'error': str(e)}), 500