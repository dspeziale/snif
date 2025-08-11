from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
from datetime import datetime, timedelta

# Blueprint per Security Analysis
security_bp = Blueprint('security', __name__, url_prefix='/security')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


# ===========================
# SECURITY OVERVIEW (ROUTE MANCANTE)
# ===========================

@security_bp.route('/overview')
@security_bp.route('/')
def overview():
    """Security Overview Dashboard"""
    try:
        db = get_db()

        # Statistiche vulnerabilità per severità
        vuln_stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }

        try:
            # Conta vulnerabilità per severità
            severity_counts = db.execute('''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities 
                WHERE severity IS NOT NULL
                GROUP BY severity
            ''').fetchall()

            for row in severity_counts:
                severity = row['severity'].lower() if row['severity'] else 'unknown'
                if severity in vuln_stats:
                    vuln_stats[severity] = row['count']
                vuln_stats['total'] += row['count']

        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo statistiche vulnerabilità: {e}")

        # Statistiche host affetti
        affected_hosts_count = 0
        try:
            affected_hosts = db.execute('''
                SELECT COUNT(DISTINCT ip_address) as count
                FROM vulnerabilities
            ''').fetchone()

            if affected_hosts:
                affected_hosts_count = affected_hosts['count']

        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo host affetti: {e}")

        # Statistiche scansioni recenti
        recent_scans_count = 0
        try:
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')

            recent_scans = db.execute('''
                SELECT COUNT(*) as count
                FROM scan_results 
                WHERE start_time > ?
            ''', (week_ago,)).fetchone()

            if recent_scans:
                recent_scans_count = recent_scans['count']

        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo scansioni recenti: {e}")

        # Top 5 CVE più comuni
        top_cves = []
        try:
            top_cves = db.execute('''
                SELECT cve_id, COUNT(*) as count, 
                       MAX(severity) as max_severity,
                       COUNT(DISTINCT ip_address) as affected_hosts
                FROM vulnerabilities 
                WHERE cve_id IS NOT NULL AND cve_id != ''
                GROUP BY cve_id 
                ORDER BY count DESC 
                LIMIT 5
            ''').fetchall()
        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo top CVE: {e}")

        # Top 5 host più vulnerabili
        vulnerable_hosts = []
        try:
            vulnerable_hosts = db.execute('''
                SELECT v.ip_address, h.hostname, 
                       COUNT(*) as vuln_count,
                       SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                       SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
                GROUP BY v.ip_address, h.hostname 
                ORDER BY vuln_count DESC 
                LIMIT 5
            ''').fetchall()
        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo host vulnerabili: {e}")

        # Calcola security score (0-100)
        security_score = 100
        if vuln_stats['total'] > 0:
            penalty = (vuln_stats['critical'] * 10 +
                       vuln_stats['high'] * 5 +
                       vuln_stats['medium'] * 2 +
                       vuln_stats['low'] * 1)
            security_score = max(0, 100 - penalty)

        return render_template('security/overview.html',
                               vuln_stats=vuln_stats,
                               affected_hosts=affected_hosts_count,
                               recent_scans=recent_scans_count,
                               security_score=security_score,
                               top_cves=top_cves,
                               vulnerable_hosts=vulnerable_hosts)

    except Exception as e:
        current_app.logger.error(f"Errore in security overview: {e}")
        return render_template('security/overview.html',
                               vuln_stats={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                               affected_hosts=0,
                               recent_scans=0,
                               security_score=100,
                               top_cves=[],
                               vulnerable_hosts=[],
                               error=str(e))


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
            conditions.append('v.cve_id = ?')
            params.append(cve_id)

        if search:
            conditions.append('(v.cve_id LIKE ? OR v.vuln_type LIKE ? OR v.ip_address LIKE ? OR h.hostname LIKE ?)')
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
                END, v.ip_address
        '''

        # Conteggio totale per paginazione
        count_query = query.replace('SELECT v.*, h.hostname, h.vendor', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        vulnerabilities = db.execute(paginated_query, params).fetchall()

        # Statistiche per i filtri correnti
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': total_count
        }

        if conditions:
            stats_query = '''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
                WHERE ''' + ' AND '.join(conditions) + '''
                GROUP BY severity
            '''
        else:
            stats_query = '''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities 
                GROUP BY severity
            '''

        try:
            severity_counts = db.execute(stats_query, params).fetchall()
            for row in severity_counts:
                severity = row['severity'].lower() if row['severity'] else 'unknown'
                if severity in stats:
                    stats[severity] = row['count']
        except Exception as e:
            current_app.logger.error(f"Errore nel calcolo statistiche filtri: {e}")

        # Informazioni paginazione
        total_pages = (total_count + per_page - 1) // per_page
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': lambda: range(max(1, page - 2), min(total_pages + 1, page + 3))
        }

        return render_template('security/vulnerabilities.html',
                               vulnerabilities=vulnerabilities,
                               stats=stats,
                               pagination=pagination)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerabilities: {e}")
        return render_template('security/vulnerabilities.html',
                               vulnerabilities=[],
                               stats={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                               pagination={},
                               error=str(e))


# ===========================
# CVE DETAILS
# ===========================

@security_bp.route('/cve/<cve_id>')
def cve_detail(cve_id):
    """Dettagli specifici di un CVE"""
    try:
        db = get_db()

        # Trova tutte le occorrenze di questo CVE
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
# VULNERABILITY DETAILS
# ===========================

@security_bp.route('/vulnerability/<int:vuln_id>')
def vulnerability_detail(vuln_id):
    """Dettaglio singola vulnerabilità"""
    try:
        db = get_db()

        # Dettagli vulnerabilità
        vulnerability = db.execute('''
            SELECT v.*, h.hostname, h.vendor, h.os_info
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            WHERE v.id = ?
        ''', (vuln_id,)).fetchone()

        if not vulnerability:
            return render_template('errors/404.html'), 404

        return render_template('security/vulnerability_detail.html',
                               vulnerability=vulnerability)

    except Exception as e:
        current_app.logger.error(f"Errore in vulnerability_detail per {vuln_id}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# SCAN RESULTS
# ===========================

@security_bp.route('/scan-results')
def scan_results():
    """Lista risultati scansioni"""
    try:
        db = get_db()

        # Filtri
        scanner = request.args.get('scanner')
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')

        query = 'SELECT * FROM scan_results'
        params = []
        conditions = []

        if scanner:
            conditions.append('scanner = ?')
            params.append(scanner)

        if status:
            conditions.append('status = ?')
            params.append(status)

        if date_from:
            conditions.append('start_time >= ?')
            params.append(date_from)

        if date_to:
            conditions.append('start_time <= ?')
            params.append(date_to + ' 23:59:59')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY start_time DESC'

        scan_results = db.execute(query, params).fetchall()

        # Statistiche
        stats = {
            'total_scans': len(scan_results),
            'successful_scans': len([s for s in scan_results if s['status'] == 'completed']),
            'failed_scans': len([s for s in scan_results if s['status'] == 'failed']),
            'vulnerabilities_found': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
        }

        return render_template('security/scan_results.html',
                               scan_results=scan_results,
                               stats=stats)

    except Exception as e:
        current_app.logger.error(f"Errore in scan_results: {e}")
        return render_template('security/scan_results.html',
                               scan_results=[],
                               stats={'total_scans': 0, 'successful_scans': 0, 'failed_scans': 0,
                                      'vulnerabilities_found': 0},
                               error=str(e))


# ===========================
# SCAN DETAIL
# ===========================

@security_bp.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """Dettagli specifici di una scansione"""
    try:
        db = get_db()

        # Dettagli scansione
        scan = db.execute('SELECT * FROM scan_results WHERE id = ?', (scan_id,)).fetchone()

        if not scan:
            return render_template('errors/404.html'), 404

        # Host scoperti in questa scansione
        discovered_hosts = []
        try:
            discovered_hosts = db.execute('''
                SELECT DISTINCT h.*, 
                       COUNT(p.id) as open_ports_count,
                       COUNT(v.id) as vulnerabilities_count
                FROM hosts h
                LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
                LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
                WHERE h.scan_id = ?
                GROUP BY h.ip_address
                ORDER BY h.ip_address
            ''', (scan_id,)).fetchall()
        except:
            pass

        # Vulnerabilità trovate in questa scansione
        vulnerabilities = []
        try:
            vulnerabilities = db.execute('''
                SELECT v.*, h.hostname 
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
                WHERE v.scan_id = ?
                ORDER BY 
                    CASE v.severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        WHEN 'MEDIUM' THEN 3 
                        WHEN 'LOW' THEN 4 
                        ELSE 5 
                    END
                LIMIT 20
            ''', (scan_id,)).fetchall()
        except:
            pass

        return render_template('security/scan_detail.html',
                               scan=scan,
                               discovered_hosts=discovered_hosts,
                               vulnerabilities=vulnerabilities)

    except Exception as e:
        current_app.logger.error(f"Errore in scan_detail per {scan_id}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# REPORTS
# ===========================

@security_bp.route('/reports')
def reports():
    """Gestione report di sicurezza"""
    try:
        db = get_db()

        # Lista report esistenti (se hai una tabella reports)
        reports_list = []
        try:
            reports_list = db.execute('''
                SELECT * FROM security_reports 
                ORDER BY created_at DESC 
                LIMIT 20
            ''').fetchall()
        except:
            # Se la tabella non esiste, lista vuota
            pass

        return render_template('security/reports.html', reports=reports_list)

    except Exception as e:
        current_app.logger.error(f"Errore in reports: {e}")
        return render_template('security/reports.html', reports=[], error=str(e))


# ===========================
# SECURITY SUMMARY
# ===========================

@security_bp.route('/security-summary')
def security_summary():
    """Riassunto sicurezza completo"""
    try:
        db = get_db()

        # Dati per il summary
        summary = {}

        # Vulnerabilità per severità
        severity_counts = db.execute('''
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities 
            GROUP BY severity
        ''').fetchall()

        summary['critical_vulnerabilities'] = 0
        summary['high_vulnerabilities'] = 0
        summary['medium_vulnerabilities'] = 0
        summary['low_vulnerabilities'] = 0
        summary['total_vulnerabilities'] = 0

        for row in severity_counts:
            severity = row['severity'].lower() if row['severity'] else 'unknown'
            count = row['count']
            summary['total_vulnerabilities'] += count
            if severity == 'critical':
                summary['critical_vulnerabilities'] = count
            elif severity == 'high':
                summary['high_vulnerabilities'] = count
            elif severity == 'medium':
                summary['medium_vulnerabilities'] = count
            elif severity == 'low':
                summary['low_vulnerabilities'] = count

        # Host totali e affetti
        summary['total_hosts'] = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
        summary['affected_hosts'] = db.execute('SELECT COUNT(DISTINCT ip_address) FROM vulnerabilities').fetchone()[0]

        # Security score
        if summary['total_vulnerabilities'] > 0:
            penalty = (summary['critical_vulnerabilities'] * 10 +
                       summary['high_vulnerabilities'] * 5 +
                       summary['medium_vulnerabilities'] * 2 +
                       summary['low_vulnerabilities'] * 1)
            summary['security_score'] = max(0, 100 - penalty)
        else:
            summary['security_score'] = 100

        # Top host vulnerabili
        top_vulnerable_hosts = db.execute('''
            SELECT v.ip_address, h.hostname,
                   COUNT(*) as total_vulnerabilities,
                   SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                   SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                   SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                   SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) as low_count
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.ip_address = h.ip_address
            GROUP BY v.ip_address, h.hostname
            ORDER BY total_vulnerabilities DESC
            LIMIT 10
        ''').fetchall()

        # Calcola risk score per ogni host
        for host in top_vulnerable_hosts:
            risk_score = (host['critical_count'] * 10 +
                          host['high_count'] * 5 +
                          host['medium_count'] * 2 +
                          host['low_count'] * 1)
            host = dict(host)
            host['risk_score'] = min(100, risk_score)

        # Top CVE
        top_cves = db.execute('''
            SELECT cve_id, 
                   COUNT(*) as total_occurrences,
                   COUNT(DISTINCT ip_address) as affected_hosts,
                   MAX(severity) as max_severity,
                   MAX(cvss_score) as max_cvss_score,
                   MIN(first_seen) as first_seen
            FROM vulnerabilities 
            WHERE cve_id IS NOT NULL AND cve_id != ''
            GROUP BY cve_id
            ORDER BY total_occurrences DESC
            LIMIT 10
        ''').fetchall()

        # Dati per i trend (mockup - potresti implementare con dati reali)
        trends_data = {
            'labels': ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            'critical': [5, 8, 3, 7],
            'high': [12, 15, 9, 11]
        }

        return render_template('security/security_summary.html',
                               summary=summary,
                               current_time=datetime.now(),
                               top_vulnerable_hosts=top_vulnerable_hosts,
                               top_cves=top_cves,
                               trends_data=trends_data)

    except Exception as e:
        current_app.logger.error(f"Errore in security_summary: {e}")
        return render_template('security/security_summary.html',
                               summary={'security_score': 0, 'total_vulnerabilities': 0},
                               top_vulnerable_hosts=[],
                               top_cves=[],
                               error=str(e))


# ===========================
# API ENDPOINTS
# ===========================

@security_bp.route('/api/stats')
def api_stats():
    """API endpoint per statistiche security"""
    try:
        db = get_db()

        stats = {
            'vulnerabilities': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'hosts': {
                'total': 0,
                'affected': 0
            }
        }

        # Conta vulnerabilità
        vuln_counts = db.execute('''
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities 
            GROUP BY severity
        ''').fetchall()

        for row in vuln_counts:
            severity = row['severity'].lower() if row['severity'] else 'unknown'
            if severity in stats['vulnerabilities']:
                stats['vulnerabilities'][severity] = row['count']
                stats['vulnerabilities']['total'] += row['count']

        # Conta host
        total_hosts = db.execute('SELECT COUNT(*) as count FROM hosts').fetchone()
        if total_hosts:
            stats['hosts']['total'] = total_hosts['count']

        affected_hosts = db.execute('SELECT COUNT(DISTINCT ip_address) as count FROM vulnerabilities').fetchone()
        if affected_hosts:
            stats['hosts']['affected'] = affected_hosts['count']

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===========================
# VULNERABILITIES OVERVIEW - ROUTE AGGIUNTA
# ===========================

@security_bp.route('/vulnerabilities/overview')
def vulnerabilities_overview():
    """Overview delle vulnerabilità con statistiche dettagliate"""
    try:
        db = get_db()

        # Statistiche per severità
        severity_stats = []
        try:
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
            severity_stats = [dict(stat) for stat in severity_stats]
        except Exception as e:
            current_app.logger.warning(f"Errore nel recupero severity_stats: {e}")
            severity_stats = []

        # Host più vulnerabili
        vulnerable_hosts = []
        try:
            vulnerable_hosts = db.execute('''
                SELECT 
                    h.ip_address,
                    h.hostname,
                    COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high_count,
                    COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) as medium_count,
                    COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) as low_count,
                    COUNT(v.id) as total_vulns
                FROM hosts h
                LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
                WHERE v.id IS NOT NULL
                GROUP BY h.ip_address
                HAVING COUNT(v.id) > 0
                ORDER BY 
                    COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) DESC,
                    COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) DESC,
                    COUNT(v.id) DESC
                LIMIT 10
            ''').fetchall()
            vulnerable_hosts = [dict(host) for host in vulnerable_hosts]
        except Exception as e:
            current_app.logger.warning(f"Errore nel recupero vulnerable_hosts: {e}")
            vulnerable_hosts = []

        # CVE più comuni
        common_cves = []
        try:
            common_cves = db.execute('''
                SELECT 
                    cve_id,
                    severity,
                    COUNT(*) as count,
                    GROUP_CONCAT(DISTINCT vuln_type) as types,
                    MAX(description) as description
                FROM vulnerabilities 
                WHERE cve_id IS NOT NULL AND cve_id != ''
                GROUP BY cve_id, severity
                ORDER BY COUNT(*) DESC, severity ASC
                LIMIT 10
            ''').fetchall()
            common_cves = [dict(cve) for cve in common_cves]
        except Exception as e:
            current_app.logger.warning(f"Errore nel recupero common_cves: {e}")
            common_cves = []

        # Vulnerabilità critiche recenti
        critical_vulns = []
        try:
            critical_vulns = db.execute('''
                SELECT v.*, h.hostname
                FROM vulnerabilities v
                LEFT JOIN hosts h ON v.ip_address = h.ip_address
                WHERE v.severity = 'CRITICAL'
                ORDER BY v.discovery_date DESC
                LIMIT 5
            ''').fetchall()
            critical_vulns = [dict(vuln) for vuln in critical_vulns]
        except Exception as e:
            current_app.logger.warning(f"Errore nel recupero critical_vulns: {e}")
            critical_vulns = []

        return render_template('security/vulnerabilities_overview.html',
                               severity_stats=severity_stats,
                               vulnerable_hosts=vulnerable_hosts,
                               common_cves=common_cves,
                               critical_vulns=critical_vulns)

    except Exception as e:
        current_app.logger.error(f"Errore generale in vulnerabilities_overview: {e}")
        return render_template('security/vulnerabilities_overview.html',
                               severity_stats=[],
                               vulnerable_hosts=[],
                               common_cves=[],
                               critical_vulns=[],
                               error=str(e))