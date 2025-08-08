from flask import Blueprint, render_template, request, jsonify, flash, current_app, redirect, url_for
import sqlite3
from datetime import datetime, timedelta
from core.nmap_scanner_db import NmapScannerDB

# Crea la blueprint per le pagine network
network_bp = Blueprint('network', __name__, url_prefix='/network')


def get_network_db():
    """Ottiene una connessione al database per la blueprint network"""
    return NmapScannerDB(current_app.config['DATABASE_PATH'])


@network_bp.route('/')
@network_bp.route('/dashboard')
def dashboard():
    """Dashboard principale della sezione network"""
    try:
        with get_network_db() as db:
            # Statistiche network specifiche
            stats = {
                'total_networks': 0,
                'active_hosts': 0,
                'open_ports': 0,
                'vulnerabilities': 0
            }

            # Conta reti uniche (basato sui primi 3 ottetti degli IP)
            networks = db.execute_query("""
                SELECT DISTINCT substr(ip_address, 1, 
                    CASE 
                        WHEN instr(substr(ip_address, instr(ip_address, '.') + 1), '.') > 0 
                        THEN instr(ip_address, '.', instr(ip_address, '.') + 1)
                        ELSE length(ip_address)
                    END
                ) as network
                FROM hosts
                WHERE ip_address IS NOT NULL
            """)
            stats['total_networks'] = len(networks)

            # Host attivi
            active_hosts = db.execute_query("""
                SELECT COUNT(*) as count FROM hosts WHERE status = 'up'
            """)
            stats['active_hosts'] = active_hosts[0]['count'] if active_hosts else 0

            # Porte aperte
            open_ports = db.execute_query("""
                SELECT COUNT(*) as count FROM ports WHERE state = 'open'
            """)
            stats['open_ports'] = open_ports[0]['count'] if open_ports else 0

            # Vulnerabilità
            vulns = db.execute_query("""
                SELECT COUNT(*) as count FROM vulnerabilities
            """)
            stats['vulnerabilities'] = vulns[0]['count'] if vulns else 0

            # Top 10 reti per numero di host
            top_networks = db.execute_query("""
                SELECT substr(ip_address, 1, 
                    CASE 
                        WHEN instr(substr(ip_address, instr(ip_address, '.') + 1), '.') > 0 
                        THEN instr(ip_address, '.', instr(ip_address, '.') + 1) + 1
                        ELSE length(ip_address)
                    END
                ) as network,
                COUNT(*) as host_count,
                SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as active_count
                FROM hosts
                WHERE ip_address IS NOT NULL
                GROUP BY network
                ORDER BY host_count DESC
                LIMIT 10
            """)

            # Servizi più comuni
            top_services = db.execute_query("""
                SELECT service, COUNT(*) as count,
                       SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_count
                FROM ports
                WHERE service IS NOT NULL AND service != ''
                GROUP BY service
                ORDER BY count DESC
                LIMIT 10
            """)

            # Host con più vulnerabilità
            vuln_hosts = db.execute_query("""
                SELECT h.ip_address, COUNT(v.id) as vuln_count,
                       MAX(v.cvss_score) as max_cvss
                FROM hosts h
                JOIN vulnerabilities v ON h.id = v.host_id
                GROUP BY h.id
                ORDER BY vuln_count DESC
                LIMIT 10
            """)

            return render_template('network/dashboard.html',
                                   stats=stats,
                                   top_networks=top_networks,
                                   top_services=top_services,
                                   vuln_hosts=vuln_hosts)

    except Exception as e:
        flash(f'Errore nel caricamento dashboard network: {str(e)}', 'error')
        return render_template('network/dashboard.html',
                               stats={}, top_networks=[], top_services=[], vuln_hosts=[])


@network_bp.route('/hosts')
def hosts():
    """Pagina lista host"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Query base
            where_clauses = []
            params = []

            if search:
                where_clauses.append("(h.ip_address LIKE ? OR h.vendor LIKE ? OR h.mac_address LIKE ?)")
                search_term = f'%{search}%'
                params.extend([search_term, search_term, search_term])

            if status_filter:
                where_clauses.append("h.status = ?")
                params.append(status_filter)

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Conta il totale
            count_query = f"""
                SELECT COUNT(*) as total
                FROM hosts h
                JOIN scan_runs sr ON h.scan_run_id = sr.id
                {where_sql}
            """
            total_result = db.execute_query(count_query, tuple(params))
            total = total_result[0]['total'] if total_result else 0

            # Ottieni gli host
            hosts_query = f"""
                SELECT h.id, h.ip_address, h.status, h.mac_address, h.vendor,
                       sr.filename, sr.start_time,
                       COUNT(p.id) as port_count,
                       SUM(CASE WHEN p.state = 'open' THEN 1 ELSE 0 END) as open_ports,
                       COUNT(v.id) as vuln_count
                FROM hosts h
                JOIN scan_runs sr ON h.scan_run_id = sr.id
                LEFT JOIN ports p ON h.id = p.host_id
                LEFT JOIN vulnerabilities v ON h.id = v.host_id
                {where_sql}
                GROUP BY h.id
                ORDER BY h.ip_address
                LIMIT ? OFFSET ?
            """
            params.extend([per_page, offset])
            hosts = db.execute_query(hosts_query, tuple(params))

            # Paginazione
            total_pages = (total + per_page - 1) // per_page

            return render_template('network/hosts.html',
                                   hosts=hosts,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   search=search,
                                   status_filter=status_filter)

    except Exception as e:
        flash(f'Errore nel caricamento host: {str(e)}', 'error')
        return render_template('network/hosts.html',
                               hosts=[], page=1, per_page=per_page, total=0, total_pages=0)


@network_bp.route('/host/<int:host_id>')
def host_detail(host_id):
    """Dettaglio singolo host"""
    try:
        with get_network_db() as db:
            # Dettagli host
            host = db.execute_query("""
                SELECT h.*, sr.filename, sr.start_time, sr.args
                FROM hosts h
                JOIN scan_runs sr ON h.scan_run_id = sr.id
                WHERE h.id = ?
            """, (host_id,))

            if not host:
                flash('Host non trovato', 'error')
                return redirect(url_for('network.hosts'))

            host = host[0]

            # Porte dell'host
            ports = db.execute_query("""
                SELECT * FROM ports 
                WHERE host_id = ?
                ORDER BY port_number
            """, (host_id,))

            # Hostname dell'host
            hostnames = db.execute_query("""
                SELECT * FROM hostnames 
                WHERE host_id = ?
            """, (host_id,))

            # Vulnerabilità dell'host
            vulnerabilities = db.execute_query("""
                SELECT * FROM vulnerabilities 
                WHERE host_id = ?
                ORDER BY cvss_score DESC
            """, (host_id,))

            # OS Detection
            os_info = db.execute_query("""
                SELECT * FROM os_matches 
                WHERE host_id = ?
                ORDER BY accuracy DESC
            """, (host_id,))

            # Info SNMP se disponibili
            snmp_system = db.execute_query("""
                SELECT * FROM snmp_system_info WHERE host_id = ?
            """, (host_id,))

            snmp_processes = db.execute_query("""
                SELECT * FROM snmp_processes WHERE host_id = ?
                ORDER BY process_name
            """, (host_id,))

            snmp_services = db.execute_query("""
                SELECT * FROM snmp_services WHERE host_id = ?
                ORDER BY service_name
            """, (host_id,))

            return render_template('network/host_detail.html',
                                   host=host,
                                   ports=ports,
                                   hostnames=hostnames,
                                   vulnerabilities=vulnerabilities,
                                   os_info=os_info,
                                   snmp_system=snmp_system[0] if snmp_system else None,
                                   snmp_processes=snmp_processes,
                                   snmp_services=snmp_services)

    except Exception as e:
        flash(f'Errore nel caricamento dettagli host: {str(e)}', 'error')
        return redirect(url_for('network.hosts'))


@network_bp.route('/ports')
def ports():
    """Pagina lista porte"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    search = request.args.get('search', '').strip()
    state_filter = request.args.get('state', '')
    service_filter = request.args.get('service', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Query base
            where_clauses = []
            params = []

            if search:
                where_clauses.append("(p.service LIKE ? OR p.version LIKE ? OR h.ip_address LIKE ?)")
                search_term = f'%{search}%'
                params.extend([search_term, search_term, search_term])

            if state_filter:
                where_clauses.append("p.state = ?")
                params.append(state_filter)

            if service_filter:
                where_clauses.append("p.service = ?")
                params.append(service_filter)

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Conta il totale
            count_query = f"""
                SELECT COUNT(*) as total
                FROM ports p
                JOIN hosts h ON p.host_id = h.id
                {where_sql}
            """
            total_result = db.execute_query(count_query, tuple(params))
            total = total_result[0]['total'] if total_result else 0

            # Ottieni le porte
            ports_query = f"""
                SELECT p.*, h.ip_address
                FROM ports p
                JOIN hosts h ON p.host_id = h.id
                {where_sql}
                ORDER BY h.ip_address, p.port_number
                LIMIT ? OFFSET ?
            """
            params.extend([per_page, offset])
            ports = db.execute_query(ports_query, tuple(params))

            # Lista servizi per filtro
            services = db.execute_query("""
                SELECT DISTINCT service
                FROM ports
                WHERE service IS NOT NULL AND service != ''
                ORDER BY service
            """)

            # Paginazione
            total_pages = (total + per_page - 1) // per_page

            return render_template('network/ports.html',
                                   ports=ports,
                                   services=services,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   search=search,
                                   state_filter=state_filter,
                                   service_filter=service_filter)

    except Exception as e:
        flash(f'Errore nel caricamento porte: {str(e)}', 'error')
        return render_template('network/ports.html',
                               ports=[], services=[], page=1, per_page=per_page,
                               total=0, total_pages=0)


@network_bp.route('/vulnerabilities')
def vulnerabilities():
    """Pagina vulnerabilità"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    severity_filter = request.args.get('severity', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Query base
            where_clauses = []
            params = []

            if search:
                where_clauses.append("(v.type LIKE ? OR h.ip_address LIKE ?)")
                search_term = f'%{search}%'
                params.extend([search_term, search_term])

            if severity_filter:
                where_clauses.append("v.severity = ?")
                params.append(severity_filter)

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Conta il totale
            count_query = f"""
                SELECT COUNT(*) as total
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                {where_sql}
            """
            total_result = db.execute_query(count_query, tuple(params))
            total = total_result[0]['total'] if total_result else 0

            # Ottieni le vulnerabilità
            vulns_query = f"""
                SELECT v.*, h.ip_address
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                {where_sql}
                ORDER BY v.cvss_score DESC, v.created_at DESC
                LIMIT ? OFFSET ?
            """
            params.extend([per_page, offset])
            vulnerabilities = db.execute_query(vulns_query, tuple(params))

            # Statistiche severità
            severity_stats = db.execute_query("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE severity IS NOT NULL
                GROUP BY severity
                ORDER BY count DESC
            """)

            # Paginazione
            total_pages = (total + per_page - 1) // per_page

            return render_template('network/vulnerabilities.html',
                                   vulnerabilities=vulnerabilities,
                                   severity_stats=severity_stats,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   search=search,
                                   severity_filter=severity_filter)

    except Exception as e:
        flash(f'Errore nel caricamento vulnerabilità: {str(e)}', 'error')
        return render_template('network/vulnerabilities.html',
                               vulnerabilities=[], severity_stats=[],
                               page=1, per_page=per_page, total=0, total_pages=0)


@network_bp.route('/search')
def search():
    """Pagina di ricerca avanzata"""
    if request.method == 'GET' and not request.args.get('q'):
        # Mostra form di ricerca vuoto
        return render_template('network/search.html', results=[], query='')

    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')

        if not query:
            return render_template('network/search.html', results=[], query='')

        with get_network_db() as db:
            results = []

            if search_type in ['all', 'hosts']:
                # Ricerca host
                host_results = db.execute_query("""
                    SELECT 'host' as result_type, h.id, h.ip_address as title,
                           h.status as description, sr.filename as context,
                           '/network/host/' || h.id as url
                    FROM hosts h
                    JOIN scan_runs sr ON h.scan_run_id = sr.id
                    WHERE h.ip_address LIKE ? OR h.vendor LIKE ? OR h.mac_address LIKE ?
                    ORDER BY h.ip_address
                    LIMIT 50
                """, (f'%{query}%', f'%{query}%', f'%{query}%'))
                results.extend(host_results)

            if search_type in ['all', 'ports']:
                # Ricerca porte/servizi
                port_results = db.execute_query("""
                    SELECT 'port' as result_type, p.id, 
                           (h.ip_address || ':' || p.port_number) as title,
                           (p.service || ' (' || p.state || ')') as description,
                           p.version as context,
                           '/network/host/' || h.id as url
                    FROM ports p
                    JOIN hosts h ON p.host_id = h.id
                    WHERE p.service LIKE ? OR p.version LIKE ? OR p.port_number = ?
                    ORDER BY h.ip_address, p.port_number
                    LIMIT 50
                """, (f'%{query}%', f'%{query}%', query if query.isdigit() else '0'))
                results.extend(port_results)

            if search_type in ['all', 'vulnerabilities']:
                # Ricerca vulnerabilità
                vuln_results = db.execute_query("""
                    SELECT 'vulnerability' as result_type, v.id,
                           v.type as title,
                           ('CVSS: ' || v.cvss_score || ' - ' || v.severity) as description,
                           h.ip_address as context,
                           '/network/host/' || h.id as url
                    FROM vulnerabilities v
                    JOIN hosts h ON v.host_id = h.id
                    WHERE v.type LIKE ? OR v.severity LIKE ?
                    ORDER BY v.cvss_score DESC
                    LIMIT 50
                """, (f'%{query}%', f'%{query}%'))
                results.extend(vuln_results)

            return render_template('network/search.html',
                                   results=results,
                                   query=query,
                                   search_type=search_type,
                                   total=len(results))

    except Exception as e:
        flash(f'Errore nella ricerca: {str(e)}', 'error')
        return render_template('network/search.html', results=[], query=query)


@network_bp.route('/scans')
def scans():
    """Pagina lista scan"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Conta il totale
            total_result = db.execute_query("SELECT COUNT(*) as total FROM scan_runs")
            total = total_result[0]['total'] if total_result else 0

            # Ottieni gli scan
            scans = db.execute_query("""
                SELECT sr.*, 
                       COUNT(h.id) as host_count,
                       SUM(CASE WHEN h.status = 'up' THEN 1 ELSE 0 END) as active_hosts
                FROM scan_runs sr
                LEFT JOIN hosts h ON sr.id = h.scan_run_id
                GROUP BY sr.id
                ORDER BY sr.created_at DESC
                LIMIT ? OFFSET ?
            """, (per_page, offset))

            # Paginazione
            total_pages = (total + per_page - 1) // per_page

            return render_template('network/scans.html',
                                   scans=scans,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages)

    except Exception as e:
        flash(f'Errore nel caricamento scan: {str(e)}', 'error')
        return render_template('network/scans.html',
                               scans=[], page=1, per_page=per_page, total=0, total_pages=0)


@network_bp.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """Dettaglio singolo scan"""
    try:
        with get_network_db() as db:
            # Dettagli scan
            scan = db.execute_query("""
                SELECT * FROM scan_runs WHERE id = ?
            """, (scan_id,))

            if not scan:
                flash('Scan non trovato', 'error')
                return redirect(url_for('network.scans'))

            scan = scan[0]

            # Host del scan
            hosts = db.execute_query("""
                SELECT h.*, 
                       COUNT(p.id) as port_count,
                       SUM(CASE WHEN p.state = 'open' THEN 1 ELSE 0 END) as open_ports
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_run_id = ?
                GROUP BY h.id
                ORDER BY h.ip_address
            """, (scan_id,))

            # Statistiche del scan
            stats = db.execute_query("""
                SELECT 
                    COUNT(DISTINCT h.id) as total_hosts,
                    SUM(CASE WHEN h.status = 'up' THEN 1 ELSE 0 END) as active_hosts,
                    COUNT(DISTINCT p.id) as total_ports,
                    SUM(CASE WHEN p.state = 'open' THEN 1 ELSE 0 END) as open_ports
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_run_id = ?
            """, (scan_id,))

            scan_stats = stats[0] if stats else {}

            return render_template('network/scan_detail.html',
                                   scan=scan,
                                   hosts=hosts,
                                   stats=scan_stats)

    except Exception as e:
        flash(f'Errore nel caricamento dettagli scan: {str(e)}', 'error')
        return redirect(url_for('network.scans'))