# Correzione completa per network.py - TUTTI gli errori delle colonne

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
    """Dashboard principale della sezione network - VERSIONE ULTRA SEMPLIFICATA"""
    try:
        with get_network_db() as db:
            # Statistiche network specifiche
            stats = {
                'total_networks': 0,
                'active_hosts': 0,
                'open_ports': 0,
                'vulnerabilities': 0
            }

            # Conta host unici per approssimare le reti (fallback semplice)
            try:
                networks = db.execute_query("""
                    SELECT COUNT(DISTINCT 
                        substr(ip_address, 1, 
                            CASE 
                                WHEN instr(ip_address, '.') > 0 THEN
                                    instr(ip_address, '.') + instr(substr(ip_address, instr(ip_address, '.') + 1), '.')
                                ELSE length(ip_address)
                            END
                        )
                    ) as network_count
                    FROM hosts
                    WHERE ip_address IS NOT NULL AND ip_address != ''
                """)
                stats['total_networks'] = networks[0]['network_count'] if networks else 0
            except:
                # Fallback ultrasemplice: conta host totali / 10
                host_count = db.execute_query("SELECT COUNT(*) as count FROM hosts")
                stats['total_networks'] = max(1, (host_count[0]['count'] if host_count else 0) // 10)

            # Host attivi - CORRETTA
            active_hosts = db.execute_query("""
                SELECT COUNT(*) as count FROM hosts WHERE status_state = 'up'
            """)
            stats['active_hosts'] = active_hosts[0]['count'] if active_hosts else 0

            # Porte aperte - CORRETTA
            open_ports = db.execute_query("""
                SELECT COUNT(*) as count FROM ports WHERE state = 'open'
            """)
            stats['open_ports'] = open_ports[0]['count'] if open_ports else 0

            # Vulnerabilità - CORRETTA
            vulns = db.execute_query("""
                SELECT COUNT(*) as count FROM vulnerabilities
            """)
            stats['vulnerabilities'] = vulns[0]['count'] if vulns else 0

            # Top reti (versione semplificata)
            try:
                top_networks = db.execute_query("""
                    SELECT 
                        substr(ip_address, 1, 
                            CASE 
                                WHEN instr(ip_address, '.') > 0 THEN
                                    instr(ip_address, '.') + instr(substr(ip_address, instr(ip_address, '.') + 1), '.')
                                ELSE length(ip_address)
                            END
                        ) as network,
                        COUNT(*) as host_count,
                        SUM(CASE WHEN status_state = 'up' THEN 1 ELSE 0 END) as active_count
                    FROM hosts
                    WHERE ip_address IS NOT NULL AND ip_address != ''
                    GROUP BY network
                    ORDER BY host_count DESC
                    LIMIT 10
                """)
            except:
                # Fallback: mostra solo i primi 10 host
                top_networks = db.execute_query("""
                    SELECT 
                        ip_address as network,
                        1 as host_count,
                        CASE WHEN status_state = 'up' THEN 1 ELSE 0 END as active_count
                    FROM hosts
                    WHERE ip_address IS NOT NULL AND ip_address != ''
                    ORDER BY ip_address
                    LIMIT 10
                """)

            # Servizi più comuni - CORRETTA
            top_services = db.execute_query("""
                SELECT service_name, COUNT(*) as count,
                       SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open_count
                FROM ports
                WHERE service_name IS NOT NULL AND service_name != ''
                GROUP BY service_name
                ORDER BY count DESC
                LIMIT 10
            """)

            # Host con più vulnerabilità - CORRETTA
            vuln_hosts = db.execute_query("""
                SELECT h.ip_address, COUNT(v.id) as vuln_count,
                       COALESCE(MAX(v.cvss_score), 0) as max_cvss
                FROM hosts h
                JOIN vulnerabilities v ON h.id = v.host_id
                GROUP BY h.id, h.ip_address
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
    """Pagina lista host - VERSIONE CORRETTA"""
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
                where_clauses.append("h.status_state = ?")  # CORRETTA: status_state non status
                params.append(status_filter)

            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Conta il totale
            count_query = f"""
                SELECT COUNT(*) as total
                FROM hosts h
                {where_sql}
            """
            total_result = db.execute_query(count_query, tuple(params))
            total = total_result[0]['total'] if total_result else 0

            # Ottieni gli host
            hosts_query = f"""
                SELECT h.*, 
                       (SELECT COUNT(*) FROM ports p WHERE p.host_id = h.id AND p.state = 'open') as open_ports,
                       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.host_id = h.id) as vuln_count
                FROM hosts h
                {where_sql}
                ORDER BY h.ip_address
                LIMIT ? OFFSET ?
            """
            params_with_limit = list(params) + [per_page, offset]
            hosts_list = db.execute_query(hosts_query, tuple(params_with_limit))

            # Calcola la paginazione
            total_pages = (total + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages

            return render_template('network/hosts.html',
                                   hosts=hosts_list,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   has_prev=has_prev,
                                   has_next=has_next,
                                   search=search,
                                   status_filter=status_filter)

    except Exception as e:
        flash(f'Errore nel caricamento host: {str(e)}', 'error')
        return render_template('network/hosts.html',
                               hosts=[], page=1, per_page=per_page, total=0,
                               total_pages=0, has_prev=False, has_next=False,
                               search=search, status_filter=status_filter)


@network_bp.route('/ports')
def ports():
    """Pagina lista porte - VERSIONE CORRETTA"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    state_filter = request.args.get('state', '')
    service_filter = request.args.get('service', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            where_clauses = []
            params = []

            if search:
                where_clauses.append(
                    "(h.ip_address LIKE ? OR p.service_name LIKE ? OR p.service_product LIKE ?)")  # CORRETTA: service_name
                search_term = f'%{search}%'
                params.extend([search_term, search_term, search_term])

            if state_filter:
                where_clauses.append("p.state = ?")
                params.append(state_filter)

            if service_filter:
                where_clauses.append("p.service_name = ?")  # CORRETTA: service_name
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

            # Ottieni le porte - QUERY CORRETTA con nomi colonne giusti
            ports_query = f"""
                SELECT p.*, h.ip_address, h.status_state as host_status
                FROM ports p
                JOIN hosts h ON p.host_id = h.id
                {where_sql}
                ORDER BY h.ip_address, p.port_id
                LIMIT ? OFFSET ?
            """
            params_with_limit = list(params) + [per_page, offset]
            ports_list = db.execute_query(ports_query, tuple(params_with_limit))

            # Ottieni lista servizi per il filtro
            services = db.execute_query("""
                SELECT DISTINCT service_name  
                FROM ports 
                WHERE service_name IS NOT NULL AND service_name != ''
                ORDER BY service_name
            """)

            # Calcola la paginazione
            total_pages = (total + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages

            return render_template('network/ports.html',
                                   ports=ports_list,
                                   services=[s['service_name'] for s in services],
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   has_prev=has_prev,
                                   has_next=has_next,
                                   search=search,
                                   state_filter=state_filter,
                                   service_filter=service_filter)

    except Exception as e:
        flash(f'Errore nel caricamento porte: {str(e)}', 'error')
        return render_template('network/ports.html',
                               ports=[], services=[], page=1, per_page=per_page, total=0,
                               total_pages=0, has_prev=False, has_next=False,
                               search=search, state_filter=state_filter, service_filter=service_filter)


@network_bp.route('/vulnerabilities')
def vulnerabilities():
    """Pagina lista vulnerabilità - VERSIONE CORRETTA"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    severity_filter = request.args.get('severity', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            where_clauses = []
            params = []

            if search:
                where_clauses.append(
                    "(h.ip_address LIKE ? OR v.vuln_id LIKE ? OR v.title LIKE ? OR v.description LIKE ?)")
                search_term = f'%{search}%'
                params.extend([search_term, search_term, search_term, search_term])

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

            # Ottieni le vulnerabilità - CORRETTO: usa discovered_at non created_at
            vulns_query = f"""
                SELECT v.*, h.ip_address
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                {where_sql}
                ORDER BY v.cvss_score DESC, v.discovered_at DESC
                LIMIT ? OFFSET ?
            """
            params_with_limit = list(params) + [per_page, offset]
            vulns_list = db.execute_query(vulns_query, tuple(params_with_limit))

            # Statistiche severità - CORRETTA
            severity_stats = db.execute_query("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE severity IS NOT NULL
                GROUP BY severity
                ORDER BY count DESC
            """)

            # Calcola la paginazione
            total_pages = (total + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages

            return render_template('network/vulnerabilities.html',
                                   vulnerabilities=vulns_list,
                                   severity_stats=severity_stats,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   has_prev=has_prev,
                                   has_next=has_next,
                                   search=search,
                                   severity_filter=severity_filter)

    except Exception as e:
        flash(f'Errore nel caricamento vulnerabilità: {str(e)}', 'error')
        return render_template('network/vulnerabilities.html',
                               vulnerabilities=[], severity_stats=[],
                               page=1, per_page=per_page, total=0, total_pages=0,
                               has_prev=False, has_next=False,
                               search=search, severity_filter=severity_filter)


# Route aggiuntive per completezza
@network_bp.route('/host/<int:host_id>')
def host_detail(host_id):
    """Dettaglio singolo host - ROUTE MANCANTE AGGIUNTA"""
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

            # Porte dell'host - QUERY CORRETTA
            ports = db.execute_query("""
                SELECT * FROM ports
                WHERE host_id = ?
                ORDER BY port_id
            """, (host_id,))

            # Vulnerabilità dell'host
            vulnerabilities = db.execute_query("""
                SELECT * FROM vulnerabilities
                WHERE host_id = ?
                ORDER BY cvss_score DESC
            """, (host_id,))

            # Hostname dell'host
            hostnames = db.execute_query("""
                SELECT * FROM hostnames
                WHERE host_id = ?
            """, (host_id,))

            # Script results per l'host
            scripts = db.execute_query("""
                SELECT s.*, p.port_id, p.protocol
                FROM scripts s
                JOIN ports p ON s.port_id = p.id
                WHERE p.host_id = ?
                ORDER BY p.port_id, s.script_id
            """, (host_id,))

            return render_template('network/host_detail.html',
                                   host=host,
                                   ports=ports,
                                   vulnerabilities=vulnerabilities,
                                   hostnames=hostnames,
                                   scripts=scripts)

    except Exception as e:
        flash(f'Errore nel caricamento dettagli host: {str(e)}', 'error')
        return redirect(url_for('network.hosts'))


@network_bp.route('/scans')
def scans():
    """Lista delle scansioni"""
    try:
        with get_network_db() as db:
            scans_list = db.execute_query("""
                SELECT s.*,
                       (SELECT COUNT(*) FROM hosts WHERE scan_run_id = s.id) as host_count,
                       (SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_run_id = s.id) as port_count
                FROM scan_runs s
                ORDER BY s.created_at DESC
                LIMIT 50
            """)

            return render_template('network/scans.html', scans=scans_list)

    except Exception as e:
        flash(f'Errore nel caricamento scansioni: {str(e)}', 'error')
        return render_template('network/scans.html', scans=[])


@network_bp.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """Dettaglio singola scansione"""
    try:
        with get_network_db() as db:
            # Dettagli scan
            scan = db.execute_query("""
                SELECT * FROM scan_runs WHERE id = ?
            """, (scan_id,))

            if not scan:
                flash('Scansione non trovata', 'error')
                return redirect(url_for('network.scans'))

            scan = scan[0]

            # Host della scansione - QUERY CORRETTA
            hosts = db.execute_query("""
                SELECT h.*, 
                       COUNT(DISTINCT p.id) as port_count,
                       SUM(CASE WHEN p.state = 'open' THEN 1 ELSE 0 END) as open_ports,
                       COUNT(DISTINCT v.id) as vuln_count
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                LEFT JOIN vulnerabilities v ON h.id = v.host_id
                WHERE h.scan_run_id = ?
                GROUP BY h.id, h.ip_address, h.status_state, h.mac_address, h.vendor, h.start_time, h.end_time, h.status_reason, h.status_reason_ttl, h.scan_run_id
                ORDER BY h.ip_address
            """, (scan_id,))

            # Statistiche del scan
            stats = db.execute_query("""
                SELECT 
                    COUNT(DISTINCT h.id) as total_hosts,
                    SUM(CASE WHEN h.status_state = 'up' THEN 1 ELSE 0 END) as active_hosts,
                    COUNT(DISTINCT p.id) as total_ports,
                    SUM(CASE WHEN p.state = 'open' THEN 1 ELSE 0 END) as open_ports,
                    COUNT(DISTINCT v.id) as total_vulns
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                LEFT JOIN vulnerabilities v ON h.id = v.host_id
                WHERE h.scan_run_id = ?
            """, (scan_id,))

            scan_stats = stats[0] if stats else {}

            return render_template('network/scan_detail.html',
                                   scan=scan,
                                   hosts=hosts,
                                   stats=scan_stats)

    except Exception as e:
        flash(f'Errore nel caricamento dettagli scansione: {str(e)}', 'error')
        return redirect(url_for('network.scans'))


@network_bp.route('/search')
def search():
    """Ricerca avanzata"""
    return render_template('network/search.html')


# Route API per ricerche AJAX
@network_bp.route('/api/search')
def api_search():
    """API di ricerca per richieste AJAX"""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')

    if not query:
        return jsonify({'results': [], 'total': 0})

    try:
        with get_network_db() as db:
            results = []

            if search_type in ['all', 'hosts']:
                hosts = db.execute_query("""
                    SELECT 'host' as type, ip_address as title, 
                           status_state as subtitle, id
                    FROM hosts 
                    WHERE ip_address LIKE ? OR vendor LIKE ?
                    LIMIT 10
                """, (f'%{query}%', f'%{query}%'))
                results.extend(hosts)

            if search_type in ['all', 'services']:
                services = db.execute_query("""
                    SELECT 'service' as type, service_name as title,
                           COUNT(*) || ' instances' as subtitle, NULL as id
                    FROM ports 
                    WHERE service_name LIKE ?
                    GROUP BY service_name
                    LIMIT 10
                """, (f'%{query}%',))
                results.extend(services)

            return jsonify({'results': results, 'total': len(results)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500