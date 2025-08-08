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
    """Lista delle scansioni con paginazione"""
    # Parametri paginazione
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    search = request.args.get('search', '').strip()

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Costruisci query base
            where_clauses = []
            params = []

            if search:
                where_clauses.append("(filename LIKE ? OR args LIKE ?)")
                search_term = f'%{search}%'
                params.extend([search_term, search_term])

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Count totale
            count_query = f"SELECT COUNT(*) as total FROM scan_runs{where_sql}"
            total_result = db.execute_query(count_query, tuple(params))
            total = total_result[0]['total'] if total_result else 0

            # Query principale con statistiche
            scans_query = f"""
                SELECT s.*,
                       (SELECT COUNT(*) FROM hosts WHERE scan_run_id = s.id) as host_count,
                       (SELECT COUNT(*) FROM hosts WHERE scan_run_id = s.id AND status_state = 'up') as active_hosts,
                       (SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_run_id = s.id) as port_count,
                       (SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_run_id = s.id AND p.state = 'open') as open_ports
                FROM scan_runs s
                {where_sql}
                ORDER BY s.created_at DESC
                LIMIT ? OFFSET ?
            """
            params_with_limit = list(params) + [per_page, offset]
            scans_list = db.execute_query(scans_query, tuple(params_with_limit))

            # Calcola paginazione
            total_pages = (total + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages

            return render_template('network/scans.html',
                                   scans=scans_list,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   total_pages=total_pages,
                                   has_prev=has_prev,
                                   has_next=has_next,
                                   search=search)

    except Exception as e:
        flash(f'Errore nel caricamento scansioni: {str(e)}', 'error')
        # Anche in caso di errore, passa tutte le variabili necessarie
        return render_template('network/scans.html',
                               scans=[],
                               page=1,
                               per_page=per_page,
                               total=0,
                               total_pages=0,
                               has_prev=False,
                               has_next=False,
                               search=search)

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


# ===============================
# AGGIUNGI QUESTE ROUTE AL FILE network.py
# ===============================

@network_bp.route('/host/<int:host_id>/snmp')
def host_snmp_detail(host_id):
    """Dettaglio SNMP completo per un host"""
    try:
        with get_network_db() as db:
            # Informazioni base host
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

            # Dati SNMP - Servizi
            services = db.execute_query("""
                SELECT * FROM snmp_services
                WHERE host_id = ?
                ORDER BY service_name
            """, (host_id,))

            # Dati SNMP - Processi
            processes = db.execute_query("""
                SELECT * FROM snmp_processes
                WHERE host_id = ?
                ORDER BY memory_usage DESC, process_name
            """, (host_id,))

            # Dati SNMP - Software installato
            software = db.execute_query("""
                SELECT * FROM snmp_software
                WHERE host_id = ?
                ORDER BY install_date DESC, software_name
            """, (host_id,))

            # Dati SNMP - Utenti
            users = db.execute_query("""
                SELECT * FROM snmp_users
                WHERE host_id = ?
                ORDER BY username
            """, (host_id,))

            # Dati SNMP - Interfacce di rete
            interfaces = db.execute_query("""
                SELECT * FROM snmp_interfaces
                WHERE host_id = ?
                ORDER BY interface_index, interface_name
            """, (host_id,))

            # Dati SNMP - Connessioni di rete
            connections = db.execute_query("""
                SELECT * FROM snmp_network_connections
                WHERE host_id = ?
                ORDER BY protocol, local_port
            """, (host_id,))

            # Dati SNMP - Condivisioni
            shares = db.execute_query("""
                SELECT * FROM snmp_shares
                WHERE host_id = ?
                ORDER BY share_name
            """, (host_id,))

            # Informazioni di sistema SNMP
            system_info = db.execute_query("""
                SELECT * FROM snmp_system_info
                WHERE host_id = ?
                LIMIT 1
            """, (host_id,))

            system_info = system_info[0] if system_info else None

            return render_template('network/host_snmp_detail.html',
                                   host=host,
                                   services=services,
                                   processes=processes,
                                   software=software,
                                   users=users,
                                   interfaces=interfaces,
                                   connections=connections,
                                   shares=shares,
                                   system_info=system_info)

    except Exception as e:
        flash(f'Errore nel caricamento dettagli SNMP: {str(e)}', 'error')
        return redirect(url_for('network.host_detail', host_id=host_id))


@network_bp.route('/snmp')
@network_bp.route('/snmp/dashboard')
def snmp_dashboard():
    """Dashboard SNMP generale"""
    try:
        with get_network_db() as db:
            # Statistiche SNMP generali
            stats = {}

            # Host con dati SNMP
            stats['snmp_hosts'] = db.execute_query("""
                SELECT COUNT(DISTINCT host_id) as count
                FROM snmp_services
            """)[0]['count']

            # Servizi totali
            stats['total_services'] = db.execute_query("""
                SELECT COUNT(*) as count
                FROM snmp_services
            """)[0]['count']

            # Software installazioni
            stats['software_installs'] = db.execute_query("""
                SELECT COUNT(*) as count
                FROM snmp_software
            """)[0]['count']

            # Utenti di sistema
            stats['system_users'] = db.execute_query("""
                SELECT COUNT(*) as count
                FROM snmp_users
            """)[0]['count']

            # Top servizi più comuni
            top_services = db.execute_query("""
                SELECT service_name, COUNT(*) as host_count
                FROM snmp_services
                GROUP BY service_name
                ORDER BY host_count DESC
                LIMIT 15
            """)

            # Host con più servizi
            busy_hosts = db.execute_query("""
                SELECT h.ip_address, h.id, COUNT(s.id) as service_count
                FROM hosts h
                JOIN snmp_services s ON h.id = s.host_id
                GROUP BY h.id, h.ip_address
                ORDER BY service_count DESC
                LIMIT 10
            """)

            # Software più installato
            popular_software = db.execute_query("""
                SELECT software_name, COUNT(*) as install_count,
                       COUNT(DISTINCT host_id) as host_count
                FROM snmp_software
                WHERE software_name IS NOT NULL
                GROUP BY software_name
                ORDER BY host_count DESC, install_count DESC
                LIMIT 15
            """)

            # Statistiche interfacce di rete
            interface_stats = db.execute_query("""
                SELECT interface_type, COUNT(*) as count,
                       AVG(CASE WHEN speed > 0 THEN speed END) as avg_speed
                FROM snmp_interfaces
                WHERE interface_type IS NOT NULL
                GROUP BY interface_type
                ORDER BY count DESC
            """)

            return render_template('network/snmp_dashboard.html',
                                   stats=stats,
                                   top_services=top_services,
                                   busy_hosts=busy_hosts,
                                   popular_software=popular_software,
                                   interface_stats=interface_stats)

    except Exception as e:
        flash(f'Errore nel caricamento dashboard SNMP: {str(e)}', 'error')
        return render_template('network/snmp_dashboard.html',
                               stats={}, top_services=[], busy_hosts=[],
                               popular_software=[], interface_stats=[])


@network_bp.route('/snmp/services')
def snmp_services():
    """Lista servizi SNMP con filtri"""
    # Parametri di ricerca e paginazione
    page = request.args.get('page', 1, type=int)
    per_page = 50
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '')

    try:
        with get_network_db() as db:
            # Query base
            base_query = """
                SELECT s.*, h.ip_address, h.vendor
                FROM snmp_services s
                JOIN hosts h ON s.host_id = h.id
            """

            conditions = []
            params = []

            if search:
                conditions.append("(s.service_name LIKE ? OR h.ip_address LIKE ?)")
                params.extend([f'%{search}%', f'%{search}%'])

            if status_filter:
                conditions.append("s.status = ?")
                params.append(status_filter)

            if conditions:
                base_query += " WHERE " + " AND ".join(conditions)

            # Count totale
            count_query = base_query.replace(
                "SELECT s.*, h.ip_address, h.vendor",
                "SELECT COUNT(*)"
            )
            total = db.execute_query(count_query, params)[0]['COUNT(*)']

            # Query con paginazione
            offset = (page - 1) * per_page
            services_query = base_query + f" ORDER BY s.service_name LIMIT {per_page} OFFSET {offset}"
            services = db.execute_query(services_query, params)

            # Statistiche per filtri
            status_counts = db.execute_query("""
                SELECT status, COUNT(*) as count
                FROM snmp_services
                GROUP BY status
                ORDER BY count DESC
            """)

            total_pages = (total + per_page - 1) // per_page

            return render_template('network/snmp_services.html',
                                   services=services,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   search=search,
                                   status_filter=status_filter,
                                   status_counts=status_counts)

    except Exception as e:
        flash(f'Errore nel caricamento servizi SNMP: {str(e)}', 'error')
        return render_template('network/snmp_services.html',
                               services=[], page=1, total_pages=0, total=0,
                               search='', status_filter='', status_counts=[])


@network_bp.route('/snmp/software')
def snmp_software():
    """Lista software SNMP installato"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    search = request.args.get('search', '').strip()

    try:
        with get_network_db() as db:
            # Query base
            base_query = """
                SELECT sw.*, h.ip_address
                FROM snmp_software sw
                JOIN hosts h ON sw.host_id = h.id
            """

            params = []

            if search:
                base_query += " WHERE (sw.software_name LIKE ? OR sw.vendor LIKE ? OR h.ip_address LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

            # Count totale
            count_query = base_query.replace(
                "SELECT sw.*, h.ip_address",
                "SELECT COUNT(*)"
            )
            total = db.execute_query(count_query, params)[0]['COUNT(*)']

            # Query con paginazione
            offset = (page - 1) * per_page
            software_query = base_query + f" ORDER BY sw.install_date DESC, sw.software_name LIMIT {per_page} OFFSET {offset}"
            software = db.execute_query(software_query, params)

            total_pages = (total + per_page - 1) // per_page

            return render_template('network/snmp_software.html',
                                   software=software,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   search=search)

    except Exception as e:
        flash(f'Errore nel caricamento software SNMP: {str(e)}', 'error')
        return render_template('network/snmp_software.html',
                               software=[], page=1, total_pages=0, total=0, search='')


@network_bp.route('/api/snmp/host/<int:host_id>/summary')
def api_snmp_summary(host_id):
    """API per riassunto SNMP di un host - per widget nella pagina host_detail"""
    try:
        with get_network_db() as db:
            summary = {}

            # Conta servizi
            services_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_services WHERE host_id = ?
            """, (host_id,))
            summary['services'] = services_count[0]['count'] if services_count else 0

            # Conta processi
            processes_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_processes WHERE host_id = ?
            """, (host_id,))
            summary['processes'] = processes_count[0]['count'] if processes_count else 0

            # Conta software
            software_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_software WHERE host_id = ?
            """, (host_id,))
            summary['software'] = software_count[0]['count'] if software_count else 0

            # Conta utenti
            users_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_users WHERE host_id = ?
            """, (host_id,))
            summary['users'] = users_count[0]['count'] if users_count else 0

            # Conta interfacce
            interfaces_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_interfaces WHERE host_id = ?
            """, (host_id,))
            summary['interfaces'] = interfaces_count[0]['count'] if interfaces_count else 0

            # Conta connessioni
            connections_count = db.execute_query("""
                SELECT COUNT(*) as count FROM snmp_network_connections WHERE host_id = ?
            """, (host_id,))
            summary['connections'] = connections_count[0]['count'] if connections_count else 0

            # Informazioni sistema se disponibili
            system_info = db.execute_query("""
                SELECT * FROM snmp_system_info WHERE host_id = ? LIMIT 1
            """, (host_id,))

            if system_info:
                summary['system'] = system_info[0]

            return jsonify(summary)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===============================
# ROUTE SNMP MANCANTI DA AGGIUNGERE A network.py
# ===============================

@network_bp.route('/snmp/interfaces')
def snmp_interfaces():
    """Lista interfacce di rete SNMP"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    type_filter = request.args.get('type', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            # Query base
            base_query = """
                SELECT i.*, h.ip_address
                FROM snmp_interfaces i
                JOIN hosts h ON i.host_id = h.id
            """

            params = []

            if search:
                base_query += " WHERE (i.interface_name LIKE ? OR h.ip_address LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%'])

                if type_filter:
                    base_query += " AND i.interface_type = ?"
                    params.append(type_filter)
            elif type_filter:
                base_query += " WHERE i.interface_type = ?"
                params.append(type_filter)

            # Count totale
            count_query = base_query.replace(
                "SELECT i.*, h.ip_address",
                "SELECT COUNT(*)"
            )
            total = db.execute_query(count_query, params)[0]['COUNT(*)']

            # Query con paginazione
            offset = (page - 1) * per_page
            interfaces_query = base_query + f" ORDER BY h.ip_address, i.interface_index LIMIT {per_page} OFFSET {offset}"
            interfaces = db.execute_query(interfaces_query, params)

            # Tipi di interfacce per filtro
            interface_types = db.execute_query("""
                SELECT DISTINCT interface_type 
                FROM snmp_interfaces 
                WHERE interface_type IS NOT NULL 
                ORDER BY interface_type
            """)

            total_pages = (total + per_page - 1) // per_page

            return render_template('network/snmp_interfaces.html',
                                   interfaces=interfaces,
                                   interface_types=[t['interface_type'] for t in interface_types],
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   search=search,
                                   type_filter=type_filter)

    except Exception as e:
        flash(f'Errore nel caricamento interfacce SNMP: {str(e)}', 'error')
        return render_template('network/snmp_interfaces.html',
                               interfaces=[], interface_types=[], page=1,
                               total_pages=0, total=0, search='', type_filter='')


@network_bp.route('/snmp/connections')
def snmp_connections():
    """Lista connessioni di rete SNMP"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()
    protocol_filter = request.args.get('protocol', '')

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            base_query = """
                SELECT c.*, h.ip_address
                FROM snmp_network_connections c
                JOIN hosts h ON c.host_id = h.id
            """

            params = []

            if search:
                base_query += " WHERE (c.remote_address LIKE ? OR h.ip_address LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%'])

                if protocol_filter:
                    base_query += " AND c.protocol = ?"
                    params.append(protocol_filter)
            elif protocol_filter:
                base_query += " WHERE c.protocol = ?"
                params.append(protocol_filter)

            # Count totale
            count_query = base_query.replace(
                "SELECT c.*, h.ip_address",
                "SELECT COUNT(*)"
            )
            total = db.execute_query(count_query, params)[0]['COUNT(*)']

            # Query con paginazione
            connections_query = base_query + f" ORDER BY h.ip_address, c.local_port LIMIT {per_page} OFFSET {offset}"
            connections = db.execute_query(connections_query, params)

            # Protocolli per filtro
            protocols = db.execute_query("""
                SELECT DISTINCT protocol 
                FROM snmp_network_connections 
                WHERE protocol IS NOT NULL 
                ORDER BY protocol
            """)

            total_pages = (total + per_page - 1) // per_page

            return render_template('network/snmp_connections.html',
                                   connections=connections,
                                   protocols=[p['protocol'] for p in protocols],
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   search=search,
                                   protocol_filter=protocol_filter)

    except Exception as e:
        flash(f'Errore nel caricamento connessioni SNMP: {str(e)}', 'error')
        return render_template('network/snmp_connections.html',
                               connections=[], protocols=[], page=1,
                               total_pages=0, total=0, search='', protocol_filter='')


@network_bp.route('/snmp/shares')
def snmp_shares():
    """Lista condivisioni SNMP"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    search = request.args.get('search', '').strip()

    offset = (page - 1) * per_page

    try:
        with get_network_db() as db:
            base_query = """
                SELECT s.*, h.ip_address
                FROM snmp_shares s
                JOIN hosts h ON s.host_id = h.id
            """

            params = []

            if search:
                base_query += " WHERE (s.share_name LIKE ? OR s.share_path LIKE ? OR h.ip_address LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

            # Count totale
            count_query = base_query.replace(
                "SELECT s.*, h.ip_address",
                "SELECT COUNT(*)"
            )
            total = db.execute_query(count_query, params)[0]['COUNT(*)']

            # Query con paginazione
            shares_query = base_query + f" ORDER BY h.ip_address, s.share_name LIMIT {per_page} OFFSET {offset}"
            shares = db.execute_query(shares_query, params)

            total_pages = (total + per_page - 1) // per_page

            return render_template('network/snmp_shares.html',
                                   shares=shares,
                                   page=page,
                                   total_pages=total_pages,
                                   total=total,
                                   search=search)

    except Exception as e:
        flash(f'Errore nel caricamento condivisioni SNMP: {str(e)}', 'error')
        return render_template('network/snmp_shares.html',
                               shares=[], page=1, total_pages=0, total=0, search='')


@network_bp.route('/snmp/stats')
def snmp_statistics():
    """Statistiche SNMP dettagliate"""
    try:
        with get_network_db() as db:
            # Statistiche generali
            general_stats = {
                'total_hosts_with_snmp': db.execute_query("""
                    SELECT COUNT(DISTINCT host_id) as count 
                    FROM snmp_interfaces
                """)[0]['count'],

                'total_interfaces': db.execute_query("""
                    SELECT COUNT(*) as count 
                    FROM snmp_interfaces
                """)[0]['count'],

                'total_connections': db.execute_query("""
                    SELECT COUNT(*) as count 
                    FROM snmp_network_connections
                """)[0]['count'],

                'total_shares': db.execute_query("""
                    SELECT COUNT(*) as count 
                    FROM snmp_shares
                """)[0]['count']
            }

            # Statistiche interfacce per tipo
            interface_stats = db.execute_query("""
                SELECT interface_type, COUNT(*) as count,
                       AVG(CASE WHEN speed > 0 THEN speed END) as avg_speed
                FROM snmp_interfaces
                WHERE interface_type IS NOT NULL
                GROUP BY interface_type
                ORDER BY count DESC
            """)

            # Top host per numero di interfacce
            top_hosts = db.execute_query("""
                SELECT h.ip_address, COUNT(i.id) as interface_count
                FROM hosts h
                JOIN snmp_interfaces i ON h.id = i.host_id
                GROUP BY h.id, h.ip_address
                ORDER BY interface_count DESC
                LIMIT 10
            """)

            # Protocolli di connessione più usati
            protocol_stats = db.execute_query("""
                SELECT protocol, COUNT(*) as count
                FROM snmp_network_connections
                WHERE protocol IS NOT NULL
                GROUP BY protocol
                ORDER BY count DESC
            """)

            return render_template('network/snmp_statistics.html',
                                   general_stats=general_stats,
                                   interface_stats=interface_stats,
                                   top_hosts=top_hosts,
                                   protocol_stats=protocol_stats)

    except Exception as e:
        flash(f'Errore nel caricamento statistiche SNMP: {str(e)}', 'error')
        return render_template('network/snmp_statistics.html',
                               general_stats={}, interface_stats=[],
                               top_hosts=[], protocol_stats=[])


@network_bp.route('/snmp/reports')
def snmp_reports():
    """Report SNMP"""
    return render_template('network/snmp_reports.html')
