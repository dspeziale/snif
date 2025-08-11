from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
from datetime import datetime

# Blueprint per Network Analysis
network_bp = Blueprint('network', __name__, url_prefix='/network')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


# ===========================
# NETWORK OVERVIEW
# ===========================

@network_bp.route('/overview')
def overview():
    """Network Overview Dashboard"""
    try:
        db = get_db()

        # Statistiche generali
        stats = {
            'total_hosts': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'active_hosts': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
            'inactive_hosts': db.execute("SELECT COUNT(*) FROM hosts WHERE status != 'up'").fetchone()[0],
            'total_ports': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
            'open_ports': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0],
            'filtered_ports': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'filtered'").fetchone()[0],
            'total_services': db.execute('SELECT COUNT(*) FROM services').fetchone()[0],
            'with_hostname':
                db.execute("SELECT COUNT(*) FROM hosts WHERE hostname IS NOT NULL AND hostname != ''").fetchone()[0]
        }

        # Distribuzione per subnet (estrai prime due ottette)
        subnet_distribution = db.execute('''
            SELECT 
                SUBSTR(ip_address, 1, INSTR(SUBSTR(ip_address, INSTR(ip_address, '.') + 1), '.') + INSTR(ip_address, '.')) as subnet,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as active_count
            FROM hosts 
            GROUP BY subnet 
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        # Top servizi
        top_services = db.execute('''
            SELECT service_name, COUNT(*) as count
            FROM services s
            JOIN ports p ON s.ip_address = p.ip_address AND s.port_number = p.port_number
            WHERE p.state = 'open' AND s.service_name IS NOT NULL AND s.service_name != ''
            GROUP BY service_name
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        # Host recenti (dalle scan_info)
        recent_activity = db.execute('''
            SELECT h.ip_address, h.hostname, h.status, h.vendor
            FROM hosts h
            ORDER BY ROWID DESC
            LIMIT 10
        ''').fetchall()

        return render_template('network/overview.html',
                               stats=stats,
                               subnet_distribution=subnet_distribution,
                               top_services=top_services,
                               recent_activity=recent_activity)

    except Exception as e:
        current_app.logger.error(f"Errore in network overview: {e}")
        return render_template('network/overview.html',
                               stats={}, error=str(e))


# ===========================
# SCAN INFORMATION
# ===========================

@network_bp.route('/scan-info')
def scan_info():
    """Informazioni sulle scansioni"""
    try:
        db = get_db()

        # Lista delle scansioni
        scans = db.execute('''
            SELECT * FROM scan_info 
            ORDER BY start_time DESC
        ''').fetchall()

        # Statistiche aggregate
        scan_stats = {
            'total_scans': len(scans),
            'total_hosts_scanned': sum(scan['total_hosts'] or 0 for scan in scans),
            'total_hosts_up': sum(scan['up_hosts'] or 0 for scan in scans),
        }

        if scans:
            # Calcola tempo totale scansioni
            total_elapsed = sum(scan['elapsed_time'] or 0 for scan in scans)
            scan_stats['total_elapsed_hours'] = round(total_elapsed / 3600, 2)

            # Ultima scansione
            last_scan = scans[0]
            scan_stats['last_scan_date'] = last_scan['start_time']
            scan_stats['last_scan_hosts'] = last_scan['total_hosts'] or 0

        return render_template('network/scan_info.html',
                               scans=scans,
                               scan_stats=scan_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in scan_info: {e}")
        return render_template('network/scan_info.html',
                               scans=[], scan_stats={}, error=str(e))


# ===========================
# HOSTS MANAGEMENT
# ===========================

@network_bp.route('/hosts')
def hosts():
    """Lista host con filtri avanzati"""
    try:
        db = get_db()

        # Gestisci filtri dalla query string
        status = request.args.get('status')
        has_hostname = request.args.get('has_hostname')
        vendor = request.args.get('vendor')
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Costruisci query base
        query = '''
            SELECT h.*, 
                   COUNT(DISTINCT p.port_number) as open_ports_count,
                   COUNT(DISTINCT v.vuln_id) as vulnerabilities_count,
                   dc.device_type, dc.confidence_score
            FROM hosts h
            LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
            LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
            LEFT JOIN device_classification dc ON h.ip_address = dc.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri
        if status:
            conditions.append('h.status = ?')
            params.append(status)

        if has_hostname == 'true':
            conditions.append('h.hostname IS NOT NULL AND h.hostname != ""')
        elif has_hostname == 'false':
            conditions.append('(h.hostname IS NULL OR h.hostname = "")')

        if vendor:
            conditions.append('h.vendor LIKE ?')
            params.append(f'%{vendor}%')

        if search:
            conditions.append('''(
                h.ip_address LIKE ? OR 
                h.hostname LIKE ? OR 
                h.vendor LIKE ? OR
                h.mac_address LIKE ?
            )''')
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += '''
            GROUP BY h.ip_address, h.mac_address, h.vendor, h.status, h.status_reason, 
                     h.hostname, h.fqdn, h.scan_id, dc.device_type, dc.confidence_score
            ORDER BY h.ip_address
        '''

        # Esegui query per ottenere tutti i risultati (per conteggio)
        all_hosts = db.execute(query, params).fetchall()
        total_count = len(all_hosts)

        # Calcola offset per paginazione
        offset = (page - 1) * per_page

        # Aggiungi LIMIT e OFFSET
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        hosts_data = db.execute(paginated_query, params).fetchall()

        # Calcola informazioni paginazione
        total_pages = (total_count + per_page - 1) // per_page
        has_prev = page > 1
        has_next = page < total_pages

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': has_prev,
            'has_next': has_next,
            'prev_num': page - 1 if has_prev else None,
            'next_num': page + 1 if has_next else None
        }

        # Ottieni vendors per filtro dropdown
        vendors = db.execute('''
            SELECT DISTINCT vendor 
            FROM hosts 
            WHERE vendor IS NOT NULL AND vendor != ""
            ORDER BY vendor
        ''').fetchall()

        # Statistiche per i filtri attuali
        filter_stats = {
            'total_filtered': total_count,
            'active_filtered': sum(1 for h in all_hosts if h['status'] == 'up'),
            'with_vulnerabilities': sum(1 for h in all_hosts if h['vulnerabilities_count'] > 0)
        }

        current_filters = {
            'status': status,
            'has_hostname': has_hostname,
            'vendor': vendor,
            'search': search
        }

        return render_template('network/hosts.html',
                               hosts=hosts_data,
                               pagination=pagination,
                               current_filters=current_filters,
                               vendors=vendors,
                               filter_stats=filter_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in hosts: {e}")
        return render_template('network/hosts.html',
                               hosts=[], pagination={}, error=str(e))


@network_bp.route('/hosts/<ip_address>')
def host_detail(ip_address):
    """Dettaglio singolo host"""
    try:
        db = get_db()

        # Informazioni host base
        host = db.execute('''
            SELECT h.*, dc.device_type, dc.device_subtype, dc.confidence_score,
                   dc.vendor_oui, dc.classification_reasons
            FROM hosts h
            LEFT JOIN device_classification dc ON h.ip_address = dc.ip_address
            WHERE h.ip_address = ?
        ''', (ip_address,)).fetchone()

        if not host:
            return render_template('errors/404.html'), 404

        # OS Information
        os_info = db.execute('''
            SELECT * FROM os_info WHERE ip_address = ?
        ''', (ip_address,)).fetchone()

        # Porte e servizi
        ports = db.execute('''
            SELECT p.*, s.service_name, s.service_product, s.service_version, s.service_info
            FROM ports p
            LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
            WHERE p.ip_address = ?
            ORDER BY p.port_number
        ''', (ip_address,)).fetchall()

        # Vulnerabilità
        vulnerabilities = db.execute('''
            SELECT * FROM vulnerabilities 
            WHERE ip_address = ?
            ORDER BY 
                CASE severity 
                    WHEN 'CRITICAL' THEN 1 
                    WHEN 'HIGH' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    WHEN 'LOW' THEN 4 
                    ELSE 5 
                END, vuln_id
        ''', (ip_address,)).fetchall()

        # Software installato
        software = db.execute('''
            SELECT * FROM installed_software 
            WHERE ip_address = ?
            ORDER BY software_name
            LIMIT 20
        ''', (ip_address,)).fetchall()

        # Processi in esecuzione
        processes = db.execute('''
            SELECT * FROM running_processes 
            WHERE ip_address = ?
            ORDER BY pid
            LIMIT 20
        ''', (ip_address,)).fetchall()

        # Hostname discovery
        hostnames = db.execute('''
            SELECT * FROM hostnames 
            WHERE ip_address = ?
            ORDER BY hostname_id
        ''', (ip_address,)).fetchall()

        # Script NSE
        nse_scripts = db.execute('''
            SELECT * FROM nse_scripts 
            WHERE ip_address = ?
            ORDER BY script_name
            LIMIT 10
        ''', (ip_address,)).fetchall()

        # Traceroute
        traceroute = db.execute('''
            SELECT * FROM traceroute 
            WHERE ip_address = ?
            ORDER BY hop_number
        ''', (ip_address,)).fetchall()

        # Statistiche
        stats = {
            'total_ports': len(ports),
            'open_ports': sum(1 for p in ports if p['state'] == 'open'),
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulns': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high_vulns': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'total_software': len(software),
            'total_processes': len(processes)
        }

        return render_template('network/host_detail.html',
                               host=host,
                               os_info=os_info,
                               ports=ports,
                               vulnerabilities=vulnerabilities,
                               software=software,
                               processes=processes,
                               hostnames=hostnames,
                               nse_scripts=nse_scripts,
                               traceroute=traceroute,
                               stats=stats)

    except Exception as e:
        current_app.logger.error(f"Errore in host_detail per {ip_address}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# PORTS & SERVICES
# ===========================

@network_bp.route('/ports')
def ports():
    """Lista porte con filtri"""
    try:
        db = get_db()

        # Filtri
        state = request.args.get('state')
        service = request.args.get('service')
        port_range = request.args.get('port_range')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))

        # Query base
        query = '''
            SELECT p.*, h.hostname, s.service_name, s.service_product, s.service_version
            FROM ports p 
            LEFT JOIN hosts h ON p.ip_address = h.ip_address
            LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
        '''

        params = []
        conditions = []

        if state:
            conditions.append('p.state = ?')
            params.append(state)

        if service:
            conditions.append('s.service_name LIKE ?')
            params.append(f'%{service}%')

        if port_range:
            if port_range == 'well-known':
                conditions.append('p.port_number <= 1023')
            elif port_range == 'registered':
                conditions.append('p.port_number BETWEEN 1024 AND 49151')
            elif port_range == 'dynamic':
                conditions.append('p.port_number >= 49152')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY p.ip_address, p.port_number'

        # Conteggio totale
        count_query = query.replace('SELECT p.*, h.hostname, s.service_name, s.service_product, s.service_version',
                                    'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        ports_data = db.execute(paginated_query, params).fetchall()

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

        # Statistiche
        port_stats = db.execute('''
            SELECT state, COUNT(*) as count
            FROM ports
            GROUP BY state
        ''').fetchall()

        return render_template('network/ports.html',
                               ports=ports_data,
                               pagination=pagination,
                               current_filters={'state': state, 'service': service, 'port_range': port_range},
                               port_stats=port_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in ports: {e}")
        return render_template('network/ports.html',
                               ports=[], pagination={}, error=str(e))


@network_bp.route('/services')
def services():
    """Lista servizi rilevati"""
    try:
        db = get_db()

        service_filter = request.args.get('service')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))

        query = '''
            SELECT s.*, h.hostname, p.state as port_state, p.reason
            FROM services s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address  
            LEFT JOIN ports p ON s.ip_address = p.ip_address AND s.port_number = p.port_number
        '''

        params = []
        if service_filter:
            query += ' WHERE s.service_name LIKE ?'
            params.append(f'%{service_filter}%')

        query += ' ORDER BY s.service_name, s.ip_address, s.port_number'

        # Conteggio e paginazione
        count_query = query.replace('SELECT s.*, h.hostname, p.state as port_state, p.reason', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        services_data = db.execute(paginated_query, params).fetchall()

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page < (total_count + per_page - 1) // per_page
        }

        # Top servizi
        top_services = db.execute('''
            SELECT service_name, COUNT(*) as count,
                   COUNT(DISTINCT ip_address) as unique_hosts
            FROM services 
            WHERE service_name IS NOT NULL AND service_name != ""
            GROUP BY service_name 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        return render_template('network/services.html',
                               services=services_data,
                               pagination=pagination,
                               current_filter=service_filter,
                               top_services=top_services)

    except Exception as e:
        current_app.logger.error(f"Errore in services: {e}")
        return render_template('network/services.html',
                               services=[], pagination={}, error=str(e))


# ===========================
# ROUTE AGGIUNTIVE
# ===========================

@network_bp.route('/topology')
def topology():
    """Visualizzazione topologia di rete"""
    try:
        db = get_db()

        # Ottieni dati per la visualizzazione
        hosts_data = db.execute('''
            SELECT h.ip_address, h.hostname, h.status, h.vendor,
                   COUNT(DISTINCT p.port_number) as open_ports,
                   dc.device_type
            FROM hosts h
            LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
            LEFT JOIN device_classification dc ON h.ip_address = dc.ip_address
            WHERE h.status = 'up'
            GROUP BY h.ip_address
            ORDER BY h.ip_address
        ''').fetchall()

        # Raggruppa per subnet
        subnets = {}
        for host in hosts_data:
            # Estrai subnet (primi 3 ottetti)
            ip_parts = host['ip_address'].split('.')
            subnet = '.'.join(ip_parts[:3]) + '.0/24'

            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(host)

        return render_template('network/topology.html',
                               hosts_data=hosts_data,
                               subnets=subnets)

    except Exception as e:
        current_app.logger.error(f"Errore in topology: {e}")
        return render_template('network/topology.html',
                               hosts_data=[], subnets={}, error=str(e))


@network_bp.route('/traceroute')
def traceroute():
    """Dati traceroute"""
    try:
        db = get_db()

        # Ottieni tutti i traceroute
        traceroute_data = db.execute('''
            SELECT t.*, h.hostname
            FROM traceroute t
            LEFT JOIN hosts h ON t.ip_address = h.ip_address
            ORDER BY t.ip_address, t.hop_number
        ''').fetchall()

        # Raggruppa per IP di destinazione
        traces = {}
        for trace in traceroute_data:
            dest_ip = trace['ip_address']
            if dest_ip not in traces:
                traces[dest_ip] = {
                    'destination': dest_ip,
                    'hostname': trace['hostname'],
                    'hops': []
                }

            traces[dest_ip]['hops'].append({
                'hop_number': trace['hop_number'],
                'hop_ip': trace['hop_ip'],
                'hop_hostname': trace['hop_hostname'],
                'rtt': trace['rtt']
            })

        return render_template('network/traceroute.html',
                               traces=traces)

    except Exception as e:
        current_app.logger.error(f"Errore in traceroute: {e}")
        return render_template('network/traceroute.html',
                               traces={}, error=str(e))


@network_bp.route('/os-info')
def os_info():
    """Informazioni sistemi operativi"""
    try:
        db = get_db()

        # OS info con statistiche
        os_data = db.execute('''
            SELECT o.*, h.hostname
            FROM os_info o
            LEFT JOIN hosts h ON o.ip_address = h.ip_address
            ORDER BY o.os_family, o.os_name
        ''').fetchall()

        # Statistiche per famiglia OS
        os_families = db.execute('''
            SELECT os_family, COUNT(*) as count,
                   AVG(accuracy) as avg_accuracy
            FROM os_info 
            WHERE os_family IS NOT NULL AND os_family != ""
            GROUP BY os_family 
            ORDER BY count DESC
        ''').fetchall()

        # OS più comuni
        os_types = db.execute('''
            SELECT os_name, COUNT(*) as count
            FROM os_info 
            WHERE os_name IS NOT NULL AND os_name != ""
            GROUP BY os_name 
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        return render_template('network/os_info.html',
                               os_data=os_data,
                               os_families=os_families,
                               os_types=os_types)

    except Exception as e:
        current_app.logger.error(f"Errore in os_info: {e}")
        return render_template('network/os_info.html',
                               os_data=[], os_families=[], os_types=[], error=str(e))


@network_bp.route('/hostnames')
def hostnames():
    """Hostname discovery"""
    try:
        db = get_db()

        # Tutti gli hostname scoperti
        hostnames_data = db.execute('''
            SELECT hn.*, h.status, h.vendor
            FROM hostnames hn
            LEFT JOIN hosts h ON hn.ip_address = h.ip_address
            ORDER BY hn.ip_address, hn.hostname_type
        ''').fetchall()

        # Statistiche hostname
        hostname_stats = db.execute('''
            SELECT hostname_type, COUNT(*) as count
            FROM hostnames 
            GROUP BY hostname_type 
            ORDER BY count DESC
        ''').fetchall()

        return render_template('network/hostnames.html',
                               hostnames_data=hostnames_data,
                               hostname_stats=hostname_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in hostnames: {e}")
        return render_template('network/hostnames.html',
                               hostnames_data=[], hostname_stats=[], error=str(e))


@network_bp.route('/nse-scripts')
def nse_scripts():
    """Risultati script NSE"""
    try:
        db = get_db()

        script_name = request.args.get('script')
        page = int(request.args.get('page', 1))
        per_page = 50

        query = '''
            SELECT n.*, h.hostname
            FROM nse_scripts n
            LEFT JOIN hosts h ON n.ip_address = h.ip_address
        '''

        params = []
        if script_name:
            query += ' WHERE n.script_name LIKE ?'
            params.append(f'%{script_name}%')

        query += ' ORDER BY n.script_name, n.ip_address'

        # Conteggio e paginazione
        count_query = query.replace('SELECT n.*, h.hostname', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        scripts_data = db.execute(paginated_query, params).fetchall()

        pagination = {
            'page': page,
            'total': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page < (total_count + per_page - 1) // per_page
        }

        # Script più comuni
        top_scripts = db.execute('''
            SELECT script_name, COUNT(*) as count,
                   COUNT(DISTINCT ip_address) as unique_hosts
            FROM nse_scripts 
            GROUP BY script_name 
            ORDER BY count DESC 
            LIMIT 15
        ''').fetchall()

        return render_template('network/nse_scripts.html',
                               scripts_data=scripts_data,
                               pagination=pagination,
                               current_filter=script_name,
                               top_scripts=top_scripts)

    except Exception as e:
        current_app.logger.error(f"Errore in nse_scripts: {e}")
        return render_template('network/nse_scripts.html',
                               scripts_data=[], pagination={}, error=str(e))


@network_bp.route('/service-detection')
def service_detection():
    """Dettagli service detection"""
    try:
        db = get_db()

        # Servizi con informazioni dettagliate
        detailed_services = db.execute('''
            SELECT s.*, h.hostname, p.state, p.reason
            FROM services s
            LEFT JOIN hosts h ON s.ip_address = h.ip_address
            LEFT JOIN ports p ON s.ip_address = p.ip_address AND s.port_number = p.port_number
            WHERE s.service_product IS NOT NULL OR s.service_version IS NOT NULL
            ORDER BY s.service_name, s.ip_address
        ''').fetchall()

        # Statistiche detection confidence
        confidence_stats = db.execute('''
            SELECT 
                CASE 
                    WHEN service_conf >= 8 THEN 'High (8-10)'
                    WHEN service_conf >= 5 THEN 'Medium (5-7)'
                    WHEN service_conf >= 3 THEN 'Low (3-4)'
                    WHEN service_conf >= 1 THEN 'Very Low (1-2)'
                    ELSE 'Unknown'
                END as confidence_range,
                COUNT(*) as count
            FROM services
            WHERE service_conf IS NOT NULL
            GROUP BY confidence_range
        ''').fetchall()

        # Prodotti/versioni più comuni
        top_products = db.execute('''
            SELECT service_product, service_version, COUNT(*) as count
            FROM services 
            WHERE service_product IS NOT NULL AND service_product != ""
            GROUP BY service_product, service_version 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

        return render_template('network/service_detection.html',
                               detailed_services=detailed_services,
                               confidence_stats=confidence_stats,
                               top_products=top_products)

    except Exception as e:
        current_app.logger.error(f"Errore in service_detection: {e}")
        return render_template('network/service_detection.html',
                               detailed_services=[], confidence_stats=[],
                               top_products=[], error=str(e))


# ===========================
# API ENDPOINTS
# ===========================

@network_bp.route('/api/hosts')
def api_hosts():
    """API endpoint per dati hosts in formato JSON"""
    try:
        db = get_db()

        hosts_data = db.execute('''
            SELECT ip_address, hostname, status, vendor, mac_address
            FROM hosts 
            ORDER BY ip_address
        ''').fetchall()

        # Converti in lista di dizionari
        hosts_list = []
        for host in hosts_data:
            hosts_list.append({
                'ip_address': host['ip_address'],
                'hostname': host['hostname'],
                'status': host['status'],
                'vendor': host['vendor'],
                'mac_address': host['mac_address']
            })

        return jsonify(hosts_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_bp.route('/api/topology')
def api_topology():
    """API endpoint per dati topologia"""
    try:
        db = get_db()

        # Nodi (hosts)
        nodes = []
        hosts_data = db.execute('''
            SELECT h.ip_address, h.hostname, h.status, dc.device_type,
                   COUNT(DISTINCT p.port_number) as open_ports
            FROM hosts h
            LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
            LEFT JOIN device_classification dc ON h.ip_address = dc.ip_address
            WHERE h.status = 'up'
            GROUP BY h.ip_address
        ''').fetchall()

        for host in hosts_data:
            nodes.append({
                'id': host['ip_address'],
                'label': host['hostname'] or host['ip_address'],
                'ip': host['ip_address'],
                'hostname': host['hostname'],
                'status': host['status'],
                'device_type': host['device_type'],
                'open_ports': host['open_ports'],
                'group': host['device_type'] or 'Unknown'
            })

        # Collegamenti (basati su traceroute se disponibile)
        links = []
        traceroute_data = db.execute('''
            SELECT DISTINCT ip_address, hop_ip
            FROM traceroute 
            WHERE hop_ip IS NOT NULL
        ''').fetchall()

        for trace in traceroute_data:
            # Aggiungi link solo se entrambi i nodi esistono
            source_exists = any(n['id'] == trace['hop_ip'] for n in nodes)
            target_exists = any(n['id'] == trace['ip_address'] for n in nodes)

            if source_exists and target_exists:
                links.append({
                    'source': trace['hop_ip'],
                    'target': trace['ip_address'],
                    'type': 'traceroute'
                })

        return jsonify({
            'nodes': nodes,
            'links': links
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_bp.route('/api/stats')
def api_network_stats():
    """API endpoint per statistiche network"""
    try:
        db = get_db()

        stats = {
            'hosts': {
                'total': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
                'active': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0],
                'with_hostname':
                    db.execute("SELECT COUNT(*) FROM hosts WHERE hostname IS NOT NULL AND hostname != ''").fetchone()[0]
            },
            'ports': {
                'total': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
                'open': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0],
                'filtered': db.execute("SELECT COUNT(*) FROM ports WHERE state = 'filtered'").fetchone()[0]
            },
            'services': {
                'total': db.execute('SELECT COUNT(*) FROM services').fetchone()[0],
                'unique': db.execute(
                    'SELECT COUNT(DISTINCT service_name) FROM services WHERE service_name IS NOT NULL').fetchone()[0]
            }
        }

        # Top porte
        top_ports = db.execute('''
            SELECT port_number, protocol, COUNT(*) as count
            FROM ports WHERE state = 'open'
            GROUP BY port_number, protocol
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        stats['top_ports'] = [{'port': f"{p['port_number']}/{p['protocol']}", 'count': p['count']} for p in top_ports]

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500