from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
from datetime import datetime

# Blueprint per Device Classification
devices_bp = Blueprint('devices', __name__, url_prefix='/devices')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


# ===========================
# CLASSIFICATION OVERVIEW
# ===========================

@devices_bp.route('/classification/overview')
def classification_overview():
    """Overview della classificazione dispositivi"""
    try:
        db = get_db()

        # Statistiche generali
        total_devices = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]
        total_hosts = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]

        classification_rate = round((total_devices / total_hosts * 100), 1) if total_hosts > 0 else 0

        # Statistiche per tipo di dispositivo
        type_stats = db.execute('''
            SELECT device_type, COUNT(*) as count,
                   AVG(confidence_score) as avg_confidence,
                   MIN(confidence_score) as min_confidence,
                   MAX(confidence_score) as max_confidence
            FROM device_classification 
            WHERE device_type IS NOT NULL
            GROUP BY device_type 
            ORDER BY count DESC
        ''').fetchall()

        # Statistiche per sottotipo
        subtype_stats = db.execute('''
            SELECT device_subtype, COUNT(*) as count
            FROM device_classification 
            WHERE device_subtype IS NOT NULL
            GROUP BY device_subtype 
            ORDER BY count DESC
            LIMIT 15
        ''').fetchall()

        # Distribuzione confidence scores
        confidence_distribution = db.execute('''
            SELECT 
                CASE 
                    WHEN confidence_score >= 0.9 THEN 'Excellent (≥0.9)'
                    WHEN confidence_score >= 0.8 THEN 'High (0.8-0.9)'
                    WHEN confidence_score >= 0.7 THEN 'Good (0.7-0.8)'
                    WHEN confidence_score >= 0.6 THEN 'Fair (0.6-0.7)'
                    WHEN confidence_score >= 0.5 THEN 'Low (0.5-0.6)'
                    ELSE 'Very Low (<0.5)'
                END as confidence_range,
                COUNT(*) as count,
                AVG(confidence_score) as avg_score
            FROM device_classification
            GROUP BY confidence_range
            ORDER BY avg_score DESC
        ''').fetchall()

        # Top vendor (da OUI)
        vendor_stats = db.execute('''
            SELECT vendor_oui, COUNT(*) as count,
                   AVG(confidence_score) as avg_confidence
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL
            GROUP BY vendor_oui 
            ORDER BY count DESC 
            LIMIT 15
        ''').fetchall()

        # Dispositivi con confidence bassa che potrebbero necessitare revisione
        low_confidence_devices = db.execute('''
            SELECT dc.*, h.hostname, h.vendor
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            WHERE dc.confidence_score < 0.5
            ORDER BY dc.confidence_score ASC
            LIMIT 10
        ''').fetchall()

        # Classificazioni recenti (se disponibili)
        recent_classifications = db.execute('''
            SELECT dc.*, h.hostname
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            ORDER BY dc.rowid DESC
            LIMIT 10
        ''').fetchall()

        # Metodi di classificazione più comuni
        classification_methods = {}
        for device in db.execute(
                'SELECT classification_reasons FROM device_classification WHERE classification_reasons IS NOT NULL').fetchall():
            reasons = device['classification_reasons']
            if 'OS detection' in reasons:
                classification_methods['OS Detection'] = classification_methods.get('OS Detection', 0) + 1
            if 'Services' in reasons:
                classification_methods['Service Analysis'] = classification_methods.get('Service Analysis', 0) + 1
            if 'Vendor' in reasons:
                classification_methods['Vendor Analysis'] = classification_methods.get('Vendor Analysis', 0) + 1
            if 'Hostname' in reasons:
                classification_methods['Hostname Pattern'] = classification_methods.get('Hostname Pattern', 0) + 1
            if 'Port pattern' in reasons:
                classification_methods['Port Pattern'] = classification_methods.get('Port Pattern', 0) + 1

        return render_template('devices/classification_overview.html',
                               total_devices=total_devices,
                               total_hosts=total_hosts,
                               classification_rate=classification_rate,
                               type_stats=type_stats,
                               subtype_stats=subtype_stats,
                               confidence_distribution=confidence_distribution,
                               vendor_stats=vendor_stats,
                               low_confidence_devices=low_confidence_devices,
                               recent_classifications=recent_classifications,
                               classification_methods=classification_methods)

    except Exception as e:
        current_app.logger.error(f"Errore in classification_overview: {e}")
        return render_template('devices/classification_overview.html', error=str(e))


# ===========================
# DEVICE CLASSIFICATION LIST
# ===========================
@devices_bp.route('/classification')
def classification():
    """Lista dispositivi classificati con filtri"""
    try:
        db = get_db()

        # Filtri dalla query string
        device_type = request.args.get('type')
        device_subtype = request.args.get('subtype')
        vendor = request.args.get('vendor')
        confidence_min = request.args.get('confidence_min', type=float)
        confidence_max = request.args.get('confidence_max', type=float)
        search = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # ✅ DEFINIRE current_filters SUBITO (prima di qualsiasi possibile errore)
        current_filters = {
            'type': device_type,
            'subtype': device_subtype,
            'vendor': vendor,
            'confidence_min': confidence_min,
            'confidence_max': confidence_max,
            'search': search
        }

        # Query base
        query = '''
            SELECT dc.*, h.hostname, h.mac_address, h.vendor as host_vendor, h.status,
                   COUNT(DISTINCT p.port_number) as open_ports,
                   COUNT(DISTINCT v.vuln_id) as vulnerabilities_count
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            LEFT JOIN ports p ON dc.ip_address = p.ip_address AND p.state = 'open'
            LEFT JOIN vulnerabilities v ON dc.ip_address = v.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri
        if device_type:
            conditions.append('dc.device_type = ?')
            params.append(device_type)

        if device_subtype:
            conditions.append('dc.device_subtype = ?')
            params.append(device_subtype)

        if vendor:
            conditions.append('(dc.vendor_oui LIKE ? OR h.vendor LIKE ?)')
            vendor_param = f'%{vendor}%'
            params.extend([vendor_param, vendor_param])

        if confidence_min is not None:
            conditions.append('dc.confidence_score >= ?')
            params.append(confidence_min)

        if confidence_max is not None:
            conditions.append('dc.confidence_score <= ?')
            params.append(confidence_max)

        if search:
            conditions.append('''(
                dc.ip_address LIKE ? OR 
                h.hostname LIKE ? OR 
                dc.device_type LIKE ? OR
                dc.vendor_oui LIKE ?
            )''')
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param, search_param])

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += '''
            GROUP BY dc.ip_address, dc.device_type, dc.device_subtype, dc.vendor, 
                     dc.vendor_oui, dc.confidence_score, dc.classification_reasons, 
                     dc.os_detected, dc.main_services, dc.hostname_pattern, dc.mac_vendor
            ORDER BY dc.confidence_score DESC, dc.ip_address
        '''

        # Conteggio totale
        count_query = query.replace(
            'SELECT dc.*, h.hostname, h.mac_address, h.vendor as host_vendor, h.status, COUNT(DISTINCT p.port_number) as open_ports, COUNT(DISTINCT v.vuln_id) as vulnerabilities_count',
            'SELECT COUNT(DISTINCT dc.ip_address)'
        ).replace(
            'GROUP BY dc.ip_address, dc.device_type, dc.device_subtype, dc.vendor, dc.vendor_oui, dc.confidence_score, dc.classification_reasons, dc.os_detected, dc.main_services, dc.hostname_pattern, dc.mac_vendor',
            '')

        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        devices_data = db.execute(paginated_query, params).fetchall()

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

        # Ottieni valori unici per filtri dropdown
        available_types = db.execute('''
            SELECT DISTINCT device_type 
            FROM device_classification 
            WHERE device_type IS NOT NULL 
            ORDER BY device_type
        ''').fetchall()

        available_subtypes = db.execute('''
            SELECT DISTINCT device_subtype 
            FROM device_classification 
            WHERE device_subtype IS NOT NULL 
            ORDER BY device_subtype
        ''').fetchall()

        available_vendors = db.execute('''
            SELECT DISTINCT vendor_oui 
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL 
            ORDER BY vendor_oui
        ''').fetchall()

        return render_template('devices/classification.html',
                               devices=devices_data,
                               pagination=pagination,
                               current_filters=current_filters,
                               available_types=available_types,
                               available_subtypes=available_subtypes,
                               available_vendors=available_vendors)

    except Exception as e:
        current_app.logger.error(f"Errore in classification: {e}")

        # ✅ ASSICURATI CHE current_filters SIA SEMPRE DEFINITO ANCHE IN CASO DI ERRORE
        current_filters = {
            'type': request.args.get('type'),
            'subtype': request.args.get('subtype'),
            'vendor': request.args.get('vendor'),
            'confidence_min': request.args.get('confidence_min', type=float),
            'confidence_max': request.args.get('confidence_max', type=float),
            'search': request.args.get('search', '').strip()
        }

        return render_template('devices/classification.html',
                               devices=[],
                               pagination={'page': 1, 'per_page': 50, 'total': 0, 'total_pages': 0, 'has_prev': False,
                                           'has_next': False},
                               current_filters=current_filters,
                               available_types=[],
                               available_subtypes=[],
                               available_vendors=[],
                               error=str(e))

@devices_bp.route('/device/<ip_address>')
def device_detail(ip_address):
    """Dettaglio singolo dispositivo"""
    try:
        db = get_db()

        # Informazioni dispositivo completo
        device = db.execute('''
            SELECT dc.*, h.hostname, h.mac_address, h.vendor, h.status, h.status_reason,
                   o.os_name, o.os_family, o.os_type, o.os_vendor, o.accuracy as os_accuracy
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            LEFT JOIN os_info o ON dc.ip_address = o.ip_address
            WHERE dc.ip_address = ?
        ''', (ip_address,)).fetchone()

        if not device:
            return render_template('errors/404.html'), 404

        # Porte e servizi
        services = db.execute('''
            SELECT p.port_number, p.protocol, p.state, s.service_name, 
                   s.service_product, s.service_version, s.service_info
            FROM ports p
            LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
            WHERE p.ip_address = ? AND p.state = 'open'
            ORDER BY p.port_number
        ''', (ip_address,)).fetchall()

        # Vulnerabilità
        vulnerabilities = db.execute('''
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities 
            WHERE ip_address = ?
            GROUP BY severity
        ''', (ip_address,)).fetchall()

        # Software installato (campione)
        software = db.execute('''
            SELECT software_name, version, install_date
            FROM installed_software 
            WHERE ip_address = ?
            ORDER BY software_name
            LIMIT 15
        ''', (ip_address,)).fetchall()

        # Processi in esecuzione (campione)
        processes = db.execute('''
            SELECT process_name, pid, process_path
            FROM running_processes 
            WHERE ip_address = ?
            ORDER BY process_name
            LIMIT 15
        ''', (ip_address,)).fetchall()

        # Hostname discovery
        hostnames = db.execute('''
            SELECT hostname, hostname_type
            FROM hostnames 
            WHERE ip_address = ?
            ORDER BY hostname_id
        ''', (ip_address,)).fetchall()

        # Analisi delle ragioni di classificazione
        classification_analysis = {}
        if device['classification_reasons']:
            reasons = device['classification_reasons'].split(';')
            for reason in reasons:
                reason = reason.strip()
                if reason:
                    # Categorizza le ragioni
                    if 'OS detection' in reason:
                        classification_analysis['OS Detection'] = reason
                    elif 'Services' in reason:
                        classification_analysis['Service Analysis'] = reason
                    elif 'Vendor' in reason:
                        classification_analysis['Vendor Analysis'] = reason
                    elif 'Hostname' in reason:
                        classification_analysis['Hostname Pattern'] = reason
                    elif 'Port pattern' in reason:
                        classification_analysis['Port Pattern'] = reason
                    else:
                        classification_analysis['Other'] = classification_analysis.get('Other', []) + [reason]

        # Dispositivi simili (stesso tipo)
        similar_devices = []
        if device['device_type']:
            similar_devices = db.execute('''
                SELECT dc.ip_address, h.hostname, dc.device_subtype, dc.confidence_score
                FROM device_classification dc
                LEFT JOIN hosts h ON dc.ip_address = h.ip_address
                WHERE dc.device_type = ? AND dc.ip_address != ?
                ORDER BY dc.confidence_score DESC
                LIMIT 5
            ''', (device['device_type'], ip_address)).fetchall()

        # Statistiche del dispositivo
        device_stats = {
            'total_ports': len(services),
            'total_vulnerabilities': sum(vuln['count'] for vuln in vulnerabilities),
            'critical_vulns': next((vuln['count'] for vuln in vulnerabilities if vuln['severity'] == 'CRITICAL'), 0),
            'total_software': len(software),
            'total_processes': len(processes),
            'total_hostnames': len(hostnames)
        }

        return render_template('devices/device_detail.html',
                               device=device,
                               services=services,
                               vulnerabilities=vulnerabilities,
                               software=software,
                               processes=processes,
                               hostnames=hostnames,
                               classification_analysis=classification_analysis,
                               similar_devices=similar_devices,
                               device_stats=device_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in device_detail per {ip_address}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# VENDOR ANALYSIS
# ===========================
@devices_bp.route('/vendors')
def vendors():
    """Analisi vendor e OUI"""
    try:
        db = get_db()

        search_vendor = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = 30

        # Query vendor con statistiche
        query = '''
            SELECT vendor_oui, 
                   COUNT(*) as device_count,
                   COUNT(DISTINCT device_type) as unique_types,
                   AVG(confidence_score) as avg_confidence,
                   GROUP_CONCAT(DISTINCT device_type) as device_types
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL AND vendor_oui != ""
        '''

        params = []
        if search_vendor:
            query += ' AND vendor_oui LIKE ?'
            params.append(f'%{search_vendor}%')

        query += '''
            GROUP BY vendor_oui 
            ORDER BY device_count DESC
        '''

        # Conteggio totale
        count_query = f'''
            SELECT COUNT(DISTINCT vendor_oui) 
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL AND vendor_oui != ""
            {f" AND vendor_oui LIKE ?" if search_vendor else ""}
        '''
        total_count = db.execute(count_query, params[:1] if search_vendor else []).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        vendors_data = db.execute(paginated_query, params).fetchall()

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page < (total_count + per_page - 1) // per_page
        }

        # Statistiche vendor
        vendor_stats = {
            'total_vendors': total_count,
            'total_devices': db.execute('SELECT COUNT(*) FROM device_classification WHERE vendor_oui IS NOT NULL').fetchone()[0],
            'avg_confidence': db.execute('SELECT AVG(confidence_score) FROM device_classification WHERE vendor_oui IS NOT NULL').fetchone()[0] or 0,
            'unique_types': db.execute('SELECT COUNT(DISTINCT device_type) FROM device_classification WHERE vendor_oui IS NOT NULL AND device_type IS NOT NULL').fetchone()[0]
        }

        return render_template('devices/vendors.html',
                               vendors_data=vendors_data,
                               pagination=pagination,
                               current_search=search_vendor,
                               vendor_stats=vendor_stats)

    except Exception as e:
        current_app.logger.error(f"Errore in vendors: {e}")
        return render_template('devices/vendors.html',
                               vendors_data=[],
                               pagination={'page': 1, 'per_page': 30, 'total': 0, 'total_pages': 0, 'has_prev': False, 'has_next': False},
                               current_search=request.args.get('search', ''),
                               vendor_stats={'total_vendors': 0, 'total_devices': 0, 'avg_confidence': 0, 'unique_types': 0},
                               error=str(e))

@devices_bp.route('/vendor/<vendor_name>')
def vendor_detail(vendor_name):
    """Dettaglio specifico vendor"""
    try:
        db = get_db()

        # Dispositivi di questo vendor
        vendor_devices = db.execute('''
            SELECT dc.*, h.hostname, h.status
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            WHERE dc.vendor_oui = ?
            ORDER BY dc.confidence_score DESC, dc.ip_address
        ''', (vendor_name,)).fetchall()

        if not vendor_devices:
            return render_template('errors/404.html'), 404

        # Statistiche per questo vendor
        vendor_info = {
            'vendor_name': vendor_name,
            'total_devices': len(vendor_devices),
            'device_types': list(set(d['device_type'] for d in vendor_devices if d['device_type'])),
            'avg_confidence': sum(d['confidence_score'] or 0 for d in vendor_devices) / len(vendor_devices),
            'active_devices': sum(1 for d in vendor_devices if d['status'] == 'up')
        }

        # Distribuzione per tipo di dispositivo
        type_distribution = {}
        for device in vendor_devices:
            device_type = device['device_type'] or 'Unknown'
            type_distribution[device_type] = type_distribution.get(device_type, 0) + 1

        # Distribuzione confidence score
        confidence_ranges = {
            'High (≥0.8)': sum(1 for d in vendor_devices if (d['confidence_score'] or 0) >= 0.8),
            'Medium (0.6-0.8)': sum(1 for d in vendor_devices if 0.6 <= (d['confidence_score'] or 0) < 0.8),
            'Low (<0.6)': sum(1 for d in vendor_devices if (d['confidence_score'] or 0) < 0.6)
        }

        return render_template('devices/vendor_detail.html',
                               vendor_info=vendor_info,
                               vendor_devices=vendor_devices,
                               type_distribution=type_distribution,
                               confidence_ranges=confidence_ranges)

    except Exception as e:
        current_app.logger.error(f"Errore in vendor_detail per {vendor_name}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# CONFIDENCE ANALYSIS
# ===========================
@devices_bp.route('/confidence')
def confidence():
    """Analisi confidence scores"""
    try:
        db = get_db()

        confidence_filter = request.args.get('confidence')
        page = int(request.args.get('page', 1))
        per_page = 50

        # Query base per dispositivi con confidence scores
        query = '''
            SELECT dc.*, h.hostname, h.status
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
        '''

        params = []
        conditions = []

        # Filtro confidence
        if confidence_filter:
            if confidence_filter == 'high':
                conditions.append('dc.confidence_score >= 0.8')
            elif confidence_filter == 'medium':
                conditions.append('dc.confidence_score >= 0.6 AND dc.confidence_score < 0.8')
            elif confidence_filter == 'low':
                conditions.append('dc.confidence_score >= 0.4 AND dc.confidence_score < 0.6')
            elif confidence_filter == 'very_low':
                conditions.append('dc.confidence_score < 0.4')

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY dc.confidence_score DESC, dc.ip_address'

        # Conteggio totale
        count_query = query.replace('SELECT dc.*, h.hostname, h.status', 'SELECT COUNT(*)')
        total_count = db.execute(count_query, params).fetchone()[0]

        # Paginazione
        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'
        devices = db.execute(paginated_query, params).fetchall()

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
            'has_prev': page > 1,
            'has_next': page < (total_count + per_page - 1) // per_page
        }

        # Statistiche confidence
        confidence_stats = db.execute('''
            SELECT 
                COUNT(*) as total_devices,
                AVG(confidence_score) as avg_confidence,
                SUM(CASE WHEN confidence_score >= 0.8 THEN 1 ELSE 0 END) as high_confidence,
                SUM(CASE WHEN confidence_score >= 0.6 AND confidence_score < 0.8 THEN 1 ELSE 0 END) as medium_confidence,
                SUM(CASE WHEN confidence_score >= 0.4 AND confidence_score < 0.6 THEN 1 ELSE 0 END) as low_confidence,
                SUM(CASE WHEN confidence_score < 0.4 THEN 1 ELSE 0 END) as very_low_confidence
            FROM device_classification
            WHERE confidence_score IS NOT NULL
        ''').fetchone()

        # Distribuzione per ranges
        confidence_distribution = db.execute('''
            SELECT 
                CASE 
                    WHEN confidence_score >= 0.9 THEN 'Excellent (≥90%)'
                    WHEN confidence_score >= 0.8 THEN 'High (80-90%)'
                    WHEN confidence_score >= 0.6 THEN 'Medium (60-80%)'
                    WHEN confidence_score >= 0.4 THEN 'Low (40-60%)'
                    ELSE 'Very Low (<40%)'
                END as confidence_range,
                COUNT(*) as count,
                AVG(confidence_score) as avg_score
            FROM device_classification
            WHERE confidence_score IS NOT NULL
            GROUP BY confidence_range
            ORDER BY avg_score DESC
        ''').fetchall()

        # Top performing vendors
        top_vendors = db.execute('''
            SELECT vendor_oui, COUNT(*) as device_count, AVG(confidence_score) as avg_confidence
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL AND confidence_score IS NOT NULL
            GROUP BY vendor_oui 
            HAVING COUNT(*) >= 3
            ORDER BY avg_confidence DESC 
            LIMIT 10
        ''').fetchall()

        return render_template('devices/confidence.html',
                               devices=devices,
                               pagination=pagination,
                               current_filter=confidence_filter,
                               confidence_stats=confidence_stats,
                               confidence_distribution=confidence_distribution,
                               top_vendors=top_vendors)

    except Exception as e:
        current_app.logger.error(f"Errore in confidence: {e}")
        return render_template('devices/confidence.html',
                               devices=[],
                               pagination={'page': 1, 'per_page': 50, 'total': 0, 'total_pages': 0, 'has_prev': False, 'has_next': False},
                               current_filter=request.args.get('confidence'),
                               confidence_stats={'total_devices': 0, 'avg_confidence': 0, 'high_confidence': 0, 'medium_confidence': 0, 'low_confidence': 0, 'very_low_confidence': 0},
                               confidence_distribution=[],
                               top_vendors=[],
                               error=str(e))

# ===========================
# API ENDPOINTS
# ===========================

@devices_bp.route('/api/classification')
def api_classification():
    """API endpoint per classificazione dispositivi in JSON"""
    try:
        db = get_db()

        device_type = request.args.get('type')
        limit = int(request.args.get('limit', 100))

        query = '''
            SELECT dc.ip_address, dc.device_type, dc.device_subtype, 
                   dc.vendor_oui, dc.confidence_score, h.hostname, h.status
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
        '''

        params = []
        if device_type:
            query += ' WHERE dc.device_type = ?'
            params.append(device_type)

        query += ' ORDER BY dc.confidence_score DESC LIMIT ?'
        params.append(limit)

        devices_data = db.execute(query, params).fetchall()

        # Converti in lista di dizionari
        devices_list = []
        for device in devices_data:
            devices_list.append({
                'ip_address': device['ip_address'],
                'hostname': device['hostname'],
                'device_type': device['device_type'],
                'device_subtype': device['device_subtype'],
                'vendor': device['vendor_oui'],
                'confidence_score': device['confidence_score'],
                'status': device['status']
            })

        return jsonify(devices_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@devices_bp.route('/api/device-stats')
def api_device_stats():
    """API endpoint per statistiche dispositivi"""
    try:
        db = get_db()

        stats = {
            'total_classified': db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0],
            'total_hosts': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'high_confidence':
                db.execute('SELECT COUNT(*) FROM device_classification WHERE confidence_score >= 0.8').fetchone()[0],
            'unique_types': db.execute(
                'SELECT COUNT(DISTINCT device_type) FROM device_classification WHERE device_type IS NOT NULL').fetchone()[
                0],
            'unique_vendors': db.execute(
                'SELECT COUNT(DISTINCT vendor_oui) FROM device_classification WHERE vendor_oui IS NOT NULL').fetchone()[
                0]
        }

        # Calcola percentuali
        if stats['total_hosts'] > 0:
            stats['classification_rate'] = round((stats['total_classified'] / stats['total_hosts']) * 100, 1)
        else:
            stats['classification_rate'] = 0

        # Distribuzione per tipo
        type_distribution = db.execute('''
            SELECT device_type, COUNT(*) as count
            FROM device_classification 
            WHERE device_type IS NOT NULL
            GROUP BY device_type
            ORDER BY count DESC
        ''').fetchall()

        stats['type_distribution'] = {t['device_type']: t['count'] for t in type_distribution}

        # Distribuzione confidence
        confidence_dist = db.execute('''
            SELECT 
                CASE 
                    WHEN confidence_score >= 0.8 THEN 'High'
                    WHEN confidence_score >= 0.6 THEN 'Medium'
                    ELSE 'Low'
                END as confidence_level,
                COUNT(*) as count
            FROM device_classification
            WHERE confidence_score IS NOT NULL
            GROUP BY confidence_level
        ''').fetchall()

        stats['confidence_distribution'] = {c['confidence_level']: c['count'] for c in confidence_dist}

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@devices_bp.route('/api/topology-data')
def api_topology_data():
    """API endpoint per dati topologia dispositivi"""
    try:
        db = get_db()

        # Nodi con classificazione
        nodes_data = db.execute('''
            SELECT dc.ip_address, h.hostname, dc.device_type, dc.device_subtype,
                   dc.confidence_score, dc.vendor_oui, h.status
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            WHERE h.status = 'up'
            ORDER BY dc.confidence_score DESC
        ''').fetchall()

        nodes = []
        for node in nodes_data:
            # Determina colore e forma basato sul tipo di dispositivo
            device_type = node['device_type'] or 'Unknown'

            if device_type == 'Server':
                color = '#e74c3c'  # Rosso
                shape = 'box'
            elif device_type == 'Workstation':
                color = '#3498db'  # Blu
                shape = 'circle'
            elif device_type == 'Network Device':
                color = '#f39c12'  # Arancione
                shape = 'diamond'
            elif device_type == 'Printer':
                color = '#9b59b6'  # Viola
                shape = 'triangle'
            elif device_type == 'IoT Device':
                color = '#2ecc71'  # Verde
                shape = 'dot'
            else:
                color = '#95a5a6'  # Grigio
                shape = 'circle'

            # Dimensione basata su confidence
            confidence = node['confidence_score'] or 0.5
            size = 10 + (confidence * 20)  # Da 10 a 30

            nodes.append({
                'id': node['ip_address'],
                'label': node['hostname'] or node['ip_address'],
                'ip': node['ip_address'],
                'hostname': node['hostname'],
                'device_type': device_type,
                'device_subtype': node['device_subtype'],
                'vendor': node['vendor_oui'],
                'confidence': confidence,
                'color': color,
                'shape': shape,
                'size': size,
                'group': device_type
            })

        # Collegamenti (basati su subnet o traceroute)
        links = []

        # Raggruppa per subnet per creare collegamenti logici
        subnet_groups = {}
        for node in nodes:
            ip_parts = node['ip'].split('.')
            subnet = '.'.join(ip_parts[:3])

            if subnet not in subnet_groups:
                subnet_groups[subnet] = []
            subnet_groups[subnet].append(node['id'])

        # Crea collegamenti tra dispositivi della stessa subnet
        for subnet, ips in subnet_groups.items():
            if len(ips) > 1:
                # Trova il "gateway" (probabilmente un Network Device)
                gateway = None
                for ip in ips:
                    node = next(n for n in nodes if n['id'] == ip)
                    if node['device_type'] == 'Network Device':
                        gateway = ip
                        break

                if gateway:
                    # Collega tutti gli altri dispositivi al gateway
                    for ip in ips:
                        if ip != gateway:
                            links.append({
                                'from': gateway,
                                'to': ip,
                                'type': 'subnet',
                                'color': {'color': '#bdc3c7', 'width': 1}
                            })
                else:
                    # Se non c'è gateway, collega in modo circolare
                    for i, ip1 in enumerate(ips[:-1]):
                        ip2 = ips[i + 1]
                        links.append({
                            'from': ip1,
                            'to': ip2,
                            'type': 'subnet',
                            'color': {'color': '#ecf0f1', 'width': 1}
                        })

        return jsonify({
            'nodes': nodes,
            'edges': links,
            'subnet_groups': list(subnet_groups.keys())
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@devices_bp.route('/api/vendor-analysis')
def api_vendor_analysis():
    """API endpoint per analisi vendor"""
    try:
        db = get_db()

        # Top vendor con statistiche
        vendor_data = db.execute('''
            SELECT vendor_oui, 
                   COUNT(*) as device_count,
                   COUNT(DISTINCT device_type) as unique_types,
                   AVG(confidence_score) as avg_confidence,
                   GROUP_CONCAT(DISTINCT device_type) as device_types
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL AND vendor_oui != ""
            GROUP BY vendor_oui 
            ORDER BY device_count DESC
            LIMIT 20
        ''').fetchall()

        vendors = []
        for vendor in vendor_data:
            vendors.append({
                'vendor': vendor['vendor_oui'],
                'device_count': vendor['device_count'],
                'unique_types': vendor['unique_types'],
                'avg_confidence': round(vendor['avg_confidence'], 2) if vendor['avg_confidence'] else 0,
                'device_types': vendor['device_types'].split(',') if vendor['device_types'] else []
            })

        return jsonify(vendors)

    except Exception as e:
        return jsonify({'error': str(e)}), 500