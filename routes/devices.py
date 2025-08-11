from flask import Blueprint, render_template, request, jsonify, g, current_app
import sqlite3
import traceback
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
                    WHEN confidence_score >= 0.6 THEN 'Medium (0.6-0.8)'
                    WHEN confidence_score >= 0.4 THEN 'Low (0.4-0.6)'
                    ELSE 'Very Low (<0.4)'
                END as confidence_range,
                COUNT(*) as count
            FROM device_classification 
            WHERE confidence_score IS NOT NULL
            GROUP BY confidence_range
        ''').fetchall()

        # Vendor più comuni
        vendor_stats = db.execute('''
            SELECT vendor_oui, COUNT(*) as count, AVG(confidence_score) as avg_confidence
            FROM device_classification 
            WHERE vendor_oui IS NOT NULL
            GROUP BY vendor_oui 
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        # Dispositivi con bassa confidenza
        low_confidence_devices = db.execute('''
            SELECT dc.*, h.hostname
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            WHERE dc.confidence_score < 0.5
            ORDER BY dc.confidence_score ASC
            LIMIT 10
        ''').fetchall()

        # Classificazioni recenti
        recent_classifications = db.execute('''
            SELECT dc.*, h.hostname
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
            ORDER BY dc.updated_at DESC
            LIMIT 10
        ''').fetchall()

        # Metodi di classificazione utilizzati
        classification_methods = {}
        for classification in recent_classifications:
            if classification['classification_reasons']:
                reasons = classification['classification_reasons'].split(';')
                for reason in reasons:
                    reason = reason.strip()
                    if 'OS detection' in reason:
                        classification_methods['OS Detection'] = classification_methods.get('OS Detection', 0) + 1
                    elif 'Services' in reason:
                        classification_methods['Service Analysis'] = classification_methods.get('Service Analysis',
                                                                                                0) + 1
                    elif 'Vendor' in reason:
                        classification_methods['Vendor Analysis'] = classification_methods.get('Vendor Analysis', 0) + 1
                    elif 'Hostname' in reason:
                        classification_methods['Hostname Pattern'] = classification_methods.get('Hostname Pattern',
                                                                                                0) + 1
                    elif 'Port pattern' in reason:
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
    """Lista dispositivi classificati con filtri - VERSIONE CORRETTA"""
    try:
        db = get_db()

        # ===== STEP 1: PARSING PARAMETRI SICURO =====

        # Gestione sicura dei parametri dalla query string
        device_type = request.args.get('type', '').strip() or None
        device_subtype = request.args.get('subtype', '').strip() or None
        vendor = request.args.get('vendor', '').strip() or None
        search = request.args.get('search', '').strip() or None

        # Parsing numerico sicuro
        try:
            confidence_min = float(request.args.get('confidence_min')) if request.args.get('confidence_min') else None
        except (ValueError, TypeError):
            confidence_min = None

        try:
            confidence_max = float(request.args.get('confidence_max')) if request.args.get('confidence_max') else None
        except (ValueError, TypeError):
            confidence_max = None

        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
        except (ValueError, TypeError):
            page = 1

        try:
            per_page = int(request.args.get('per_page', 50))
            if per_page < 10:
                per_page = 10
            elif per_page > 100:
                per_page = 100
        except (ValueError, TypeError):
            per_page = 50

        # Dizionario filtri corrente - SEMPRE DEFINITO
        current_filters = {
            'type': device_type,
            'subtype': device_subtype,
            'vendor': vendor,
            'confidence_min': confidence_min,
            'confidence_max': confidence_max,
            'search': search
        }

        current_app.logger.info(f"Classification filters: {current_filters}")

        # ===== STEP 2: VERIFICA DATI DATABASE =====

        # Verifica presenza dati
        classification_count = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]
        current_app.logger.info(f"Device classification records: {classification_count}")

        if classification_count == 0:
            current_app.logger.warning("No device classification data found")
            # Ritorna template con messaggio informativo
            return render_template('devices/classification.html',
                                   devices=[],
                                   pagination={
                                       'page': 1,
                                       'per_page': per_page,
                                       'total': 0,
                                       'total_pages': 0,
                                       'has_prev': False,
                                       'has_next': False
                                   },
                                   current_filters=current_filters,
                                   available_types=[],
                                   available_subtypes=[],
                                   available_vendors=[],
                                   error="No device classification data available. Please run device classification first.")

        # ===== STEP 3: COSTRUZIONE QUERY SICURA =====

        # Query base semplificata
        base_query = '''
            SELECT 
                dc.ip_address,
                dc.device_type,
                dc.device_subtype,
                dc.vendor,
                dc.vendor_oui,
                dc.confidence_score,
                dc.classification_reasons,
                dc.os_detected,
                dc.updated_at,
                h.hostname,
                h.mac_address,
                h.vendor as host_vendor,
                h.status
            FROM device_classification dc
            LEFT JOIN hosts h ON dc.ip_address = h.ip_address
        '''

        params = []
        conditions = []

        # Applica filtri con validazione
        if device_type:
            conditions.append('dc.device_type = ?')
            params.append(str(device_type))

        if device_subtype:
            conditions.append('dc.device_subtype = ?')
            params.append(str(device_subtype))

        if vendor:
            conditions.append('(dc.vendor_oui LIKE ? OR dc.vendor LIKE ? OR h.vendor LIKE ?)')
            vendor_param = f'%{str(vendor)}%'
            params.extend([vendor_param, vendor_param, vendor_param])

        if confidence_min is not None:
            conditions.append('dc.confidence_score >= ?')
            params.append(float(confidence_min))

        if confidence_max is not None:
            conditions.append('dc.confidence_score <= ?')
            params.append(float(confidence_max))

        if search:
            conditions.append('''(
                dc.ip_address LIKE ? OR 
                h.hostname LIKE ? OR 
                dc.device_type LIKE ? OR
                dc.device_subtype LIKE ? OR
                dc.vendor_oui LIKE ?
            )''')
            search_param = f'%{str(search)}%'
            params.extend([search_param] * 5)

        # Costruisci query completa
        if conditions:
            query = base_query + ' WHERE ' + ' AND '.join(conditions)
        else:
            query = base_query

        query += ' ORDER BY dc.confidence_score DESC, dc.ip_address'

        current_app.logger.debug(f"Final query: {query}")
        current_app.logger.debug(f"Query params: {params}")

        # ===== STEP 4: CONTEGGIO TOTALE SICURO =====

        count_query = base_query.replace('''
            SELECT 
                dc.ip_address,
                dc.device_type,
                dc.device_subtype,
                dc.vendor,
                dc.vendor_oui,
                dc.confidence_score,
                dc.classification_reasons,
                dc.os_detected,
                dc.updated_at,
                h.hostname,
                h.mac_address,
                h.vendor as host_vendor,
                h.status''', 'SELECT COUNT(*)')

        if conditions:
            count_query += ' WHERE ' + ' AND '.join(conditions)

        try:
            total_count = db.execute(count_query, params).fetchone()[0]
            current_app.logger.info(f"Total devices found: {total_count}")
        except Exception as e:
            current_app.logger.error(f"Error in count query: {e}")
            total_count = 0

        # ===== STEP 5: PAGINAZIONE SICURA =====

        if total_count == 0:
            # Nessun risultato
            return render_template('devices/classification.html',
                                   devices=[],
                                   pagination={
                                       'page': 1,
                                       'per_page': per_page,
                                       'total': 0,
                                       'total_pages': 0,
                                       'has_prev': False,
                                       'has_next': False
                                   },
                                   current_filters=current_filters,
                                   available_types=[],
                                   available_subtypes=[],
                                   available_vendors=[])

        total_pages = max(1, (total_count + per_page - 1) // per_page)
        page = min(page, total_pages)  # Assicurati che page non superi total_pages

        offset = (page - 1) * per_page
        paginated_query = query + f' LIMIT {per_page} OFFSET {offset}'

        try:
            devices_data = db.execute(paginated_query, params).fetchall()
            current_app.logger.info(f"Query returned {len(devices_data)} devices")
        except Exception as e:
            current_app.logger.error(f"Error in paginated query: {e}")
            devices_data = []

        # Informazioni paginazione
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total_count,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        }

        # ===== STEP 6: DATI PER DROPDOWN FILTRI =====

        try:
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

        except Exception as e:
            current_app.logger.error(f"Error loading filter data: {e}")
            available_types = []
            available_subtypes = []
            available_vendors = []

        # ===== STEP 7: AGGIUNGI DATI AGGIUNTIVI =====

        # Aggiungi statistiche aggiuntive per ports e vulnerabilities se necessario
        enhanced_devices = []
        for device in devices_data:
            device_dict = dict(device)

            # Conta porte aperte (query semplice)
            try:
                open_ports = db.execute('''
                    SELECT COUNT(*) FROM ports 
                    WHERE ip_address = ? AND state = 'open'
                ''', (device['ip_address'],)).fetchone()[0]
                device_dict['open_ports'] = open_ports
            except:
                device_dict['open_ports'] = 0

            # Conta vulnerabilità (query semplice se la tabella esiste)
            try:
                vulns = db.execute('''
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE ip_address = ?
                ''', (device['ip_address'],)).fetchone()[0]
                device_dict['vulnerabilities_count'] = vulns
            except:
                device_dict['vulnerabilities_count'] = 0

            enhanced_devices.append(device_dict)

        # ===== STEP 8: RENDERING TEMPLATE =====

        return render_template('devices/classification.html',
                               devices=enhanced_devices,
                               pagination=pagination,
                               current_filters=current_filters,
                               available_types=available_types,
                               available_subtypes=available_subtypes,
                               available_vendors=available_vendors)

    except Exception as e:
        current_app.logger.error(f"Critical error in classification: {e}")
        current_app.logger.error(f"Stack trace: {traceback.format_exc()}")

        # Fallback con filtri di base
        current_filters = {
            'type': request.args.get('type'),
            'subtype': request.args.get('subtype'),
            'vendor': request.args.get('vendor'),
            'confidence_min': None,
            'confidence_max': None,
            'search': request.args.get('search', '').strip()
        }

        return render_template('devices/classification.html',
                               devices=[],
                               pagination={
                                   'page': 1,
                                   'per_page': 50,
                                   'total': 0,
                                   'total_pages': 0,
                                   'has_prev': False,
                                   'has_next': False
                               },
                               current_filters=current_filters,
                               available_types=[],
                               available_subtypes=[],
                               available_vendors=[],
                               error=f"Error loading devices: {str(e)}")


# ===========================
# DEVICE DETAIL
# ===========================

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

        # Porte aperte
        open_ports = db.execute('''
            SELECT p.*, s.service_name, s.service_product, s.service_version
            FROM ports p
            LEFT JOIN services s ON p.ip_address = s.ip_address AND p.port_number = s.port_number
            WHERE p.ip_address = ? AND p.state = 'open'
            ORDER BY p.port_number
        ''', (ip_address,)).fetchall()

        # Vulnerabilità (se la tabella esiste)
        vulnerabilities = []
        try:
            vulnerabilities = db.execute('''
                SELECT * FROM vulnerabilities 
                WHERE ip_address = ?
                ORDER BY severity DESC, vuln_id
            ''', (ip_address,)).fetchall()
        except:
            pass

        # Software installato (se la tabella esiste)
        software = []
        try:
            software = db.execute('''
                SELECT software_name, software_version
                FROM installed_software 
                WHERE ip_address = ?
                ORDER BY software_name
                LIMIT 15
            ''', (ip_address,)).fetchall()
        except:
            pass

        # Processi in esecuzione (se la tabella esiste)
        processes = []
        try:
            processes = db.execute('''
                SELECT process_name, pid, process_path
                FROM running_processes 
                WHERE ip_address = ?
                ORDER BY process_name
                LIMIT 15
            ''', (ip_address,)).fetchall()
        except:
            pass

        # Hostname discovery (se la tabella esiste)
        hostnames = []
        try:
            hostnames = db.execute('''
                SELECT hostname, hostname_type
                FROM hostnames 
                WHERE ip_address = ?
                ORDER BY hostname_id
            ''', (ip_address,)).fetchall()
        except:
            pass

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
                        if 'Other' not in classification_analysis:
                            classification_analysis['Other'] = []
                        classification_analysis['Other'].append(reason)

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

        return render_template('devices/device_detail.html',
                               device=device,
                               open_ports=open_ports,
                               vulnerabilities=vulnerabilities,
                               software=software,
                               processes=processes,
                               hostnames=hostnames,
                               classification_analysis=classification_analysis,
                               similar_devices=similar_devices)

    except Exception as e:
        current_app.logger.error(f"Error in device_detail for {ip_address}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# CONFIDENCE ANALYSIS
# ===========================

@devices_bp.route('/confidence')
def confidence_analysis():
    """Analisi della confidenza delle classificazioni"""
    try:
        db = get_db()

        # Parametri filtro
        confidence_filter = request.args.get('confidence')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Query base
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
                    WHEN confidence_score >= 0.8 THEN 'High (≥0.8)'
                    WHEN confidence_score >= 0.6 THEN 'Medium (0.6-0.8)'
                    WHEN confidence_score >= 0.4 THEN 'Low (0.4-0.6)'
                    ELSE 'Very Low (<0.4)'
                END as range_name,
                COUNT(*) as count,
                AVG(confidence_score) as avg_score
            FROM device_classification
            WHERE confidence_score IS NOT NULL
            GROUP BY range_name
            ORDER BY avg_score DESC
        ''').fetchall()

        return render_template('devices/confidence_analysis.html',
                               devices=devices,
                               pagination=pagination,
                               confidence_filter=confidence_filter,
                               confidence_stats=confidence_stats,
                               confidence_distribution=confidence_distribution)

    except Exception as e:
        current_app.logger.error(f"Error in confidence_analysis: {e}")
        return render_template('devices/confidence_analysis.html',
                               devices=[], pagination={}, error=str(e))


# ===========================
# VENDORS MANAGEMENT
# ===========================

@devices_bp.route('/vendors')
def vendors():
    """Lista vendor con statistiche"""
    try:
        db = get_db()

        # Parametri
        search_vendor = request.args.get('search', '').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 30))

        # Query vendors
        query = '''
            SELECT 
                vendor_oui,
                COUNT(*) as device_count,
                AVG(confidence_score) as avg_confidence,
                COUNT(DISTINCT device_type) as unique_types
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
            'total_devices':
                db.execute('SELECT COUNT(*) FROM device_classification WHERE vendor_oui IS NOT NULL').fetchone()[0],
            'avg_confidence': db.execute(
                'SELECT AVG(confidence_score) FROM device_classification WHERE vendor_oui IS NOT NULL').fetchone()[
                                  0] or 0,
            'unique_types': db.execute(
                'SELECT COUNT(DISTINCT device_type) FROM device_classification WHERE vendor_oui IS NOT NULL AND device_type IS NOT NULL').fetchone()[
                0]
        }

        return render_template('devices/vendors.html',
                               vendors_data=vendors_data,
                               pagination=pagination,
                               current_search=search_vendor,
                               vendor_stats=vendor_stats)

    except Exception as e:
        current_app.logger.error(f"Error in vendors: {e}")
        return render_template('devices/vendors.html',
                               vendors_data=[],
                               pagination={'page': 1, 'per_page': 30, 'total': 0, 'total_pages': 0, 'has_prev': False,
                                           'has_next': False},
                               current_search=request.args.get('search', ''),
                               vendor_stats={'total_vendors': 0, 'total_devices': 0, 'avg_confidence': 0,
                                             'unique_types': 0},
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
            ORDER BY dc.confidence_score DESC
        ''', (vendor_name,)).fetchall()

        if not vendor_devices:
            return render_template('errors/404.html'), 404

        # Statistiche vendor
        vendor_stats = db.execute('''
            SELECT 
                COUNT(*) as total_devices,
                AVG(confidence_score) as avg_confidence,
                COUNT(DISTINCT device_type) as unique_types,
                COUNT(DISTINCT device_subtype) as unique_subtypes
            FROM device_classification
            WHERE vendor_oui = ?
        ''', (vendor_name,)).fetchone()

        # Distribuzione per tipo
        type_distribution = db.execute('''
            SELECT device_type, COUNT(*) as count
            FROM device_classification
            WHERE vendor_oui = ? AND device_type IS NOT NULL
            GROUP BY device_type
            ORDER BY count DESC
        ''', (vendor_name,)).fetchall()

        return render_template('devices/vendor_detail.html',
                               vendor_name=vendor_name,
                               vendor_devices=vendor_devices,
                               vendor_stats=vendor_stats,
                               type_distribution=type_distribution)

    except Exception as e:
        current_app.logger.error(f"Error in vendor_detail for {vendor_name}: {e}")
        return render_template('errors/500.html'), 500


# ===========================
# API ENDPOINTS
# ===========================

@devices_bp.route('/api/classification')
def api_classification():
    """API endpoint per dati classificazione"""
    try:
        db = get_db()

        # Parametri
        device_type = request.args.get('type')
        limit = int(request.args.get('limit', 100))

        # Query base
        query = '''
            SELECT dc.*, h.hostname, h.status
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

        return jsonify(stats)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================
# DEBUG E UTILITY ROUTES
# ===========================

@devices_bp.route('/classification/debug')
def classification_debug():
    """Endpoint di debug per verificare lo stato della classificazione"""
    try:
        db = get_db()

        debug_info = {
            'database_status': {},
            'sample_data': {},
            'tables_info': {},
            'timestamp': datetime.now().isoformat()
        }

        # Statistiche tabelle
        debug_info['database_status'] = {
            'device_classification_count': db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0],
            'hosts_count': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0],
            'hosts_up_count': db.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"').fetchone()[0],
            'ports_count': db.execute('SELECT COUNT(*) FROM ports').fetchone()[0],
        }

        # Verifica se vulnerabilities table esiste
        try:
            vuln_count = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
            debug_info['database_status']['vulnerabilities_count'] = vuln_count
        except:
            debug_info['database_status']['vulnerabilities_count'] = 'Table not found'

        # Campioni di dati
        try:
            sample_classifications = db.execute('''
                SELECT ip_address, device_type, confidence_score 
                FROM device_classification 
                ORDER BY confidence_score DESC 
                LIMIT 5
            ''').fetchall()
            debug_info['sample_data']['classifications'] = [dict(row) for row in sample_classifications]
        except Exception as e:
            debug_info['sample_data']['classifications'] = f"Error: {str(e)}"

        try:
            sample_hosts = db.execute('''
                SELECT ip_address, hostname, status 
                FROM hosts 
                WHERE status = "up" 
                LIMIT 5
            ''').fetchall()
            debug_info['sample_data']['hosts'] = [dict(row) for row in sample_hosts]
        except Exception as e:
            debug_info['sample_data']['hosts'] = f"Error: {str(e)}"

        # Struttura tabelle
        try:
            classification_schema = db.execute('PRAGMA table_info(device_classification)').fetchall()
            debug_info['tables_info']['device_classification'] = [dict(row) for row in classification_schema]
        except Exception as e:
            debug_info['tables_info']['device_classification'] = f"Error: {str(e)}"

        return jsonify(debug_info)

    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@devices_bp.route('/classification/run-manual')
def run_manual_classification():
    """Endpoint per eseguire classificazione manuale"""
    try:
        # Verifica prima se ci sono host
        db = get_db()
        hosts_count = db.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"').fetchone()[0]

        if hosts_count == 0:
            return jsonify({
                'status': 'error',
                'message': 'No active hosts found in database'
            })

        # Prova a importare e eseguire il classificatore
        try:
            from core.device_classifier import DeviceClassifier
            from core.database_manager import DatabaseManager

            db_manager = DatabaseManager()
            classifier = DeviceClassifier(db_manager)

            current_app.logger.info("Starting manual classification...")
            classifier.classify_all_devices()

            # Conta risultati
            new_count = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]

            return jsonify({
                'status': 'success',
                'message': f'Classification completed. {new_count} devices classified.',
                'classified_devices': new_count,
                'hosts_processed': hosts_count
            })

        except ImportError as ie:
            return jsonify({
                'status': 'error',
                'message': f'Could not import classifier modules: {str(ie)}',
                'suggestion': 'Check if core modules are available'
            })

        except Exception as ce:
            return jsonify({
                'status': 'error',
                'message': f'Classification error: {str(ce)}',
                'traceback': traceback.format_exc()
            })

    except Exception as e:
        current_app.logger.error(f"Error in manual classification: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500


@devices_bp.route('/classification/force-populate')
def force_populate_classification():
    """Forza il popolamento della tabella device_classification"""
    try:
        db = get_db()

        # Conta host attuali
        hosts_count = db.execute('SELECT COUNT(*) FROM hosts WHERE status = "up"').fetchone()[0]

        if hosts_count == 0:
            return jsonify({
                'status': 'error',
                'message': 'No active hosts found in database'
            })

        # Conta classificazioni esistenti
        existing_count = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]

        # Se la tabella è vuota o ha pochi record, popolala
        if existing_count < hosts_count:
            # Inserisci record di base per ogni host
            db.execute('''
                INSERT OR REPLACE INTO device_classification 
                (ip_address, device_type, confidence_score, updated_at)
                SELECT 
                    ip_address, 
                    'Unknown' as device_type,
                    0.1 as confidence_score,
                    datetime('now') as updated_at
                FROM hosts 
                WHERE status = 'up'
                AND ip_address NOT IN (SELECT ip_address FROM device_classification)
            ''')

            new_count = db.execute('SELECT COUNT(*) FROM device_classification').fetchone()[0]

            return jsonify({
                'status': 'success',
                'message': f'Created {new_count - existing_count} base records in device_classification table',
                'hosts_available': hosts_count,
                'records_created': new_count - existing_count,
                'total_records': new_count
            })
        else:
            return jsonify({
                'status': 'info',
                'message': f'device_classification table already contains {existing_count} records',
                'existing_count': existing_count,
                'hosts_available': hosts_count
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'traceback': traceback.format_exc()
        }), 500