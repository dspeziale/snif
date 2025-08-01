"""
API Blueprint per l'interfaccia web del sistema di network scanning
"""
from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import tempfile
import logging
from datetime import datetime
from typing import Dict, Any

from .network_scanner import NetworkScanManager, ScanTemplateManager, validate_target, estimate_scan_time

logger = logging.getLogger(__name__)

# Crea blueprint
scanner_bp = Blueprint('scanner', __name__, url_prefix='/api/scanner')

# Variabile globale per il manager (inizializzata dall'app principale)
scan_manager: NetworkScanManager = None


def init_scanner_api(manager: NetworkScanManager):
    """Inizializza l'API con il manager"""
    global scan_manager
    scan_manager = manager


@scanner_bp.route('/status', methods=['GET'])
def get_system_status():
    """Restituisce lo stato del sistema"""
    try:
        status = scan_manager.get_system_status()
        return jsonify({
            'success': True,
            'data': status
        })
    except Exception as e:
        logger.error(f"Errore getting system status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scans', methods=['GET'])
def get_scan_history():
    """Recupera la cronologia delle scansioni"""
    try:
        limit = request.args.get('limit', 50, type=int)
        scan_type = request.args.get('type')

        history = scan_manager.get_scan_history(limit)

        # Filtra per tipo se specificato
        if scan_type:
            history = [s for s in history if s.get('scan_type') == scan_type]

        return jsonify({
            'success': True,
            'data': history
        })
    except Exception as e:
        logger.error(f"Errore getting scan history: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scans/active', methods=['GET'])
def get_active_scans():
    """Recupera le scansioni attualmente in corso"""
    try:
        active = scan_manager.scanner.get_active_scans()
        return jsonify({
            'success': True,
            'data': active
        })
    except Exception as e:
        logger.error(f"Errore getting active scans: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scans/execute', methods=['POST'])
def execute_scan():
    """Esegue una scansione manuale"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'Dati JSON richiesti'
            }), 400

        scan_type = data.get('scan_type')
        target = data.get('target')
        options = data.get('options', '')
        async_scan = data.get('async', True)

        # Validazione
        if not scan_type or not target:
            return jsonify({
                'success': False,
                'error': 'scan_type e target sono obbligatori'
            }), 400

        if not validate_target(target):
            return jsonify({
                'success': False,
                'error': 'Target non valido'
            }), 400

        # Esegui scansione
        if async_scan:
            future = scan_manager.execute_async_scan(scan_type, target, options)
            return jsonify({
                'success': True,
                'message': 'Scansione avviata in background',
                'estimated_time': estimate_scan_time(scan_type, target)
            })
        else:
            result = scan_manager.execute_manual_scan(scan_type, target, options)
            return jsonify({
                'success': result.get('success', False),
                'data': result
            })

    except Exception as e:
        logger.error(f"Errore executing scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scans/<scan_id>/kill', methods=['POST'])
def kill_scan(scan_id):
    """Termina una scansione in corso"""
    try:
        success = scan_manager.scanner.kill_scan(scan_id)
        return jsonify({
            'success': success,
            'message': 'Scansione terminata' if success else 'Scansione non trovata'
        })
    except Exception as e:
        logger.error(f"Errore killing scan {scan_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/templates', methods=['GET'])
def get_scan_templates():
    """Recupera i template di scansione disponibili"""
    try:
        template_manager = ScanTemplateManager(scan_manager.config)
        templates = template_manager.get_all_templates()

        return jsonify({
            'success': True,
            'data': templates
        })
    except Exception as e:
        logger.error(f"Errore getting scan templates: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/templates/<template_name>', methods=['GET'])
def get_scan_template(template_name):
    """Recupera un template specifico"""
    try:
        template_manager = ScanTemplateManager(scan_manager.config)
        template = template_manager.get_template(template_name)

        if not template:
            return jsonify({
                'success': False,
                'error': 'Template non trovato'
            }), 404

        return jsonify({
            'success': True,
            'data': template
        })
    except Exception as e:
        logger.error(f"Errore getting template {template_name}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/inventory', methods=['GET'])
def get_inventory():
    """Recupera l'inventario completo della rete"""
    try:
        include_ports = request.args.get('include_ports', 'false').lower() == 'true'
        include_vulns = request.args.get('include_vulns', 'false').lower() == 'true'

        inventory = scan_manager.get_network_inventory()

        # Filtra dati se non richiesti (per performance)
        if not include_ports:
            for host in inventory['hosts']:
                host.pop('ports', None)

        if not include_vulns:
            for host in inventory['hosts']:
                host.pop('vulnerabilities', None)

        return jsonify({
            'success': True,
            'data': inventory
        })
    except Exception as e:
        logger.error(f"Errore getting inventory: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/hosts', methods=['GET'])
def get_hosts():
    """Recupera lista host con filtri"""
    try:
        device_type = request.args.get('device_type')
        status = request.args.get('status')
        has_vulns = request.args.get('has_vulnerabilities')

        hosts = scan_manager.db.get_all_hosts()

        # Applica filtri
        if device_type:
            hosts = [h for h in hosts if h.get('device_type') == device_type]

        if status:
            hosts = [h for h in hosts if h.get('status') == status]

        if has_vulns == 'true':
            # Filtra host con vulnerabilità
            filtered_hosts = []
            for host in hosts:
                vulns = scan_manager.db.get_host_vulnerabilities(host['id'])
                if vulns:
                    host['vulnerability_count'] = len(vulns)
                    filtered_hosts.append(host)
            hosts = filtered_hosts

        return jsonify({
            'success': True,
            'data': hosts
        })
    except Exception as e:
        logger.error(f"Errore getting hosts: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/hosts/<host_id>', methods=['GET'])
def get_host_details(host_id):
    """Recupera dettagli completi di un host"""
    try:
        host = scan_manager.db.get_host_by_id(int(host_id))
        if not host:
            return jsonify({
                'success': False,
                'error': 'Host non trovato'
            }), 404

        # Arricchisci con dati aggiuntivi
        host['ports'] = scan_manager.db.get_host_ports(host['id'])
        host['vulnerabilities'] = scan_manager.db.get_host_vulnerabilities(host['id'])

        # Informazioni MAC/Vendor
        if host.get('mac_address'):
            mac_info = scan_manager.oui_manager.get_comprehensive_mac_info(host['mac_address'])
            host['mac_info'] = mac_info

        return jsonify({
            'success': True,
            'data': host
        })
    except Exception as e:
        logger.error(f"Errore getting host {host_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Recupera vulnerabilità con filtri"""
    try:
        severity = request.args.get('severity')
        host_id = request.args.get('host_id', type=int)
        cve_id = request.args.get('cve_id')
        limit = request.args.get('limit', 100, type=int)

        with scan_manager.db.get_connection() as conn:
            query = """
                SELECT v.*, h.ip_address, h.hostname
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                WHERE v.status = 'open'
            """
            params = []

            if severity:
                query += " AND v.severity = ?"
                params.append(severity)

            if host_id:
                query += " AND v.host_id = ?"
                params.append(host_id)

            if cve_id:
                query += " AND v.cve_id LIKE ?"
                params.append(f'%{cve_id}%')

            query += " ORDER BY v.cvss_score DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            vulnerabilities = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'success': True,
            'data': vulnerabilities
        })
    except Exception as e:
        logger.error(f"Errore getting vulnerabilities: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/reports/<report_type>', methods=['GET'])
def generate_report(report_type):
    """Genera report specifici"""
    try:
        if report_type not in ['summary', 'vulnerabilities', 'topology']:
            return jsonify({
                'success': False,
                'error': 'Tipo di report non supportato'
            }), 400

        report = scan_manager.generate_report(report_type)

        return jsonify({
            'success': True,
            'data': report
        })
    except Exception as e:
        logger.error(f"Errore generating report {report_type}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/export/inventory', methods=['GET'])
def export_inventory():
    """Esporta inventario in vari formati"""
    try:
        format_type = request.args.get('format', 'json').lower()

        if format_type not in ['json', 'csv']:
            return jsonify({
                'success': False,
                'error': 'Formato non supportato (json, csv)'
            }), 400

        # Crea file temporaneo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"network_inventory_{timestamp}.{format_type}"
        temp_file = os.path.join(tempfile.gettempdir(), filename)

        # Esporta
        scan_manager.export_inventory(temp_file, format_type)

        return send_file(
            temp_file,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"Errore exporting inventory: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/import/nmap', methods=['POST'])
def import_nmap_xml():
    """Importa risultati da file XML NMAP"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'Nessun file fornito'
            }), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Nome file vuoto'
            }), 400

        # Salva file temporaneo
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(temp_path)

        try:
            # Importa risultati
            result = scan_manager.import_nmap_xml(temp_path, 'imported')

            return jsonify({
                'success': True,
                'message': f"Importati {len(result.get('hosts', []))} host",
                'data': result
            })
        finally:
            # Rimuovi file temporaneo
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        logger.error(f"Errore importing NMAP XML: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scheduler/jobs', methods=['GET'])
def get_scheduled_jobs():
    """Recupera job schedulati"""
    try:
        jobs = scan_manager.scheduler.get_jobs()
        return jsonify({
            'success': True,
            'data': jobs
        })
    except Exception as e:
        logger.error(f"Errore getting scheduled jobs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scheduler/jobs', methods=['POST'])
def add_scheduled_job():
    """Aggiunge un job schedulato"""
    try:
        data = request.get_json()

        required_fields = ['job_id', 'scan_type', 'target', 'interval_minutes']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Campo obbligatorio mancante: {field}'
                }), 400

        if not validate_target(data['target']):
            return jsonify({
                'success': False,
                'error': 'Target non valido'
            }), 400

        scan_manager.scheduler.add_job(
            data['job_id'],
            data['scan_type'],
            data['target'],
            data['interval_minutes'],
            data.get('options', ''),
            data.get('enabled', True)
        )

        return jsonify({
            'success': True,
            'message': f"Job {data['job_id']} aggiunto"
        })
    except Exception as e:
        logger.error(f"Errore adding scheduled job: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scheduler/jobs/<job_id>', methods=['DELETE'])
def remove_scheduled_job(job_id):
    """Rimuove un job schedulato"""
    try:
        scan_manager.scheduler.remove_job(job_id)
        return jsonify({
            'success': True,
            'message': f"Job {job_id} rimosso"
        })
    except Exception as e:
        logger.error(f"Errore removing scheduled job {job_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/scheduler/jobs/<job_id>/toggle', methods=['POST'])
def toggle_scheduled_job(job_id):
    """Abilita/disabilita un job schedulato"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)

        scan_manager.scheduler.enable_job(job_id, enabled)

        status = "abilitato" if enabled else "disabilitato"
        return jsonify({
            'success': True,
            'message': f"Job {job_id} {status}"
        })
    except Exception as e:
        logger.error(f"Errore toggling scheduled job {job_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/oui/update', methods=['POST'])
def update_oui_database():
    """Aggiorna database OUI"""
    try:
        result = scan_manager.oui_manager.update_database()
        return jsonify({
            'success': result.get('success', False),
            'data': result
        })
    except Exception as e:
        logger.error(f"Errore updating OUI database: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/nvd/update', methods=['POST'])
def update_nvd_database():
    """Aggiorna database NVD"""
    try:
        days_back = request.json.get('days_back', 7) if request.json else 7
        result = scan_manager.nvd_manager.update_nvd_database(days_back)
        return jsonify({
            'success': result.get('success', False),
            'data': result
        })
    except Exception as e:
        logger.error(f"Errore updating NVD database: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/cve/<cve_id>', methods=['GET'])
def get_cve_info(cve_id):
    """Recupera informazioni su un CVE specifico"""
    try:
        cve_info = scan_manager.nvd_manager.get_cve_info(cve_id)

        if not cve_info:
            return jsonify({
                'success': False,
                'error': 'CVE non trovato'
            }), 404

        return jsonify({
            'success': True,
            'data': cve_info
        })
    except Exception as e:
        logger.error(f"Errore getting CVE {cve_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/cve/search', methods=['GET'])
def search_cves():
    """Cerca CVE per termine"""
    try:
        search_term = request.args.get('q', '')
        limit = request.args.get('limit', 50, type=int)

        if not search_term:
            return jsonify({
                'success': False,
                'error': 'Termine di ricerca richiesto'
            }), 400

        cves = scan_manager.nvd_manager.search_cves(search_term, limit)

        return jsonify({
            'success': True,
            'data': cves
        })
    except Exception as e:
        logger.error(f"Errore searching CVEs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/maintenance', methods=['POST'])
def perform_maintenance():
    """Esegue manutenzione del sistema"""
    try:
        scan_manager.perform_maintenance()
        return jsonify({
            'success': True,
            'message': 'Manutenzione completata'
        })
    except Exception as e:
        logger.error(f"Errore performing maintenance: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scanner_bp.route('/validate/target', methods=['POST'])
def validate_scan_target():
    """Valida un target di scansione"""
    try:
        data = request.get_json()
        target = data.get('target', '')

        is_valid = validate_target(target)

        result = {
            'valid': is_valid,
            'target': target
        }

        if is_valid:
            # Aggiungi stima tempo per diversi tipi di scansione
            result['estimated_times'] = {
                'discovery': estimate_scan_time('discovery', target),
                'quick_scan': estimate_scan_time('quick_scan', target),
                'comprehensive': estimate_scan_time('comprehensive', target),
                'vulnerability': estimate_scan_time('vulnerability', target)
            }

        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Errore validating target: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Error handlers
@scanner_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint non trovato'
    }), 404


@scanner_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'error': 'Metodo non consentito'
    }), 405


@scanner_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Errore interno del server'
    }), 500