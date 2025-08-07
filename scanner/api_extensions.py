# ===================================================================
# scanner/api_extensions.py - Estensioni API aggiuntive
from flask import Blueprint, jsonify, request, send_file
import tempfile
import os


def create_api_blueprint(scanner, db_manager, report_generator, scheduler):
    """Crea blueprint con API estese"""

    api_bp = Blueprint('api_extended', __name__, url_prefix='/api/v2')

    @api_bp.route('/status')
    def get_system_status():
        """Stato del sistema scanner"""
        try:
            # Statistiche sistema
            stats = db_manager.get_dashboard_stats()

            # Stato scheduler
            scheduled_tasks = scheduler.get_scheduled_tasks() if scheduler else []

            # Ultimi scan
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_type, target, start_time, status, devices_found
                FROM scan_history
                ORDER BY start_time DESC
                LIMIT 10
            ''')
            recent_scans = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return jsonify({
                'status': 'running',
                'statistics': stats,
                'scheduled_tasks': len(scheduled_tasks),
                'recent_scans': recent_scans
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @api_bp.route('/devices/search')
    def search_devices():
        """Ricerca dispositivi con filtri"""
        try:
            # Parametri di ricerca
            ip = request.args.get('ip', '')
            hostname = request.args.get('hostname', '')
            vendor = request.args.get('vendor', '')
            os_name = request.args.get('os', '')
            has_vulnerabilities = request.args.get('has_vulns', '').lower() == 'true'

            conn = db_manager.get_connection()
            cursor = conn.cursor()

            # Costruisci query dinamica
            where_clauses = ['d.is_active = 1']
            params = []

            if ip:
                where_clauses.append('d.ip_address LIKE ?')
                params.append(f'%{ip}%')

            if hostname:
                where_clauses.append('d.hostname LIKE ?')
                params.append(f'%{hostname}%')

            if vendor:
                where_clauses.append('d.vendor LIKE ?')
                params.append(f'%{vendor}%')

            if os_name:
                where_clauses.append('d.os_name LIKE ?')
                params.append(f'%{os_name}%')

            query = f'''
                SELECT d.*, 
                       COUNT(DISTINCT s.id) as services_count,
                       COUNT(DISTINCT v.id) as vulnerabilities_count
                FROM devices d
                LEFT JOIN services s ON d.id = s.device_id AND s.is_active = 1
                LEFT JOIN vulnerabilities v ON d.id = v.device_id AND v.is_active = 1
                WHERE {' AND '.join(where_clauses)}
                GROUP BY d.id
            '''

            if has_vulnerabilities:
                query += ' HAVING vulnerabilities_count > 0'

            query += ' ORDER BY d.last_seen DESC'

            cursor.execute(query, params)
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return jsonify({
                'devices': devices,
                'count': len(devices)
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @api_bp.route('/vulnerabilities/summary')
    def get_vulnerabilities_summary():
        """Riassunto vulnerabilità"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            # Conteggio per severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE is_active = 1
                GROUP BY severity
                ORDER BY 
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            ''')
            severity_counts = dict(cursor.fetchall())

            # Top CVE
            cursor.execute('''
                SELECT cve_id, severity, COUNT(*) as affected_devices
                FROM vulnerabilities v
                WHERE v.is_active = 1 AND v.cve_id IS NOT NULL
                GROUP BY cve_id, severity
                ORDER BY affected_devices DESC
                LIMIT 10
            ''')
            top_cves = [dict(row) for row in cursor.fetchall()]

            # Dispositivi più vulnerabili
            cursor.execute('''
                SELECT d.ip_address, d.hostname, COUNT(v.id) as vuln_count,
                       SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
                FROM devices d
                JOIN vulnerabilities v ON d.id = v.device_id
                WHERE v.is_active = 1 AND d.is_active = 1
                GROUP BY d.id
                ORDER BY critical_count DESC, vuln_count DESC
                LIMIT 10
            ''')
            most_vulnerable = [dict(row) for row in cursor.fetchall()]

            conn.close()

            return jsonify({
                'severity_distribution': severity_counts,
                'top_cves': top_cves,
                'most_vulnerable_devices': most_vulnerable
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @api_bp.route('/reports/generate/<report_type>')
    def generate_report(report_type):
        """Genera e scarica report"""
        try:
            if report_type == 'summary':
                report = report_generator.generate_summary_report()
                filename = report_generator.export_to_json(report)
                return send_file(filename, as_attachment=True)

            elif report_type == 'devices_csv':
                filename = report_generator.export_to_csv('devices')
                return send_file(filename, as_attachment=True)

            elif report_type == 'vulnerabilities_csv':
                filename = report_generator.export_to_csv('vulnerabilities')
                return send_file(filename, as_attachment=True)

            else:
                return jsonify({'error': 'Report type non supportato'}), 400

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @api_bp.route('/scan/bulk', methods=['POST'])
    def bulk_scan():
        """Avvia scansioni multiple"""
        try:
            data = request.get_json()
            scan_type = data.get('type', 'services')
            device_ids = data.get('device_ids', [])

            if not device_ids:
                return jsonify({'error': 'Nessun dispositivo specificato'}), 400

            results = []
            for device_id in device_ids:
                if scheduler:
                    # Usa scheduler per gestire le scansioni
                    scheduler.schedule_task(scan_type, device_id, priority=2)
                    results.append({'device_id': device_id, 'status': 'scheduled'})
                else:
                    # Esegui direttamente (non raccomandato per molti dispositivi)
                    if scan_type == 'services':
                        result = scanner.run_services_scan(device_id)
                    elif scan_type == 'vulnerabilities':
                        result = scanner.run_vulnerability_scan(device_id)
                    else:
                        result = {'error': 'Tipo scan non supportato'}

                    results.append({'device_id': device_id, 'result': result})

            return jsonify({
                'scheduled': len(results),
                'results': results
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @api_bp.route('/network/topology')
    def get_network_topology():
        """Ottieni topologia di rete semplificata"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            # Raggruppa dispositivi per subnet
            cursor.execute('''
                SELECT 
                    SUBSTR(ip_address, 1, INSTR(ip_address || '.', '.', -1, 2) - 1) as subnet,
                    COUNT(*) as device_count,
                    GROUP_CONCAT(ip_address) as devices
                FROM devices
                WHERE is_active = 1
                GROUP BY subnet
                ORDER BY device_count DESC
            ''')

            subnets = []
            for row in cursor.fetchall():
                subnet_data = dict(row)
                subnet_data['devices'] = subnet_data['devices'].split(',')[:10]  # Limit devices shown
                subnets.append(subnet_data)

            # Servizi più comuni
            cursor.execute('''
                SELECT service_name, port, COUNT(*) as count
                FROM services
                WHERE is_active = 1 AND service_name IS NOT NULL
                GROUP BY service_name, port
                ORDER BY count DESC
                LIMIT 20
            ''')

            common_services = [dict(row) for row in cursor.fetchall()]

            conn.close()

            return jsonify({
                'subnets': subnets,
                'common_services': common_services
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return api_bp