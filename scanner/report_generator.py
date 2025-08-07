# ===================================================================
# scanner/report_generator.py - Generatore report
import json
from datetime import datetime, timedelta
import os


class ReportGenerator:
    """Generatore di report per lo scanner"""

    def __init__(self, db_manager):
        self.db = db_manager

    def generate_summary_report(self):
        """Genera report riassuntivo"""
        conn = self.db.get_connection()
        cursor = conn.cursor()

        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {},
            'devices': [],
            'top_vulnerabilities': [],
            'service_distribution': {}
        }

        # Statistiche generali
        cursor.execute('SELECT COUNT(*) FROM devices WHERE is_active = 1')
        report['summary']['total_devices'] = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM services WHERE is_active = 1')
        report['summary']['total_services'] = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE is_active = 1')
        report['summary']['total_vulnerabilities'] = cursor.fetchone()[0]

        # Dispositivi con più vulnerabilità
        cursor.execute('''
            SELECT d.ip_address, d.hostname, COUNT(v.id) as vuln_count
            FROM devices d
            LEFT JOIN vulnerabilities v ON d.id = v.device_id AND v.is_active = 1
            WHERE d.is_active = 1
            GROUP BY d.id
            ORDER BY vuln_count DESC
            LIMIT 10
        ''')

        report['devices'] = [dict(row) for row in cursor.fetchall()]

        # Vulnerabilità più comuni
        cursor.execute('''
            SELECT cve_id, severity, COUNT(*) as count
            FROM vulnerabilities
            WHERE is_active = 1 AND cve_id IS NOT NULL
            GROUP BY cve_id, severity
            ORDER BY count DESC
            LIMIT 10
        ''')

        report['top_vulnerabilities'] = [dict(row) for row in cursor.fetchall()]

        # Distribuzione servizi
        cursor.execute('''
            SELECT service_name, COUNT(*) as count
            FROM services
            WHERE is_active = 1 AND service_name IS NOT NULL
            GROUP BY service_name
            ORDER BY count DESC
            LIMIT 15
        ''')

        services = cursor.fetchall()
        report['service_distribution'] = {row['service_name']: row['count'] for row in services}

        conn.close()
        return report

    def generate_device_report(self, device_id):
        """Genera report dettagliato per un dispositivo"""
        device = self.db.get_device_details(device_id)
        if not device:
            return None

        report = {
            'generated_at': datetime.now().isoformat(),
            'device': device,
            'risk_assessment': self._assess_device_risk(device),
            'recommendations': self._generate_recommendations(device)
        }

        return report

    def _assess_device_risk(self, device):
        """Valuta il rischio di un dispositivo"""
        risk_score = 0
        risk_factors = []

        # Fattori di rischio
        vulnerabilities = device.get('vulnerabilities', [])
        services = device.get('services', [])

        # Vulnerabilità critiche
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']

        if critical_vulns:
            risk_score += len(critical_vulns) * 30
            risk_factors.append(f"{len(critical_vulns)} vulnerabilità critiche")

        if high_vulns:
            risk_score += len(high_vulns) * 15
            risk_factors.append(f"{len(high_vulns)} vulnerabilità ad alto rischio")

        # Servizi esposti rischiosi
        risky_services = ['ftp', 'telnet', 'ssh', 'rdp', 'vnc', 'snmp']
        exposed_risky = [s for s in services if s.get('service_name', '').lower() in risky_services]

        if exposed_risky:
            risk_score += len(exposed_risky) * 10
            risk_factors.append(f"{len(exposed_risky)} servizi potenzialmente rischiosi esposti")

        # Servizi con versioni note vulnerabili
        outdated_services = [s for s in services if s.get('version') and 'old' in s.get('version', '').lower()]
        if outdated_services:
            risk_score += len(outdated_services) * 5
            risk_factors.append(f"{len(outdated_services)} servizi con versioni datate")

        # Determina livello di rischio
        if risk_score >= 100:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 20:
            risk_level = 'MEDIUM'
        elif risk_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'

        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors
        }

    def _generate_recommendations(self, device):
        """Genera raccomandazioni di sicurezza per il dispositivo"""
        recommendations = []

        vulnerabilities = device.get('vulnerabilities', [])
        services = device.get('services', [])

        # Raccomandazioni per vulnerabilità
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        if critical_vulns:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Vulnerabilità',
                'action': f'Correggere immediatamente {len(critical_vulns)} vulnerabilità critiche',
                'details': [v.get('cve_id', v.get('id')) for v in critical_vulns[:5]]
            })

        # Raccomandazioni per servizi
        unnecessary_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        risky_exposed = [s for s in services if s.get('service_name', '').lower() in unnecessary_services]

        if risky_exposed:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Servizi',
                'action': 'Disabilitare servizi non sicuri',
                'details': [f"{s.get('service_name')} su porta {s.get('port')}" for s in risky_exposed]
            })

        # Raccomandazioni SNMP
        snmp_info = device.get('snmp')
        if snmp_info and snmp_info.get('community_string') == 'public':
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'SNMP',
                'action': 'Cambiare community string SNMP predefinita',
                'details': ['Community string "public" è insicura']
            })

        # Raccomandazioni generali
        if not device.get('os_name'):
            recommendations.append({
                'priority': 'LOW',
                'category': 'Inventario',
                'action': 'Identificare sistema operativo',
                'details': ['OS non identificato, necessaria verifica manuale']
            })

        return recommendations

    def export_to_json(self, report, filename=None):
        """Esporta report in formato JSON"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scanner/reports/report_{timestamp}.json"

        os.makedirs(os.path.dirname(filename), exist_ok=True)

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return filename

    def export_to_csv(self, report_type='devices'):
        """Esporta dati in formato CSV"""
        import csv

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scanner/reports/{report_type}_{timestamp}.csv"
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        conn = self.db.get_connection()
        cursor = conn.cursor()

        if report_type == 'devices':
            cursor.execute('''
                SELECT d.ip_address, d.mac_address, d.hostname, d.vendor, d.os_name,
                       d.first_seen, d.last_seen,
                       COUNT(s.id) as services_count,
                       COUNT(v.id) as vulnerabilities_count
                FROM devices d
                LEFT JOIN services s ON d.id = s.device_id AND s.is_active = 1
                LEFT JOIN vulnerabilities v ON d.id = v.device_id AND v.is_active = 1
                WHERE d.is_active = 1
                GROUP BY d.id
            ''')

            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'MAC Address', 'Hostname', 'Vendor', 'OS',
                                 'First Seen', 'Last Seen', 'Services', 'Vulnerabilities'])
                writer.writerows(cursor.fetchall())

        elif report_type == 'vulnerabilities':
            cursor.execute('''
                SELECT d.ip_address, d.hostname, v.cve_id, v.severity, v.score,
                       v.description, v.first_detected
                FROM vulnerabilities v
                JOIN devices d ON v.device_id = d.id
                WHERE v.is_active = 1
                ORDER BY v.score DESC, d.ip_address
            ''')

            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Hostname', 'CVE ID', 'Severity', 'Score',
                                 'Description', 'First Detected'])
                writer.writerows(cursor.fetchall())

        conn.close()
        return filename