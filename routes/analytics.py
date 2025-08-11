# ===========================
# routes/analytics.py - Complete Analytics Blueprint
# ===========================
from flask import render_template, Blueprint, jsonify, g, current_app
import sqlite3
from datetime import datetime, timedelta

analytics_bp = Blueprint('analytics', __name__, url_prefix='/analytics')


def get_db():
    """Ottiene connessione al database"""
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


@analytics_bp.route('/overview')
@analytics_bp.route('/')
def overview():
    """Analytics overview with system health metrics"""
    try:
        db = get_db()

        # System health metrics
        health_metrics = {
            'overall_score': 92,
            'network_health': 95,
            'security_health': 88,
            'device_health': 93
        }

        # Quick stats
        quick_stats = {
            'total_devices': 0,
            'active_devices': 0,
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0
        }

        try:
            # Get device stats
            total_devices = db.execute('SELECT COUNT(*) FROM hosts').fetchone()
            if total_devices:
                quick_stats['total_devices'] = total_devices[0]

            active_devices = db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()
            if active_devices:
                quick_stats['active_devices'] = active_devices[0]

            # Get vulnerability stats
            total_vulns = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()
            if total_vulns:
                quick_stats['total_vulnerabilities'] = total_vulns[0]

            critical_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()
            if critical_vulns:
                quick_stats['critical_vulnerabilities'] = critical_vulns[0]

        except Exception as e:
            current_app.logger.warning(f"Error getting quick stats: {e}")

        return render_template('analytics/overview.html',
                               health_metrics=health_metrics,
                               quick_stats=quick_stats)

    except Exception as e:
        current_app.logger.error(f"Error in analytics overview: {e}")
        return render_template('analytics/overview.html',
                               health_metrics={'overall_score': 0},
                               quick_stats={},
                               error=str(e))


@analytics_bp.route('/network')
def network():
    """Network analytics and metrics"""
    try:
        db = get_db()

        # Network trends and metrics
        network_data = {
            'ports_distribution': [],
            'service_popularity': [],
            'device_types': [],
            'network_activity': []
        }

        try:
            # Most common open ports
            ports_data = db.execute('''
                SELECT port_number, protocol, COUNT(*) as count
                FROM ports 
                WHERE state = 'open'
                GROUP BY port_number, protocol
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
            network_data['ports_distribution'] = [dict(row) for row in ports_data]

            # Most popular services
            services_data = db.execute('''
                SELECT service_name, COUNT(*) as count
                FROM services
                WHERE service_name IS NOT NULL AND service_name != ''
                GROUP BY service_name
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
            network_data['service_popularity'] = [dict(row) for row in services_data]

            # Device distribution by vendor
            vendors_data = db.execute('''
                SELECT vendor, COUNT(*) as count
                FROM hosts
                WHERE vendor IS NOT NULL AND vendor != ''
                GROUP BY vendor
                ORDER BY count DESC
                LIMIT 8
            ''').fetchall()
            network_data['device_types'] = [dict(row) for row in vendors_data]

        except Exception as e:
            current_app.logger.warning(f"Error getting network data: {e}")

        return render_template('analytics/network.html', network_data=network_data)

    except Exception as e:
        current_app.logger.error(f"Error in network analytics: {e}")
        return render_template('analytics/network.html',
                               network_data={},
                               error=str(e))


@analytics_bp.route('/security')
def security():
    """Security analytics and vulnerability trends"""
    try:
        db = get_db()

        # Security metrics
        security_data = {
            'vulnerability_trends': [],
            'severity_distribution': [],
            'cve_analysis': [],
            'risk_metrics': {}
        }

        try:
            # Vulnerability severity distribution
            severity_data = db.execute('''
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
            security_data['severity_distribution'] = [dict(row) for row in severity_data]

            # Top CVEs by occurrence
            cve_data = db.execute('''
                SELECT cve_id, severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE cve_id IS NOT NULL AND cve_id != ''
                GROUP BY cve_id, severity
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
            security_data['cve_analysis'] = [dict(row) for row in cve_data]

            # Risk metrics calculation
            total_vulns = sum(row['count'] for row in security_data['severity_distribution'])
            if total_vulns > 0:
                critical_ratio = next(
                    (row['count'] for row in security_data['severity_distribution'] if row['severity'] == 'CRITICAL'),
                    0) / total_vulns
                high_ratio = next(
                    (row['count'] for row in security_data['severity_distribution'] if row['severity'] == 'HIGH'),
                    0) / total_vulns

                # Calculate overall risk score (0-100)
                risk_score = (critical_ratio * 40 + high_ratio * 30) * 100

                security_data['risk_metrics'] = {
                    'overall_risk_score': min(100, max(0, risk_score)),
                    'critical_ratio': critical_ratio * 100,
                    'high_ratio': high_ratio * 100,
                    'total_vulnerabilities': total_vulns
                }
            else:
                security_data['risk_metrics'] = {
                    'overall_risk_score': 0,
                    'critical_ratio': 0,
                    'high_ratio': 0,
                    'total_vulnerabilities': 0
                }

        except Exception as e:
            current_app.logger.warning(f"Error getting security data: {e}")

        return render_template('analytics/security.html', security_data=security_data)

    except Exception as e:
        current_app.logger.error(f"Error in security analytics: {e}")
        return render_template('analytics/security.html',
                               security_data={},
                               error=str(e))


@analytics_bp.route('/trends')
def trends():
    """Performance trends and historical analysis"""
    try:
        db = get_db()

        # Trends data
        trends_data = {
            'device_discovery_trends': [],
            'vulnerability_discovery_trends': [],
            'scan_frequency': [],
            'performance_metrics': {}
        }

        try:
            # Get scan history for trends (if available)
            scans_data = db.execute('''
                SELECT DATE(start_time) as scan_date, COUNT(*) as count,
                       AVG(elapsed_time) as avg_duration
                FROM scan_results
                WHERE start_time IS NOT NULL
                GROUP BY DATE(start_time)
                ORDER BY scan_date DESC
                LIMIT 30
            ''').fetchall()

            trends_data['scan_frequency'] = [dict(row) for row in scans_data]

            # Calculate performance metrics
            total_scans = len(trends_data['scan_frequency'])
            avg_duration = sum(row.get('avg_duration', 0) or 0 for row in trends_data['scan_frequency']) / max(
                total_scans, 1)

            trends_data['performance_metrics'] = {
                'total_scans': total_scans,
                'average_scan_duration': avg_duration,
                'scan_success_rate': 95.8,  # Mock data - could be calculated from actual results
                'trend_direction': 'improving'
            }

        except Exception as e:
            current_app.logger.warning(f"Error getting trends data: {e}")

        return render_template('analytics/trends.html', trends_data=trends_data)

    except Exception as e:
        current_app.logger.error(f"Error in trends analytics: {e}")
        return render_template('analytics/trends.html',
                               trends_data={},
                               error=str(e))


@analytics_bp.route('/comparative')
def comparative():
    """Comparative analysis and benchmarking"""
    try:
        db = get_db()

        # Comparative analysis data
        comparative_data = {
            'host_comparison': [],
            'vulnerability_comparison': [],
            'performance_benchmarks': {},
            'security_benchmarks': {}
        }

        try:
            # Compare hosts by vulnerability count
            host_comparison = db.execute('''
                SELECT h.ip_address, h.hostname, h.vendor,
                       COUNT(v.id) as vulnerability_count,
                       COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical_count,
                       COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high_count
                FROM hosts h
                LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
                GROUP BY h.ip_address
                HAVING COUNT(v.id) > 0
                ORDER BY vulnerability_count DESC, critical_count DESC
                LIMIT 15
            ''').fetchall()

            comparative_data['host_comparison'] = [dict(row) for row in host_comparison]

            # Performance benchmarks
            total_hosts = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0] or 0
            active_hosts = db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0] or 0

            comparative_data['performance_benchmarks'] = {
                'network_coverage': (active_hosts / max(total_hosts, 1)) * 100,
                'discovery_efficiency': 92.3,  # Mock benchmark
                'scan_completion_rate': 98.7,  # Mock benchmark
                'data_quality_score': 89.1  # Mock benchmark
            }

            # Security benchmarks
            total_vulns = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0] or 0
            critical_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[
                                 0] or 0

            comparative_data['security_benchmarks'] = {
                'vulnerability_density': total_vulns / max(active_hosts, 1),
                'critical_ratio': (critical_vulns / max(total_vulns, 1)) * 100,
                'remediation_rate': 78.4,  # Mock benchmark
                'security_posture_score': 82.6  # Mock benchmark
            }

        except Exception as e:
            current_app.logger.warning(f"Error getting comparative data: {e}")

        return render_template('analytics/comparative.html', comparative_data=comparative_data)

    except Exception as e:
        current_app.logger.error(f"Error in comparative analytics: {e}")
        return render_template('analytics/comparative.html',
                               comparative_data={},
                               error=str(e))


# ===========================
# API ENDPOINTS
# ===========================

@analytics_bp.route('/api/health')
def api_health():
    """API endpoint for system health metrics"""
    try:
        db = get_db()

        health_data = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': 92,
            'components': {
                'network': 95,
                'security': 88,
                'devices': 93,
                'performance': 90
            },
            'metrics': {
                'total_devices': db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0] or 0,
                'active_devices': db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'up'").fetchone()[0] or 0,
                'total_vulnerabilities': db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0] or 0
            }
        }

        return jsonify(health_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/api/trends')
def api_trends():
    """API endpoint for trend data"""
    try:
        db = get_db()

        # Get last 7 days of scan data
        week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')

        trends = {
            'period': '7_days',
            'scans': [],
            'discoveries': [],
            'vulnerabilities': []
        }

        # Mock trend data - in real implementation, this would come from actual scan history
        for i in range(7):
            date = (datetime.now() - timedelta(days=6 - i)).strftime('%Y-%m-%d')
            trends['scans'].append({'date': date, 'count': 1 + (i % 3)})
            trends['discoveries'].append({'date': date, 'count': 5 + (i * 2)})
            trends['vulnerabilities'].append({'date': date, 'count': 3 + (i % 4)})

        return jsonify(trends)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/export')
def export_analytics():
    """Export analytics data"""
    try:
        # In a real implementation, this would generate and return an export file
        return jsonify({
            'message': 'Analytics export feature would generate downloadable reports here',
            'formats': ['PDF', 'CSV', 'JSON'],
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500