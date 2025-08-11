# ===========================
# routes/analytics.py - Analytics Blueprint
# ===========================
from flask import render_template, Blueprint


analytics_bp = Blueprint('analytics', __name__, url_prefix='/analytics')


@analytics_bp.route('/overview')
@analytics_bp.route('/')
def overview():
    """Analytics overview"""
    return render_template('analytics/overview.html')


@analytics_bp.route('/network')
def network():
    """Network analytics"""
    try:
        db = get_db()

        # Trend analysis
        network_trends = {
            'hosts_over_time': [],  # Se hai timestamp nelle scansioni
            'ports_distribution': db.execute('''
                SELECT port_number, COUNT(*) as count
                FROM ports WHERE state = 'open'
                GROUP BY port_number
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall(),
            'service_popularity': db.execute('''
                SELECT service_name, COUNT(*) as count
                FROM services
                WHERE service_name IS NOT NULL
                GROUP BY service_name
                ORDER BY count DESC
                LIMIT 10
            ''').fetchall()
        }

        return render_template('analytics/network.html', trends=network_trends)

    except Exception as e:
        return render_template('analytics/network.html', error=str(e))