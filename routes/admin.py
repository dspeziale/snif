# ===========================
# routes/admin.py - Admin Blueprint
# ===========================
from datetime import datetime

from flask import render_template, Blueprint, current_app

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/config')
def config():
    """Configurazione sistema"""
    config_info = {
        'database_path': current_app.config.get('DATABASE_PATH', 'N/A'),
        'debug_mode': current_app.debug,
        'secret_key_set': bool(current_app.config.get('SECRET_KEY')),
        'templates_auto_reload': current_app.config.get('TEMPLATES_AUTO_RELOAD', False)
    }

    return render_template('admin/config.html', config=config_info)


@admin_bp.route('/logs/parsing')
def parsing_logs():
    """Log di parsing"""
    # Simulazione log di parsing
    log_entries = [
        {
            'timestamp': datetime.now(),
            'level': 'INFO',
            'message': 'XML file parsed successfully: network_scan.xml',
            'details': '150 hosts processed'
        },
        {
            'timestamp': datetime.now(),
            'level': 'WARNING',
            'message': 'Unable to classify device 192.168.1.100',
            'details': 'Low confidence score: 0.3'
        }
    ]

    return render_template('admin/parsing_logs.html', logs=log_entries)