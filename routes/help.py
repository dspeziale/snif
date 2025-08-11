# ===========================
# routes/help.py - Help Blueprint
# ===========================
from flask import render_template, Blueprint

help_bp = Blueprint('help', __name__, url_prefix='/help')


@help_bp.route('/docs')
@help_bp.route('/')
def documentation():
    """Documentazione principale"""
    return render_template('help/documentation.html')


@help_bp.route('/docs/user-guide')
def user_guide():
    """Guida utente"""
    return render_template('help/user_guide.html')


@help_bp.route('/docs/api')
def api_reference():
    """API Reference"""
    # Lista degli endpoint API disponibili
    api_endpoints = [
        {
            'endpoint': '/api/stats',
            'method': 'GET',
            'description': 'Ottieni statistiche generali del sistema',
            'example': '/api/stats'
        },
        {
            'endpoint': '/network/api/hosts',
            'method': 'GET',
            'description': 'Lista degli host in formato JSON',
            'example': '/network/api/hosts?limit=100'
        },
        {
            'endpoint': '/security/api/vulnerabilities',
            'method': 'GET',
            'description': 'Lista delle vulnerabilità',
            'example': '/security/api/vulnerabilities?severity=CRITICAL'
        }
    ]

    return render_template('help/api_reference.html', endpoints=api_endpoints)