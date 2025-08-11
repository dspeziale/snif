from flask import Flask, render_template, request, jsonify, g, flash, redirect, url_for
import os
import sqlite3
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any

# Crea l'applicazione Flask
app = Flask(__name__)

# Configurazione
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'


# Importa e registra la blueprint del menu dopo aver creato l'app
from menu import menu_bp

app.register_blueprint(menu_bp)

def format_datetime(value):
    """Formatta datetime per i template"""
    if value is None:
        return 'N/A'
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value
    return value.strftime('%d/%m/%Y %H:%M:%S')


def format_timestamp(value):
    """Formatta timestamp Unix per i template"""
    if value is None:
        return 'N/A'
    try:
        dt = datetime.fromtimestamp(float(value))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except:
        return str(value)


# Registra i filtri per i template
app.jinja_env.filters['datetime'] = format_datetime
app.jinja_env.filters['timestamp'] = format_timestamp


@app.route('/')
def index():
    """Homepage con dashboard principale"""
    return redirect(url_for('network.dashboard'))



# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


# Context processor per rendere disponibili alcune variabili in tutti i template
@app.context_processor
def inject_template_vars():
    """Inietta variabili in tutti i template"""
    return {
        'current_endpoint': getattr(g, 'current_endpoint', None),
        'now': datetime.now()
    }


@app.before_request
def before_request():
    """Eseguito prima di ogni richiesta"""
    g.current_endpoint = request.endpoint


if __name__ == '__main__':
    # Assicurati che le cartelle necessarie esistano
    for directory in ['templates', 'templates/errors', 'templates/network',
                      'static', 'static/css', 'static/js', 'static/img', 'instance']:
        if not os.path.exists(directory):
            os.makedirs(directory)

    app.run(debug=True, host='0.0.0.0', port=8132)