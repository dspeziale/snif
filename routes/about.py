# ===========================
# routes/about.py - About Blueprint
# ===========================
from datetime import datetime

from flask import Blueprint, render_template

about_bp = Blueprint('about', __name__, url_prefix='/about')


@about_bp.route('/')
def index():
    """Pagina about principale"""
    app_info = {
        'name': 'Network Analysis Tool',
        'version': '1.0.0',
        'description': 'Comprehensive network analysis and vulnerability assessment tool',
        'author': 'Security Team',
        'build_date': datetime.now().strftime('%Y-%m-%d')
    }

    return render_template('about/index.html', app_info=app_info)


@about_bp.route('/version')
def version():
    """Informazioni versione"""
    version_info = {
        'app_version': '1.0.0',
        'python_version': '3.9+',
        'flask_version': '2.3.3',
        'database_version': 'SQLite 3',
        'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    return render_template('about/version.html', version_info=version_info)


@about_bp.route('/credits')
def credits():
    """Credits e riconoscimenti"""
    credits_info = {
        'development_team': [
            'Network Security Team',
            'Database Analytics Team',
            'UI/UX Design Team'
        ],
        'open_source_libraries': [
            'Flask - Web Framework',
            'Bootstrap - UI Framework',
            'AdminLTE - Admin Template',
            'ApexCharts - Data Visualization',
            'SQLite - Database Engine'
        ],
        'special_thanks': [
            'Nmap Development Team',
            'Security Research Community',
            'Open Source Contributors'
        ]
    }

    return render_template('about/credits.html', credits=credits_info)


@about_bp.route('/license')
def license():
    """Informazioni licenza"""
    license_info = {
        'license_type': 'MIT License',
        'copyright_year': datetime.now().year,
        'copyright_holder': 'Network Security Team',
        'license_text': '''
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        '''
    }

    return render_template('about/license.html', license_info=license_info)