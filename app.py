from flask import Flask, render_template, redirect, url_for
from blueprint.api import api
import os


def create_app():
    """Factory per creare l'applicazione Flask"""
    app = Flask(__name__)

    # Configurazione base
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Registrazione del blueprint API
    app.register_blueprint(api)

    # Route principale
    @app.route('/')
    def index():
        """Homepage con dashboard"""
        return render_template('index.html')

    # Route per le diverse sezioni
    @app.route('/dashboard')
    @app.route('/dashboard/<version>')
    def dashboard(version='v1'):
        """Dashboard con versioni diverse"""
        return render_template('index.html', dashboard_version=version)

    @app.route('/widgets')
    def widgets():
        """Pagina widgets"""
        return render_template('widgets.html')

    @app.route('/charts/<chart_type>')
    def charts(chart_type):
        """Pagine per i grafici"""
        return render_template(f'charts/{chart_type}.html')

    @app.route('/ui/<ui_type>')
    def ui_elements(ui_type):
        """Elementi UI"""
        return render_template(f'ui/{ui_type}.html')

    @app.route('/forms/<form_type>')
    def forms(form_type):
        """Pagine dei form"""
        return render_template(f'forms/{form_type}.html')

    @app.route('/tables/<table_type>')
    def tables(table_type):
        """Pagine delle tabelle"""
        return render_template(f'tables/{table_type}.html')

    @app.route('/calendar')
    def calendar():
        """Pagina calendario"""
        return render_template('calendar.html')

    @app.route('/gallery')
    def gallery():
        """Pagina galleria"""
        return render_template('gallery.html')

    @app.route('/kanban')
    def kanban():
        """Pagina kanban board"""
        return render_template('kanban.html')

    @app.route('/layout/<layout_type>')
    def layout_options(layout_type):
        """Opzioni di layout"""
        return render_template(f'layouts/{layout_type}.html')

    # Route per l'autenticazione (placeholder)
    @app.route('/login')
    def login():
        """Pagina di login"""
        return render_template('auth/login.html')

    @app.route('/logout')
    def logout():
        """Logout dell'utente"""
        # Qui implementeresti la logica di logout
        return redirect(url_for('login'))

    @app.route('/profile')
    def profile():
        """Profilo utente"""
        return render_template('profile.html')

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        """Pagina 404"""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Pagina 500"""
        return render_template('errors/500.html'), 500

    # Context processor per informazioni globali
    @app.context_processor
    def inject_global_vars():
        """Inietta variabili globali nei template"""
        return {
            'app_name': 'AdminLTE Flask Dashboard',
            'app_version': '4.0.0',
            'current_user': {
                'name': 'Alexander Pierce',
                'email': 'alexander@example.com',
                'join_date': 'Nov. 2023',
                'avatar': '/static/assets/img/user2-160x160.jpg'
            }
        }

    return app


# Per l'esecuzione diretta
if __name__ == '__main__':
    app = create_app()

    # Crea le directory necessarie se non esistono
    directories = [
        'static/css', 'static/js', 'static/assets/img',
        'templates/charts', 'templates/ui', 'templates/forms',
        'templates/tables', 'templates/layouts', 'templates/auth',
        'templates/errors'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)

    print("🚀 Avvio dell'applicazione Flask AdminLTE")
    print("📁 Struttura directory creata")
    print("🔧 Per utilizzare l'applicazione:")
    print("   1. Copia i file CSS e JS di AdminLTE nella cartella static/")
    print("   2. Copia le immagini di AdminLTE nella cartella static/assets/img/")
    print("   3. Assicurati che il file config.json sia nella root del progetto")
    print("📊 Dashboard disponibile su: http://localhost:5000")

    app.run(host='0.0.0.0', port=5000, debug=True)