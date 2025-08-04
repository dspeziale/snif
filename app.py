"""
Applicazione Flask AdminLTE aggiornata per utilizzare il database SQLite
al posto dei file JSON per menu, messaggi e notifiche
"""
from flask import Flask, render_template, redirect, url_for, request, jsonify
import os

# Import delle configurazioni e modelli del database
from database_config import init_database, get_database_info
from models import db
from db_manager import menu_manager, message_manager, notification_manager, stats_manager

# Import del nuovo blueprint API
from blueprint.api import api


def create_app():
    """Factory per creare l'applicazione Flask"""
    app = Flask(__name__)

    # Configurazione base
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Inizializza il database SQLite
    init_database(app)

    # Registrazione del blueprint API aggiornato
    app.register_blueprint(api)

    # ===============================
    # ROUTE PRINCIPALI
    # ===============================

    @app.route('/')
    def index():
        """Homepage con dashboard"""
        return render_template('index.html')

    @app.route('/dashboard')
    @app.route('/dashboard/<version>')
    def dashboard(version='v1'):
        """Dashboard con versioni diverse"""
        # Imposta il menu attivo
        menu_manager.set_active_menu_item(request.path)
        return render_template('index.html', dashboard_version=version)

    @app.route('/widgets')
    def widgets():
        """Pagina widgets"""
        menu_manager.set_active_menu_item(request.path)
        return render_template('widgets.html')

    @app.route('/charts/<chart_type>')
    def charts(chart_type):
        """Pagine per i grafici"""
        menu_manager.set_active_menu_item(request.path)
        return render_template(f'charts/{chart_type}.html')

    @app.route('/ui/<ui_type>')
    def ui_elements(ui_type):
        """Elementi UI"""
        menu_manager.set_active_menu_item(request.path)
        return render_template(f'ui/{ui_type}.html')

    @app.route('/forms/<form_type>')
    def forms(form_type):
        """Pagine dei form"""
        menu_manager.set_active_menu_item(request.path)
        return render_template(f'forms/{form_type}.html')

    @app.route('/tables/<table_type>')
    def tables(table_type):
        """Pagine delle tabelle"""
        menu_manager.set_active_menu_item(request.path)
        return render_template(f'tables/{table_type}.html')

    @app.route('/calendar')
    def calendar():
        """Pagina calendario"""
        menu_manager.set_active_menu_item(request.path)
        return render_template('calendar.html')

    @app.route('/gallery')
    def gallery():
        """Pagina galleria"""
        menu_manager.set_active_menu_item(request.path)
        return render_template('gallery.html')

    @app.route('/kanban')
    def kanban():
        """Pagina kanban board"""
        menu_manager.set_active_menu_item(request.path)
        return render_template('kanban.html')

    @app.route('/layout/<layout_type>')
    def layout_options(layout_type):
        """Opzioni di layout"""
        menu_manager.set_active_menu_item(request.path)
        return render_template(f'layouts/{layout_type}.html')

    # ===============================
    # ROUTE PER L'AUTENTICAZIONE
    # ===============================

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
        menu_manager.set_active_menu_item(request.path)
        return render_template('profile.html')

    # ===============================
    # ROUTE PER L'AMMINISTRAZIONE DATABASE
    # ===============================

    @app.route('/admin')
    def admin_dashboard():
        """Dashboard di amministrazione"""
        menu_manager.set_active_menu_item(request.path)

        # Ottieni informazioni sul database
        db_info = get_database_info(app)
        stats = stats_manager.get_dashboard_stats()

        return render_template('admin/dashboard.html',
                             database_info=db_info,
                             stats=stats)

    @app.route('/admin/database')
    def admin_database():
        """Gestione database"""
        menu_manager.set_active_menu_item(request.path)

        db_info = get_database_info(app)
        return render_template('admin/database.html', database_info=db_info)

    @app.route('/admin/messages')
    def admin_messages():
        """Gestione messaggi"""
        menu_manager.set_active_menu_item(request.path)

        # Ottieni parametri di paginazione
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Ottieni i messaggi
        messages_data = message_manager.get_messages(page=page, per_page=per_page)
        message_types = message_manager.get_message_types()
        priorities = message_manager.get_message_priorities()

        return render_template('admin/messages.html',
                             messages=messages_data.get('messages', []),
                             pagination=messages_data.get('pagination', {}),
                             message_types=message_types,
                             priorities=priorities)

    @app.route('/admin/notifications')
    def admin_notifications():
        """Gestione notifiche"""
        menu_manager.set_active_menu_item(request.path)

        # Ottieni parametri di paginazione
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Ottieni le notifiche
        notifications_data = notification_manager.get_notifications(page=page, per_page=per_page)
        notification_types = notification_manager.get_notification_types()
        categories = notification_manager.get_notification_categories()
        priorities = notification_manager.get_notification_priorities()

        return render_template('admin/notifications.html',
                             notifications=notifications_data.get('notifications', []),
                             pagination=notifications_data.get('pagination', {}),
                             notification_types=notification_types,
                             categories=categories,
                             priorities=priorities)

    @app.route('/admin/menu')
    def admin_menu():
        """Gestione menu"""
        menu_manager.set_active_menu_item(request.path)

        sidebar_menu = menu_manager.get_sidebar_menu()
        return render_template('admin/menu.html', sidebar_menu=sidebar_menu)

    # ===============================
    # ROUTE PER LE DEMO
    # ===============================

    @app.route('/demo/create-sample-data', methods=['POST'])
    def create_sample_data():
        """Crea dati di esempio per la demo"""
        try:
            # Crea alcuni messaggi di esempio
            message_manager.create_message(
                sender="Demo User",
                content="Questo è un messaggio di esempio creato dalla demo.",
                subject="Messaggio Demo",
                message_type="system",
                priority="medium"
            )

            message_manager.create_message(
                sender="Admin",
                content="Benvenuto nel sistema AdminLTE con database SQLite!",
                subject="Benvenuto",
                message_type="welcome",
                priority="high"
            )

            # Crea alcune notifiche di esempio
            notification_manager.create_notification(
                message="Sistema inizializzato correttamente",
                notification_type="success",
                category="system",
                priority="low",
                icon="bi-check-circle-fill"
            )

            notification_manager.create_notification(
                message="Nuovi dati demo creati",
                notification_type="info",
                category="system",
                priority="medium",
                icon="bi-info-circle-fill"
            )

            return jsonify({
                'success': True,
                'message': 'Dati di esempio creati con successo'
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Errore nella creazione dei dati: {str(e)}'
            }), 500

    # ===============================
    # ERROR HANDLERS
    # ===============================

    @app.errorhandler(404)
    def not_found(error):
        """Pagina 404"""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Pagina 500"""
        db.session.rollback()  # Rollback in caso di errore database
        return render_template('errors/500.html'), 500

    # ===============================
    # CONTEXT PROCESSOR PERSONALIZZATO
    # ===============================

    @app.context_processor
    def inject_global_vars():
        """Inietta variabili globali nei template usando il database"""
        try:
            # Ottieni i dati dal database
            sidebar_menu = menu_manager.get_sidebar_menu('sidebar')
            messages_data = message_manager.get_messages(limit=5)
            notifications_data = notification_manager.get_notifications(limit=5)

            # Statistiche per la navbar
            unread_messages = messages_data.get('unread_count', 0)
            unread_notifications = notifications_data.get('unread_count', 0)

            return {
                'app_name': 'AdminLTE Flask Dashboard',
                'app_version': '4.0.0',
                'sidebar_menu': sidebar_menu,
                'messages': messages_data.get('messages', []),
                'notifications': notifications_data.get('notifications', []),
                'unread_messages_count': unread_messages,
                'unread_notifications_count': unread_notifications,
                'database_mode': True,
                'current_user': {
                    'name': 'Alexander Pierce',
                    'email': 'alexander@example.com',
                    'join_date': 'Nov. 2023',
                    'avatar': '/static/assets/img/user2-160x160.jpg'
                }
            }

        except Exception as e:
            app.logger.error(f"Errore nell'iniezione delle variabili globali: {str(e)}")
            # Fallback in caso di errore
            return {
                'app_name': 'AdminLTE Flask Dashboard',
                'app_version': '4.0.0',
                'sidebar_menu': [],
                'messages': [],
                'notifications': [],
                'unread_messages_count': 0,
                'unread_notifications_count': 0,
                'database_mode': True,
                'current_user': {
                    'name': 'Alexander Pierce',
                    'email': 'alexander@example.com',
                    'join_date': 'Nov. 2023',
                    'avatar': '/static/assets/img/user2-160x160.jpg'
                }
            }

    # ===============================
    # COMANDI CLI PERSONALIZZATI
    # ===============================

    @app.cli.command()
    def init_db():
        """Inizializza il database"""
        try:
            db.create_all()
            print("✓ Database inizializzato con successo")
        except Exception as e:
            print(f"✗ Errore nell'inizializzazione del database: {e}")

    @app.cli.command()
    def reset_db():
        """Resetta il database (elimina e ricrea tutte le tabelle)"""
        try:
            from database_config import reset_database
            if reset_database(app):
                print("✓ Database resettato con successo")
            else:
                print("✗ Errore nel reset del database")
        except Exception as e:
            print(f"✗ Errore nel reset del database: {e}")

    @app.cli.command()
    def migrate_json():
        """Migra i dati dai file JSON al database"""
        try:
            from migrate_json_to_db import JSONToDBMigrator
            migrator = JSONToDBMigrator(app)
            success = migrator.run_migration(clear_existing=True)

            if success:
                print("✓ Migrazione completata con successo")
            else:
                print("✗ Migrazione fallita o completata con errori")
        except Exception as e:
            print(f"✗ Errore nella migrazione: {e}")

    @app.cli.command()
    def create_sample_data():
        """Crea dati di esempio per test e demo"""
        try:
            with app.app_context():
                # Crea tipi di messaggio se non esistono
                from models import MessageType, MessagePriority, NotificationType, NotificationCategory, NotificationPriority

                # Tipi di messaggio
                message_types = [
                    {'type': 'system', 'label': 'System', 'color': 'info', 'icon': 'bi-gear'},
                    {'type': 'welcome', 'label': 'Welcome', 'color': 'success', 'icon': 'bi-hand-wave'},
                    {'type': 'security', 'label': 'Security', 'color': 'danger', 'icon': 'bi-shield-exclamation'},
                ]

                for type_data in message_types:
                    if not MessageType.query.filter_by(type=type_data['type']).first():
                        msg_type = MessageType(**type_data)
                        db.session.add(msg_type)

                # Priorità messaggi
                priorities = [
                    {'level': 'low', 'label': 'Low', 'color': 'secondary', 'sort_order': 1},
                    {'level': 'medium', 'label': 'Medium', 'color': 'warning', 'sort_order': 2},
                    {'level': 'high', 'label': 'High', 'color': 'danger', 'sort_order': 3},
                ]

                for priority_data in priorities:
                    if not MessagePriority.query.filter_by(level=priority_data['level']).first():
                        priority = MessagePriority(**priority_data)
                        db.session.add(priority)

                # Tipi di notifica
                notification_types = [
                    {'type': 'success', 'label': 'Success', 'color': 'success', 'icon': 'bi-check-circle-fill'},
                    {'type': 'info', 'label': 'Info', 'color': 'info', 'icon': 'bi-info-circle-fill'},
                    {'type': 'warning', 'label': 'Warning', 'color': 'warning', 'icon': 'bi-exclamation-triangle-fill'},
                ]

                for type_data in notification_types:
                    if not NotificationType.query.filter_by(type=type_data['type']).first():
                        notif_type = NotificationType(**type_data)
                        db.session.add(notif_type)

                # Categorie notifiche
                categories = [
                    {'category': 'system', 'label': 'System', 'color': 'info', 'icon': 'bi-gear'},
                    {'category': 'user', 'label': 'User', 'color': 'primary', 'icon': 'bi-person'},
                ]

                for category_data in categories:
                    if not NotificationCategory.query.filter_by(category=category_data['category']).first():
                        category = NotificationCategory(**category_data)
                        db.session.add(category)

                # Priorità notifiche
                for priority_data in priorities:
                    if not NotificationPriority.query.filter_by(level=priority_data['level']).first():
                        priority = NotificationPriority(**priority_data)
                        db.session.add(priority)

                db.session.commit()

                # Crea messaggi di esempio
                message_manager.create_message(
                    sender="System Administrator",
                    content="Benvenuto nel nuovo sistema AdminLTE con database SQLite! Il sistema è stato inizializzato correttamente.",
                    subject="Sistema Inizializzato",
                    message_type="system",
                    priority="high"
                )

                message_manager.create_message(
                    sender="Demo User",
                    content="Questo è un messaggio di esempio per mostrare le funzionalità del sistema di messaggistica.",
                    subject="Messaggio Demo",
                    message_type="welcome",
                    priority="medium"
                )

                # Crea notifiche di esempio
                notification_manager.create_notification(
                    message="Database SQLite inizializzato con successo",
                    notification_type="success",
                    category="system",
                    priority="medium",
                    icon="bi-check-circle-fill"
                )

                notification_manager.create_notification(
                    message="Dati di esempio creati per la demo",
                    notification_type="info",
                    category="system",
                    priority="low",
                    icon="bi-info-circle-fill"
                )

                print("✓ Dati di esempio creati con successo")

        except Exception as e:
            print(f"✗ Errore nella creazione dei dati di esempio: {e}")

    @app.cli.command()
    def backup_db():
        """Crea un backup del database"""
        try:
            from database_config import backup_database
            backup_path = backup_database(app)
            print(f"✓ Backup creato: {backup_path}")
        except Exception as e:
            print(f"✗ Errore nel backup: {e}")

    @app.cli.command()
    def optimize_db():
        """Ottimizza il database"""
        try:
            from database_config import optimize_database
            if optimize_database(app):
                print("✓ Database ottimizzato con successo")
            else:
                print("✗ Errore nell'ottimizzazione del database")
        except Exception as e:
            print(f"✗ Errore nell'ottimizzazione: {e}")

    @app.cli.command()
    def db_info():
        """Mostra informazioni sul database"""
        try:
            info = get_database_info(app)
            print("📊 Informazioni Database:")
            print(f"  Database: {info.get('database_path', 'N/A')}")
            print(f"  Dimensione: {info.get('database_size_mb', 0)} MB")
            print("\n📋 Tabelle:")
            tables = info.get('tables', {})
            for table, count in tables.items():
                print(f"  {table}: {count} record")
            print(f"\n📬 Messaggi non letti: {info.get('unread_messages', 0)}")
            print(f"🔔 Notifiche non lette: {info.get('unread_notifications', 0)}")
        except Exception as e:
            print(f"✗ Errore nel caricamento delle informazioni: {e}")

    @app.cli.command()
    def cleanup_old_data():
        """Pulisce i dati vecchi dal database"""
        try:
            from database_config import cleanup_old_data
            result = cleanup_old_data(app, days=30)

            if result.get('status') == 'success':
                print(f"✓ Pulizia completata:")
                print(f"  Messaggi eliminati: {result.get('deleted_messages', 0)}")
                print(f"  Notifiche eliminate: {result.get('deleted_notifications', 0)}")
            else:
                print(f"✗ Errore nella pulizia: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"✗ Errore nella pulizia: {e}")

    return app


# ===============================
# ESECUZIONE DIRETTA
# ===============================

if __name__ == '__main__':
    app = create_app()

    # Crea le directory necessarie se non esistono
    directories = [
        'static/css', 'static/js', 'static/assets/img',
        'templates/charts', 'templates/ui', 'templates/forms',
        'templates/tables', 'templates/layouts', 'templates/auth',
        'templates/errors', 'templates/admin'
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)

    print("🚀 Avvio dell'applicazione Flask AdminLTE con Database SQLite")
    print("=" * 70)
    print("📁 Struttura directory creata")
    print("🗄 Database SQLite configurato nella directory instance/")
    print("")
    print("🔧 Comandi disponibili:")
    print("   flask init-db          - Inizializza il database")
    print("   flask reset-db         - Resetta il database")
    print("   flask migrate-json     - Migra i dati dai file JSON")
    print("   flask create-sample-data - Crea dati di esempio")
    print("   flask backup-db        - Crea backup del database")
    print("   flask optimize-db      - Ottimizza il database")
    print("   flask db-info          - Mostra info database")
    print("   flask cleanup-old-data - Pulisce dati vecchi")
    print("")
    print("📊 Dashboard disponibile su: http://localhost:5000")
    print("🔧 Admin panel disponibile su: http://localhost:5000/admin")
    print("🔌 API endpoints disponibili su: http://localhost:5000/api/")
    print("")
    print("💡 Per iniziare:")
    print("   1. Esegui 'flask create-sample-data' per creare dati di test")
    print("   2. Oppure esegui 'flask migrate-json' per migrare dai file JSON esistenti")
    print("   3. Visita http://localhost:5000 per vedere la dashboard")
    print("=" * 70)

    app.run(host='0.0.0.0', port=5000, debug=True)