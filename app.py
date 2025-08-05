from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

# Import models and blueprints
from models import db, Menu
from blueprint.menu import menu_bp


# from cli import register_commands  # Opzionale: per comandi CLI

def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///adminlte.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(menu_bp)

    # Register CLI commands (optional)
    # register_commands(app)

    # Routes
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/dashboard2')
    def dashboard2():
        return render_template('index.html')  # Per ora usa lo stesso template

    @app.route('/dashboard3')
    def dashboard3():
        return render_template('index.html')  # Per ora usa lo stesso template

    # API endpoint per ottenere il menu (utilizzato dal JavaScript)
    @app.route('/api/menu')
    def api_menu():
        try:
            menu_tree = Menu.get_menu_tree()
            return jsonify({
                'success': True,
                'data': menu_tree
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    # Database initialization
    with app.app_context():
        db.create_all()

        # Crea il menu di default se non esistono menu
        if Menu.query.count() == 0:
            Menu.create_default_menu()
            print("Menu di default creato")

    return app


# Create the Flask application
app = create_app()

if __name__ == '__main__':
    with app.app_context():
        # Crea le tabelle
        db.create_all()

        # Crea il menu di default se non esistono menu
        if Menu.query.count() == 0:
            Menu.create_default_menu()
            print("Menu di default creato")

    app.run(debug=True, host='0.0.0.0', port=5000)