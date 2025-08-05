from flask import Flask, render_template, jsonify


def create_app():
    """Factory function per creare l'applicazione Flask"""
    app = Flask(__name__)

    # Configurazione
    app.config['SECRET_KEY'] = 'your-secret-key-here'
    app.config['DEBUG'] = True

    # Importa e registra il blueprint API
    from blueprint.api import api_bp
    app.register_blueprint(api_bp)

    return app


# Crea l'istanza dell'app
app = create_app()


@app.route('/')
def index():
    """Dashboard principale"""
    return render_template('index.html')


@app.route('/demo')
def demo():
    """Pagina demo per testare il menu"""
    return render_template('demo.html')


@app.route('/dashboard-v2')
def dashboard_v2():
    """Dashboard v2"""
    return render_template('dashboard_v2.html')


@app.route('/dashboard-v3')
def dashboard_v3():
    """Dashboard v3"""
    return render_template('dashboard_v3.html')


@app.route('/generate/theme')
def theme_generate():
    """Generatore di temi"""
    return render_template('theme_generate.html')


@app.route('/widgets/small-box')
def widgets_small_box():
    """Widget Small Box"""
    return render_template('widgets/small_box.html')


@app.route('/widgets/info-box')
def widgets_info_box():
    """Widget Info Box"""
    return render_template('widgets/info_box.html')


@app.route('/widgets/cards')
def widgets_cards():
    """Widget Cards"""
    return render_template('widgets/cards.html')


@app.route('/layout/unfixed-sidebar')
def layout_unfixed_sidebar():
    """Layout con sidebar non fissa"""
    return render_template('layout/unfixed_sidebar.html')


@app.route('/layout/fixed-sidebar')
def layout_fixed_sidebar():
    """Layout con sidebar fissa"""
    return render_template('layout/fixed_sidebar.html')


@app.route('/layout/fixed-header')
def layout_fixed_header():
    """Layout con header fisso"""
    return render_template('layout/fixed_header.html')


@app.route('/layout/fixed-footer')
def layout_fixed_footer():
    """Layout con footer fisso"""
    return render_template('layout/fixed_footer.html')


@app.route('/layout/fixed-complete')
def layout_fixed_complete():
    """Layout completamente fisso"""
    return render_template('layout/fixed_complete.html')


@app.route('/layout/sidebar-mini')
def layout_sidebar_mini():
    """Layout con sidebar mini"""
    return render_template('layout/sidebar_mini.html')


@app.route('/ui/general')
def ui_general():
    """UI Elements - General"""
    return render_template('ui/general.html')


@app.route('/ui/icons')
def ui_icons():
    """UI Elements - Icons"""
    return render_template('ui/icons.html')


@app.route('/ui/timeline')
def ui_timeline():
    """UI Elements - Timeline"""
    return render_template('ui/timeline.html')


@app.route('/forms/general')
def forms_general():
    """Forms - General Elements"""
    return render_template('forms/general.html')


@app.route('/tables/simple')
def tables_simple():
    """Tables - Simple"""
    return render_template('tables/simple.html')


@app.route('/examples/login')
def examples_login():
    """Examples - Login v1"""
    return render_template('examples/login.html')


@app.route('/examples/register')
def examples_register():
    """Examples - Register v1"""
    return render_template('examples/register.html')


@app.route('/examples/login-v2')
def examples_login_v2():
    """Examples - Login v2"""
    return render_template('examples/login_v2.html')


@app.route('/examples/register-v2')
def examples_register_v2():
    """Examples - Register v2"""
    return render_template('examples/register_v2.html')


@app.route('/examples/lockscreen')
def examples_lockscreen():
    """Examples - Lockscreen"""
    return render_template('examples/lockscreen.html')


@app.route('/docs/introduction')
def docs_introduction():
    """Documentation - Introduction"""
    return render_template('docs/introduction.html')


@app.route('/docs/layout')
def docs_layout():
    """Documentation - Layout"""
    return render_template('docs/layout.html')


@app.errorhandler(404)
def page_not_found(error):
    """Gestione errore 404"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    """Gestione errore 500"""
    return render_template('errors/500.html'), 500


# Debug route per testare l'API
@app.route('/test-api')
def test_api():
    """Route di test per verificare che l'API funzioni"""
    try:
        from blueprint.api import get_menu_data
        menu_data = get_menu_data()
        return jsonify({
            'status': 'success',
            'menu_items_count': len(menu_data),
            'first_item': menu_data[0] if menu_data else None
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)