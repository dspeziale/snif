from flask import Flask, render_template, url_for, jsonify
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'


# Route per l'API del menu
@app.route('/api/menu')
def api_menu():
    """
    Endpoint API che restituisce la configurazione del menu in formato JSON.
    Il file menu.json deve essere nella cartella static/data/
    """
    try:
        # Percorso del file JSON del menu
        menu_file = os.path.join(app.static_folder, 'data', 'menu.json')

        # Se il file non esiste nella cartella static/data, prova nella root
        if not os.path.exists(menu_file):
            menu_file = 'menu.json'

        # Leggi il file JSON
        with open(menu_file, 'r', encoding='utf-8') as f:
            menu_data = json.load(f)

        # Restituisci i dati come JSON
        return jsonify(menu_data)

    except FileNotFoundError:
        # Se il file non viene trovato, restituisci un menu di default
        default_menu = {
            "menu_items": [
                {
                    "type": "header",
                    "text": "MAIN NAVIGATION"
                },
                {
                    "type": "item",
                    "text": "Dashboard",
                    "icon": "bi-speedometer",
                    "url": "/",
                    "active": True
                },
                {
                    "type": "item",
                    "text": "Error: menu.json not found",
                    "icon": "bi-exclamation-triangle",
                    "url": "#"
                }
            ]
        }
        return jsonify(default_menu), 404

    except json.JSONDecodeError as e:
        # Se c'è un errore nel parsing del JSON
        return jsonify({
            "error": "Invalid JSON format",
            "message": str(e)
        }), 500

    except Exception as e:
        # Per qualsiasi altro errore
        return jsonify({
            "error": "Server error",
            "message": str(e)
        }), 500


# Route principale - Dashboard
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html',
                           current_user='Daniele Speziale',
                           page_title='Dashboard')


# Route Dashboard v2
@app.route('/dashboard-v2')
def dashboard_v2():
    return render_template('dashboard_v2.html',
                           page_title='Dashboard v2')


# Route Dashboard v3
@app.route('/dashboard-v3')
def dashboard_v3():
    return render_template('dashboard_v3.html',
                           page_title='Dashboard v3')


# Route Theme Generate
@app.route('/theme-generate')
def theme_generate():
    return render_template('theme_generate.html',
                           page_title='Theme Generate')


# Routes Widgets
@app.route('/widgets/small-box')
def widgets_small_box():
    return render_template('widgets/small_box.html',
                           page_title='Small Box Widget')


@app.route('/widgets/info-box')
def widgets_info_box():
    return render_template('widgets/info_box.html',
                           page_title='Info Box Widget')


@app.route('/widgets/cards')
def widgets_cards():
    return render_template('widgets/cards.html',
                           page_title='Cards Widget')


# Routes Layout Options
@app.route('/layout/unfixed-sidebar')
def layout_unfixed_sidebar():
    return render_template('layout/unfixed_sidebar.html',
                           page_title='Default Sidebar')


@app.route('/layout/fixed-sidebar')
def layout_fixed_sidebar():
    return render_template('layout/fixed_sidebar.html',
                           page_title='Fixed Sidebar')


@app.route('/layout/fixed-header')
def layout_fixed_header():
    return render_template('layout/fixed_header.html',
                           page_title='Fixed Header')


@app.route('/layout/fixed-footer')
def layout_fixed_footer():
    return render_template('layout/fixed_footer.html',
                           page_title='Fixed Footer')


@app.route('/layout/fixed-complete')
def layout_fixed_complete():
    return render_template('layout/fixed_complete.html',
                           page_title='Fixed Complete')


@app.route('/layout/layout-custom-area')
def layout_custom_area():
    return render_template('layout/layout_custom_area.html',
                           page_title='Layout + Custom Area')


@app.route('/layout/sidebar-mini')
def layout_sidebar_mini():
    return render_template('layout/sidebar_mini.html',
                           page_title='Sidebar Mini')


@app.route('/layout/collapsed-sidebar')
def layout_collapsed_sidebar():
    return render_template('layout/collapsed_sidebar.html',
                           page_title='Sidebar Mini + Collapsed')


@app.route('/layout/logo-switch')
def layout_logo_switch():
    return render_template('layout/logo_switch.html',
                           page_title='Sidebar Mini + Logo Switch')


@app.route('/layout/layout-rtl')
def layout_rtl():
    return render_template('layout/layout_rtl.html',
                           page_title='Layout RTL')


# Routes UI Elements
@app.route('/ui/general')
def ui_general():
    return render_template('ui/general.html',
                           page_title='General UI')


@app.route('/ui/icons')
def ui_icons():
    return render_template('ui/icons.html',
                           page_title='Icons')


@app.route('/ui/timeline')
def ui_timeline():
    return render_template('ui/timeline.html',
                           page_title='Timeline')


# Routes Forms
@app.route('/forms/general')
def forms_general():
    return render_template('forms/general.html',
                           page_title='General Elements')


# Routes Tables
@app.route('/tables/simple')
def tables_simple():
    return render_template('tables/simple.html',
                           page_title='Simple Tables')


# Routes Auth
@app.route('/login')
def login():
    return render_template('auth/login.html')


@app.route('/register')
def register():
    return render_template('auth/register.html')


@app.route('/login-v2')
def login_v2():
    return render_template('auth/login_v2.html')


@app.route('/register-v2')
def register_v2():
    return render_template('auth/register_v2.html')


@app.route('/lockscreen')
def lockscreen():
    return render_template('auth/lockscreen.html')


# Routes Documentation
@app.route('/docs/introduction')
def docs_introduction():
    return render_template('docs/introduction.html',
                           page_title='Installation')


@app.route('/docs/layout')
def docs_layout():
    return render_template('docs/layout.html',
                           page_title='Layout Documentation')


@app.route('/docs/color-mode')
def docs_color_mode():
    return render_template('docs/color_mode.html',
                           page_title='Color Mode')


@app.route('/docs/components/main-header')
def docs_main_header():
    return render_template('docs/components/main_header.html',
                           page_title='Main Header')


@app.route('/docs/components/main-sidebar')
def docs_main_sidebar():
    return render_template('docs/components/main_sidebar.html',
                           page_title='Main Sidebar')


@app.route('/docs/javascript/treeview')
def docs_treeview():
    return render_template('docs/javascript/treeview.html',
                           page_title='Treeview')


@app.route('/docs/browser-support')
def docs_browser_support():
    return render_template('docs/browser_support.html',
                           page_title='Browser Support')


@app.route('/docs/how-to-contribute')
def docs_contribute():
    return render_template('docs/how_to_contribute.html',
                           page_title='How To Contribute')


@app.route('/docs/faq')
def docs_faq():
    return render_template('docs/faq.html',
                           page_title='FAQ')


@app.route('/docs/license')
def docs_license():
    return render_template('docs/license.html',
                           page_title='License')


# Routes per pagine di errore
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500


# Context processor per variabili globali
@app.context_processor
def inject_globals():
    return {
        'current_year': datetime.now().year,
        'app_name': 'AdminLTE 4',
        'app_version': '4.0'
    }


if __name__ == '__main__':
    app.run(debug=True, port=5000)