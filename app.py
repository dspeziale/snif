"""
Flask Application with SQLite Menu Database
Applicazione Flask aggiornata per utilizzare SQLite invece di JSON
"""

from flask import Flask, render_template, url_for, jsonify, request, redirect, flash
from datetime import datetime
import json
import os
from menu_database import MenuDatabase, MenuItem, migrate_from_json_file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['MENU_DATABASE'] = 'menu.db'

# Inizializza il database dei menu
menu_db = MenuDatabase(app.config['MENU_DATABASE'])


# ==================== API ENDPOINTS ====================

@app.route('/api/menu')
def api_menu():
    """
    Endpoint API che restituisce la configurazione del menu dal database SQLite.
    Mantiene la stessa struttura JSON per compatibilità con il frontend esistente.
    """
    try:
        # Recupera l'albero del menu dal database
        menu_tree = menu_db.get_menu_tree()

        # Converte in formato JSON compatibile
        menu_data = {
            "menu_items": [item.to_dict() for item in menu_tree]
        }

        return jsonify(menu_data)

    except Exception as e:
        app.logger.error(f"Errore nel recupero del menu: {str(e)}")
        return jsonify({
            "error": "Server error",
            "message": str(e)
        }), 500


@app.route('/api/menu/item/<int:item_id>')
def api_menu_item(item_id):
    """Recupera un singolo menu item"""
    try:
        item = menu_db.get_menu_item(item_id)
        if item:
            return jsonify(item.to_dict())
        else:
            return jsonify({"error": "Menu item not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/menu/search')
def api_menu_search():
    """Cerca menu items"""
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({"results": []})

        results = menu_db.search_menu_items(query)
        return jsonify({
            "results": [item.to_dict(include_children=False) for item in results]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/menu/item', methods=['POST'])
def api_create_menu_item():
    """Crea un nuovo menu item"""
    try:
        data = request.json
        item = MenuItem(
            parent_id=data.get('parent_id') or None,
            type=data.get('type', 'item'),
            text=data.get('text', ''),
            icon=data.get('icon'),
            url=data.get('url'),
            active=data.get('active', False),
            badge_text=data.get('badge_text'),
            badge_color=data.get('badge_color'),
            position=data.get('position', 0)
        )

        item_id = menu_db.insert_menu_item(item)
        item.id = item_id

        return jsonify({
            "success": True,
            "item": item.to_dict()
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/menu/item/<int:item_id>', methods=['PUT'])
def api_update_menu_item(item_id):
    """Aggiorna un menu item esistente"""
    try:
        data = request.json
        item = menu_db.get_menu_item(item_id)

        if not item:
            return jsonify({"error": "Menu item not found"}), 404

        # Aggiorna i campi
        item.parent_id = data.get('parent_id', item.parent_id)
        item.type = data.get('type', item.type)
        item.text = data.get('text', item.text)
        item.icon = data.get('icon', item.icon)
        item.url = data.get('url', item.url)
        item.active = data.get('active', item.active)
        item.badge_text = data.get('badge_text', item.badge_text)
        item.badge_color = data.get('badge_color', item.badge_color)
        item.position = data.get('position', item.position)

        success = menu_db.update_menu_item(item)

        if success:
            return jsonify({
                "success": True,
                "item": item.to_dict()
            })
        else:
            return jsonify({"error": "Update failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/menu/item/<int:item_id>', methods=['DELETE'])
def api_delete_menu_item(item_id):
    """Elimina un menu item"""
    try:
        success = menu_db.delete_menu_item(item_id)
        if success:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Menu item not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/menu/reorder', methods=['POST'])
def api_reorder_menu():
    """Riordina gli items del menu"""
    try:
        data = request.json
        item_ids = data.get('item_ids', [])
        parent_id = data.get('parent_id')

        menu_db.reorder_items(item_ids, parent_id)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== ADMIN INTERFACE ====================

@app.route('/admin/menu')
def admin_menu():
    """Interfaccia di amministrazione per gestire i menu"""
    menu_tree = menu_db.get_menu_tree()
    return render_template('admin/menu_manager.html',
                           menu_tree=menu_tree,
                           page_title='Gestione Menu')


@app.route('/admin/menu/add', methods=['GET', 'POST'])
def admin_menu_add():
    """Aggiungi nuovo menu item"""
    if request.method == 'POST':
        try:
            item = MenuItem(
                parent_id=request.form.get('parent_id') or None,
                type=request.form.get('type', 'item'),
                text=request.form.get('text', ''),
                icon=request.form.get('icon'),
                url=request.form.get('url'),
                active='active' in request.form,
                badge_text=request.form.get('badge_text'),
                badge_color=request.form.get('badge_color'),
                position=int(request.form.get('position', 0))
            )

            menu_db.insert_menu_item(item)
            flash('Menu item aggiunto con successo!', 'success')
            return redirect(url_for('admin_menu'))
        except Exception as e:
            flash(f'Errore: {str(e)}', 'danger')

    # GET: mostra il form
    parent_items = menu_db.get_flat_menu_list()
    return render_template('admin/menu_form.html',
                           parent_items=parent_items,
                           page_title='Aggiungi Menu Item')


@app.route('/admin/menu/edit/<int:item_id>', methods=['GET', 'POST'])
def admin_menu_edit(item_id):
    """Modifica menu item esistente"""
    item = menu_db.get_menu_item(item_id)
    if not item:
        flash('Menu item non trovato', 'danger')
        return redirect(url_for('admin_menu'))

    if request.method == 'POST':
        try:
            item.parent_id = request.form.get('parent_id') or None
            item.type = request.form.get('type', 'item')
            item.text = request.form.get('text', '')
            item.icon = request.form.get('icon')
            item.url = request.form.get('url')
            item.active = 'active' in request.form
            item.badge_text = request.form.get('badge_text')
            item.badge_color = request.form.get('badge_color')
            item.position = int(request.form.get('position', 0))

            menu_db.update_menu_item(item)
            flash('Menu item aggiornato con successo!', 'success')
            return redirect(url_for('admin_menu'))
        except Exception as e:
            flash(f'Errore: {str(e)}', 'danger')

    # GET: mostra il form con i dati esistenti
    parent_items = [i for i in menu_db.get_flat_menu_list() if i.id != item_id]
    return render_template('admin/menu_form.html',
                           item=item,
                           parent_items=parent_items,
                           page_title='Modifica Menu Item')


@app.route('/admin/menu/delete/<int:item_id>', methods=['POST'])
def admin_menu_delete(item_id):
    """Elimina menu item"""
    try:
        menu_db.delete_menu_item(item_id)
        flash('Menu item eliminato con successo!', 'success')
    except Exception as e:
        flash(f'Errore: {str(e)}', 'danger')

    return redirect(url_for('admin_menu'))


@app.route('/admin/menu/migrate')
def admin_menu_migrate():
    """Migra i dati dal file JSON al database"""
    try:
        json_file = os.path.join(app.static_folder, 'data', 'menu.json')
        if not os.path.exists(json_file):
            json_file = 'menu.json'

        if os.path.exists(json_file):
            migrate_from_json_file(json_file, app.config['MENU_DATABASE'])
            flash('Migrazione completata con successo!', 'success')
        else:
            flash('File menu.json non trovato', 'warning')
    except Exception as e:
        flash(f'Errore durante la migrazione: {str(e)}', 'danger')

    return redirect(url_for('admin_menu'))


@app.route('/admin/menu/export')
def admin_menu_export():
    """Esporta il menu corrente in formato JSON"""
    try:
        menu_data = menu_db.export_to_json()
        return jsonify(menu_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== ORIGINAL ROUTES ====================

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html',
                           current_user='Daniele Speziale',
                           page_title='Dashboard')


@app.route('/dashboard-v2')
def dashboard_v2():
    return render_template('dashboard_v2.html',
                           current_user='Daniele Speziale',
                           page_title='Dashboard v2')


@app.route('/dashboard-v3')
def dashboard_v3():
    return render_template('dashboard_v3.html',
                           current_user='Daniele Speziale',
                           page_title='Dashboard v3')


# ==================== CLI COMMANDS ====================

@app.cli.command('init-db')
def init_db_command():
    """Inizializza il database dei menu"""
    menu_db.init_database()
    print('Database inizializzato.')


@app.cli.command('migrate-menu')
def migrate_menu_command():
    """Migra il menu da JSON a SQLite"""
    json_file = 'menu.json'
    if os.path.exists(json_file):
        migrate_from_json_file(json_file, app.config['MENU_DATABASE'])
    else:
        print(f'File {json_file} non trovato.')


@app.cli.command('seed-menu')
def seed_menu_command():
    """Popola il database con dati di esempio"""
    # Crea alcuni menu items di esempio
    items = [
        MenuItem(type='header', text='NAVIGAZIONE PRINCIPALE', position=0),
        MenuItem(type='item', text='Dashboard', icon='bi-speedometer', url='/', position=1),
        MenuItem(type='item', text='Utenti', icon='bi-people', url='/users', position=2),
        MenuItem(type='header', text='AMMINISTRAZIONE', position=3),
        MenuItem(type='item', text='Impostazioni', icon='bi-gear', url='/settings', position=4),
    ]

    for item in items:
        menu_db.insert_menu_item(item)

    print('Menu di esempio creati.')


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


# ==================== CONTEXT PROCESSORS ====================

@app.context_processor
def inject_menu():
    """Inietta il menu in tutti i template"""

    def get_menu():
        try:
            return menu_db.get_menu_tree()
        except:
            return []

    return dict(get_menu=get_menu)


if __name__ == '__main__':
    # Assicurati che il database sia inizializzato
    if not os.path.exists(app.config['MENU_DATABASE']):
        menu_db.init_database()

        # Se esiste un file menu.json, migra automaticamente
        if os.path.exists('menu.json'):
            print("Migrazione automatica del menu.json...")
            migrate_from_json_file('menu.json', app.config['MENU_DATABASE'])

    app.run(debug=True)