from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from models import db, Menu
from sqlalchemy import and_

menu_bp = Blueprint('menu', __name__, url_prefix='/menu')


@menu_bp.route('/')
def index():
    """Pagina principale per la gestione dei menu"""
    return render_template('menu/index.html')


@menu_bp.route('/api/menus')
def api_get_menus():
    """API per ottenere tutti i menu in formato JSON"""
    try:
        menus = Menu.get_menu_tree()
        return jsonify({
            'success': True,
            'data': menus
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menus/flat')
def api_get_menus_flat():
    """API per ottenere tutti i menu in formato piatto"""
    try:
        menus = Menu.query.order_by(Menu.order_position).all()
        menu_data = []

        for menu in menus:
            menu_dict = menu.to_dict()
            # Aggiungi informazioni sul parent
            if menu.parent:
                menu_dict['parent_title'] = menu.parent.title
            else:
                menu_dict['parent_title'] = 'Root'
            menu_data.append(menu_dict)

        return jsonify({
            'success': True,
            'data': menu_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu/<int:menu_id>')
def api_get_menu(menu_id):
    """API per ottenere un singolo menu"""
    try:
        menu = Menu.query.get_or_404(menu_id)
        return jsonify({
            'success': True,
            'data': menu.to_dict()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu', methods=['POST'])
def api_create_menu():
    """API per creare un nuovo menu"""
    try:
        data = request.get_json()

        # Validazione
        if not data.get('title'):
            return jsonify({
                'success': False,
                'message': 'Il titolo è obbligatorio'
            }), 400

        # Verifica livello massimo (massimo 2 livelli di profondità)
        parent_id = data.get('parent_id')
        if parent_id:
            parent = Menu.query.get(parent_id)
            if parent and parent.level >= 2:
                return jsonify({
                    'success': False,
                    'message': 'Non è possibile creare menu con più di 2 livelli di profondità'
                }), 400

        # Calcola prossima posizione
        if parent_id:
            max_order = db.session.query(db.func.max(Menu.order_position)).filter_by(parent_id=parent_id).scalar() or 0
        else:
            max_order = db.session.query(db.func.max(Menu.order_position)).filter_by(parent_id=None).scalar() or 0

        # Crea il menu
        menu = Menu(
            title=data['title'],
            icon=data.get('icon', 'bi-circle'),
            url=data.get('url', ''),
            parent_id=parent_id,
            order_position=max_order + 1,
            is_active=data.get('is_active', True),
            is_header=data.get('is_header', False)
        )

        db.session.add(menu)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Menu creato con successo',
            'data': menu.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu/<int:menu_id>', methods=['PUT'])
def api_update_menu(menu_id):
    """API per aggiornare un menu"""
    try:
        menu = Menu.query.get_or_404(menu_id)
        data = request.get_json()

        # Validazione
        if not data.get('title'):
            return jsonify({
                'success': False,
                'message': 'Il titolo è obbligatorio'
            }), 400

        # Verifica che non si stia creando un ciclo
        new_parent_id = data.get('parent_id')
        if new_parent_id and new_parent_id != menu.parent_id:
            # Verifica che il nuovo parent non sia un discendente del menu corrente
            if menu.id == new_parent_id:
                return jsonify({
                    'success': False,
                    'message': 'Un menu non può essere parent di se stesso'
                }), 400

            # Verifica livello massimo
            if new_parent_id:
                parent = Menu.query.get(new_parent_id)
                if parent and parent.level >= 2:
                    return jsonify({
                        'success': False,
                        'message': 'Non è possibile creare menu con più di 2 livelli di profondità'
                    }), 400

        # Aggiorna i campi
        menu.title = data.get('title', menu.title)
        menu.icon = data.get('icon', menu.icon)
        menu.url = data.get('url', menu.url)
        menu.parent_id = new_parent_id
        menu.is_active = data.get('is_active', menu.is_active)
        menu.is_header = data.get('is_header', menu.is_header)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Menu aggiornato con successo',
            'data': menu.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu/<int:menu_id>', methods=['DELETE'])
def api_delete_menu(menu_id):
    """API per eliminare un menu"""
    try:
        menu = Menu.query.get_or_404(menu_id)

        # Verifica se ha figli
        if menu.children:
            return jsonify({
                'success': False,
                'message': 'Non è possibile eliminare un menu che ha sottomenu. Eliminare prima i sottomenu.'
            }), 400

        db.session.delete(menu)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Menu eliminato con successo'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu/<int:menu_id>/reorder', methods=['POST'])
def api_reorder_menu(menu_id):
    """API per riordinare i menu"""
    try:
        data = request.get_json()
        new_position = data.get('new_position')

        if new_position is None:
            return jsonify({
                'success': False,
                'message': 'Posizione non specificata'
            }), 400

        menu = Menu.query.get_or_404(menu_id)
        old_position = menu.order_position

        # Ottieni tutti i menu dello stesso livello
        if menu.parent_id:
            siblings = Menu.query.filter_by(parent_id=menu.parent_id).order_by(Menu.order_position).all()
        else:
            siblings = Menu.query.filter_by(parent_id=None).order_by(Menu.order_position).all()

        # Rimuovi il menu corrente dalla lista
        siblings = [m for m in siblings if m.id != menu_id]

        # Inserisci il menu nella nuova posizione
        siblings.insert(new_position - 1, menu)

        # Aggiorna le posizioni
        for i, sibling in enumerate(siblings):
            sibling.order_position = i + 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Menu riordinato con successo'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/menu/parents')
def api_get_parent_options():
    """API per ottenere le opzioni per il parent (solo menu di livello 0 e 1)"""
    try:
        # Ottieni menu di livello 0 (root)
        root_menus = Menu.query.filter_by(parent_id=None, is_active=True, is_header=False).order_by(
            Menu.order_position).all()

        options = [{'id': '', 'title': 'Root (Nessun Parent)', 'level': -1}]

        for root_menu in root_menus:
            options.append({
                'id': root_menu.id,
                'title': root_menu.title,
                'level': 0
            })

            # Aggiungi i figli di primo livello
            for child in root_menu.children:
                if child.is_active and not child.is_header:
                    options.append({
                        'id': child.id,
                        'title': f"-- {child.title}",
                        'level': 1
                    })

        return jsonify({
            'success': True,
            'data': options
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@menu_bp.route('/api/icons')
def api_get_icons():
    """API per ottenere la lista delle icone Bootstrap disponibili"""
    icons = [
        'bi-speedometer', 'bi-house', 'bi-person', 'bi-gear', 'bi-box-seam-fill',
        'bi-clipboard-fill', 'bi-tree-fill', 'bi-pencil-square', 'bi-table',
        'bi-box-arrow-in-right', 'bi-download', 'bi-grip-horizontal', 'bi-star-half',
        'bi-ui-checks-grid', 'bi-filetype-js', 'bi-browser-edge', 'bi-hand-thumbs-up-fill',
        'bi-question-circle-fill', 'bi-patch-check-fill', 'bi-circle-fill', 'bi-circle',
        'bi-record-circle-fill', 'bi-list-ul', 'bi-folder', 'bi-file-text',
        'bi-graph-up', 'bi-bar-chart', 'bi-pie-chart', 'bi-card-list',
        'bi-envelope', 'bi-bell', 'bi-chat', 'bi-calendar', 'bi-clock',
        'bi-shield-check', 'bi-key', 'bi-lock', 'bi-unlock', 'bi-eye',
        'bi-camera', 'bi-image', 'bi-music-note', 'bi-play-circle',
        'bi-stop-circle', 'bi-pause-circle', 'bi-skip-forward', 'bi-skip-backward'
    ]

    return jsonify({
        'success': True,
        'data': icons
    })