from flask import Blueprint, request, jsonify
from menu_config import MENU_STRUCTURE

# Crea la blueprint per il menu
menu_bp = Blueprint('menu', __name__, url_prefix='/menu')


def find_active_path(menu_dict, current_endpoint):
    """
    Trova il percorso dell'elemento attivo nel menu
    """
    if not current_endpoint:
        return []

    def search_recursive(items, current_path):
        if not isinstance(items, dict):
            return None

        for key, item in items.items():
            if key.startswith('_header'):
                continue

            if not isinstance(item, dict):
                continue

            new_path = current_path + [key]

            # Controlla se questo è l'elemento attivo
            item_endpoint = item.get('endpoint')
            if item_endpoint and item_endpoint == current_endpoint:
                return new_path

            # Cerca ricorsivamente nei children
            children = item.get('children')
            if children and isinstance(children, dict):
                result = search_recursive(children, new_path)
                if result:
                    return result

        return None

    try:
        result = search_recursive(menu_dict, [])
        return result if result else []
    except Exception as e:
        print(f"Errore in find_active_path: {str(e)}")
        return []


def render_menu_item(key, item, active_path, level=0):
    """
    Renderizza un singolo elemento del menu
    """
    try:
        # Gestisci gli header
        if key.startswith('_header'):
            return f'<li class="nav-header">{item.get("label", "")}</li>'

        # Verifica se è attivo
        is_active = key in active_path if active_path else False
        has_children = 'children' in item
        is_open = False

        if active_path and has_children:
            is_open = any(child_key in active_path for child_key in item.get('children', {}).keys())

        # Classe CSS per l'elemento
        nav_item_class = 'nav-item'
        if has_children and (is_active or is_open):
            nav_item_class += ' menu-open'

        # Classe CSS per il link
        nav_link_class = 'nav-link'
        if is_active and not has_children:
            nav_link_class += ' active'
        elif has_children and is_open:
            nav_link_class += ' active'

        # URL del link
        url = item.get('url', '#')
        if url is None:
            url = '#'

        # Badge
        badge_html = ''
        badge = item.get('badge')
        if badge and isinstance(badge, dict):
            badge_text = badge.get('text', '')
            badge_class = badge.get('class', '')
            badge_html = f'<span class="nav-badge badge {badge_class} me-3">{badge_text}</span>'

        # Freccia per sottomenu
        arrow_html = ''
        if has_children:
            arrow_html = '<i class="nav-arrow bi bi-chevron-right"></i>'

        # Small text
        small_text = ''
        small_text_value = item.get('small_text')
        if small_text_value:
            small_text = f' <small>{small_text_value}</small>'

        # Classe per il testo
        text_class = item.get('text_class', '')

        # Icona - gestisci il caso in cui non ci sia
        icon = item.get('icon', 'bi bi-circle')

        # Label - gestisci il caso in cui non ci sia
        label = item.get('label', 'Unknown')

        # HTML principale dell'elemento
        html = f'''<li class="{nav_item_class}">
    <a href="{url}" class="{nav_link_class}" data-menu-key="{key}">
        <i class="nav-icon {icon}"></i>
        <p class="{text_class}">
            {label}{small_text}
            {badge_html}
            {arrow_html}
        </p>
    </a>'''

        # Renderizza i children se presenti
        if has_children:
            html += '<ul class="nav nav-treeview">'
            children = item.get('children', {})
            for child_key, child_item in children.items():
                html += render_menu_item(child_key, child_item, active_path, level + 1)
            html += '</ul>'

        html += '</li>'

        return html

    except Exception as e:
        # Ritorna un elemento di errore invece di far crashare tutto
        error_msg = f"Error rendering {key}: {str(e)}"
        return f'<li class="nav-item"><a href="#" class="nav-link text-danger"><i class="nav-icon bi bi-exclamation-triangle"></i><p>{error_msg}</p></a></li>'


@menu_bp.route('/render')
def render_menu():
    """
    Renderizza il menu completo
    """
    try:
        current_endpoint = request.args.get('endpoint', 'index')

        # Step 1: Find active path
        active_path = find_active_path(MENU_STRUCTURE, current_endpoint)

        # Step 2: Render menu items
        menu_html = ''
        item_count = 0

        for key, item in MENU_STRUCTURE.items():
            try:
                item_html = render_menu_item(key, item, active_path)
                menu_html += item_html
                item_count += 1
            except Exception as e:
                # Log l'errore ma continua con gli altri elementi
                print(f"Errore nel rendering dell'elemento {key}: {str(e)}")
                menu_html += f'<li class="nav-item"><a href="#" class="nav-link text-warning"><i class="nav-icon bi bi-exclamation-triangle"></i><p>Errore: {key}</p></a></li>'

        return jsonify({
            'html': menu_html,
            'active_path': active_path,
            'status': 'success',
            'items_rendered': item_count,
            'total_items': len(MENU_STRUCTURE)
        })

    except Exception as e:
        # Log dettagliato dell'errore
        import traceback
        error_details = {
            'error_type': type(e).__name__,
            'error_message': str(e),
            'traceback': traceback.format_exc()
        }

        print("ERRORE DETTAGLIATO NEL MENU:")
        print(f"Tipo: {error_details['error_type']}")
        print(f"Messaggio: {error_details['error_message']}")
        print("Traceback:")
        print(error_details['traceback'])

        return jsonify({
            'html': '<li class="nav-item"><a href="#" class="nav-link text-danger"><i class="nav-icon bi bi-exclamation-triangle"></i><p>Errore grave nel menu</p></a></li>',
            'active_path': [],
            'status': 'error',
            'error_details': error_details
        }), 500


@menu_bp.route('/state')
def get_menu_state():
    """
    Ottiene lo stato del menu per un endpoint specifico
    """
    try:
        current_endpoint = request.args.get('endpoint', 'index')
        active_path = find_active_path(MENU_STRUCTURE, current_endpoint)

        return jsonify({
            'active_path': active_path,
            'endpoint': current_endpoint,
            'status': 'success'
        })
    except Exception as e:
        print(f"Errore nel recupero dello stato del menu: {str(e)}")
        return jsonify({
            'active_path': [],
            'endpoint': current_endpoint,
            'status': 'error',
            'error': str(e)
        }), 500


# Test endpoint per verificare che la blueprint funzioni
@menu_bp.route('/test')
def test_menu():
    """Endpoint di test per verificare che la blueprint sia accessibile"""
    try:
        return jsonify({
            'status': 'success',
            'message': 'Menu blueprint is working',
            'endpoints': len(MENU_STRUCTURE),
            'structure_keys': list(MENU_STRUCTURE.keys())[:5]  # Prime 5 chiavi per debug
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_type': type(e).__name__
        }), 500


@menu_bp.route('/debug')
def debug_menu():
    """Endpoint di debug per identificare problemi"""
    try:
        current_endpoint = request.args.get('endpoint', 'index')

        # Test step by step
        debug_info = {
            'step1_import': 'OK - MENU_STRUCTURE imported',
            'step2_endpoint': f'Current endpoint: {current_endpoint}',
            'step3_structure_type': str(type(MENU_STRUCTURE)),
            'step4_structure_len': len(MENU_STRUCTURE),
        }

        # Test find_active_path
        try:
            active_path = find_active_path(MENU_STRUCTURE, current_endpoint)
            debug_info['step5_active_path'] = f'Active path: {active_path}'
        except Exception as e:
            debug_info['step5_active_path'] = f'ERROR: {str(e)}'

        # Test render_menu_item on first item
        try:
            first_key = next(iter(MENU_STRUCTURE.keys()))
            first_item = MENU_STRUCTURE[first_key]
            test_html = render_menu_item(first_key, first_item, [])
            debug_info['step6_render_test'] = 'OK - render_menu_item works'
        except Exception as e:
            debug_info['step6_render_test'] = f'ERROR: {str(e)}'

        return jsonify({
            'status': 'debug_complete',
            'debug_info': debug_info
        })

    except Exception as e:
        import traceback
        return jsonify({
            'status': 'debug_failed',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500