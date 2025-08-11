from flask import Blueprint, request, jsonify, url_for
from menu_config import MENU_STRUCTURE

# Crea la blueprint per il menu
menu_bp = Blueprint('menu', __name__, url_prefix='/menu')


def get_current_url():
    """Ottiene l'URL corrente della richiesta"""
    try:
        return request.path
    except:
        return '/'


def find_active_path_smart(menu_dict, current_endpoint, current_url):
    """
    Trova il percorso dell'elemento attivo nel menu usando multiple strategie MIGLIORATE
    """
    if not current_endpoint and not current_url:
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

            # STRATEGIA 1: Match esatto per endpoint (PRIORITÀ MASSIMA)
            item_endpoint = item.get('endpoint')
            if item_endpoint and current_endpoint and item_endpoint == current_endpoint:
                print(f"✅ Match ENDPOINT esatto: {item_endpoint} == {current_endpoint}")
                return new_path

            # STRATEGIA 2: Match per URL esatto (PRIORITÀ ALTA)
            item_url = item.get('url')
            if item_url and current_url:
                # Match esatto
                if item_url == current_url:
                    print(f"✅ Match URL esatto: {item_url} == {current_url}")
                    return new_path
                # Match rimuovendo trailing slash
                if item_url.rstrip('/') == current_url.rstrip('/'):
                    print(f"✅ Match URL (no slash): {item_url} == {current_url}")
                    return new_path

            # STRATEGIA 3: Match per URL che inizia con il path (per sotto-pagine)
            if item_url and current_url and item_url != '/' and item_url != '#':
                if current_url.startswith(item_url.rstrip('/')):
                    print(f"✅ Match URL prefisso: {current_url} inizia con {item_url}")
                    return new_path

            # STRATEGIA 4: Match avanzato per endpoint con parametri
            if current_endpoint and item_endpoint:
                # Per endpoint come 'network.hosts' che potrebbero avere ?status=up
                base_current = current_endpoint.split('?')[0] if '?' in current_endpoint else current_endpoint
                base_item = item_endpoint.split('?')[0] if '?' in item_endpoint else item_endpoint

                if base_current == base_item:
                    print(f"✅ Match ENDPOINT base: {base_current} == {base_item}")
                    return new_path

            # STRATEGIA 5: Match per URL con query parameters
            if item_url and current_url and '?' in item_url:
                # Estrai il base URL (senza query params) dall'item
                item_base_url = item_url.split('?')[0]
                if item_base_url == current_url:
                    print(f"✅ Match URL base con query: {item_base_url} == {current_url}")
                    return new_path

            # STRATEGIA 6: Match intelligente per route con blueprint
            if current_endpoint and item_endpoint:
                # Rimuovi il prefisso blueprint per confronto
                current_clean = current_endpoint.replace('network.', '').replace('snmp_', '')
                item_clean = item_endpoint.replace('network.', '').replace('snmp_', '')

                if current_clean == item_clean:
                    print(f"✅ Match ENDPOINT pulito: {current_clean} == {item_clean}")
                    return new_path

            # STRATEGIA 7: Match fuzzy migliorato
            if current_endpoint:
                # Per endpoint come 'network.snmp_interfaces'
                endpoint_parts = current_endpoint.split('.')
                if len(endpoint_parts) > 1:
                    endpoint_name = endpoint_parts[-1]  # es: 'snmp_interfaces'

                    # Verifica se il nome dell'endpoint è contenuto nella chiave
                    if endpoint_name in key:
                        print(f"✅ Match FUZZY endpoint nella chiave: {endpoint_name} in {key}")
                        return new_path

                    # Verifica se la chiave è contenuta nell'endpoint
                    if key in endpoint_name:
                        print(f"✅ Match FUZZY chiave nell'endpoint: {key} in {endpoint_name}")
                        return new_path

            # Cerca ricorsivamente nei children
            children = item.get('children')
            if children and isinstance(children, dict):
                result = search_recursive(children, new_path)
                if result:
                    return result

        return None

    try:
        print(f"🔍 Ricerca percorso attivo per:")
        print(f"   Current Endpoint: {current_endpoint}")
        print(f"   Current URL: {current_url}")

        result = search_recursive(menu_dict, [])

        if result:
            print(f"✅ Percorso trovato: {' → '.join(result)}")
        else:
            print("❌ Nessun percorso trovato")

        return result if result else []
    except Exception as e:
        print(f"❌ Errore in find_active_path_smart: {str(e)}")
        return []


def render_menu_item(key, item, active_path, level=0):
    """
    Renderizza un singolo elemento del menu con highlighting migliorato
    """
    try:
        # Gestisci gli header
        if key.startswith('_header'):
            return f'<li class="nav-header">{item.get("label", "")}</li>'

        # Verifica se è attivo (LOGICA MIGLIORATA)
        is_active = key in active_path if active_path else False
        has_children = 'children' in item and item['children']
        is_open = False

        # Se ha figli, controlla se qualche figlio è attivo
        if active_path and has_children:
            children_keys = list(item.get('children', {}).keys())
            is_open = any(child_key in active_path for child_key in children_keys)

            # Se un figlio è attivo, anche il parent dovrebbe essere considerato "attivo"
            if is_open and not is_active:
                # Il parent è "attivo" se ha un child attivo
                parent_active = True
            else:
                parent_active = is_active
        else:
            parent_active = is_active

        # Classe CSS per l'elemento del menu
        nav_item_class = 'nav-item'
        if has_children and (is_active or is_open):
            nav_item_class += ' menu-open'

        # Classe CSS per il link (LOGICA MIGLIORATA)
        nav_link_class = 'nav-link'

        # Per elementi senza figli: attivo se è nel percorso
        if not has_children and is_active:
            nav_link_class += ' active'

        # Per elementi con figli: attivo se ha un figlio attivo
        elif has_children and is_open:
            nav_link_class += ' active'

        # URL del link
        url = item.get('url', '#')
        if url is None:
            url = '#'

        # Se l'URL è vuoto ma c'è un endpoint, prova a generarlo
        if (url == '#' or not url) and item.get('endpoint'):
            try:
                url = url_for(item['endpoint'])
            except:
                url = '#'

        # Icona
        icon = item.get('icon', 'bi bi-circle')

        # Label
        label = item.get('label', 'Unknown')

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

        # Debug info
        print(f"🎨 Rendering {key}:")
        print(f"   is_active: {is_active}")
        print(f"   has_children: {has_children}")
        print(f"   is_open: {is_open}")
        print(f"   CSS classes: {nav_link_class}")
        print(f"   URL: {url}")

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
        error_msg = f"Error rendering {key}: {str(e)}"
        print(f"❌ {error_msg}")
        return f'<li class="nav-item"><a href="#" class="nav-link text-danger"><i class="nav-icon bi bi-exclamation-triangle"></i><p>{error_msg}</p></a></li>'
@menu_bp.route('/render')
def render_menu():
    """
    Renderizza il menu completo con rilevamento automatico dell'elemento attivo
    """
    try:
        current_endpoint = request.args.get('endpoint', 'index')
        current_url = get_current_url()

        print(f"DEBUG - Endpoint corrente: {current_endpoint}")
        print(f"DEBUG - URL corrente: {current_url}")

        # Step 1: Find active path usando il nuovo algoritmo smart
        active_path = find_active_path_smart(MENU_STRUCTURE, current_endpoint, current_url)

        print(f"DEBUG - Percorso attivo trovato: {active_path}")

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
            'current_endpoint': current_endpoint,
            'current_url': current_url,
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
        current_url = get_current_url()
        active_path = find_active_path_smart(MENU_STRUCTURE, current_endpoint, current_url)

        return jsonify({
            'active_path': active_path,
            'endpoint': current_endpoint,
            'url': current_url,
            'status': 'success'
        })
    except Exception as e:
        print(f"Errore nel recupero dello stato del menu: {str(e)}")
        return jsonify({
            'active_path': [],
            'endpoint': current_endpoint,
            'url': current_url,
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
        current_url = get_current_url()

        # Test step by step
        debug_info = {
            'step1_import': 'OK - MENU_STRUCTURE imported',
            'step2_endpoint': f'Current endpoint: {current_endpoint}',
            'step3_url': f'Current URL: {current_url}',
            'step4_structure_type': str(type(MENU_STRUCTURE)),
            'step5_structure_len': len(MENU_STRUCTURE),
        }

        # Test find_active_path_smart
        try:
            active_path = find_active_path_smart(MENU_STRUCTURE, current_endpoint, current_url)
            debug_info['step6_active_path'] = f'Active path: {active_path}'
        except Exception as e:
            debug_info['step6_active_path'] = f'ERROR: {str(e)}'

        # Test render_menu_item on first item
        try:
            first_key = next(iter(MENU_STRUCTURE.keys()))
            first_item = MENU_STRUCTURE[first_key]
            test_html = render_menu_item(first_key, first_item, [])
            debug_info['step7_render_test'] = 'OK - render_menu_item works'
        except Exception as e:
            debug_info['step7_render_test'] = f'ERROR: {str(e)}'

        # Test ogni elemento del menu
        debug_info['menu_items_analysis'] = {}
        for key, item in MENU_STRUCTURE.items():
            if not key.startswith('_header'):
                item_info = {
                    'url': item.get('url', 'NOT_SET'),
                    'endpoint': item.get('endpoint', 'NOT_SET'),
                    'has_children': 'children' in item
                }
                debug_info['menu_items_analysis'][key] = item_info

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