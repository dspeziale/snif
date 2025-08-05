from flask import Blueprint, jsonify, request
from typing import List, Dict, Any, Optional

# Crea il blueprint API
api_bp = Blueprint('api', __name__, url_prefix='/api')


def get_menu_data() -> List[Dict[str, Any]]:
    """
    Restituisce i dati del menu in formato JSON.
    Struttura del menu con supporto per due livelli di sottomenu.
    """
    menu_items = [
        {
            "id": "dashboard",
            "title": "Dashboard",
            "icon": "bi bi-speedometer",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "dashboard-v1",
                    "title": "Dashboard v1",
                    "icon": "bi bi-circle",
                    "url": "/",
                    "active": False
                },
                {
                    "id": "dashboard-v2",
                    "title": "Dashboard v2",
                    "icon": "bi bi-circle",
                    "url": "/dashboard-v2",
                    "active": False
                },
                {
                    "id": "dashboard-v3",
                    "title": "Dashboard v3",
                    "icon": "bi bi-circle",
                    "url": "/dashboard-v3",
                    "active": False
                }
            ]
        },
        {
            "id": "theme-generate",
            "title": "Theme Generate",
            "icon": "bi bi-palette",
            "url": "/generate/theme",
            "active": False,
            "children": []
        },
        {
            "id": "widgets",
            "title": "Widgets",
            "icon": "bi bi-box-seam-fill",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "small-box",
                    "title": "Small Box",
                    "icon": "bi bi-circle",
                    "url": "/widgets/small-box",
                    "active": False
                },
                {
                    "id": "info-box",
                    "title": "Info Box",
                    "icon": "bi bi-circle",
                    "url": "/widgets/info-box",
                    "active": False
                },
                {
                    "id": "cards",
                    "title": "Cards",
                    "icon": "bi bi-circle",
                    "url": "/widgets/cards",
                    "active": False
                }
            ]
        },
        {
            "id": "layout-options",
            "title": "Layout Options",
            "icon": "bi bi-clipboard-fill",
            "url": None,
            "active": False,
            "open": False,
            "badge": {
                "text": "6",
                "class": "nav-badge badge text-bg-secondary me-3"
            },
            "children": [
                {
                    "id": "default-sidebar",
                    "title": "Default Sidebar",
                    "icon": "bi bi-circle",
                    "url": "/layout/unfixed-sidebar",
                    "active": False
                },
                {
                    "id": "fixed-sidebar",
                    "title": "Fixed Sidebar",
                    "icon": "bi bi-circle",
                    "url": "/layout/fixed-sidebar",
                    "active": False
                },
                {
                    "id": "fixed-header",
                    "title": "Fixed Header",
                    "icon": "bi bi-circle",
                    "url": "/layout/fixed-header",
                    "active": False
                },
                {
                    "id": "fixed-footer",
                    "title": "Fixed Footer",
                    "icon": "bi bi-circle",
                    "url": "/layout/fixed-footer",
                    "active": False
                },
                {
                    "id": "fixed-complete",
                    "title": "Fixed Complete",
                    "icon": "bi bi-circle",
                    "url": "/layout/fixed-complete",
                    "active": False
                },
                {
                    "id": "sidebar-mini",
                    "title": "Sidebar Mini",
                    "icon": "bi bi-circle",
                    "url": "/layout/sidebar-mini",
                    "active": False
                }
            ]
        },
        {
            "id": "ui-elements",
            "title": "UI Elements",
            "icon": "bi bi-tree-fill",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "general",
                    "title": "General",
                    "icon": "bi bi-circle",
                    "url": "/ui/general",
                    "active": False
                },
                {
                    "id": "icons",
                    "title": "Icons",
                    "icon": "bi bi-circle",
                    "url": "/ui/icons",
                    "active": False
                },
                {
                    "id": "timeline",
                    "title": "Timeline",
                    "icon": "bi bi-circle",
                    "url": "/ui/timeline",
                    "active": False
                }
            ]
        },
        {
            "id": "forms",
            "title": "Forms",
            "icon": "bi bi-pencil-square",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "general-elements",
                    "title": "General Elements",
                    "icon": "bi bi-circle",
                    "url": "/forms/general",
                    "active": False
                }
            ]
        },
        {
            "id": "tables",
            "title": "Tables",
            "icon": "bi bi-table",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "simple-tables",
                    "title": "Simple Tables",
                    "icon": "bi bi-circle",
                    "url": "/tables/simple",
                    "active": False
                }
            ]
        },
        {
            "type": "header",
            "title": "EXAMPLES"
        },
        {
            "id": "auth",
            "title": "Auth",
            "icon": "bi bi-box-arrow-in-right",
            "url": None,
            "active": False,
            "open": False,
            "children": [
                {
                    "id": "version-1",
                    "title": "Version 1",
                    "icon": "bi bi-box-arrow-in-right",
                    "url": None,
                    "active": False,
                    "open": False,
                    "children": [
                        {
                            "id": "login-v1",
                            "title": "Login",
                            "icon": "bi bi-circle",
                            "url": "/examples/login",
                            "active": False
                        },
                        {
                            "id": "register-v1",
                            "title": "Register",
                            "icon": "bi bi-circle",
                            "url": "/examples/register",
                            "active": False
                        }
                    ]
                },
                {
                    "id": "version-2",
                    "title": "Version 2",
                    "icon": "bi bi-box-arrow-in-right",
                    "url": None,
                    "active": False,
                    "open": False,
                    "children": [
                        {
                            "id": "login-v2",
                            "title": "Login",
                            "icon": "bi bi-circle",
                            "url": "/examples/login-v2",
                            "active": False
                        },
                        {
                            "id": "register-v2",
                            "title": "Register",
                            "icon": "bi bi-circle",
                            "url": "/examples/register-v2",
                            "active": False
                        }
                    ]
                },
                {
                    "id": "lockscreen",
                    "title": "Lockscreen",
                    "icon": "bi bi-circle",
                    "url": "/examples/lockscreen",
                    "active": False
                }
            ]
        },
        {
            "type": "header",
            "title": "DOCUMENTATIONS"
        },
        {
            "id": "installation",
            "title": "Installation",
            "icon": "bi bi-download",
            "url": "/docs/introduction",
            "active": False,
            "children": []
        },
        {
            "id": "layout-docs",
            "title": "Layout",
            "icon": "bi bi-grip-horizontal",
            "url": "/docs/layout",
            "active": False,
            "children": []
        }
    ]

    return menu_items


def set_active_menu_item(menu_items: List[Dict[str, Any]], current_path: str) -> List[Dict[str, Any]]:
    """
    Imposta l'elemento del menu attivo e apre l'albero dei menu genitore.
    """

    def mark_active_recursive(items: List[Dict[str, Any]], path: str, parent_ids: List[str] = []) -> bool:
        found = False

        for item in items:
            if item.get('type') == 'header':
                continue

            # Assicurati che l'item abbia un ID
            if 'id' not in item:
                continue

            current_parent_ids = parent_ids + [item['id']]

            # Controlla se questo è l'elemento attivo
            if item.get('url') == path:
                item['active'] = True
                found = True

                # Apri tutti i menu genitore
                for menu_item in menu_items:
                    if menu_item.get('id') in current_parent_ids:
                        menu_item['open'] = True
                        if 'children' in menu_item and menu_item['children']:
                            for child in menu_item['children']:
                                if child.get('id') in current_parent_ids:
                                    child['open'] = True

            # Controlla ricorsivamente nei children
            if 'children' in item and item['children']:
                child_found = mark_active_recursive(item['children'], path, current_parent_ids)
                if child_found:
                    item['open'] = True
                    found = True

        return found

    mark_active_recursive(menu_items, current_path)
    return menu_items


@api_bp.route('/menu')
def get_menu():
    """
    Endpoint per ottenere i dati del menu.
    Accetta un parametro 'current_path' per impostare l'elemento attivo.
    """
    current_path = request.args.get('current_path', '/')

    try:
        menu_items = get_menu_data()
        menu_items = set_active_menu_item(menu_items, current_path)

        return jsonify({
            'success': True,
            'data': menu_items
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/menu/update-active', methods=['POST'])
def update_active_menu():
    """
    Endpoint per aggiornare l'elemento del menu attivo.
    """
    data = request.get_json()
    current_path = data.get('current_path', '/')

    try:
        menu_items = get_menu_data()
        menu_items = set_active_menu_item(menu_items, current_path)

        return jsonify({
            'success': True,
            'data': menu_items
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500