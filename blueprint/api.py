from flask import Blueprint, jsonify, render_template, current_app
import json
import os
from datetime import datetime

api = Blueprint('api', __name__)


def load_config():
    """Carica la configurazione dal file config.json"""
    try:
        config_path = os.path.join(current_app.root_path, 'config.json')
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        current_app.logger.error("File config.json non trovato")
        return get_default_config()
    except json.JSONDecodeError:
        current_app.logger.error("Errore nel parsing di config.json")
        return get_default_config()


def get_default_config():
    """Configurazione predefinita nel caso il file non sia trovato"""
    return {
        "sidebar_menu": [
            {
                "title": "Dashboard",
                "icon": "bi bi-speedometer",
                "url": "/",
                "active": True,
                "children": [
                    {
                        "title": "Dashboard v1",
                        "icon": "bi bi-circle",
                        "url": "/dashboard/v1",
                        "active": True
                    },
                    {
                        "title": "Dashboard v2",
                        "icon": "bi bi-circle",
                        "url": "/dashboard/v2",
                        "active": False
                    }
                ]
            },
            {
                "title": "Widgets",
                "icon": "bi bi-grid",
                "url": "/widgets",
                "active": False
            },
            {
                "title": "Layout Options",
                "icon": "bi bi-layout-three-columns",
                "url": "#",
                "active": False,
                "children": [
                    {
                        "title": "Top Navigation",
                        "icon": "bi bi-circle",
                        "url": "/layout/top-nav",
                        "active": False
                    },
                    {
                        "title": "Boxed",
                        "icon": "bi bi-circle",
                        "url": "/layout/boxed",
                        "active": False
                    },
                    {
                        "title": "Fixed Sidebar",
                        "icon": "bi bi-circle",
                        "url": "/layout/fixed-sidebar",
                        "active": False
                    }
                ]
            },
            {
                "title": "Charts",
                "icon": "bi bi-pie-chart",
                "url": "#",
                "active": False,
                "children": [
                    {
                        "title": "ChartJS",
                        "icon": "bi bi-circle",
                        "url": "/charts/chartjs",
                        "active": False
                    },
                    {
                        "title": "Flot",
                        "icon": "bi bi-circle",
                        "url": "/charts/flot",
                        "active": False
                    },
                    {
                        "title": "Inline",
                        "icon": "bi bi-circle",
                        "url": "/charts/inline",
                        "active": False
                    }
                ]
            },
            {
                "title": "UI Elements",
                "icon": "bi bi-tree",
                "url": "#",
                "active": False,
                "children": [
                    {
                        "title": "General",
                        "icon": "bi bi-circle",
                        "url": "/ui/general",
                        "active": False
                    },
                    {
                        "title": "Icons",
                        "icon": "bi bi-circle",
                        "url": "/ui/icons",
                        "active": False
                    },
                    {
                        "title": "Buttons",
                        "icon": "bi bi-circle",
                        "url": "/ui/buttons",
                        "active": False
                    },
                    {
                        "title": "Sliders",
                        "icon": "bi bi-circle",
                        "url": "/ui/sliders",
                        "active": False
                    },
                    {
                        "title": "Modals & Alerts",
                        "icon": "bi bi-circle",
                        "url": "/ui/modals",
                        "active": False
                    },
                    {
                        "title": "Navbar & Tabs",
                        "icon": "bi bi-circle",
                        "url": "/ui/navbar",
                        "active": False
                    },
                    {
                        "title": "Timeline",
                        "icon": "bi bi-circle",
                        "url": "/ui/timeline",
                        "active": False
                    },
                    {
                        "title": "Ribbons",
                        "icon": "bi bi-circle",
                        "url": "/ui/ribbons",
                        "active": False
                    }
                ]
            },
            {
                "title": "Forms",
                "icon": "bi bi-pencil-square",
                "url": "#",
                "active": False,
                "children": [
                    {
                        "title": "General Elements",
                        "icon": "bi bi-circle",
                        "url": "/forms/general",
                        "active": False
                    },
                    {
                        "title": "Advanced Elements",
                        "icon": "bi bi-circle",
                        "url": "/forms/advanced",
                        "active": False
                    },
                    {
                        "title": "Editors",
                        "icon": "bi bi-circle",
                        "url": "/forms/editors",
                        "active": False
                    },
                    {
                        "title": "Validation",
                        "icon": "bi bi-circle",
                        "url": "/forms/validation",
                        "active": False
                    }
                ]
            },
            {
                "title": "Tables",
                "icon": "bi bi-table",
                "url": "#",
                "active": False,
                "children": [
                    {
                        "title": "Simple Tables",
                        "icon": "bi bi-circle",
                        "url": "/tables/simple",
                        "active": False
                    },
                    {
                        "title": "Data Tables",
                        "icon": "bi bi-circle",
                        "url": "/tables/data",
                        "active": False
                    }
                ]
            }
        ],
        "messages": [
            {
                "id": 1,
                "sender": "Alexander Pierce",
                "content": "Store your password safely using a password manager...",
                "time": "4 hours ago",
                "avatar": "/static/assets/img/user1-128x128.jpg",
                "unread": True
            },
            {
                "id": 2,
                "sender": "Sarah Bullock",
                "content": "You better believe it!",
                "time": "4 hours ago",
                "avatar": "/static/assets/img/user3-128x128.jpg",
                "unread": True
            },
            {
                "id": 3,
                "sender": "Nora Silvester",
                "content": "The subject goes here",
                "time": "4 hours ago",
                "avatar": "/static/assets/img/user4-128x128.jpg",
                "unread": False
            }
        ],
        "notifications": [
            {
                "id": 1,
                "message": "15 friends sent you a friend request",
                "time": "Just now",
                "icon": "bi-person-fill-add",
                "type": "friend_request"
            },
            {
                "id": 2,
                "message": "You have 5 new followers",
                "time": "10 minutes ago",
                "icon": "bi-people-fill",
                "type": "followers"
            },
            {
                "id": 3,
                "message": "You have 3 new messages",
                "time": "4 minutes ago",
                "icon": "bi-chat-text-fill",
                "type": "messages"
            },
            {
                "id": 4,
                "message": "Server overloaded with requests. Please check!",
                "time": "17 minutes ago",
                "icon": "bi-exclamation-triangle-fill",
                "type": "warning"
            }
        ]
    }


@api.route('/api/sidebar-menu')
def get_sidebar_menu():
    """Endpoint per ottenere il menu della sidebar"""
    try:
        config = load_config()
        return jsonify({
            'success': True,
            'data': config.get('sidebar_menu', [])
        })
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento del menu sidebar: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento del menu'
        }), 500


@api.route('/api/messages')
def get_messages():
    """Endpoint per ottenere i messaggi"""
    try:
        config = load_config()
        messages = config.get('messages', [])

        # Aggiungi informazioni aggiuntive
        for message in messages:
            if 'timestamp' not in message:
                message['timestamp'] = datetime.now().isoformat()

        return jsonify({
            'success': True,
            'data': messages,
            'count': len(messages),
            'unread_count': len([m for m in messages if m.get('unread', False)])
        })
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento dei messaggi: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento dei messaggi'
        }), 500


@api.route('/api/notifications')
def get_notifications():
    """Endpoint per ottenere le notifiche"""
    try:
        config = load_config()
        notifications = config.get('notifications', [])

        # Aggiungi informazioni aggiuntive
        for notification in notifications:
            if 'timestamp' not in notification:
                notification['timestamp'] = datetime.now().isoformat()
            if 'read' not in notification:
                notification['read'] = False

        return jsonify({
            'success': True,
            'data': notifications,
            'count': len(notifications),
            'unread_count': len([n for n in notifications if not n.get('read', False)])
        })
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle notifiche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle notifiche'
        }), 500


@api.route('/api/messages/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    """Segna un messaggio come letto"""
    try:
        config = load_config()
        messages = config.get('messages', [])

        for message in messages:
            if message.get('id') == message_id:
                message['unread'] = False
                message['read_at'] = datetime.now().isoformat()
                break

        # Qui dovresti salvare la configurazione aggiornata
        # save_config(config)

        return jsonify({
            'success': True,
            'message': 'Messaggio segnato come letto'
        })
    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento del messaggio: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento del messaggio'
        }), 500


@api.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Segna una notifica come letta"""
    try:
        config = load_config()
        notifications = config.get('notifications', [])

        for notification in notifications:
            if notification.get('id') == notification_id:
                notification['read'] = True
                notification['read_at'] = datetime.now().isoformat()
                break

        # Qui dovresti salvare la configurazione aggiornata
        # save_config(config)

        return jsonify({
            'success': True,
            'message': 'Notifica segnata come letta'
        })
    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento della notifica: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento della notifica'
        }), 500


@api.route('/api/config')
def get_full_config():
    """Endpoint per ottenere l'intera configurazione"""
    try:
        config = load_config()
        return jsonify({
            'success': True,
            'data': config
        })
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento della configurazione: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento della configurazione'
        }), 500


def save_config(config):
    """Salva la configurazione nel file config.json"""
    try:
        config_path = os.path.join(current_app.root_path, 'config.json')
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        current_app.logger.error(f"Errore nel salvataggio della configurazione: {str(e)}")
        return False


# Context processor per rendere disponibili i dati in tutti i template
@api.app_context_processor
def inject_menu_data():
    """Inietta i dati del menu, messaggi e notifiche in tutti i template"""
    try:
        config = load_config()
        return {
            'sidebar_menu': config.get('sidebar_menu', []),
            'messages': config.get('messages', []),
            'notifications': config.get('notifications', [])
        }
    except Exception as e:
        current_app.logger.error(f"Errore nell'iniezione dei dati del menu: {str(e)}")
        return {
            'sidebar_menu': [],
            'messages': [],
            'notifications': []
        }