"""
Blueprint API aggiornato per utilizzare il database SQLite al posto dei file JSON
"""
from flask import Blueprint, jsonify, request, current_app
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

# Import dei manager per l'accesso ai dati
from db_manager import (
    MenuManager, MessageManager, NotificationManager, StatsManager,
    menu_manager, message_manager, notification_manager, stats_manager
)
from models import db

# Crea il blueprint
api = Blueprint('api', __name__)


# ===============================
# API ENDPOINTS PER IL MENU
# ===============================

@api.route('/api/menu')
@api.route('/api/sidebar-menu')
def get_sidebar_menu():
    """Endpoint per ottenere il menu della sidebar"""
    try:
        menu_data = menu_manager.get_sidebar_menu()

        return jsonify({
            'success': True,
            'data': menu_data,
            'count': len(menu_data),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento del menu sidebar: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento del menu',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/menu/items', methods=['POST'])
def create_menu_item():
    """Endpoint per creare un nuovo elemento del menu"""
    try:
        data = request.get_json()
        if not data or 'title' not in data:
            return jsonify({
                'success': False,
                'error': 'Dati non validi. Il campo "title" è obbligatorio.'
            }), 400

        menu_item = menu_manager.add_menu_item(
            title=data['title'],
            icon=data.get('icon'),
            url=data.get('url'),
            parent_id=data.get('parent_id'),
            menu_type_name=data.get('menu_type', 'sidebar'),
            sort_order=data.get('sort_order', 0),
            active=data.get('active', False),
            extra_data=data.get('extra_data')
        )

        if menu_item:
            return jsonify({
                'success': True,
                'data': menu_item.to_dict(),
                'message': 'Elemento menu creato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nella creazione dell\'elemento menu'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nella creazione dell'elemento menu: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nella creazione dell\'elemento menu',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/menu/items/<int:item_id>', methods=['PUT'])
def update_menu_item(item_id):
    """Endpoint per aggiornare un elemento del menu"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Nessun dato fornito'
            }), 400

        success = menu_manager.update_menu_item(item_id, **data)

        if success:
            return jsonify({
                'success': True,
                'message': 'Elemento menu aggiornato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Elemento menu non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento dell'elemento menu: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento dell\'elemento menu',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/menu/items/<int:item_id>', methods=['DELETE'])
def delete_menu_item(item_id):
    """Endpoint per eliminare un elemento del menu"""
    try:
        success = menu_manager.delete_menu_item(item_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Elemento menu eliminato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Elemento menu non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'eliminazione dell'elemento menu: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'eliminazione dell\'elemento menu',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/menu/set-active', methods=['POST'])
def set_active_menu():
    """Endpoint per impostare l'elemento del menu attivo"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL richiesto'
            }), 400

        success = menu_manager.set_active_menu_item(data['url'])

        if success:
            return jsonify({
                'success': True,
                'message': 'Menu attivo aggiornato'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nell\'aggiornamento del menu attivo'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nell'impostazione del menu attivo: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'impostazione del menu attivo',
            'details': str(e) if current_app.debug else None
        }), 500


# ===============================
# API ENDPOINTS PER I MESSAGGI
# ===============================
@api.route('/api/messages')
def get_messages():
    """Endpoint semplificato per ottenere i messaggi"""
    try:
        # Parametri di query con valori di default
        limit = request.args.get('limit', type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        message_type = request.args.get('type')
        priority = request.args.get('priority')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)

        # Usa il manager per ottenere i messaggi
        messages_data = message_manager.get_messages(
            limit=limit,
            unread_only=unread_only,
            message_type=message_type,
            priority=priority,
            page=page,
            per_page=per_page
        )

        # Verifica che abbiamo dati validi
        if not messages_data:
            messages_data = {'messages': [], 'total': 0, 'unread_count': 0}

        # Prepara i dati per DataTables
        messages_list = messages_data.get('messages', [])

        # Formato DataTables standard
        response = {
            'draw': request.args.get('draw', 1, type=int),  # Per DataTables server-side
            'recordsTotal': messages_data.get('total', len(messages_list)),
            'recordsFiltered': messages_data.get('total', len(messages_list)),
            'data': messages_list,
            'success': True,
            'messages': messages_list,  # Backward compatibility
            'total': messages_data.get('total', len(messages_list)),
            'unread_count': messages_data.get('unread_count', 0)
        }

        return jsonify(response)

    except Exception as e:
        current_app.logger.error(f"Errore API messages: {str(e)}")

        # Risposta di errore in formato DataTables
        error_response = {
            'draw': request.args.get('draw', 1, type=int),
            'recordsTotal': 0,
            'recordsFiltered': 0,
            'data': [],
            'success': False,
            'error': str(e),
            'messages': [],
            'total': 0,
            'unread_count': 0
        }

        return jsonify(error_response), 500


@api.route('/api/messages/<int:message_id>')
def get_message(message_id):
    """Endpoint per ottenere un messaggio specifico"""
    try:
        message = message_manager.get_message(message_id)

        if message:
            return jsonify({
                'success': True,
                'data': message,
                'message': message  # Backward compatibility
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Message not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore get_message {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/messages', methods=['POST'])
def create_message():
    """Endpoint per creare un nuovo messaggio"""
    try:
        data = request.get_json()

        # Validazione dati di base
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        if not data.get('sender') or not data.get('content'):
            return jsonify({
                'success': False,
                'error': 'Sender and content are required'
            }), 400

        # Crea il messaggio
        message = message_manager.create_message(
            sender=data.get('sender'),
            content=data.get('content'),
            subject=data.get('subject'),
            message_type=data.get('type'),
            priority=data.get('priority', 'medium'),
            avatar=data.get('avatar'),
            extra_data=data.get('extra_data')
        )

        if message:
            return jsonify({
                'success': True,
                'data': message.to_dict(),
                'message': 'Message created successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create message'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore create_message: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/messages/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    """Endpoint per segnare un messaggio come letto"""
    try:
        success = message_manager.mark_message_read(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Message marked as read'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Message not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore mark_message_read {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/messages/mark-all-read', methods=['POST'])
def mark_all_messages_read():
    """Endpoint per segnare tutti i messaggi come letti"""
    try:
        success = message_manager.mark_all_messages_read()

        if success:
            return jsonify({
                'success': True,
                'message': 'All messages marked as read'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to mark messages as read'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore mark_all_messages_read: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/messages/<int:message_id>/archive', methods=['POST'])
def archive_message(message_id):
    """Endpoint per archiviare un messaggio"""
    try:
        success = message_manager.archive_message(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Message archived'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Message not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore archive_message {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/messages/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    """Endpoint per eliminare un messaggio"""
    try:
        success = message_manager.delete_message(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Message deleted'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Message not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore delete_message {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ===============================
# API ENDPOINTS PER LE NOTIFICHE
# ===============================
@api.route('/api/notifications')
def get_notifications():
    """Endpoint semplificato per ottenere le notifiche"""
    try:
        # Parametri di query con valori di default
        limit = request.args.get('limit', type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        notification_type = request.args.get('type')
        category = request.args.get('category')
        priority = request.args.get('priority')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)

        # Usa il manager per ottenere le notifiche
        notifications_data = notification_manager.get_notifications(
            limit=limit,
            unread_only=unread_only,
            notification_type=notification_type,
            category=category,
            priority=priority,
            page=page,
            per_page=per_page
        )

        # Verifica che abbiamo dati validi
        if not notifications_data:
            notifications_data = {'notifications': [], 'total': 0, 'unread_count': 0}

        # Prepara i dati per DataTables
        notifications_list = notifications_data.get('notifications', [])

        # Formato DataTables standard
        response = {
            'draw': request.args.get('draw', 1, type=int),  # Per DataTables server-side
            'recordsTotal': notifications_data.get('total', len(notifications_list)),
            'recordsFiltered': notifications_data.get('total', len(notifications_list)),
            'data': notifications_list,
            'success': True,
            'notifications': notifications_list,  # Backward compatibility
            'total': notifications_data.get('total', len(notifications_list)),
            'unread_count': notifications_data.get('unread_count', 0)
        }

        return jsonify(response)

    except Exception as e:
        current_app.logger.error(f"Errore API notifications: {str(e)}")

        # Risposta di errore in formato DataTables
        error_response = {
            'draw': request.args.get('draw', 1, type=int),
            'recordsTotal': 0,
            'recordsFiltered': 0,
            'data': [],
            'success': False,
            'error': str(e),
            'notifications': [],
            'total': 0,
            'unread_count': 0
        }

        return jsonify(error_response), 500


@api.route('/api/notifications/<int:notification_id>')
def get_notification(notification_id):
    """Endpoint per ottenere una notifica specifica"""
    try:
        notification = notification_manager.get_notification(notification_id)

        if notification:
            return jsonify({
                'success': True,
                'data': notification,
                'notification': notification  # Backward compatibility
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore get_notification {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/notifications', methods=['POST'])
def create_notification():
    """Endpoint per creare una nuova notifica"""
    try:
        data = request.get_json()

        # Validazione dati di base
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        if not data.get('message'):
            return jsonify({
                'success': False,
                'error': 'Message is required'
            }), 400

        # Crea la notifica
        notification = notification_manager.create_notification(
            message=data.get('message'),
            notification_type=data.get('type'),
            category=data.get('category'),
            priority=data.get('priority', 'low'),
            icon=data.get('icon'),
            action_url=data.get('action_url'),
            extra_data=data.get('extra_data')
        )

        if notification:
            return jsonify({
                'success': True,
                'data': notification.to_dict(),
                'message': 'Notification created successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create notification'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore create_notification: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Endpoint per segnare una notifica come letta"""
    try:
        success = notification_manager.mark_notification_read(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notification marked as read'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore mark_notification_read {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_read():
    """Endpoint per segnare tutte le notifiche come lette"""
    try:
        success = notification_manager.mark_all_notifications_read()

        if success:
            return jsonify({
                'success': True,
                'message': 'All notifications marked as read'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to mark notifications as read'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore mark_all_notifications_read: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/notifications/<int:notification_id>/dismiss', methods=['POST'])
def dismiss_notification(notification_id):
    """Endpoint per rimuovere una notifica"""
    try:
        success = notification_manager.dismiss_notification(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notification dismissed'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore dismiss_notification {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    """Endpoint per eliminare una notifica"""
    try:
        success = notification_manager.delete_notification(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notification deleted'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notification not found'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore delete_notification {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ===============================
# API ENDPOINTS PER LE STATISTICHE
# ===============================

@api.route('/api/stats')
@api.route('/api/dashboard-stats')
def get_dashboard_stats():
    """Endpoint per ottenere le statistiche della dashboard"""
    try:
        stats = stats_manager.get_dashboard_stats()

        return jsonify({
            'success': True,
            'data': stats,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle statistiche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle statistiche',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/activity-timeline')
def get_activity_timeline():
    """Endpoint per ottenere la timeline delle attività"""
    try:
        days = request.args.get('days', 7, type=int)
        timeline = stats_manager.get_activity_timeline(days)

        return jsonify({
            'success': True,
            'data': timeline,
            'days': days,
            'count': len(timeline),
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento della timeline: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento della timeline',
            'details': str(e) if current_app.debug else None
        }), 500


# ===============================
# API ENDPOINTS PER LA CONFIGURAZIONE DATABASE
# ===============================

@api.route('/api/database/info')
def get_database_info():
    """Endpoint per ottenere informazioni sul database"""
    try:
        from database_config import get_database_info
        info = get_database_info(current_app)

        return jsonify({
            'success': True,
            'data': info,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle info database: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle informazioni database',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/database/backup', methods=['POST'])
def create_database_backup():
    """Endpoint per creare un backup del database"""
    try:
        from database_config import backup_database
        backup_path = backup_database(current_app)

        return jsonify({
            'success': True,
            'backup_path': backup_path,
            'message': 'Backup creato con successo'
        })

    except Exception as e:
        current_app.logger.error(f"Errore nella creazione del backup: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nella creazione del backup',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/database/optimize', methods=['POST'])
def optimize_database():
    """Endpoint per ottimizzare il database"""
    try:
        from database_config import optimize_database
        success = optimize_database(current_app)

        if success:
            return jsonify({
                'success': True,
                'message': 'Database ottimizzato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nell\'ottimizzazione del database'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nell'ottimizzazione del database: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'ottimizzazione del database',
            'details': str(e) if current_app.debug else None
        }), 500


# ===============================
# CONTEXT PROCESSOR
# ===============================

@api.app_context_processor
def inject_template_data():
    """Inietta i dati nei template utilizzando il database"""
    try:
        # Ottieni i dati per i template
        sidebar_menu = menu_manager.get_sidebar_menu()
        messages_data = message_manager.get_messages(limit=5)
        notifications_data = notification_manager.get_notifications(limit=5)

        return {
            'sidebar_menu': sidebar_menu,
            'messages': messages_data.get('messages', []),
            'notifications': notifications_data.get('notifications', []),
            'app_name': 'AdminLTE Flask Dashboard',
            'app_version': '4.0.0',
            'database_mode': True  # Flag per indicare che si sta usando il database
        }

    except Exception as e:
        current_app.logger.error(f"Errore nell'iniezione dei dati del template: {str(e)}")
        return {
            'sidebar_menu': [],
            'messages': [],
            'notifications': [],
            'app_name': 'AdminLTE Flask Dashboard',
            'app_version': '4.0.0',
            'database_mode': True
        }


# ===============================
# ERROR HANDLERS
# ===============================

@api.errorhandler(400)
def bad_request(error):
    """Handler per errori 400"""
    return jsonify({
        'success': False,
        'error': 'Richiesta non valida',
        'details': str(error) if current_app.debug else None
    }), 400


@api.errorhandler(404)
def api_not_found(error):
    """Handler per errori 404 delle API"""
    return jsonify({
        'success': False,
        'error': 'Endpoint non trovato'
    }), 404


@api.errorhandler(500)
def api_internal_error(error):
    """Handler per errori 500 delle API"""
    return jsonify({
        'success': False,
        'error': 'Errore interno del server',
        'details': str(error) if current_app.debug else None
    }), 500


# ===============================
# UTILITY FUNCTIONS
# ===============================

def validate_json_data(data: dict, required_fields: List[str]) -> Optional[str]:
    """
    Valida i dati JSON ricevuti

    Args:
        data: Dati da validare
        required_fields: Campi obbligatori

    Returns:
        Messaggio di errore se la validazione fallisce, None altrimenti
    """
    if not isinstance(data, dict):
        return "I dati devono essere un oggetto JSON valido"

    for field in required_fields:
        if field not in data:
            return f"Il campo '{field}' è obbligatorio"

        if not data[field] or (isinstance(data[field], str) and not data[field].strip()):
            return f"Il campo '{field}' non può essere vuoto"

    return None


def paginate_query_results(query_result: dict, page: int, per_page: int) -> dict:
    """
    Aggiunge informazioni di paginazione ai risultati

    Args:
        query_result: Risultato della query
        page: Numero di pagina corrente
        per_page: Elementi per pagina

    Returns:
        Risultato con informazioni di paginazione aggiunte
    """
    if 'pagination' not in query_result:
        query_result['pagination'] = {
            'page': page,
            'per_page': per_page,
            'total': query_result.get('total', 0),
            'pages': 1,
            'has_next': False,
            'has_prev': False
        }

    return query_result


# ===============================
# API ENDPOINT PER STATUS APPLICAZIONE
# ===============================

@api.route('/api/app/status')
def get_app_status():
    """Endpoint completo per ottenere lo stato dell'applicazione"""
    try:
        import psutil
        import os
        import platform
        from datetime import datetime, timedelta

        # Informazioni sistema
        system_info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
        }

        # Informazioni processo Python
        process = psutil.Process()
        process_info = {
            'pid': process.pid,
            'memory_usage_mb': round(process.memory_info().rss / 1024 / 1024, 2),
            'cpu_percent': process.cpu_percent(),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
            'num_threads': process.num_threads(),
            'status': process.status(),
        }

        # Informazioni memoria sistema
        memory = psutil.virtual_memory()
        memory_info = {
            'total_gb': round(memory.total / 1024 / 1024 / 1024, 2),
            'available_gb': round(memory.available / 1024 / 1024 / 1024, 2),
            'used_gb': round(memory.used / 1024 / 1024 / 1024, 2),
            'percentage': memory.percent,
        }

        # Informazioni disco
        disk = psutil.disk_usage('/')
        disk_info = {
            'total_gb': round(disk.total / 1024 / 1024 / 1024, 2),
            'used_gb': round(disk.used / 1024 / 1024 / 1024, 2),
            'free_gb': round(disk.free / 1024 / 1024 / 1024, 2),
            'percentage': round((disk.used / disk.total) * 100, 2),
        }

        # Informazioni CPU
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'total_cores': psutil.cpu_count(logical=True),
            'max_frequency': round(psutil.cpu_freq().max, 2) if psutil.cpu_freq() else 0,
            'current_frequency': round(psutil.cpu_freq().current, 2) if psutil.cpu_freq() else 0,
            'cpu_usage': psutil.cpu_percent(interval=1),
        }

    except ImportError:
        # Fallback se psutil non è disponibile
        system_info = {
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
        }
        process_info = {'pid': os.getpid()}
        memory_info = {'status': 'unavailable'}
        disk_info = {'status': 'unavailable'}
        cpu_info = {'status': 'unavailable'}

    # Ottieni informazioni database
    try:
        from database_config import get_database_info
        db_info = get_database_info(current_app)
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento info database: {str(e)}")
        db_info = {'error': str(e)}

    # Ottieni statistiche applicazione
    try:
        app_stats = stats_manager.get_dashboard_stats()
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento statistiche: {str(e)}")
        app_stats = {'error': str(e)}

    # Informazioni configurazione Flask
    flask_info = {
        'debug_mode': current_app.debug,
        'testing': current_app.testing,
        'secret_key_set': bool(current_app.secret_key),
        'instance_path': current_app.instance_path,
        'root_path': current_app.root_path,
    }

    # Test connettività API
    api_health = {
        'messages_api': 'unknown',
        'notifications_api': 'unknown',
        'database_api': 'unknown',
        'stats_api': 'unknown'
    }

    try:
        # Test API messaggi
        messages_data = message_manager.get_messages(limit=1)
        api_health['messages_api'] = 'healthy' if messages_data else 'error'
    except Exception:
        api_health['messages_api'] = 'error'

    try:
        # Test API notifiche
        notifications_data = notification_manager.get_notifications(limit=1)
        api_health['notifications_api'] = 'healthy' if notifications_data else 'error'
    except Exception:
        api_health['notifications_api'] = 'error'

    try:
        # Test accesso database
        from models import db
        db.session.execute('SELECT 1').fetchone()
        api_health['database_api'] = 'healthy'
    except Exception:
        api_health['database_api'] = 'error'

    try:
        # Test API statistiche
        stats_test = stats_manager.get_dashboard_stats()
        api_health['stats_api'] = 'healthy' if stats_test else 'error'
    except Exception:
        api_health['stats_api'] = 'error'

    # Calcola stato generale
    total_apis = len(api_health)
    healthy_apis = sum(1 for status in api_health.values() if status == 'healthy')

    if healthy_apis == total_apis:
        overall_status = 'healthy'
    elif healthy_apis >= total_apis * 0.5:
        overall_status = 'warning'
    else:
        overall_status = 'critical'

    # Componi risposta completa
    status_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'overall_status': overall_status,
        'health_score': round((healthy_apis / total_apis) * 100, 2),
        'system': system_info,
        'process': process_info,
        'memory': memory_info,
        'disk': disk_info,
        'cpu': cpu_info,
        'flask': flask_info,
        'database': db_info,
        'statistics': app_stats,
        'api_health': api_health,
        'uptime': {
            'application_start': datetime.utcnow().isoformat(),  # Approssimativo
            'last_restart': datetime.utcnow().isoformat(),  # Approssimativo
        }
    }

    return jsonify({
        'success': True,
        'data': status_data,
        'timestamp': datetime.utcnow().isoformat()
    })


@api.route('/api/app/health')
def get_app_health():
    """Endpoint leggero per health check"""
    try:
        # Test rapido database
        from models import db
        db.session.execute('SELECT 1').fetchone()
        db_status = 'healthy'
    except Exception as e:
        db_status = 'error'
        current_app.logger.error(f"Database health check failed: {str(e)}")

    # Test rapido API
    try:
        messages_count = message_manager.get_messages(limit=1).get('total', 0)
        api_status = 'healthy'
    except Exception as e:
        api_status = 'error'
        current_app.logger.error(f"API health check failed: {str(e)}")

    # Stato generale
    if db_status == 'healthy' and api_status == 'healthy':
        overall_status = 'healthy'
        http_status = 200
    else:
        overall_status = 'unhealthy'
        http_status = 503

    response_data = {
        'status': overall_status,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': {
            'database': db_status,
            'api': api_status
        }
    }

    return jsonify(response_data), http_status


@api.route('/api/app/metrics')
def get_app_metrics():
    """Endpoint per metriche dell'applicazione"""
    try:
        # Statistiche database
        db_stats = stats_manager.get_dashboard_stats()

        # Metriche personalizzate
        metrics = {
            'messages': {
                'total': db_stats.get('messages', {}).get('total', 0),
                'unread': db_stats.get('messages', {}).get('unread', 0),
                'read_percentage': db_stats.get('messages', {}).get('read_percentage', 0),
            },
            'notifications': {
                'total': db_stats.get('notifications', {}).get('total', 0),
                'unread': db_stats.get('notifications', {}).get('unread', 0),
                'read_percentage': db_stats.get('notifications', {}).get('read_percentage', 0),
            },
            'database': {
                'size_mb': 0,  # Verrà calcolato se disponibile
                'tables': 0,
                'total_records': 0,
            },
            'system': {
                'timestamp': datetime.utcnow().isoformat(),
                'uptime_seconds': 0,  # Approssimativo
            }
        }

        # Aggiungi informazioni database se disponibili
        try:
            from database_config import get_database_info
            db_info = get_database_info(current_app)

            metrics['database']['size_mb'] = db_info.get('database_size_mb', 0)
            metrics['database']['tables'] = len(db_info.get('tables', {}))

            # Calcola totale record
            tables = db_info.get('tables', {})
            total_records = sum(tables.values()) if tables else 0
            metrics['database']['total_records'] = total_records

        except Exception as e:
            current_app.logger.error(f"Errore nel caricamento metriche database: {str(e)}")

        return jsonify({
            'success': True,
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento metriche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle metriche',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/app/version')
def get_app_version():
    """Endpoint per informazioni versione applicazione"""
    try:
        import sys
        import flask
        from datetime import datetime

        version_info = {
            'application': {
                'name': 'AdminLTE Flask Dashboard',
                'version': '4.0.0',
                'description': 'A comprehensive admin dashboard built with Flask and AdminLTE 4',
                'author': 'Development Team',
                'license': 'MIT'
            },
            'framework': {
                'flask_version': flask.__version__,
                'python_version': sys.version,
                'python_executable': sys.executable,
            },
            'dependencies': {
                'sqlalchemy': 'Unknown',  # Potresti aggiungere versioni specifiche
                'bootstrap': '5.3.2',
                'adminlte': '4.0.0',
                'jquery': '3.7.1',
            },
            'build_info': {
                'build_date': datetime.utcnow().isoformat(),
                'environment': 'development' if current_app.debug else 'production',
                'debug_mode': current_app.debug,
            }
        }

        # Prova a ottenere versioni dei package installati
        try:
            import pkg_resources
            installed_packages = {pkg.project_name: pkg.version
                                  for pkg in pkg_resources.working_set}

            # Aggiorna con versioni reali se disponibili
            for pkg_name in ['flask', 'sqlalchemy', 'jinja2']:
                if pkg_name in installed_packages:
                    version_info['dependencies'][pkg_name] = installed_packages[pkg_name]

        except ImportError:
            pass  # pkg_resources non disponibile

        return jsonify({
            'success': True,
            'data': version_info,
            'timestamp': datetime.utcnow().isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento info versione: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle informazioni versione',
            'details': str(e) if current_app.debug else None
        }), 500