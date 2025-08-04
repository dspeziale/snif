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
    """Endpoint per ottenere i messaggi"""
    try:
        # Parametri di query
        limit = request.args.get('limit', type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        message_type = request.args.get('type')
        priority = request.args.get('priority')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Ottieni i messaggi
        result = message_manager.get_messages(
            limit=limit,
            unread_only=unread_only,
            message_type=message_type,
            priority=priority,
            page=page,
            per_page=per_page
        )

        # Aggiungi metadati aggiuntivi
        result['success'] = True
        result['timestamp'] = datetime.utcnow().isoformat()
        result['message_types'] = message_manager.get_message_types()
        result['priorities'] = message_manager.get_message_priorities()

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento dei messaggi: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento dei messaggi',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages/<int:message_id>')
def get_message(message_id):
    """Endpoint per ottenere un messaggio specifico"""
    try:
        message = message_manager.get_message(message_id)

        if message:
            return jsonify({
                'success': True,
                'data': message,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento del messaggio',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages', methods=['POST'])
def create_message():
    """Endpoint per creare un nuovo messaggio"""
    try:
        data = request.get_json()
        if not data or 'sender' not in data or 'content' not in data:
            return jsonify({
                'success': False,
                'error': 'Dati non validi. I campi "sender" e "content" sono obbligatori.'
            }), 400

        message = message_manager.create_message(
            sender=data['sender'],
            content=data['content'],
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
                'message': 'Messaggio creato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nella creazione del messaggio'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nella creazione del messaggio: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nella creazione del messaggio',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    """Endpoint per segnare un messaggio come letto"""
    try:
        success = message_manager.mark_message_read(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Messaggio segnato come letto'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento del messaggio',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages/mark-all-read', methods=['POST'])
def mark_all_messages_read():
    """Endpoint per segnare tutti i messaggi come letti"""
    try:
        success = message_manager.mark_all_messages_read()

        if success:
            return jsonify({
                'success': True,
                'message': 'Tutti i messaggi sono stati segnati come letti'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nell\'operazione'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nel segnare tutti i messaggi come letti: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'operazione',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages/<int:message_id>/archive', methods=['POST'])
def archive_message(message_id):
    """Endpoint per archiviare un messaggio"""
    try:
        success = message_manager.archive_message(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Messaggio archiviato'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'archiviazione del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'archiviazione del messaggio',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/messages/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    """Endpoint per eliminare un messaggio"""
    try:
        success = message_manager.delete_message(message_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Messaggio eliminato'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'eliminazione del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'eliminazione del messaggio',
            'details': str(e) if current_app.debug else None
        }), 500


# ===============================
# API ENDPOINTS PER LE NOTIFICHE
# ===============================

@api.route('/api/notifications')
def get_notifications():
    """Endpoint per ottenere le notifiche"""
    try:
        # Parametri di query
        limit = request.args.get('limit', type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        notification_type = request.args.get('type')
        category = request.args.get('category')
        priority = request.args.get('priority')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        # Ottieni le notifiche
        result = notification_manager.get_notifications(
            limit=limit,
            unread_only=unread_only,
            notification_type=notification_type,
            category=category,
            priority=priority,
            page=page,
            per_page=per_page
        )

        # Aggiungi metadati aggiuntivi
        result['success'] = True
        result['timestamp'] = datetime.utcnow().isoformat()
        result['notification_types'] = notification_manager.get_notification_types()
        result['categories'] = notification_manager.get_notification_categories()
        result['priorities'] = notification_manager.get_notification_priorities()

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle notifiche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle notifiche',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications/<int:notification_id>')
def get_notification(notification_id):
    """Endpoint per ottenere una notifica specifica"""
    try:
        notification = notification_manager.get_notification(notification_id)

        if notification:
            return jsonify({
                'success': True,
                'data': notification,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notifica non trovata'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento della notifica {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento della notifica',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications', methods=['POST'])
def create_notification():
    """Endpoint per creare una nuova notifica"""
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({
                'success': False,
                'error': 'Dati non validi. Il campo "message" è obbligatorio.'
            }), 400

        notification = notification_manager.create_notification(
            message=data['message'],
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
                'message': 'Notifica creata con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nella creazione della notifica'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nella creazione della notifica: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nella creazione della notifica',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Endpoint per segnare una notifica come letta"""
    try:
        success = notification_manager.mark_notification_read(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notifica segnata come letta'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notifica non trovata'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento della notifica {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento della notifica',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_read():
    """Endpoint per segnare tutte le notifiche come lette"""
    try:
        success = notification_manager.mark_all_notifications_read()

        if success:
            return jsonify({
                'success': True,
                'message': 'Tutte le notifiche sono state segnate come lette'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nell\'operazione'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nel segnare tutte le notifiche come lette: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'operazione',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications/<int:notification_id>/dismiss', methods=['POST'])
def dismiss_notification(notification_id):
    """Endpoint per rimuovere una notifica"""
    try:
        success = notification_manager.dismiss_notification(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notifica rimossa'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notifica non trovata'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nella rimozione della notifica {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nella rimozione della notifica',
            'details': str(e) if current_app.debug else None
        }), 500


@api.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    """Endpoint per eliminare una notifica"""
    try:
        success = notification_manager.delete_notification(notification_id)

        if success:
            return jsonify({
                'success': True,
                'message': 'Notifica eliminata'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Notifica non trovata'
            }), 404

    except Exception as e:
        current_app.logger.error(f"Errore nell'eliminazione della notifica {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'eliminazione della notifica',
            'details': str(e) if current_app.debug else None
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