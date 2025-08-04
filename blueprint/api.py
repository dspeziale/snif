from flask import Blueprint, jsonify, render_template, current_app, request
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging

api = Blueprint('api', __name__)

# File di configurazione separati
CONFIG_FILES = {
    'menu': 'config/menu.json',
    'messages': 'config/messages.json',
    'notifications': 'config/notifications.json',
    'app_config': 'config/app_config.json'
}


class ConfigManager:
    """Gestisce il caricamento e salvataggio delle configurazioni"""

    def __init__(self):
        self.cache = {}
        self.cache_timeout = 300  # 5 minuti
        self.last_loaded = {}

    def load_config(self, config_type: str) -> Dict[str, Any]:
        """Carica una configurazione specifica con cache"""
        now = datetime.now()

        # Controlla se è in cache e non è scaduto
        if (config_type in self.cache and
                config_type in self.last_loaded and
                (now - self.last_loaded[config_type]).seconds < self.cache_timeout):
            return self.cache[config_type]

        try:
            config_file = CONFIG_FILES.get(config_type)
            if not config_file:
                current_app.logger.error(f"Tipo di configurazione non valido: {config_type}")
                return self._get_default_config(config_type)

            config_path = os.path.join(current_app.root_path, config_file)

            if not os.path.exists(config_path):
                current_app.logger.warning(f"File {config_file} non trovato, creando configurazione predefinita")
                default_config = self._get_default_config(config_type)
                self.save_config(config_type, default_config)
                return default_config

            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Aggiorna cache
            self.cache[config_type] = config
            self.last_loaded[config_type] = now

            return config

        except json.JSONDecodeError as e:
            current_app.logger.error(f"Errore nel parsing di {config_file}: {str(e)}")
            return self._get_default_config(config_type)
        except Exception as e:
            current_app.logger.error(f"Errore nel caricamento di {config_file}: {str(e)}")
            return self._get_default_config(config_type)

    def save_config(self, config_type: str, config: Dict[str, Any]) -> bool:
        """Salva una configurazione specifica"""
        try:
            config_file = CONFIG_FILES.get(config_type)
            if not config_file:
                current_app.logger.error(f"Tipo di configurazione non valido: {config_type}")
                return False

            config_path = os.path.join(current_app.root_path, config_file)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            # Aggiorna cache
            self.cache[config_type] = config
            self.last_loaded[config_type] = datetime.now()

            return True

        except Exception as e:
            current_app.logger.error(f"Errore nel salvataggio di {config_file}: {str(e)}")
            return False

    def reload_config(self, config_type: str) -> Dict[str, Any]:
        """Forza il ricaricamento di una configurazione"""
        if config_type in self.cache:
            del self.cache[config_type]
        if config_type in self.last_loaded:
            del self.last_loaded[config_type]

        return self.load_config(config_type)

    def clear_cache(self):
        """Pulisce tutta la cache"""
        self.cache.clear()
        self.last_loaded.clear()

    def _get_default_config(self, config_type: str) -> Dict[str, Any]:
        """Restituisce la configurazione predefinita per tipo"""
        defaults = {
            'menu': {
                'sidebar_menu': [
                    {
                        'title': 'Dashboard',
                        'icon': 'bi bi-speedometer',
                        'url': '/',
                        'active': True,
                        'children': [
                            {
                                'title': 'Dashboard v1',
                                'icon': 'bi bi-circle',
                                'url': '/dashboard/v1',
                                'active': True
                            }
                        ]
                    },
                    {
                        'title': 'Widgets',
                        'icon': 'bi bi-grid',
                        'url': '/widgets',
                        'active': False
                    }
                ]
            },
            'messages': {
                'messages': [
                    {
                        'id': 1,
                        'sender': 'System',
                        'content': 'Welcome to the system!',
                        'time': 'Just now',
                        'avatar': '/static/assets/img/user-default.jpg',
                        'unread': True,
                        'subject': 'Welcome',
                        'timestamp': datetime.now().isoformat(),
                        'priority': 'medium',
                        'type': 'system'
                    }
                ],
                'message_types': [],
                'priorities': []
            },
            'notifications': {
                'notifications': [
                    {
                        'id': 1,
                        'message': 'System started successfully',
                        'time': 'Just now',
                        'icon': 'bi-check-circle-fill',
                        'type': 'success',
                        'read': False,
                        'priority': 'low',
                        'timestamp': datetime.now().isoformat(),
                        'category': 'system'
                    }
                ],
                'notification_types': [],
                'categories': [],
                'priorities': []
            },
            'app_config': {
                'app_info': {
                    'name': 'AdminLTE Flask Dashboard',
                    'version': '4.0.0'
                },
                'user_settings': {
                    'theme': 'light',
                    'language': 'en',
                    'timezone': 'UTC'
                },
                'app_settings': {
                    'maintenance_mode': False,
                    'registration_enabled': True
                }
            }
        }

        return defaults.get(config_type, {})


# Istanza globale del gestore configurazioni
config_manager = ConfigManager()


# API Endpoints per il Menu
@api.route('/api/menu')
@api.route('/api/sidebar-menu')
def get_sidebar_menu():
    """Endpoint per ottenere il menu della sidebar"""
    try:
        config = config_manager.load_config('menu')
        return jsonify({
            'success': True,
            'data': config.get('sidebar_menu', []),
            'count': len(config.get('sidebar_menu', []))
        })
    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento del menu sidebar: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento del menu'
        }), 500


@api.route('/api/menu/update', methods=['POST'])
def update_sidebar_menu():
    """Endpoint per aggiornare il menu della sidebar"""
    try:
        data = request.get_json()
        if not data or 'sidebar_menu' not in data:
            return jsonify({
                'success': False,
                'error': 'Dati del menu non validi'
            }), 400

        config = config_manager.load_config('menu')
        config['sidebar_menu'] = data['sidebar_menu']

        if config_manager.save_config('menu', config):
            return jsonify({
                'success': True,
                'message': 'Menu aggiornato con successo'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio del menu'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento del menu: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento del menu'
        }), 500


# API Endpoints per i Messaggi
@api.route('/api/messages')
def get_messages():
    """Endpoint per ottenere i messaggi"""
    try:
        config = config_manager.load_config('messages')
        messages = config.get('messages', [])

        # Filtra per stato se richiesto
        status_filter = request.args.get('status')
        if status_filter == 'unread':
            messages = [m for m in messages if m.get('unread', False)]
        elif status_filter == 'read':
            messages = [m for m in messages if not m.get('unread', True)]

        # Filtra per tipo se richiesto
        type_filter = request.args.get('type')
        if type_filter:
            messages = [m for m in messages if m.get('type') == type_filter]

        # Ordina per timestamp (più recenti prima)
        messages.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Paginazione
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        start = (page - 1) * per_page
        end = start + per_page

        paginated_messages = messages[start:end]

        return jsonify({
            'success': True,
            'data': paginated_messages,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': len(messages),
                'pages': (len(messages) + per_page - 1) // per_page
            },
            'count': len(messages),
            'unread_count': len([m for m in config.get('messages', []) if m.get('unread', False)]),
            'message_types': config.get('message_types', []),
            'priorities': config.get('priorities', [])
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento dei messaggi: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento dei messaggi'
        }), 500


@api.route('/api/messages/<int:message_id>')
def get_message(message_id):
    """Endpoint per ottenere un messaggio specifico"""
    try:
        config = config_manager.load_config('messages')
        messages = config.get('messages', [])

        message = next((m for m in messages if m.get('id') == message_id), None)

        if not message:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

        return jsonify({
            'success': True,
            'data': message
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento del messaggio'
        }), 500


@api.route('/api/messages/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    """Segna un messaggio come letto"""
    try:
        config = config_manager.load_config('messages')
        messages = config.get('messages', [])

        message_found = False
        for message in messages:
            if message.get('id') == message_id:
                message['unread'] = False
                message['read_at'] = datetime.now().isoformat()
                message_found = True
                break

        if not message_found:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404

        if config_manager.save_config('messages', config):
            return jsonify({
                'success': True,
                'message': 'Messaggio segnato come letto'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento del messaggio {message_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento del messaggio'
        }), 500


@api.route('/api/messages/mark-all-read', methods=['POST'])
def mark_all_messages_read():
    """Segna tutti i messaggi come letti"""
    try:
        config = config_manager.load_config('messages')
        messages = config.get('messages', [])

        read_at = datetime.now().isoformat()
        for message in messages:
            if message.get('unread', False):
                message['unread'] = False
                message['read_at'] = read_at

        if config_manager.save_config('messages', config):
            return jsonify({
                'success': True,
                'message': 'Tutti i messaggi sono stati segnati come letti'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nel segnare tutti i messaggi come letti: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'operazione'
        }), 500


# API Endpoints per le Notifiche
@api.route('/api/notifications')
def get_notifications():
    """Endpoint per ottenere le notifiche"""
    try:
        config = config_manager.load_config('notifications')
        notifications = config.get('notifications', [])

        # Filtra per stato se richiesto
        status_filter = request.args.get('status')
        if status_filter == 'unread':
            notifications = [n for n in notifications if not n.get('read', False)]
        elif status_filter == 'read':
            notifications = [n for n in notifications if n.get('read', False)]

        # Filtra per categoria se richiesto
        category_filter = request.args.get('category')
        if category_filter:
            notifications = [n for n in notifications if n.get('category') == category_filter]

        # Filtra per priorità se richiesto
        priority_filter = request.args.get('priority')
        if priority_filter:
            notifications = [n for n in notifications if n.get('priority') == priority_filter]

        # Ordina per timestamp (più recenti prima)
        notifications.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Paginazione
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        start = (page - 1) * per_page
        end = start + per_page

        paginated_notifications = notifications[start:end]

        return jsonify({
            'success': True,
            'data': paginated_notifications,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': len(notifications),
                'pages': (len(notifications) + per_page - 1) // per_page
            },
            'count': len(notifications),
            'unread_count': len([n for n in config.get('notifications', []) if not n.get('read', False)]),
            'notification_types': config.get('notification_types', []),
            'categories': config.get('categories', []),
            'priorities': config.get('priorities', [])
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle notifiche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle notifiche'
        }), 500


@api.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Segna una notifica come letta"""
    try:
        config = config_manager.load_config('notifications')
        notifications = config.get('notifications', [])

        notification_found = False
        for notification in notifications:
            if notification.get('id') == notification_id:
                notification['read'] = True
                notification['read_at'] = datetime.now().isoformat()
                notification_found = True
                break

        if not notification_found:
            return jsonify({
                'success': False,
                'error': 'Notifica non trovata'
            }), 404

        if config_manager.save_config('notifications', config):
            return jsonify({
                'success': True,
                'message': 'Notifica segnata come letta'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nell'aggiornamento della notifica {notification_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'aggiornamento della notifica'
        }), 500


@api.route('/api/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_read():
    """Segna tutte le notifiche come lette"""
    try:
        config = config_manager.load_config('notifications')
        notifications = config.get('notifications', [])

        read_at = datetime.now().isoformat()
        for notification in notifications:
            if not notification.get('read', False):
                notification['read'] = True
                notification['read_at'] = read_at

        if config_manager.save_config('notifications', config):
            return jsonify({
                'success': True,
                'message': 'Tutte le notifiche sono state segnate come lette'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Errore nel salvataggio'
            }), 500

    except Exception as e:
        current_app.logger.error(f"Errore nel segnare tutte le notifiche come lette: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nell\'operazione'
        }), 500


# API Endpoints per la Configurazione App
@api.route('/api/config')
@api.route('/api/app-config')
def get_app_config():
    """Endpoint per ottenere la configurazione dell'app"""
    try:
        config = config_manager.load_config('app_config')

        # Non esporre informazioni sensibili
        safe_config = {
            'app_info': config.get('app_info', {}),
            'theme': config.get('theme', {}),
            'layout': config.get('layout', {}),
            'user_settings': config.get('user_settings', {}),
            'features': config.get('features', {}),
            'localization': config.get('localization', {})
        }

        return jsonify({
            'success': True,
            'data': safe_config
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento della configurazione: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento della configurazione'
        }), 500


@api.route('/api/config/reload', methods=['POST'])
def reload_configs():
    """Ricarica tutte le configurazioni"""
    try:
        config_manager.clear_cache()

        # Ricarica tutte le configurazioni
        for config_type in CONFIG_FILES.keys():
            config_manager.load_config(config_type)

        return jsonify({
            'success': True,
            'message': 'Configurazioni ricaricate con successo'
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel ricaricamento delle configurazioni: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel ricaricamento delle configurazioni'
        }), 500


# API Endpoints per Statistiche
@api.route('/api/stats')
def get_stats():
    """Endpoint per ottenere statistiche generali"""
    try:
        messages_config = config_manager.load_config('messages')
        notifications_config = config_manager.load_config('notifications')

        messages = messages_config.get('messages', [])
        notifications = notifications_config.get('notifications', [])

        # Calcola statistiche
        stats = {
            'messages': {
                'total': len(messages),
                'unread': len([m for m in messages if m.get('unread', False)]),
                'by_type': {},
                'by_priority': {}
            },
            'notifications': {
                'total': len(notifications),
                'unread': len([n for n in notifications if not n.get('read', False)]),
                'by_category': {},
                'by_priority': {}
            }
        }

        # Statistiche messaggi per tipo
        for message in messages:
            msg_type = message.get('type', 'unknown')
            stats['messages']['by_type'][msg_type] = stats['messages']['by_type'].get(msg_type, 0) + 1

            priority = message.get('priority', 'medium')
            stats['messages']['by_priority'][priority] = stats['messages']['by_priority'].get(priority, 0) + 1

        # Statistiche notifiche per categoria
        for notification in notifications:
            category = notification.get('category', 'unknown')
            stats['notifications']['by_category'][category] = stats['notifications']['by_category'].get(category, 0) + 1

            priority = notification.get('priority', 'low')
            stats['notifications']['by_priority'][priority] = stats['notifications']['by_priority'].get(priority, 0) + 1

        return jsonify({
            'success': True,
            'data': stats
        })

    except Exception as e:
        current_app.logger.error(f"Errore nel caricamento delle statistiche: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Errore nel caricamento delle statistiche'
        }), 500


# Context processor per rendere disponibili i dati in tutti i template
@api.app_context_processor
def inject_template_data():
    """Inietta i dati nei template"""
    try:
        menu_config = config_manager.load_config('menu')
        messages_config = config_manager.load_config('messages')
        notifications_config = config_manager.load_config('notifications')
        app_config = config_manager.load_config('app_config')

        return {
            'sidebar_menu': menu_config.get('sidebar_menu', []),
            'messages': messages_config.get('messages', [])[:5],  # Solo i primi 5 per il template
            'notifications': notifications_config.get('notifications', [])[:5],  # Solo i primi 5 per il template
            'app_name': app_config.get('app_info', {}).get('name', 'AdminLTE Flask Dashboard'),
            'app_version': app_config.get('app_info', {}).get('version', '4.0.0'),
            'theme_settings': app_config.get('theme', {}),
            'layout_settings': app_config.get('layout', {})
        }

    except Exception as e:
        current_app.logger.error(f"Errore nell'iniezione dei dati del template: {str(e)}")
        return {
            'sidebar_menu': [],
            'messages': [],
            'notifications': [],
            'app_name': 'AdminLTE Flask Dashboard',
            'app_version': '4.0.0',
            'theme_settings': {},
            'layout_settings': {}
        }


# Error handlers per le API
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
        'error': 'Errore interno del server'
    }), 500