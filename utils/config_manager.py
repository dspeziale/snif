"""
Utility per la gestione centralizzata delle configurazioni
"""
import json
import os
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import logging
from pathlib import Path


class ConfigManager:
    """Gestisce il caricamento, salvataggio e validazione delle configurazioni"""

    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path.cwd()
        self.cache = {}
        self.cache_timeout = 300  # 5 minuti
        self.last_loaded = {}
        self.logger = logging.getLogger(__name__)

        # File di configurazione disponibili
        self.config_files = {
            'menu': 'menu.json',
            'messages': 'messages.json',
            'notifications': 'notifications.json',
            'app_config': 'app_config.json',
            'users': 'users.json',
            'sessions': 'sessions.json'
        }

        # Schema di validazione per ogni tipo di configurazione
        self.validation_schemas = {
            'menu': self._validate_menu_config,
            'messages': self._validate_messages_config,
            'notifications': self._validate_notifications_config,
            'app_config': self._validate_app_config
        }

    def load_config(self, config_type: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Carica una configurazione specifica

        Args:
            config_type: Tipo di configurazione ('menu', 'messages', 'notifications', 'app_config')
            use_cache: Se utilizzare la cache

        Returns:
            Dict contenente la configurazione
        """
        if not use_cache:
            return self._load_from_file(config_type)

        now = datetime.now()

        # Controlla se è in cache e non è scaduto
        if (config_type in self.cache and
                config_type in self.last_loaded and
                (now - self.last_loaded[config_type]).total_seconds() < self.cache_timeout):
            return self.cache[config_type]

        return self._load_from_file(config_type)

    def _load_from_file(self, config_type: str) -> Dict[str, Any]:
        """Carica la configurazione dal file"""
        try:
            config_file = self.config_files.get(config_type)
            if not config_file:
                self.logger.error(f"Tipo di configurazione non valido: {config_type}")
                return self._get_default_config(config_type)

            config_path = self.base_path / config_file

            if not config_path.exists():
                self.logger.warning(f"File {config_file} non trovato, creando configurazione predefinita")
                default_config = self._get_default_config(config_type)
                self.save_config(config_type, default_config)
                return default_config

            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Validazione
            if config_type in self.validation_schemas:
                is_valid, errors = self.validation_schemas[config_type](config)
                if not is_valid:
                    self.logger.warning(f"Configurazione {config_type} non valida: {errors}")
                    # Tenta di correggere o usa default
                    config = self._fix_or_default_config(config_type, config, errors)

            # Aggiorna cache
            self.cache[config_type] = config
            self.last_loaded[config_type] = datetime.now()

            return config

        except json.JSONDecodeError as e:
            self.logger.error(f"Errore nel parsing di {config_file}: {str(e)}")
            return self._get_default_config(config_type)
        except Exception as e:
            self.logger.error(f"Errore nel caricamento di {config_file}: {str(e)}")
            return self._get_default_config(config_type)

    def save_config(self, config_type: str, config: Dict[str, Any], validate: bool = True) -> bool:
        """
        Salva una configurazione

        Args:
            config_type: Tipo di configurazione
            config: Dati da salvare
            validate: Se validare prima del salvataggio

        Returns:
            True se salvato con successo, False altrimenti
        """
        try:
            if validate and config_type in self.validation_schemas:
                is_valid, errors = self.validation_schemas[config_type](config)
                if not is_valid:
                    self.logger.error(f"Configurazione {config_type} non valida: {errors}")
                    return False

            config_file = self.config_files.get(config_type)
            if not config_file:
                self.logger.error(f"Tipo di configurazione non valido: {config_type}")
                return False

            config_path = self.base_path / config_file

            # Backup del file esistente
            if config_path.exists():
                backup_path = config_path.with_suffix(f'{config_path.suffix}.backup')
                config_path.rename(backup_path)

            # Salva la nuova configurazione
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            # Aggiorna cache
            self.cache[config_type] = config
            self.last_loaded[config_type] = datetime.now()

            return True

        except Exception as e:
            self.logger.error(f"Errore nel salvataggio di {config_type}: {str(e)}")
            return False

    def reload_config(self, config_type: str) -> Dict[str, Any]:
        """Forza il ricaricamento di una configurazione"""
        if config_type in self.cache:
            del self.cache[config_type]
        if config_type in self.last_loaded:
            del self.last_loaded[config_type]

        return self.load_config(config_type, use_cache=False)

    def clear_cache(self):
        """Pulisce tutta la cache"""
        self.cache.clear()
        self.last_loaded.clear()

    def backup_config(self, config_type: str, backup_dir: Optional[str] = None) -> bool:
        """Crea un backup della configurazione"""
        try:
            config_file = self.config_files.get(config_type)
            if not config_file:
                return False

            config_path = self.base_path / config_file
            if not config_path.exists():
                return False

            backup_path = Path(backup_dir) if backup_dir else self.base_path / 'backups'
            backup_path.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = backup_path / f"{config_path.stem}_{timestamp}.json"

            config_path.copy2(backup_file)
            return True

        except Exception as e:
            self.logger.error(f"Errore nel backup di {config_type}: {str(e)}")
            return False

    def restore_config(self, config_type: str, backup_file: str) -> bool:
        """Ripristina una configurazione da backup"""
        try:
            config_file = self.config_files.get(config_type)
            if not config_file:
                return False

            backup_path = Path(backup_file)
            if not backup_path.exists():
                return False

            config_path = self.base_path / config_file
            backup_path.copy2(config_path)

            # Ricarica la configurazione
            self.reload_config(config_type)
            return True

        except Exception as e:
            self.logger.error(f"Errore nel ripristino di {config_type}: {str(e)}")
            return False

    def get_config_info(self, config_type: str) -> Dict[str, Any]:
        """Ottiene informazioni su una configurazione"""
        try:
            config_file = self.config_files.get(config_type)
            if not config_file:
                return {}

            config_path = self.base_path / config_file

            info = {
                'type': config_type,
                'file': config_file,
                'path': str(config_path),
                'exists': config_path.exists(),
                'cached': config_type in self.cache,
                'last_loaded': self.last_loaded.get(config_type),
                'size': 0,
                'modified': None
            }

            if config_path.exists():
                stat = config_path.stat()
                info['size'] = stat.st_size
                info['modified'] = datetime.fromtimestamp(stat.st_mtime)

            return info

        except Exception as e:
            self.logger.error(f"Errore nell'ottenere info per {config_type}: {str(e)}")
            return {}

    def list_backups(self, config_type: str, backup_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lista i backup disponibili per una configurazione"""
        try:
            config_file = self.config_files.get(config_type)
            if not config_file:
                return []

            backup_path = Path(backup_dir) if backup_dir else self.base_path / 'backups'
            if not backup_path.exists():
                return []

            config_name = Path(config_file).stem
            pattern = f"{config_name}_*.json"

            backups = []
            for backup_file in backup_path.glob(pattern):
                stat = backup_file.stat()
                backups.append({
                    'file': backup_file.name,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'modified': datetime.fromtimestamp(stat.st_mtime)
                })

            # Ordina per data di creazione (più recenti prima)
            backups.sort(key=lambda x: x['created'], reverse=True)
            return backups

        except Exception as e:
            self.logger.error(f"Errore nel listare backup per {config_type}: {str(e)}")
            return []

    def merge_configs(self, config_type: str, updates: Dict[str, Any], deep_merge: bool = True) -> bool:
        """Unisce aggiornamenti alla configurazione esistente"""
        try:
            current_config = self.load_config(config_type)

            if deep_merge:
                merged_config = self._deep_merge(current_config, updates)
            else:
                merged_config = {**current_config, **updates}

            return self.save_config(config_type, merged_config)

        except Exception as e:
            self.logger.error(f"Errore nel merge di {config_type}: {str(e)}")
            return False

    def _deep_merge(self, base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        """Merge profondo di due dizionari"""
        result = base.copy()

        for key, value in updates.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

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
                            },
                            {
                                'title': 'Dashboard v2',
                                'icon': 'bi bi-circle',
                                'url': '/dashboard/v2',
                                'active': False
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
                        'content': 'Welcome to the AdminLTE Flask Dashboard!',
                        'time': 'Just now',
                        'avatar': '/static/assets/img/user-default.jpg',
                        'unread': True,
                        'subject': 'Welcome',
                        'timestamp': datetime.now().isoformat(),
                        'priority': 'medium',
                        'type': 'system'
                    }
                ],
                'message_types': [
                    {
                        'type': 'system',
                        'label': 'System',
                        'color': 'info',
                        'icon': 'bi-gear'
                    }
                ],
                'priorities': [
                    {
                        'level': 'low',
                        'label': 'Low Priority',
                        'color': 'secondary',
                        'icon': 'bi-arrow-down'
                    },
                    {
                        'level': 'medium',
                        'label': 'Medium Priority',
                        'color': 'warning',
                        'icon': 'bi-dash'
                    },
                    {
                        'level': 'high',
                        'label': 'High Priority',
                        'color': 'danger',
                        'icon': 'bi-arrow-up'
                    }
                ]
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
                'notification_types': [
                    {
                        'type': 'success',
                        'label': 'Success',
                        'color': 'success',
                        'icon': 'bi-check-circle-fill'
                    }
                ],
                'categories': [
                    {
                        'category': 'system',
                        'label': 'System',
                        'color': 'info',
                        'icon': 'bi-gear'
                    }
                ],
                'priorities': [
                    {
                        'level': 'low',
                        'label': 'Low Priority',
                        'color': 'secondary',
                        'icon': 'bi-arrow-down'
                    }
                ]
            },
            'app_config': {
                'app_info': {
                    'name': 'AdminLTE Flask Dashboard',
                    'version': '4.0.0',
                    'description': 'A comprehensive admin dashboard built with Flask and AdminLTE 4',
                    'author': 'Development Team',
                    'license': 'MIT'
                },
                'theme': {
                    'default_theme': 'light',
                    'available_themes': ['light', 'dark', 'auto'],
                    'primary_color': '#007bff'
                },
                'user_settings': {
                    'theme': 'light',
                    'language': 'en',
                    'timezone': 'UTC',
                    'notifications_enabled': True
                },
                'app_settings': {
                    'maintenance_mode': False,
                    'registration_enabled': True,
                    'session_timeout': 3600
                }
            }
        }

        return defaults.get(config_type, {})

    def _fix_or_default_config(self, config_type: str, config: Dict[str, Any], errors: List[str]) -> Dict[str, Any]:
        """Tenta di correggere la configurazione o restituisce quella predefinita"""
        # Per ora restituisce la configurazione predefinita
        # In futuro si potrebbero implementare correzioni automatiche
        self.logger.warning(f"Usando configurazione predefinita per {config_type} a causa di errori: {errors}")
        return self._get_default_config(config_type)

    # Metodi di validazione
    def _validate_menu_config(self, config: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Valida la configurazione del menu"""
        errors = []

        if 'sidebar_menu' not in config:
            errors.append("Manca 'sidebar_menu'")
            return False, errors

        sidebar_menu = config['sidebar_menu']
        if not isinstance(sidebar_menu, list):
            errors.append("'sidebar_menu' deve essere una lista")
            return False, errors

        for i, item in enumerate(sidebar_menu):
            if not isinstance(item, dict):
                errors.append(f"Elemento menu {i} deve essere un dizionario")
                continue

            required_fields = ['title', 'icon']
            for field in required_fields:
                if field not in item:
                    errors.append(f"Elemento menu {i} manca del campo '{field}'")

            # Valida children se presente
            if 'children' in item:
                if not isinstance(item['children'], list):
                    errors.append(f"Elemento menu {i} 'children' deve essere una lista")

        return len(errors) == 0, errors

    def _validate_messages_config(self, config: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Valida la configurazione dei messaggi"""
        errors = []

        if 'messages' not in config:
            errors.append("Manca 'messages'")
            return False, errors

        messages = config['messages']
        if not isinstance(messages, list):
            errors.append("'messages' deve essere una lista")
            return False, errors

        for i, message in enumerate(messages):
            if not isinstance(message, dict):
                errors.append(f"Messaggio {i} deve essere un dizionario")
                continue

            required_fields = ['id', 'sender', 'content']
            for field in required_fields:
                if field not in message:
                    errors.append(f"Messaggio {i} manca del campo '{field}'")

        return len(errors) == 0, errors

    def _validate_notifications_config(self, config: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Valida la configurazione delle notifiche"""
        errors = []

        if 'notifications' not in config:
            errors.append("Manca 'notifications'")
            return False, errors

        notifications = config['notifications']
        if not isinstance(notifications, list):
            errors.append("'notifications' deve essere una lista")
            return False, errors

        for i, notification in enumerate(notifications):
            if not isinstance(notification, dict):
                errors.append(f"Notifica {i} deve essere un dizionario")
                continue

            required_fields = ['id', 'message']
            for field in required_fields:
                if field not in notification:
                    errors.append(f"Notifica {i} manca del campo '{field}'")

        return len(errors) == 0, errors

    def _validate_app_config(self, config: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Valida la configurazione dell'app"""
        errors = []

        required_sections = ['app_info', 'user_settings', 'app_settings']
        for section in required_sections:
            if section not in config:
                errors.append(f"Manca la sezione '{section}'")

        # Valida app_info se presente
        if 'app_info' in config:
            app_info = config['app_info']
            if not isinstance(app_info, dict):
                errors.append("'app_info' deve essere un dizionario")
            else:
                if 'name' not in app_info:
                    errors.append("'app_info' manca del campo 'name'")
                if 'version' not in app_info:
                    errors.append("'app_info' manca del campo 'version'")

        return len(errors) == 0, errors


# Istanza globale del gestore configurazioni
config_manager = ConfigManager()


def get_config_manager(base_path: Optional[str] = None) -> ConfigManager:
    """Factory function per ottenere un'istanza del ConfigManager"""
    if base_path:
        return ConfigManager(base_path)
    return config_manager


# Funzioni di utilità
def load_menu() -> Dict[str, Any]:
    """Carica la configurazione del menu"""
    return config_manager.load_config('menu')


def load_messages() -> Dict[str, Any]:
    """Carica la configurazione dei messaggi"""
    return config_manager.load_config('messages')


def load_notifications() -> Dict[str, Any]:
    """Carica la configurazione delle notifiche"""
    return config_manager.load_config('notifications')


def load_app_config() -> Dict[str, Any]:
    """Carica la configurazione dell'app"""
    return config_manager.load_config('app_config')


def save_menu(config: Dict[str, Any]) -> bool:
    """Salva la configurazione del menu"""
    return config_manager.save_config('menu', config)


def save_messages(config: Dict[str, Any]) -> bool:
    """Salva la configurazione dei messaggi"""
    return config_manager.save_config('messages', config)


def save_notifications(config: Dict[str, Any]) -> bool:
    """Salva la configurazione delle notifiche"""
    return config_manager.save_config('notifications', config)


def save_app_config(config: Dict[str, Any]) -> bool:
    """Salva la configurazione dell'app"""
    return config_manager.save_config('app_config', config)