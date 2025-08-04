#!/usr/bin/env python3
"""
Script per inizializzare tutte le configurazioni JSON del progetto AdminLTE Flask
"""
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


def create_menu_config() -> Dict[str, Any]:
    """Crea la configurazione del menu di default"""
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
                    },
                    {
                        "title": "Dashboard v3",
                        "icon": "bi bi-circle",
                        "url": "/dashboard/v3",
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
                        "title": "Top Navigation + Sidebar",
                        "icon": "bi bi-circle",
                        "url": "/layout/top-nav-sidebar",
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
                    },
                    {
                        "title": "Fixed Navbar",
                        "icon": "bi bi-circle",
                        "url": "/layout/fixed-navbar",
                        "active": False
                    },
                    {
                        "title": "Fixed Footer",
                        "icon": "bi bi-circle",
                        "url": "/layout/fixed-footer",
                        "active": False
                    },
                    {
                        "title": "Collapsed Sidebar",
                        "icon": "bi bi-circle",
                        "url": "/layout/collapsed-sidebar",
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
            },
            {
                "title": "Calendar",
                "icon": "bi bi-calendar",
                "url": "/calendar",
                "active": False
            },
            {
                "title": "Gallery",
                "icon": "bi bi-image",
                "url": "/gallery",
                "active": False
            },
            {
                "title": "Kanban Board",
                "icon": "bi bi-kanban",
                "url": "/kanban",
                "active": False
            }
        ]
    }


def create_messages_config() -> Dict[str, Any]:
    """Crea la configurazione dei messaggi di default"""
    now = datetime.now()
    return {
        "messages": [
            {
                "id": 1,
                "sender": "Alexander Pierce",
                "content": "Welcome to the AdminLTE Flask Dashboard! This is your admin panel for managing your application.",
                "time": "Just now",
                "avatar": "/static/assets/img/user1-128x128.jpg",
                "unread": True,
                "subject": "Welcome to AdminLTE",
                "timestamp": now.isoformat(),
                "priority": "high",
                "type": "welcome"
            },
            {
                "id": 2,
                "sender": "System Administrator",
                "content": "Please review the system settings and configure your dashboard according to your needs.",
                "time": "1 hour ago",
                "avatar": "/static/assets/img/user-default.jpg",
                "unread": True,
                "subject": "System Configuration",
                "timestamp": (now.replace(hour=now.hour - 1)).isoformat(),
                "priority": "medium",
                "type": "system"
            },
            {
                "id": 3,
                "sender": "Support Team",
                "content": "If you need help getting started, please check our documentation or contact support.",
                "time": "2 hours ago",
                "avatar": "/static/assets/img/user2-160x160.jpg",
                "unread": False,
                "subject": "Getting Started",
                "timestamp": (now.replace(hour=now.hour - 2)).isoformat(),
                "priority": "low",
                "type": "support"
            }
        ],
        "message_types": [
            {
                "type": "welcome",
                "label": "Welcome",
                "color": "success",
                "icon": "bi-hand-wave"
            },
            {
                "type": "system",
                "label": "System",
                "color": "info",
                "icon": "bi-gear"
            },
            {
                "type": "support",
                "label": "Support",
                "color": "primary",
                "icon": "bi-question-circle"
            },
            {
                "type": "security",
                "label": "Security",
                "color": "danger",
                "icon": "bi-shield-exclamation"
            },
            {
                "type": "update",
                "label": "Update",
                "color": "warning",
                "icon": "bi-arrow-clockwise"
            }
        ],
        "priorities": [
            {
                "level": "low",
                "label": "Low Priority",
                "color": "secondary",
                "icon": "bi-arrow-down"
            },
            {
                "level": "medium",
                "label": "Medium Priority",
                "color": "warning",
                "icon": "bi-dash"
            },
            {
                "level": "high",
                "label": "High Priority",
                "color": "danger",
                "icon": "bi-arrow-up"
            }
        ]
    }


def create_notifications_config() -> Dict[str, Any]:
    """Crea la configurazione delle notifiche di default"""
    now = datetime.now()
    return {
        "notifications": [
            {
                "id": 1,
                "message": "AdminLTE Flask Dashboard initialized successfully",
                "time": "Just now",
                "icon": "bi-check-circle-fill",
                "type": "success",
                "read": False,
                "priority": "medium",
                "timestamp": now.isoformat(),
                "action_url": "/dashboard",
                "category": "system"
            },
            {
                "id": 2,
                "message": "Configuration files loaded and validated",
                "time": "1 minute ago",
                "icon": "bi-file-check",
                "type": "info",
                "read": False,
                "priority": "low",
                "timestamp": (now.replace(minute=now.minute - 1)).isoformat(),
                "action_url": "/admin/config",
                "category": "system"
            },
            {
                "id": 3,
                "message": "Welcome! Complete your profile setup",
                "time": "5 minutes ago",
                "icon": "bi-person-plus",
                "type": "info",
                "read": False,
                "priority": "medium",
                "timestamp": (now.replace(minute=now.minute - 5)).isoformat(),
                "action_url": "/profile",
                "category": "user"
            }
        ],
        "notification_types": [
            {
                "type": "success",
                "label": "Success",
                "color": "success",
                "icon": "bi-check-circle-fill"
            },
            {
                "type": "info",
                "label": "Information",
                "color": "info",
                "icon": "bi-info-circle-fill"
            },
            {
                "type": "warning",
                "label": "Warning",
                "color": "warning",
                "icon": "bi-exclamation-triangle-fill"
            },
            {
                "type": "error",
                "label": "Error",
                "color": "danger",
                "icon": "bi-x-circle-fill"
            }
        ],
        "categories": [
            {
                "category": "system",
                "label": "System",
                "color": "info",
                "icon": "bi-gear"
            },
            {
                "category": "user",
                "label": "User",
                "color": "primary",
                "icon": "bi-person"
            },
            {
                "category": "security",
                "label": "Security",
                "color": "danger",
                "icon": "bi-shield"
            },
            {
                "category": "business",
                "label": "Business",
                "color": "success",
                "icon": "bi-briefcase"
            }
        ],
        "priorities": [
            {
                "level": "low",
                "label": "Low Priority",
                "color": "secondary",
                "icon": "bi-arrow-down"
            },
            {
                "level": "medium",
                "label": "Medium Priority",
                "color": "warning",
                "icon": "bi-dash"
            },
            {
                "level": "high",
                "label": "High Priority",
                "color": "danger",
                "icon": "bi-arrow-up"
            }
        ]
    }


def create_app_config() -> Dict[str, Any]:
    """Crea la configurazione dell'app di default"""
    return {
        "app_info": {
            "name": "AdminLTE Flask Dashboard",
            "version": "4.0.0",
            "description": "A comprehensive admin dashboard built with Flask and AdminLTE 4",
            "author": "Development Team",
            "license": "MIT",
            "homepage": "https://adminlte.io",
            "repository": "https://github.com/your-org/adminlte-flask",
            "documentation": "https://docs.adminlte.io"
        },
        "theme": {
            "default_theme": "light",
            "available_themes": ["light", "dark", "auto"],
            "primary_color": "#007bff",
            "secondary_color": "#6c757d",
            "success_color": "#28a745",
            "info_color": "#17a2b8",
            "warning_color": "#ffc107",
            "danger_color": "#dc3545",
            "light_color": "#f8f9fa",
            "dark_color": "#343a40"
        },
        "layout": {
            "sidebar_collapsed": False,
            "navbar_fixed": True,
            "footer_fixed": False,
            "sidebar_fixed": True,
            "layout_boxed": False,
            "dark_mode": False,
            "rtl_mode": False
        },
        "user_settings": {
            "theme": "light",
            "language": "en",
            "timezone": "UTC",
            "date_format": "DD/MM/YYYY",
            "time_format": "24h",
            "notifications_enabled": True,
            "email_notifications": True,
            "push_notifications": False,
            "sound_enabled": True,
            "auto_save": True,
            "show_tooltips": True
        },
        "app_settings": {
            "maintenance_mode": False,
            "registration_enabled": True,
            "email_verification_required": False,
            "max_login_attempts": 5,
            "session_timeout": 3600,
            "password_min_length": 6,
            "api_rate_limit": 1000,
            "max_file_upload_size": "10MB",
            "allowed_file_types": ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx"],
            "backup_enabled": True,
            "backup_frequency": "daily",
            "log_level": "INFO",
            "debug_mode": False
        },
        "features": {
            "dashboard": {
                "enabled": True,
                "widgets": ["stats", "charts", "recent_activity", "notifications"]
            },
            "user_management": {
                "enabled": True,
                "roles": ["admin", "moderator", "user"],
                "permissions": ["read", "write", "delete", "admin"]
            },
            "messaging": {
                "enabled": True,
                "max_message_length": 1000,
                "file_attachments": True,
                "message_history": True
            },
            "notifications": {
                "enabled": True,
                "real_time": True,
                "email_digest": True,
                "categories": ["system", "user", "security", "business"]
            }
        },
        "security": {
            "csrf_protection": True,
            "session_security": True,
            "password_hashing": "bcrypt",
            "two_factor_auth": False,
            "login_rate_limiting": True,
            "ssl_required": False,
            "security_headers": True
        },
        "localization": {
            "default_language": "en",
            "available_languages": ["en", "it", "es", "fr", "de"],
            "fallback_language": "en",
            "auto_detect": False
        }
    }


def save_json_file(filepath: Path, data: Dict[str, Any], backup: bool = True) -> bool:
    """Salva un file JSON con backup opzionale"""
    try:
        # Backup del file esistente se richiesto
        if backup and filepath.exists():
            backup_path = filepath.with_suffix(f'{filepath.suffix}.backup')
            filepath.rename(backup_path)
            print(f"✓ Backup creato: {backup_path}")

        # Salva il nuovo file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"✓ File creato: {filepath}")
        return True

    except Exception as e:
        print(f"✗ Errore nel salvare {filepath}: {e}")
        return False


def init_all_configs(base_path: str = ".", force: bool = False, backup: bool = True) -> bool:
    """Inizializza tutti i file di configurazione"""
    base_path = Path(base_path)

    configs = {
        'menu.json': create_menu_config,
        'messages.json': create_messages_config,
        'notifications.json': create_notifications_config,
        'app_config.json': create_app_config
    }

    success_count = 0
    total_count = len(configs)

    print(f"🚀 Inizializzazione configurazioni in: {base_path.absolute()}")
    print("-" * 60)

    for filename, create_func in configs.items():
        filepath = base_path / filename

        # Controlla se il file esiste già
        if filepath.exists() and not force:
            print(f"⚠ File già esistente (usa --force per sovrascrivere): {filepath}")
            continue

        # Crea i dati di configurazione
        config_data = create_func()

        # Salva il file
        if save_json_file(filepath, config_data, backup):
            success_count += 1
        else:
            print(f"✗ Errore nel creare: {filepath}")

    print("-" * 60)
    print(f"✅ Completato: {success_count}/{total_count} file creati con successo")

    if success_count == total_count:
        print("\n🎉 Tutti i file di configurazione sono stati inizializzati!")
        print("\nProssimi passi:")
        print("1. Verifica le configurazioni nei file JSON")
        print("2. Personalizza menu, messaggi e notifiche secondo le tue esigenze")
        print("3. Avvia l'applicazione Flask: python app.py")
        return True
    else:
        print(f"\n⚠ Alcuni file non sono stati creati ({total_count - success_count} errori)")
        return False


def validate_configs(base_path: str = ".") -> bool:
    """Valida tutti i file di configurazione esistenti"""
    base_path = Path(base_path)
    configs = ['menu.json', 'messages.json', 'notifications.json', 'app_config.json']

    print(f"🔍 Validazione configurazioni in: {base_path.absolute()}")
    print("-" * 60)

    all_valid = True

    for config_file in configs:
        filepath = base_path / config_file

        if not filepath.exists():
            print(f"✗ File mancante: {filepath}")
            all_valid = False
            continue

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"✓ Valido: {filepath}")
        except json.JSONDecodeError as e:
            print(f"✗ JSON non valido in {filepath}: {e}")
            all_valid = False
        except Exception as e:
            print(f"✗ Errore nel leggere {filepath}: {e}")
            all_valid = False

    print("-" * 60)
    if all_valid:
        print("✅ Tutti i file di configurazione sono validi!")
    else:
        print("⚠ Alcuni file di configurazione hanno problemi")

    return all_valid


def main():
    """Funzione principale del script"""
    parser = argparse.ArgumentParser(
        description="Inizializza le configurazioni JSON per AdminLTE Flask Dashboard"
    )
    parser.add_argument(
        '--path', '-p',
        default='.',
        help='Percorso dove creare i file di configurazione (default: directory corrente)'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Sovrascrive i file esistenti'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Non crea backup dei file esistenti'
    )
    parser.add_argument(
        '--validate', '-v',
        action='store_true',
        help='Valida solo i file esistenti senza crearli'
    )

    args = parser.parse_args()

    if args.validate:
        success = validate_configs(args.path)
        sys.exit(0 if success else 1)
    else:
        success = init_all_configs(
            base_path=args.path,
            force=args.force,
            backup=not args.no_backup
        )
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()