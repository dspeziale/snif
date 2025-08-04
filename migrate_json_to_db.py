#!/usr/bin/env python3
"""
Script per migrare i dati dai file JSON al database SQLite
"""
import os
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import argparse

# Aggiungi la directory root al path per importare i moduli
sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask
from models import (
    db, MenuItem, MenuType, Message, MessageType, MessagePriority,
    Notification, NotificationType, NotificationCategory, NotificationPriority
)
from database_config import init_database


class JSONToDBMigrator:
    """Classe per gestire la migrazione dai file JSON al database"""

    def __init__(self, app: Flask, json_config_path: str = "config"):
        self.app = app
        self.config_path = Path(json_config_path)
        self.migration_stats = {
            'menu': {'success': 0, 'errors': 0, 'details': []},
            'messages': {'success': 0, 'errors': 0, 'details': []},
            'notifications': {'success': 0, 'errors': 0, 'details': []}
        }

    def load_json_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """Carica un file JSON"""
        file_path = self.config_path / filename

        if not file_path.exists():
            print(f"⚠ File non trovato: {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"✗ Errore nel parsing di {filename}: {e}")
            return None
        except Exception as e:
            print(f"✗ Errore nel caricamento di {filename}: {e}")
            return None

    def migrate_menu_data(self) -> bool:
        """Migra i dati del menu"""
        print("📋 Migrazione dati menu...")

        menu_data = self.load_json_file('menu.json')
        if not menu_data:
            return False

        try:
            with self.app.app_context():
                # Crea il tipo di menu predefinito
                menu_type = MenuType.query.filter_by(name='sidebar').first()
                if not menu_type:
                    menu_type = MenuType(
                        name='sidebar',
                        label='Sidebar Menu',
                        description='Menu principale della sidebar'
                    )
                    db.session.add(menu_type)
                    db.session.commit()

                # Migra gli elementi del menu
                sidebar_menu = menu_data.get('sidebar_menu', [])
                for sort_order, item_data in enumerate(sidebar_menu):
                    self._migrate_menu_item(item_data, menu_type.id, None, sort_order)

                db.session.commit()
                self.migration_stats['menu']['success'] = len(sidebar_menu)
                print(f"✓ Menu migrato: {len(sidebar_menu)} elementi principali")
                return True

        except Exception as e:
            print(f"✗ Errore nella migrazione del menu: {e}")
            self.migration_stats['menu']['errors'] += 1
            self.migration_stats['menu']['details'].append(str(e))
            return False

    def _migrate_menu_item(self, item_data: Dict[str, Any], menu_type_id: int,
                           parent_id: Optional[int], sort_order: int) -> Optional[MenuItem]:
        """Migra un singolo elemento del menu"""
        try:
            # Controlla se l'elemento esiste già
            existing_item = MenuItem.query.filter_by(
                title=item_data['title'],
                parent_id=parent_id,
                menu_type_id=menu_type_id
            ).first()

            if existing_item:
                # Aggiorna l'elemento esistente
                menu_item = existing_item
                menu_item.icon = item_data.get('icon')
                menu_item.url = item_data.get('url')
                menu_item.active = item_data.get('active', False)
                menu_item.sort_order = sort_order
                menu_item.enabled = True
            else:
                # Crea nuovo elemento
                menu_item = MenuItem(
                    title=item_data['title'],
                    icon=item_data.get('icon'),
                    url=item_data.get('url'),
                    active=item_data.get('active', False),
                    sort_order=sort_order,
                    enabled=True,
                    parent_id=parent_id,
                    menu_type_id=menu_type_id
                )
                db.session.add(menu_item)

            # Salva per ottenere l'ID
            db.session.flush()

            # Migra i figli se presenti
            children = item_data.get('children', [])
            for child_order, child_data in enumerate(children):
                self._migrate_menu_item(child_data, menu_type_id, menu_item.id, child_order)

            return menu_item

        except Exception as e:
            print(f"✗ Errore nella migrazione dell'elemento menu '{item_data.get('title', 'Unknown')}': {e}")
            self.migration_stats['menu']['errors'] += 1
            self.migration_stats['menu']['details'].append(f"Item '{item_data.get('title', 'Unknown')}': {str(e)}")
            return None

    def migrate_messages_data(self) -> bool:
        """Migra i dati dei messaggi"""
        print("💬 Migrazione dati messaggi...")

        messages_data = self.load_json_file('messages.json')
        if not messages_data:
            return False

        try:
            with self.app.app_context():
                # Migra i tipi di messaggio
                message_types = messages_data.get('message_types', [])
                for type_data in message_types:
                    self._migrate_message_type(type_data)

                # Migra le priorità
                priorities = messages_data.get('priorities', [])
                for priority_data in priorities:
                    self._migrate_message_priority(priority_data)

                # Migra i messaggi
                messages = messages_data.get('messages', [])
                for msg_data in messages:
                    self._migrate_message(msg_data)

                db.session.commit()
                self.migration_stats['messages']['success'] = len(messages)
                print(
                    f"✓ Messaggi migrati: {len(messages)} messaggi, {len(message_types)} tipi, {len(priorities)} priorità")
                return True

        except Exception as e:
            print(f"✗ Errore nella migrazione dei messaggi: {e}")
            self.migration_stats['messages']['errors'] += 1
            self.migration_stats['messages']['details'].append(str(e))
            return False

    def _migrate_message_type(self, type_data: Dict[str, Any]) -> MessageType:
        """Migra un tipo di messaggio"""
        message_type = MessageType.query.filter_by(type=type_data['type']).first()

        if not message_type:
            message_type = MessageType(
                type=type_data['type'],
                label=type_data['label'],
                color=type_data.get('color', 'primary'),
                icon=type_data.get('icon'),
                description=type_data.get('description')
            )
            db.session.add(message_type)
        else:
            # Aggiorna i dati esistenti
            message_type.label = type_data['label']
            message_type.color = type_data.get('color', 'primary')
            message_type.icon = type_data.get('icon')
            message_type.description = type_data.get('description')

        return message_type

    def _migrate_message_priority(self, priority_data: Dict[str, Any]) -> MessagePriority:
        """Migra una priorità di messaggio"""
        priority = MessagePriority.query.filter_by(level=priority_data['level']).first()

        if not priority:
            priority = MessagePriority(
                level=priority_data['level'],
                label=priority_data['label'],
                color=priority_data.get('color', 'secondary'),
                icon=priority_data.get('icon'),
                sort_order=self._get_priority_sort_order(priority_data['level'])
            )
            db.session.add(priority)
        else:
            # Aggiorna i dati esistenti
            priority.label = priority_data['label']
            priority.color = priority_data.get('color', 'secondary')
            priority.icon = priority_data.get('icon')

        return priority

    def _migrate_message(self, msg_data: Dict[str, Any]) -> Message:
        """Migra un singolo messaggio"""
        try:
            # Controlla se il messaggio esiste già (per ID)
            existing_msg = Message.query.filter_by(id=msg_data['id']).first()

            if existing_msg:
                message = existing_msg
            else:
                message = Message()
                db.session.add(message)

            # Trova il tipo di messaggio
            message_type = None
            if 'type' in msg_data:
                message_type = MessageType.query.filter_by(type=msg_data['type']).first()

            # Trova la priorità
            priority = None
            if 'priority' in msg_data:
                priority = MessagePriority.query.filter_by(level=msg_data['priority']).first()

            # Parsing della data
            timestamp = datetime.utcnow()
            if 'timestamp' in msg_data:
                try:
                    timestamp = datetime.fromisoformat(msg_data['timestamp'].replace('Z', '+00:00'))
                except:
                    timestamp = datetime.utcnow()

            # Imposta i dati del messaggio
            message.sender = msg_data['sender']
            message.subject = msg_data.get('subject')
            message.content = msg_data['content']
            message.avatar = msg_data.get('avatar')
            message.unread = msg_data.get('unread', True)
            message.timestamp = timestamp
            message.type_id = message_type.id if message_type else None
            message.priority_id = priority.id if priority else None

            return message

        except Exception as e:
            print(f"✗ Errore nella migrazione del messaggio ID {msg_data.get('id', 'Unknown')}: {e}")
            self.migration_stats['messages']['errors'] += 1
            self.migration_stats['messages']['details'].append(f"Message ID {msg_data.get('id', 'Unknown')}: {str(e)}")
            return None

    def migrate_notifications_data(self) -> bool:
        """Migra i dati delle notifiche"""
        print("🔔 Migrazione dati notifiche...")

        notifications_data = self.load_json_file('notifications.json')
        if not notifications_data:
            return False

        try:
            with self.app.app_context():
                # Migra i tipi di notifica
                notification_types = notifications_data.get('notification_types', [])
                for type_data in notification_types:
                    self._migrate_notification_type(type_data)

                # Migra le categorie
                categories = notifications_data.get('categories', [])
                for category_data in categories:
                    self._migrate_notification_category(category_data)

                # Migra le priorità
                priorities = notifications_data.get('priorities', [])
                for priority_data in priorities:
                    self._migrate_notification_priority(priority_data)

                # Migra le notifiche
                notifications = notifications_data.get('notifications', [])
                for notif_data in notifications:
                    self._migrate_notification(notif_data)

                db.session.commit()
                self.migration_stats['notifications']['success'] = len(notifications)
                print(
                    f"✓ Notifiche migrate: {len(notifications)} notifiche, {len(notification_types)} tipi, {len(categories)} categorie, {len(priorities)} priorità")
                return True

        except Exception as e:
            print(f"✗ Errore nella migrazione delle notifiche: {e}")
            self.migration_stats['notifications']['errors'] += 1
            self.migration_stats['notifications']['details'].append(str(e))
            return False

    def _migrate_notification_type(self, type_data: Dict[str, Any]) -> NotificationType:
        """Migra un tipo di notifica"""
        notification_type = NotificationType.query.filter_by(type=type_data['type']).first()

        if not notification_type:
            notification_type = NotificationType(
                type=type_data['type'],
                label=type_data['label'],
                color=type_data.get('color', 'info'),
                icon=type_data.get('icon'),
                description=type_data.get('description')
            )
            db.session.add(notification_type)
        else:
            # Aggiorna i dati esistenti
            notification_type.label = type_data['label']
            notification_type.color = type_data.get('color', 'info')
            notification_type.icon = type_data.get('icon')
            notification_type.description = type_data.get('description')

        return notification_type

    def _migrate_notification_category(self, category_data: Dict[str, Any]) -> NotificationCategory:
        """Migra una categoria di notifica"""
        category = NotificationCategory.query.filter_by(category=category_data['category']).first()

        if not category:
            category = NotificationCategory(
                category=category_data['category'],
                label=category_data['label'],
                color=category_data.get('color', 'secondary'),
                icon=category_data.get('icon'),
                description=category_data.get('description')
            )
            db.session.add(category)
        else:
            # Aggiorna i dati esistenti
            category.label = category_data['label']
            category.color = category_data.get('color', 'secondary')
            category.icon = category_data.get('icon')
            category.description = category_data.get('description')

        return category

    def _migrate_notification_priority(self, priority_data: Dict[str, Any]) -> NotificationPriority:
        """Migra una priorità di notifica"""
        priority = NotificationPriority.query.filter_by(level=priority_data['level']).first()

        if not priority:
            priority = NotificationPriority(
                level=priority_data['level'],
                label=priority_data['label'],
                color=priority_data.get('color', 'secondary'),
                icon=priority_data.get('icon'),
                sort_order=self._get_priority_sort_order(priority_data['level'])
            )
            db.session.add(priority)
        else:
            # Aggiorna i dati esistenti
            priority.label = priority_data['label']
            priority.color = priority_data.get('color', 'secondary')
            priority.icon = priority_data.get('icon')

        return priority

    def _migrate_notification(self, notif_data: Dict[str, Any]) -> Notification:
        """Migra una singola notifica"""
        try:
            # Controlla se la notifica esiste già (per ID)
            existing_notif = Notification.query.filter_by(id=notif_data['id']).first()

            if existing_notif:
                notification = existing_notif
            else:
                notification = Notification()
                db.session.add(notification)

            # Trova il tipo di notifica
            notification_type = None
            if 'type' in notif_data:
                notification_type = NotificationType.query.filter_by(type=notif_data['type']).first()

            # Trova la categoria
            category = None
            if 'category' in notif_data:
                category = NotificationCategory.query.filter_by(category=notif_data['category']).first()

            # Trova la priorità
            priority = None
            if 'priority' in notif_data:
                priority = NotificationPriority.query.filter_by(level=notif_data['priority']).first()

            # Parsing della data
            timestamp = datetime.utcnow()
            if 'timestamp' in notif_data:
                try:
                    timestamp = datetime.fromisoformat(notif_data['timestamp'].replace('Z', '+00:00'))
                except:
                    timestamp = datetime.utcnow()

            # Imposta i dati della notifica
            notification.message = notif_data['message']
            notification.icon = notif_data.get('icon')
            notification.read = notif_data.get('read', False)
            notification.timestamp = timestamp
            notification.action_url = notif_data.get('action_url')
            notification.type_id = notification_type.id if notification_type else None
            notification.category_id = category.id if category else None
            notification.priority_id = priority.id if priority else None

            return notification

        except Exception as e:
            print(f"✗ Errore nella migrazione della notifica ID {notif_data.get('id', 'Unknown')}: {e}")
            self.migration_stats['notifications']['errors'] += 1
            self.migration_stats['notifications']['details'].append(
                f"Notification ID {notif_data.get('id', 'Unknown')}: {str(e)}")
            return None

    def _get_priority_sort_order(self, level: str) -> int:
        """Ottiene l'ordine di sorting per una priorità"""
        priority_order = {
            'low': 1,
            'medium': 2,
            'high': 3
        }
        return priority_order.get(level.lower(), 0)

    def run_migration(self, clear_existing: bool = False) -> bool:
        """Esegue la migrazione completa"""
        print("🚀 Inizio migrazione da JSON a database SQLite")
        print("=" * 60)

        # Pulisci i dati esistenti se richiesto
        if clear_existing:
            print("🗑 Pulizia dati esistenti...")
            with self.app.app_context():
                # Elimina in ordine inverso per rispettare le foreign key
                Notification.query.delete()
                Message.query.delete()
                MenuItem.query.delete()

                NotificationPriority.query.delete()
                NotificationCategory.query.delete()
                NotificationType.query.delete()
                MessagePriority.query.delete()
                MessageType.query.delete()
                MenuType.query.delete()

                db.session.commit()
                print("✓ Dati esistenti eliminati")

        # Esegui le migrazioni
        success_count = 0

        if self.migrate_menu_data():
            success_count += 1

        if self.migrate_messages_data():
            success_count += 1

        if self.migrate_notifications_data():
            success_count += 1

        # Stampa il riepilogo
        print("=" * 60)
        print("📊 Riepilogo migrazione:")

        for category, stats in self.migration_stats.items():
            print(f"  {category.title()}:")
            print(f"    ✓ Successi: {stats['success']}")
            print(f"    ✗ Errori: {stats['errors']}")

            if stats['details']:
                print(f"    Dettagli errori:")
                for detail in stats['details'][:5]:  # Mostra solo i primi 5 errori
                    print(f"      - {detail}")
                if len(stats['details']) > 5:
                    print(f"      ... e altri {len(stats['details']) - 5} errori")

        print("=" * 60)

        if success_count == 3:
            print("🎉 Migrazione completata con successo!")
            return True
        else:
            print(f"⚠ Migrazione completata con alcuni errori ({success_count}/3 sezioni migrate)")
            return False


def create_test_app() -> Flask:
    """Crea un'applicazione Flask per il test"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'migration-test-key'

    # Inizializza il database
    init_database(app)

    return app


def main():
    """Funzione principale del script"""
    parser = argparse.ArgumentParser(description="Migra i dati JSON al database SQLite")
    parser.add_argument(
        '--config-path', '-c',
        default='config',
        help='Percorso della directory con i file JSON (default: config)'
    )
    parser.add_argument(
        '--clear', '-x',
        action='store_true',
        help='Elimina i dati esistenti prima della migrazione'
    )
    parser.add_argument(
        '--dry-run', '-d',
        action='store_true',
        help='Esegue una simulazione senza modificare il database'
    )

    args = parser.parse_args()

    # Crea l'applicazione Flask
    app = create_test_app()

    if args.dry_run:
        print("🔍 Modalità DRY RUN - Nessuna modifica verrà effettuata")
        # Per il dry run, potremmo implementare una logica di simulazione
        # Per ora, usciamo
        print("Dry run non ancora implementato")
        return

    # Esegui la migrazione
    migrator = JSONToDBMigrator(app, args.config_path)
    success = migrator.run_migration(clear_existing=args.clear)

    if success:
        print("\n✅ Migrazione completata!")
        print("\nPer utilizzare il database nella tua applicazione:")
        print("1. Aggiorna app.py per utilizzare il database al posto dei file JSON")
        print("2. Modifica blueprint/api.py per utilizzare i nuovi modelli")
        print("3. Testa l'applicazione")
    else:
        print("\n❌ Migrazione fallita o completata con errori")
        sys.exit(1)


if __name__ == '__main__':
    main()