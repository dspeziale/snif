"""
Manager per l'accesso centralizzato ai dati del database
Sostituisce il sistema basato su file JSON
"""
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, desc, asc
from sqlalchemy.orm import joinedload
from models import (
    db, MenuItem, MenuType, Message, MessageType, MessagePriority,
    Notification, NotificationType, NotificationCategory, NotificationPriority
)


class MenuManager:
    """Manager per la gestione del menu"""

    @staticmethod
    def get_sidebar_menu(menu_type_name: str = 'sidebar') -> List[Dict[str, Any]]:
        """
        Ottiene il menu della sidebar formattato per i template

        Args:
            menu_type_name: Nome del tipo di menu

        Returns:
            Lista di elementi del menu formattata
        """
        try:
            menu_type = MenuType.query.filter_by(name=menu_type_name).first()
            if not menu_type:
                return []

            root_items = MenuItem.query.filter_by(
                parent_id=None,
                menu_type_id=menu_type.id,
                enabled=True
            ).order_by(MenuItem.sort_order, MenuItem.title).all()

            return [item.to_dict(include_children=True) for item in root_items]

        except Exception as e:
            print(f"Errore nel caricamento del menu: {e}")
            return []

    @staticmethod
    def add_menu_item(title: str, icon: str = None, url: str = None,
                     parent_id: int = None, menu_type_name: str = 'sidebar',
                     sort_order: int = 0, active: bool = False,
                     extra_data: Dict[str, Any] = None) -> Optional[MenuItem]:
        """
        Aggiunge un nuovo elemento al menu

        Args:
            title: Titolo dell'elemento
            icon: Icona
            url: URL di destinazione
            parent_id: ID dell'elemento padre (per sottomenu)
            menu_type_name: Nome del tipo di menu
            sort_order: Ordine di visualizzazione
            active: Se l'elemento è attivo
            extra_data: Metadati aggiuntivi

        Returns:
            Nuovo elemento del menu o None se errore
        """
        try:
            # Trova o crea il tipo di menu
            menu_type = MenuType.query.filter_by(name=menu_type_name).first()
            if not menu_type:
                menu_type = MenuType(
                    name=menu_type_name,
                    label=menu_type_name.title(),
                    description=f"Menu type: {menu_type_name}"
                )
                db.session.add(menu_type)
                db.session.flush()

            # Crea il nuovo elemento
            menu_item = MenuItem(
                title=title,
                icon=icon,
                url=url,
                parent_id=parent_id,
                menu_type_id=menu_type.id,
                sort_order=sort_order,
                active=active,
                enabled=True
            )

            if extra_data:
                menu_item.set_metadata(extra_data)

            db.session.add(menu_item)
            db.session.commit()

            return menu_item

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'aggiunta dell'elemento menu: {e}")
            return None

    @staticmethod
    def update_menu_item(item_id: int, **kwargs) -> bool:
        """
        Aggiorna un elemento del menu

        Args:
            item_id: ID dell'elemento da aggiornare
            **kwargs: Campi da aggiornare

        Returns:
            True se aggiornato con successo
        """
        try:
            menu_item = MenuItem.query.get(item_id)
            if not menu_item:
                return False

            for key, value in kwargs.items():
                if key == 'extra_data' and isinstance(value, dict):
                    menu_item.set_metadata(value)
                elif hasattr(menu_item, key):
                    setattr(menu_item, key, value)

            db.session.commit()
            return True

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'aggiornamento dell'elemento menu: {e}")
            return False

    @staticmethod
    def delete_menu_item(item_id: int) -> bool:
        """
        Elimina un elemento del menu

        Args:
            item_id: ID dell'elemento da eliminare

        Returns:
            True se eliminato con successo
        """
        try:
            menu_item = MenuItem.query.get(item_id)
            if not menu_item:
                return False

            db.session.delete(menu_item)
            db.session.commit()
            return True

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'eliminazione dell'elemento menu: {e}")
            return False

    @staticmethod
    def set_active_menu_item(url: str) -> bool:
        """
        Imposta l'elemento del menu attivo in base all'URL

        Args:
            url: URL corrente

        Returns:
            True se aggiornato con successo
        """
        try:
            # Disattiva tutti gli elementi
            MenuItem.query.update({'active': False})

            # Attiva l'elemento corrispondente all'URL
            menu_item = MenuItem.query.filter_by(url=url).first()
            if menu_item:
                menu_item.active = True
                # Attiva anche i genitori
                parent = menu_item.parent
                while parent:
                    parent.active = True
                    parent = parent.parent

            db.session.commit()
            return True

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'impostazione del menu attivo: {e}")
            return False


class MessageManager:
    """Manager per la gestione dei messaggi"""

    @staticmethod
    def get_messages(limit: int = None, unread_only: bool = False,
                    message_type: str = None, priority: str = None,
                    page: int = 1, per_page: int = 10) -> Dict[str, Any]:
        """
        Ottiene i messaggi con filtri e paginazione

        Args:
            limit: Numero massimo di messaggi
            unread_only: Solo messaggi non letti
            message_type: Filtra per tipo di messaggio
            priority: Filtra per priorità
            page: Numero di pagina
            per_page: Messaggi per pagina

        Returns:
            Dizionario con messaggi e metadati
        """
        try:
            query = Message.query.filter_by(archived=False)

            # Applica filtri
            if unread_only:
                query = query.filter_by(unread=True)

            if message_type:
                query = query.join(MessageType).filter(MessageType.type == message_type)

            if priority:
                query = query.join(MessagePriority).filter(MessagePriority.level == priority)

            # Ordina per timestamp (più recenti prima)
            query = query.order_by(desc(Message.timestamp))

            # Applica limit se specificato
            if limit:
                messages = query.limit(limit).all()
                return {
                    'messages': [msg.to_dict() for msg in messages],
                    'total': query.count(),
                    'unread_count': Message.query.filter_by(unread=True, archived=False).count()
                }

            # Paginazione
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )

            return {
                'messages': [msg.to_dict() for msg in pagination.items],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                },
                'total': pagination.total,
                'unread_count': Message.query.filter_by(unread=True, archived=False).count()
            }

        except Exception as e:
            print(f"Errore nel caricamento dei messaggi: {e}")
            return {'messages': [], 'total': 0, 'unread_count': 0}

    @staticmethod
    def get_message(message_id: int) -> Optional[Dict[str, Any]]:
        """
        Ottiene un messaggio specifico

        Args:
            message_id: ID del messaggio

        Returns:
            Dizionario con i dati del messaggio o None
        """
        try:
            message = Message.query.get(message_id)
            return message.to_dict() if message else None

        except Exception as e:
            print(f"Errore nel caricamento del messaggio {message_id}: {e}")
            return None

    @staticmethod
    def create_message(sender: str, content: str, subject: str = None,
                      message_type: str = None, priority: str = 'medium',
                      avatar: str = None, extra_data: Dict[str, Any] = None) -> Optional[Message]:
        """
        Crea un nuovo messaggio

        Args:
            sender: Mittente del messaggio
            content: Contenuto del messaggio
            subject: Oggetto del messaggio
            message_type: Tipo di messaggio
            priority: Priorità del messaggio
            avatar: Avatar del mittente
            extra_data: Metadati aggiuntivi

        Returns:
            Nuovo messaggio o None se errore
        """
        try:
            # Trova il tipo di messaggio
            msg_type = None
            if message_type:
                msg_type = MessageType.query.filter_by(type=message_type).first()

            # Trova la priorità
            msg_priority = MessagePriority.query.filter_by(level=priority).first()

            # Crea il messaggio
            message = Message(
                sender=sender,
                content=content,
                subject=subject,
                avatar=avatar,
                unread=True,
                timestamp=datetime.utcnow(),
                type_id=msg_type.id if msg_type else None,
                priority_id=msg_priority.id if msg_priority else None
            )

            if extra_data:
                message.set_metadata(extra_data)

            db.session.add(message)
            db.session.commit()

            return message

        except Exception as e:
            db.session.rollback()
            print(f"Errore nella creazione del messaggio: {e}")
            return None

    @staticmethod
    def mark_message_read(message_id: int) -> bool:
        """
        Segna un messaggio come letto

        Args:
            message_id: ID del messaggio

        Returns:
            True se aggiornato con successo
        """
        try:
            message = Message.query.get(message_id)
            if message:
                message.mark_as_read()
                return True
            return False

        except Exception as e:
            print(f"Errore nel segnare il messaggio come letto: {e}")
            return False

    @staticmethod
    def mark_all_messages_read() -> bool:
        """
        Segna tutti i messaggi come letti

        Returns:
            True se aggiornato con successo
        """
        try:
            messages = Message.query.filter_by(unread=True, archived=False).all()
            for message in messages:
                message.mark_as_read()
            return True

        except Exception as e:
            print(f"Errore nel segnare tutti i messaggi come letti: {e}")
            return False

    @staticmethod
    def archive_message(message_id: int) -> bool:
        """
        Archivia un messaggio

        Args:
            message_id: ID del messaggio

        Returns:
            True se archiviato con successo
        """
        try:
            message = Message.query.get(message_id)
            if message:
                message.archive()
                return True
            return False

        except Exception as e:
            print(f"Errore nell'archiviazione del messaggio: {e}")
            return False

    @staticmethod
    def delete_message(message_id: int) -> bool:
        """
        Elimina un messaggio

        Args:
            message_id: ID del messaggio

        Returns:
            True se eliminato con successo
        """
        try:
            message = Message.query.get(message_id)
            if message:
                db.session.delete(message)
                db.session.commit()
                return True
            return False

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'eliminazione del messaggio: {e}")
            return False

    @staticmethod
    def get_message_types() -> List[Dict[str, Any]]:
        """
        Ottiene tutti i tipi di messaggio

        Returns:
            Lista di tipi di messaggio
        """
        try:
            types = MessageType.query.all()
            return [msg_type.to_dict() for msg_type in types]

        except Exception as e:
            print(f"Errore nel caricamento dei tipi di messaggio: {e}")
            return []

    @staticmethod
    def get_message_priorities() -> List[Dict[str, Any]]:
        """
        Ottiene tutte le priorità dei messaggi

        Returns:
            Lista di priorità
        """
        try:
            priorities = MessagePriority.query.order_by(MessagePriority.sort_order).all()
            return [priority.to_dict() for priority in priorities]

        except Exception as e:
            print(f"Errore nel caricamento delle priorità dei messaggi: {e}")
            return []


class NotificationManager:
    """Manager per la gestione delle notifiche"""

    @staticmethod
    def get_notifications(limit: int = None, unread_only: bool = False,
                         notification_type: str = None, category: str = None,
                         priority: str = None, page: int = 1, per_page: int = 10) -> Dict[str, Any]:
        """
        Ottiene le notifiche con filtri e paginazione

        Args:
            limit: Numero massimo di notifiche
            unread_only: Solo notifiche non lette
            notification_type: Filtra per tipo
            category: Filtra per categoria
            priority: Filtra per priorità
            page: Numero di pagina
            per_page: Notifiche per pagina

        Returns:
            Dizionario con notifiche e metadati
        """
        try:
            query = Notification.query.filter_by(dismissed=False)

            # Applica filtri
            if unread_only:
                query = query.filter_by(read=False)

            if notification_type:
                query = query.join(NotificationType).filter(NotificationType.type == notification_type)

            if category:
                query = query.join(NotificationCategory).filter(NotificationCategory.category == category)

            if priority:
                query = query.join(NotificationPriority).filter(NotificationPriority.level == priority)

            # Ordina per timestamp (più recenti prima)
            query = query.order_by(desc(Notification.timestamp))

            # Applica limit se specificato
            if limit:
                notifications = query.limit(limit).all()
                return {
                    'notifications': [notif.to_dict() for notif in notifications],
                    'total': query.count(),
                    'unread_count': Notification.query.filter_by(read=False, dismissed=False).count()
                }

            # Paginazione
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )

            return {
                'notifications': [notif.to_dict() for notif in pagination.items],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                },
                'total': pagination.total,
                'unread_count': Notification.query.filter_by(read=False, dismissed=False).count()
            }

        except Exception as e:
            print(f"Errore nel caricamento delle notifiche: {e}")
            return {'notifications': [], 'total': 0, 'unread_count': 0}

    @staticmethod
    def get_notification(notification_id: int) -> Optional[Dict[str, Any]]:
        """
        Ottiene una notifica specifica

        Args:
            notification_id: ID della notifica

        Returns:
            Dizionario con i dati della notifica o None
        """
        try:
            notification = Notification.query.get(notification_id)
            return notification.to_dict() if notification else None

        except Exception as e:
            print(f"Errore nel caricamento della notifica {notification_id}: {e}")
            return None

    @staticmethod
    def create_notification(message: str, notification_type: str = None,
                           category: str = None, priority: str = 'low',
                           icon: str = None, action_url: str = None,
                           extra_data: Dict[str, Any] = None) -> Optional[Notification]:
        """
        Crea una nuova notifica

        Args:
            message: Messaggio della notifica
            notification_type: Tipo di notifica
            category: Categoria della notifica
            priority: Priorità della notifica
            icon: Icona della notifica
            action_url: URL di azione
            extra_data: Metadati aggiuntivi

        Returns:
            Nuova notifica o None se errore
        """
        try:
            # Trova il tipo di notifica
            notif_type = None
            if notification_type:
                notif_type = NotificationType.query.filter_by(type=notification_type).first()

            # Trova la categoria
            notif_category = None
            if category:
                notif_category = NotificationCategory.query.filter_by(category=category).first()

            # Trova la priorità
            notif_priority = NotificationPriority.query.filter_by(level=priority).first()

            # Crea la notifica
            notification = Notification(
                message=message,
                icon=icon,
                read=False,
                timestamp=datetime.utcnow(),
                action_url=action_url,
                type_id=notif_type.id if notif_type else None,
                category_id=notif_category.id if notif_category else None,
                priority_id=notif_priority.id if notif_priority else None
            )

            if extra_data:
                notification.set_metadata(extra_data)

            db.session.add(notification)
            db.session.commit()

            return notification

        except Exception as e:
            db.session.rollback()
            print(f"Errore nella creazione della notifica: {e}")
            return None

    @staticmethod
    def mark_notification_read(notification_id: int) -> bool:
        """
        Segna una notifica come letta

        Args:
            notification_id: ID della notifica

        Returns:
            True se aggiornata con successo
        """
        try:
            notification = Notification.query.get(notification_id)
            if notification:
                notification.mark_as_read()
                return True
            return False

        except Exception as e:
            print(f"Errore nel segnare la notifica come letta: {e}")
            return False

    @staticmethod
    def mark_all_notifications_read() -> bool:
        """
        Segna tutte le notifiche come lette

        Returns:
            True se aggiornate con successo
        """
        try:
            notifications = Notification.query.filter_by(read=False, dismissed=False).all()
            for notification in notifications:
                notification.mark_as_read()
            return True

        except Exception as e:
            print(f"Errore nel segnare tutte le notifiche come lette: {e}")
            return False

    @staticmethod
    def dismiss_notification(notification_id: int) -> bool:
        """
        Rimuove una notifica

        Args:
            notification_id: ID della notifica

        Returns:
            True se rimossa con successo
        """
        try:
            notification = Notification.query.get(notification_id)
            if notification:
                notification.dismiss()
                return True
            return False

        except Exception as e:
            print(f"Errore nella rimozione della notifica: {e}")
            return False

    @staticmethod
    def delete_notification(notification_id: int) -> bool:
        """
        Elimina una notifica

        Args:
            notification_id: ID della notifica

        Returns:
            True se eliminata con successo
        """
        try:
            notification = Notification.query.get(notification_id)
            if notification:
                db.session.delete(notification)
                db.session.commit()
                return True
            return False

        except Exception as e:
            db.session.rollback()
            print(f"Errore nell'eliminazione della notifica: {e}")
            return False

    @staticmethod
    def get_notification_types() -> List[Dict[str, Any]]:
        """
        Ottiene tutti i tipi di notifica

        Returns:
            Lista di tipi di notifica
        """
        try:
            types = NotificationType.query.all()
            return [notif_type.to_dict() for notif_type in types]

        except Exception as e:
            print(f"Errore nel caricamento dei tipi di notifica: {e}")
            return []

    @staticmethod
    def get_notification_categories() -> List[Dict[str, Any]]:
        """
        Ottiene tutte le categorie di notifica

        Returns:
            Lista di categorie
        """
        try:
            categories = NotificationCategory.query.all()
            return [category.to_dict() for category in categories]

        except Exception as e:
            print(f"Errore nel caricamento delle categorie di notifica: {e}")
            return []

    @staticmethod
    def get_notification_priorities() -> List[Dict[str, Any]]:
        """
        Ottiene tutte le priorità delle notifiche

        Returns:
            Lista di priorità
        """
        try:
            priorities = NotificationPriority.query.order_by(NotificationPriority.sort_order).all()
            return [priority.to_dict() for priority in priorities]

        except Exception as e:
            print(f"Errore nel caricamento delle priorità delle notifiche: {e}")
            return []


class StatsManager:
    """Manager per le statistiche generali"""

    @staticmethod
    def get_dashboard_stats() -> Dict[str, Any]:
        """
        Ottiene le statistiche per la dashboard

        Returns:
            Dizionario con le statistiche
        """
        try:
            # Statistiche messaggi
            total_messages = Message.query.filter_by(archived=False).count()
            unread_messages = Message.query.filter_by(unread=True, archived=False).count()

            # Statistiche notifiche
            total_notifications = Notification.query.filter_by(dismissed=False).count()
            unread_notifications = Notification.query.filter_by(read=False, dismissed=False).count()

            # Statistiche menu
            total_menu_items = MenuItem.query.filter_by(enabled=True).count()

            # Messaggi per tipo (ultimi 30 giorni)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_messages_by_type = db.session.query(
                MessageType.type,
                MessageType.label,
                db.func.count(Message.id)
            ).join(Message).filter(
                Message.timestamp >= thirty_days_ago,
                Message.archived == False
            ).group_by(MessageType.type, MessageType.label).all()

            # Notifiche per categoria (ultimi 30 giorni)
            recent_notifications_by_category = db.session.query(
                NotificationCategory.category,
                NotificationCategory.label,
                db.func.count(Notification.id)
            ).join(Notification).filter(
                Notification.timestamp >= thirty_days_ago,
                Notification.dismissed == False
            ).group_by(NotificationCategory.category, NotificationCategory.label).all()

            return {
                'messages': {
                    'total': total_messages,
                    'unread': unread_messages,
                    'read_percentage': round((total_messages - unread_messages) / total_messages * 100, 1) if total_messages > 0 else 0,
                    'by_type': [
                        {
                            'type': row[0],
                            'label': row[1],
                            'count': row[2]
                        }
                        for row in recent_messages_by_type
                    ]
                },
                'notifications': {
                    'total': total_notifications,
                    'unread': unread_notifications,
                    'read_percentage': round((total_notifications - unread_notifications) / total_notifications * 100, 1) if total_notifications > 0 else 0,
                    'by_category': [
                        {
                            'category': row[0],
                            'label': row[1],
                            'count': row[2]
                        }
                        for row in recent_notifications_by_category
                    ]
                },
                'menu': {
                    'total_items': total_menu_items
                },
                'activity': {
                    'recent_messages': Message.query.filter(
                        Message.timestamp >= thirty_days_ago,
                        Message.archived == False
                    ).count(),
                    'recent_notifications': Notification.query.filter(
                        Notification.timestamp >= thirty_days_ago,
                        Notification.dismissed == False
                    ).count()
                }
            }

        except Exception as e:
            print(f"Errore nel caricamento delle statistiche: {e}")
            return {
                'messages': {'total': 0, 'unread': 0, 'read_percentage': 0, 'by_type': []},
                'notifications': {'total': 0, 'unread': 0, 'read_percentage': 0, 'by_category': []},
                'menu': {'total_items': 0},
                'activity': {'recent_messages': 0, 'recent_notifications': 0}
            }

    @staticmethod
    def get_activity_timeline(days: int = 7) -> List[Dict[str, Any]]:
        """
        Ottiene la timeline delle attività recenti

        Args:
            days: Numero di giorni da includere

        Returns:
            Lista di attività ordinate per data
        """
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            # Messaggi recenti
            recent_messages = Message.query.filter(
                Message.timestamp >= start_date,
                Message.archived == False
            ).order_by(desc(Message.timestamp)).limit(20).all()

            # Notifiche recenti
            recent_notifications = Notification.query.filter(
                Notification.timestamp >= start_date,
                Notification.dismissed == False
            ).order_by(desc(Notification.timestamp)).limit(20).all()

            # Combina e ordina
            timeline = []

            for msg in recent_messages:
                timeline.append({
                    'type': 'message',
                    'id': msg.id,
                    'title': msg.subject or f"Message from {msg.sender}",
                    'description': msg.content[:100] + ('...' if len(msg.content) > 100 else ''),
                    'timestamp': msg.timestamp,
                    'icon': 'bi-envelope',
                    'color': 'primary'
                })

            for notif in recent_notifications:
                timeline.append({
                    'type': 'notification',
                    'id': notif.id,
                    'title': 'Notification',
                    'description': notif.message[:100] + ('...' if len(notif.message) > 100 else ''),
                    'timestamp': notif.timestamp,
                    'icon': notif.icon or 'bi-bell',
                    'color': 'info'
                })

            # Ordina per timestamp (più recenti prima)
            timeline.sort(key=lambda x: x['timestamp'], reverse=True)

            return timeline[:50]  # Limita a 50 elementi

        except Exception as e:
            print(f"Errore nel caricamento della timeline: {e}")
            return []


# Istanze globali dei manager per facilità d'uso
menu_manager = MenuManager()
message_manager = MessageManager()
notification_manager = NotificationManager()
stats_manager = StatsManager()