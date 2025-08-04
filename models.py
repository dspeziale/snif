"""
Modelli SQLAlchemy per la gestione di Menu, Messaggi e Notifiche
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from typing import Dict, List, Any, Optional
import json

db = SQLAlchemy()


class BaseModel(db.Model):
    """Modello base con campi comuni"""
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        """Converte il modello in dizionario"""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                result[column.name] = value.isoformat()
            else:
                result[column.name] = value
        return result


class MenuType(BaseModel):
    """Tipi di menu per classificazione"""
    __tablename__ = 'menu_types'

    name = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    # Relazione con menu items
    menu_items = db.relationship('MenuItem', backref='menu_type', lazy='dynamic')

    def __repr__(self):
        return f'<MenuType {self.name}>'


class MenuItem(BaseModel):
    """Elementi del menu con supporto per struttura gerarchica"""
    __tablename__ = 'menu_items'

    title = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(100))
    url = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=False)
    sort_order = db.Column(db.Integer, default=0)
    enabled = db.Column(db.Boolean, default=True)

    # Chiavi esterne
    parent_id = db.Column(db.Integer, db.ForeignKey('menu_items.id'))
    menu_type_id = db.Column(db.Integer, db.ForeignKey('menu_types.id'))

    # Relazioni self-referencing per la gerarchia
    children = db.relationship(
        'MenuItem',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    # Metadati aggiuntivi come JSON
    extra_data = db.Column(db.Text)  # JSON string per dati aggiuntivi

    def get_metadata(self) -> Dict[str, Any]:
        """Ottiene i metadati come dizionario"""
        if self.extra_data:
            try:
                return json.loads(self.extra_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_metadata(self, data: Dict[str, Any]):
        """Imposta i metadati da dizionario"""
        self.extra_data = json.dumps(data) if data else None

    def to_dict(self, include_children: bool = True) -> Dict[str, Any]:
        """Converte in dizionario con opzione per includere i figli"""
        result = super().to_dict()
        result['extra_data'] = self.get_metadata()

        if include_children and self.children.count() > 0:
            result['children'] = [
                child.to_dict(include_children=True)
                for child in self.children.order_by(MenuItem.sort_order, MenuItem.title)
            ]

        return result

    @classmethod
    def get_root_items(cls, menu_type_name: str = None):
        """Ottiene gli elementi root del menu"""
        query = cls.query.filter_by(parent_id=None, enabled=True)

        if menu_type_name:
            query = query.join(MenuType).filter(MenuType.name == menu_type_name)

        return query.order_by(cls.sort_order, cls.title).all()

    def __repr__(self):
        return f'<MenuItem {self.title}>'


class MessageType(BaseModel):
    """Tipi di messaggio"""
    __tablename__ = 'message_types'

    type = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), default='primary')
    icon = db.Column(db.String(100))
    description = db.Column(db.Text)

    # Relazione con messaggi
    messages = db.relationship('Message', backref='message_type', lazy='dynamic')

    def __repr__(self):
        return f'<MessageType {self.type}>'


class MessagePriority(BaseModel):
    """Priorità dei messaggi"""
    __tablename__ = 'message_priorities'

    level = db.Column(db.String(20), unique=True, nullable=False)
    label = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(20), default='secondary')
    icon = db.Column(db.String(100))
    sort_order = db.Column(db.Integer, default=0)

    # Relazione con messaggi
    messages = db.relationship('Message', backref='priority', lazy='dynamic')

    def __repr__(self):
        return f'<MessagePriority {self.level}>'


class Message(BaseModel):
    """Messaggi del sistema"""
    __tablename__ = 'messages'

    sender = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(255))
    content = db.Column(db.Text, nullable=False)
    avatar = db.Column(db.String(255))
    unread = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Chiavi esterne
    type_id = db.Column(db.Integer, db.ForeignKey('message_types.id'))
    priority_id = db.Column(db.Integer, db.ForeignKey('message_priorities.id'))

    # Campi per tracciamento
    read_at = db.Column(db.DateTime)
    archived = db.Column(db.Boolean, default=False)
    archived_at = db.Column(db.DateTime)

    # Metadati aggiuntivi
    extra_data = db.Column(db.Text)  # JSON per dati aggiuntivi

    def get_metadata(self) -> Dict[str, Any]:
        """Ottiene i metadati come dizionario"""
        if self.extra_data:
            try:
                return json.loads(self.extra_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_metadata(self, data: Dict[str, Any]):
        """Imposta i metadati da dizionario"""
        self.extra_data = json.dumps(data) if data else None

    def mark_as_read(self):
        """Segna il messaggio come letto"""
        self.unread = False
        self.read_at = datetime.utcnow()
        db.session.commit()

    def archive(self):
        """Archivia il messaggio"""
        self.archived = True
        self.archived_at = datetime.utcnow()
        db.session.commit()

    def get_time_display(self) -> str:
        """Ottiene una rappresentazione user-friendly del tempo"""
        if not self.timestamp:
            return "Unknown"

        now = datetime.utcnow()
        diff = now - self.timestamp

        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario con campi aggiuntivi"""
        result = super().to_dict()
        result['time'] = self.get_time_display()
        result['extra_data'] = self.get_metadata()

        # Includi informazioni su tipo e priorità
        if self.message_type:
            result['type'] = self.message_type.type
            result['type_info'] = {
                'label': self.message_type.label,
                'color': self.message_type.color,
                'icon': self.message_type.icon
            }

        if self.priority:
            result['priority'] = self.priority.level
            result['priority_info'] = {
                'label': self.priority.label,
                'color': self.priority.color,
                'icon': self.priority.icon
            }

        return result

    def __repr__(self):
        return f'<Message {self.subject or self.content[:50]}>'


class NotificationType(BaseModel):
    """Tipi di notifica"""
    __tablename__ = 'notification_types'

    type = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), default='info')
    icon = db.Column(db.String(100))
    description = db.Column(db.Text)

    # Relazione con notifiche
    notifications = db.relationship('Notification', backref='notification_type', lazy='dynamic')

    def __repr__(self):
        return f'<NotificationType {self.type}>'


class NotificationCategory(BaseModel):
    """Categorie delle notifiche"""
    __tablename__ = 'notification_categories'

    category = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20), default='secondary')
    icon = db.Column(db.String(100))
    description = db.Column(db.Text)

    # Relazione con notifiche
    notifications = db.relationship('Notification', backref='category', lazy='dynamic')

    def __repr__(self):
        return f'<NotificationCategory {self.category}>'


class NotificationPriority(BaseModel):
    """Priorità delle notifiche"""
    __tablename__ = 'notification_priorities'

    level = db.Column(db.String(20), unique=True, nullable=False)
    label = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(20), default='secondary')
    icon = db.Column(db.String(100))
    sort_order = db.Column(db.Integer, default=0)

    # Relazione con notifiche
    notifications = db.relationship('Notification', backref='priority', lazy='dynamic')

    def __repr__(self):
        return f'<NotificationPriority {self.level}>'


class Notification(BaseModel):
    """Notifiche del sistema"""
    __tablename__ = 'notifications'

    message = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(100))
    read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_url = db.Column(db.String(255))

    # Chiavi esterne
    type_id = db.Column(db.Integer, db.ForeignKey('notification_types.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('notification_categories.id'))
    priority_id = db.Column(db.Integer, db.ForeignKey('notification_priorities.id'))

    # Campi per tracciamento
    read_at = db.Column(db.DateTime)
    dismissed = db.Column(db.Boolean, default=False)
    dismissed_at = db.Column(db.DateTime)

    # Metadati aggiuntivi
    extra_data = db.Column(db.Text)  # JSON per dati aggiuntivi

    def get_metadata(self) -> Dict[str, Any]:
        """Ottiene i metadati come dizionario"""
        if self.extra_data:
            try:
                return json.loads(self.extra_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_metadata(self, data: Dict[str, Any]):
        """Imposta i metadati da dizionario"""
        self.extra_data = json.dumps(data) if data else None

    def mark_as_read(self):
        """Segna la notifica come letta"""
        self.read = True
        self.read_at = datetime.utcnow()
        db.session.commit()

    def dismiss(self):
        """Rimuove la notifica"""
        self.dismissed = True
        self.dismissed_at = datetime.utcnow()
        db.session.commit()

    def get_time_display(self) -> str:
        """Ottiene una rappresentazione user-friendly del tempo"""
        if not self.timestamp:
            return "Unknown"

        now = datetime.utcnow()
        diff = now - self.timestamp

        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "Just now"

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario con campi aggiuntivi"""
        result = super().to_dict()
        result['time'] = self.get_time_display()
        result['extra_data'] = self.get_metadata()

        # Includi informazioni su tipo, categoria e priorità
        if self.notification_type:
            result['type'] = self.notification_type.type
            result['type_info'] = {
                'label': self.notification_type.label,
                'color': self.notification_type.color,
                'icon': self.notification_type.icon
            }

        if self.category:
            result['category'] = self.category.category
            result['category_info'] = {
                'label': self.category.label,
                'color': self.category.color,
                'icon': self.category.icon
            }

        if self.priority:
            result['priority'] = self.priority.level
            result['priority_info'] = {
                'label': self.priority.label,
                'color': self.priority.color,
                'icon': self.priority.icon
            }

        return result

    def __repr__(self):
        return f'<Notification {self.message[:50]}>'