from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///adminlte.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'

db = SQLAlchemy(app)

# Define models here to avoid circular imports
class MenuItem(db.Model):
    __tablename__ = 'menu_items'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(200), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('menu_items.id'), nullable=True)
    order_index = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=False)
    has_children = db.Column(db.Boolean, default=False)
    badge = db.Column(db.String(20), nullable=True)
    badge_class = db.Column(db.String(100), nullable=True)
    is_header = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Self-referential relationship
    children = db.relationship(
        'MenuItem',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic',
        order_by='MenuItem.order_index'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'icon': self.icon,
            'url': self.url,
            'parent_id': self.parent_id,
            'order_index': self.order_index,
            'is_active': self.is_active,
            'has_children': self.has_children,
            'badge': self.badge,
            'badge_class': self.badge_class,
            'is_header': self.is_header,
            'children': [child.to_dict() for child in self.children.all()]
        }


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_name = db.Column(db.String(100), nullable=False)
    sender_avatar = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_important = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        try:
            return {
                'id': self.id,
                'sender_name': self.sender_name,
                'sender_avatar': self.sender_avatar or './static/assets/img/default-avatar.jpg',
                'message': self.message,
                'timestamp': self.timestamp.strftime('%m/%d/%Y %I:%M %p') if self.timestamp else 'Unknown',
                'time_ago': self.get_time_ago(),
                'is_read': self.is_read,
                'is_important': self.is_important
            }
        except Exception as e:
            logger.error(f"Error converting message {self.id} to dict: {e}")
            return {
                'id': self.id,
                'sender_name': self.sender_name or 'Unknown',
                'sender_avatar': './static/assets/img/default-avatar.jpg',
                'message': self.message or '',
                'timestamp': 'Unknown',
                'time_ago': 'Unknown time',
                'is_read': self.is_read,
                'is_important': self.is_important
            }

    def get_time_ago(self):
        try:
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
        except Exception as e:
            logger.error(f"Error calculating time ago for message {self.id}: {e}")
            return "Unknown time"


class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    icon = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=True)
    time_ago = db.Column(db.String(50), nullable=True)
    url = db.Column(db.String(200), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'icon': self.icon,
            'title': self.title,
            'message': self.message,
            'time_ago': self.time_ago,
            'url': self.url,
            'is_read': self.is_read
        }


# Import blueprints (create them after models are defined)
from blueprints.menu_blueprint import create_menu_blueprint
from blueprints.messages_blueprint import create_messages_blueprint
from blueprints.notifications_blueprint import create_notifications_blueprint
from blueprints.system_blueprint import create_system_blueprint

# Create blueprint instances
menu_bp = create_menu_blueprint(db, MenuItem)
messages_bp = create_messages_blueprint(db, Message)
notifications_bp = create_notifications_blueprint(db, Notification)
system_bp = create_system_blueprint()

# Register blueprints
app.register_blueprint(menu_bp, url_prefix='/api/menu')
app.register_blueprint(messages_bp, url_prefix='/api/messages')
app.register_blueprint(notifications_bp, url_prefix='/api/notifications')
app.register_blueprint(system_bp, url_prefix='/api/system')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/test')
def test():
    """Test endpoint to check database data"""
    try:
        menu_count = MenuItem.query.count()
        message_count = Message.query.count()
        notification_count = Notification.query.count()

        # Get first message for testing
        first_message = Message.query.first()
        message_data = first_message.to_dict() if first_message else None

        return jsonify({
            'success': True,
            'data': {
                'menu_items': menu_count,
                'messages': message_count,
                'notifications': notification_count,
                'first_message': message_data
            }
        })
    except Exception as e:
        logger.error(f"Test endpoint error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'details': str(error)
    }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Not found'
    }), 404


def create_tables():
    """Initialize database tables and sample data"""
    db.create_all()

    # Populate sample data if tables are empty
    if MenuItem.query.count() == 0:
        populate_sample_data()


def populate_sample_data():
    """Populate database with sample menu items, messages, and notifications"""
    # Menu items
    dashboard = MenuItem(
        name='Dashboard',
        icon='bi bi-speedometer',
        url='#',
        parent_id=None,
        order_index=1,
        is_active=True,
        has_children=True
    )
    db.session.add(dashboard)
    db.session.flush()

    # Dashboard subitems
    dashboard_v1 = MenuItem(
        name='Dashboard v1',
        icon='bi bi-circle',
        url='./index.html',
        parent_id=dashboard.id,
        order_index=1,
        is_active=True
    )
    dashboard_v2 = MenuItem(
        name='Dashboard v2',
        icon='bi bi-circle',
        url='./index2.html',
        parent_id=dashboard.id,
        order_index=2
    )
    dashboard_v3 = MenuItem(
        name='Dashboard v3',
        icon='bi bi-circle',
        url='./index3.html',
        parent_id=dashboard.id,
        order_index=3
    )

    db.session.add_all([dashboard_v1, dashboard_v2, dashboard_v3])

    # Theme Generate
    theme_generate = MenuItem(
        name='Theme Generate',
        icon='bi bi-palette',
        url='./generate/theme.html',
        parent_id=None,
        order_index=2
    )
    db.session.add(theme_generate)

    # Widgets
    widgets = MenuItem(
        name='Widgets',
        icon='bi bi-box-seam-fill',
        url='#',
        parent_id=None,
        order_index=3,
        has_children=True
    )
    db.session.add(widgets)
    db.session.flush()

    widgets_small = MenuItem(
        name='Small Box',
        icon='bi bi-circle',
        url='./widgets/small-box.html',
        parent_id=widgets.id,
        order_index=1
    )
    widgets_info = MenuItem(
        name='Info Box',
        icon='bi bi-circle',
        url='./widgets/info-box.html',
        parent_id=widgets.id,
        order_index=2
    )
    widgets_cards = MenuItem(
        name='Cards',
        icon='bi bi-circle',
        url='./widgets/cards.html',
        parent_id=widgets.id,
        order_index=3
    )

    db.session.add_all([widgets_small, widgets_info, widgets_cards])

    # Layout Options
    layout = MenuItem(
        name='Layout Options',
        icon='bi bi-clipboard-fill',
        url='#',
        parent_id=None,
        order_index=4,
        has_children=True,
        badge='6',
        badge_class='nav-badge badge text-bg-secondary me-3'
    )
    db.session.add(layout)
    db.session.flush()

    layout_items = [
        ('Default Sidebar', './layout/unfixed-sidebar.html'),
        ('Fixed Sidebar', './layout/fixed-sidebar.html'),
        ('Fixed Header', './layout/fixed-header.html'),
        ('Fixed Footer', './layout/fixed-footer.html'),
        ('Fixed Complete', './layout/fixed-complete.html'),
        ('Layout + Custom Area', './layout/layout-custom-area.html'),
        ('Sidebar Mini', './layout/sidebar-mini.html'),
        ('Sidebar Mini + Collapsed', './layout/collapsed-sidebar.html'),
        ('Sidebar Mini + Logo Switch', './layout/logo-switch.html'),
        ('Layout RTL', './layout/layout-rtl.html')
    ]

    for idx, (name, url) in enumerate(layout_items, 1):
        item = MenuItem(
            name=name,
            icon='bi bi-circle',
            url=url,
            parent_id=layout.id,
            order_index=idx
        )
        db.session.add(item)

    # UI Elements
    ui_elements = MenuItem(
        name='UI Elements',
        icon='bi bi-tree-fill',
        url='#',
        parent_id=None,
        order_index=5,
        has_children=True
    )
    db.session.add(ui_elements)
    db.session.flush()

    ui_items = [
        ('General', './UI/general.html'),
        ('Icons', './UI/icons.html'),
        ('Timeline', './UI/timeline.html')
    ]

    for idx, (name, url) in enumerate(ui_items, 1):
        item = MenuItem(
            name=name,
            icon='bi bi-circle',
            url=url,
            parent_id=ui_elements.id,
            order_index=idx
        )
        db.session.add(item)

    # Forms
    forms = MenuItem(
        name='Forms',
        icon='bi bi-pencil-square',
        url='#',
        parent_id=None,
        order_index=6,
        has_children=True
    )
    db.session.add(forms)
    db.session.flush()

    forms_general = MenuItem(
        name='General Elements',
        icon='bi bi-circle',
        url='./forms/general.html',
        parent_id=forms.id,
        order_index=1
    )
    db.session.add(forms_general)

    # Tables
    tables = MenuItem(
        name='Tables',
        icon='bi bi-table',
        url='#',
        parent_id=None,
        order_index=7,
        has_children=True
    )
    db.session.add(tables)
    db.session.flush()

    tables_simple = MenuItem(
        name='Simple Tables',
        icon='bi bi-circle',
        url='./tables/simple.html',
        parent_id=tables.id,
        order_index=1
    )
    db.session.add(tables_simple)

    # Examples Header
    examples_header = MenuItem(
        name='EXAMPLES',
        icon='',
        url='#',
        parent_id=None,
        order_index=8,
        is_header=True
    )
    db.session.add(examples_header)

    # Auth
    auth = MenuItem(
        name='Auth',
        icon='bi bi-box-arrow-in-right',
        url='#',
        parent_id=None,
        order_index=9,
        has_children=True
    )
    db.session.add(auth)
    db.session.flush()

    # Auth Version 1
    auth_v1 = MenuItem(
        name='Version 1',
        icon='bi bi-box-arrow-in-right',
        url='#',
        parent_id=auth.id,
        order_index=1,
        has_children=True
    )
    db.session.add(auth_v1)
    db.session.flush()

    auth_v1_login = MenuItem(
        name='Login',
        icon='bi bi-circle',
        url='./examples/login.html',
        parent_id=auth_v1.id,
        order_index=1
    )
    auth_v1_register = MenuItem(
        name='Register',
        icon='bi bi-circle',
        url='./examples/register.html',
        parent_id=auth_v1.id,
        order_index=2
    )
    db.session.add_all([auth_v1_login, auth_v1_register])

    # Documentation Header
    docs_header = MenuItem(
        name='DOCUMENTATIONS',
        icon='',
        url='#',
        parent_id=None,
        order_index=10,
        is_header=True
    )
    db.session.add(docs_header)

    # Installation
    installation = MenuItem(
        name='Installation',
        icon='bi bi-download',
        url='./docs/introduction.html',
        parent_id=None,
        order_index=11
    )
    db.session.add(installation)

    # Sample Messages
    messages_data = [
        {
            'sender_name': 'Brad Diesel',
            'sender_avatar': './static/assets/img/user1-128x128.jpg',
            'message': 'Call me whenever you can...',
            'timestamp': datetime.now(),
            'is_important': True,
            'is_read': False
        },
        {
            'sender_name': 'John Pierce',
            'sender_avatar': './static/assets/img/user8-128x128.jpg',
            'message': 'I got your message bro',
            'timestamp': datetime.now(),
            'is_important': False,
            'is_read': False
        },
        {
            'sender_name': 'Nora Silvester',
            'sender_avatar': './static/assets/img/user3-128x128.jpg',
            'message': 'The subject goes here',
            'timestamp': datetime.now(),
            'is_important': False,
            'is_read': False
        }
    ]

    for msg_data in messages_data:
        message = Message(**msg_data)
        db.session.add(message)

    # Sample Notifications
    notifications_data = [
        {
            'icon': 'bi bi-envelope me-2',
            'title': '4 new messages',
            'time_ago': '3 mins',
            'is_read': False
        },
        {
            'icon': 'bi bi-people-fill me-2',
            'title': '8 friend requests',
            'time_ago': '12 hours',
            'is_read': False
        },
        {
            'icon': 'bi bi-file-earmark-fill me-2',
            'title': '3 new reports',
            'time_ago': '2 days',
            'is_read': False
        }
    ]

    for notif_data in notifications_data:
        notification = Notification(**notif_data)
        db.session.add(notification)

    db.session.commit()


# Initialize database when app starts
with app.app_context():
    create_tables()


if __name__ == '__main__':
    app.run(debug=True, host="fusion.capecchispa.eu")