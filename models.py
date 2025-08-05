from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Menu(db.Model):
    __tablename__ = 'menus'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    icon = db.Column(db.String(50), default='bi-circle')
    url = db.Column(db.String(200))
    parent_id = db.Column(db.Integer, db.ForeignKey('menus.id'), nullable=True)
    order_position = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    is_header = db.Column(db.Boolean, default=False)  # Per gli header come "EXAMPLES"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relazioni
    children = db.relationship('Menu',
                               backref=db.backref('parent', remote_side=[id]),
                               cascade='all, delete-orphan',
                               order_by='Menu.order_position')

    def __repr__(self):
        return f'<Menu {self.title}>'

    @property
    def level(self):
        """Restituisce il livello del menu (0=root, 1=primo livello, 2=secondo livello)"""
        if self.parent_id is None:
            return 0
        elif self.parent and self.parent.parent_id is None:
            return 1
        else:
            return 2

    @property
    def has_children(self):
        """Verifica se il menu ha figli"""
        return len(self.children) > 0

    def to_dict(self):
        """Converte il menu in dizionario per JSON"""
        return {
            'id': self.id,
            'title': self.title,
            'icon': self.icon,
            'url': self.url,
            'parent_id': self.parent_id,
            'order_position': self.order_position,
            'is_active': self.is_active,
            'is_header': self.is_header,
            'level': self.level,
            'has_children': self.has_children,
            'children': [child.to_dict() for child in self.children if child.is_active]
        }

    @staticmethod
    def get_menu_tree():
        """Restituisce l'albero completo dei menu attivi"""
        root_menus = Menu.query.filter_by(parent_id=None, is_active=True).order_by(Menu.order_position).all()
        return [menu.to_dict() for menu in root_menus]

    @staticmethod
    def create_default_menu():
        """Crea il menu di default"""
        # Verifica se esistono già menu
        if Menu.query.count() > 0:
            return

        # Dashboard
        dashboard = Menu(title='Dashboard', icon='bi-speedometer', order_position=1)
        db.session.add(dashboard)
        db.session.flush()

        # Dashboard submenu
        dashboard_v1 = Menu(title='Dashboard v1', icon='bi-circle', url='/', parent_id=dashboard.id, order_position=1)
        dashboard_v2 = Menu(title='Dashboard v2', icon='bi-circle', url='/dashboard2', parent_id=dashboard.id,
                            order_position=2)
        dashboard_v3 = Menu(title='Dashboard v3', icon='bi-circle', url='/dashboard3', parent_id=dashboard.id,
                            order_position=3)

        db.session.add_all([dashboard_v1, dashboard_v2, dashboard_v3])

        # Widgets
        widgets = Menu(title='Widgets', icon='bi-box-seam-fill', order_position=2)
        db.session.add(widgets)
        db.session.flush()

        # Widget submenu
        small_box = Menu(title='Small Box', icon='bi-circle', url='/widgets/small-box', parent_id=widgets.id,
                         order_position=1)
        info_box = Menu(title='Info Box', icon='bi-circle', url='/widgets/info-box', parent_id=widgets.id,
                        order_position=2)
        cards = Menu(title='Cards', icon='bi-circle', url='/widgets/cards', parent_id=widgets.id, order_position=3)

        db.session.add_all([small_box, info_box, cards])

        # Layout Options
        layout = Menu(title='Layout Options', icon='bi-clipboard-fill', order_position=3)
        db.session.add(layout)
        db.session.flush()

        # Layout submenu
        fixed_sidebar = Menu(title='Fixed Sidebar', icon='bi-circle', url='/layout/fixed-sidebar', parent_id=layout.id,
                             order_position=1)
        fixed_header = Menu(title='Fixed Header', icon='bi-circle', url='/layout/fixed-header', parent_id=layout.id,
                            order_position=2)

        db.session.add_all([fixed_sidebar, fixed_header])

        # UI Elements
        ui_elements = Menu(title='UI Elements', icon='bi-tree-fill', order_position=4)
        db.session.add(ui_elements)
        db.session.flush()

        # UI Elements submenu
        general = Menu(title='General', icon='bi-circle', url='/ui/general', parent_id=ui_elements.id, order_position=1)
        icons = Menu(title='Icons', icon='bi-circle', url='/ui/icons', parent_id=ui_elements.id, order_position=2)

        db.session.add_all([general, icons])

        # Forms
        forms = Menu(title='Forms', icon='bi-pencil-square', order_position=5)
        db.session.add(forms)
        db.session.flush()

        # Forms submenu
        general_forms = Menu(title='General Elements', icon='bi-circle', url='/forms/general', parent_id=forms.id,
                             order_position=1)
        db.session.add(general_forms)

        # Tables
        tables = Menu(title='Tables', icon='bi-table', order_position=6)
        db.session.add(tables)
        db.session.flush()

        # Tables submenu
        simple_tables = Menu(title='Simple Tables', icon='bi-circle', url='/tables/simple', parent_id=tables.id,
                             order_position=1)
        db.session.add(simple_tables)

        # Header EXAMPLES
        examples_header = Menu(title='EXAMPLES', is_header=True, order_position=7)
        db.session.add(examples_header)

        # Auth
        auth = Menu(title='Auth', icon='bi-box-arrow-in-right', order_position=8)
        db.session.add(auth)
        db.session.flush()

        # Auth Version 1
        auth_v1 = Menu(title='Version 1', icon='bi-box-arrow-in-right', parent_id=auth.id, order_position=1)
        db.session.add(auth_v1)
        db.session.flush()

        # Auth Version 1 submenu
        login_v1 = Menu(title='Login', icon='bi-circle', url='/auth/login', parent_id=auth_v1.id, order_position=1)
        register_v1 = Menu(title='Register', icon='bi-circle', url='/auth/register', parent_id=auth_v1.id,
                           order_position=2)

        db.session.add_all([login_v1, register_v1])

        # Auth Version 2
        auth_v2 = Menu(title='Version 2', icon='bi-box-arrow-in-right', parent_id=auth.id, order_position=2)
        db.session.add(auth_v2)
        db.session.flush()

        # Auth Version 2 submenu
        login_v2 = Menu(title='Login', icon='bi-circle', url='/auth/login-v2', parent_id=auth_v2.id, order_position=1)
        register_v2 = Menu(title='Register', icon='bi-circle', url='/auth/register-v2', parent_id=auth_v2.id,
                           order_position=2)

        db.session.add_all([login_v2, register_v2])

        # Lockscreen
        lockscreen = Menu(title='Lockscreen', icon='bi-circle', url='/auth/lockscreen', parent_id=auth.id,
                          order_position=3)
        db.session.add(lockscreen)

        # Header DOCUMENTATIONS
        docs_header = Menu(title='DOCUMENTATIONS', is_header=True, order_position=9)
        db.session.add(docs_header)

        # Documentation menu items
        installation = Menu(title='Installation', icon='bi-download', url='/docs/installation', order_position=10)
        layout_docs = Menu(title='Layout', icon='bi-grip-horizontal', url='/docs/layout', order_position=11)
        components = Menu(title='Components', icon='bi-ui-checks-grid', order_position=12)

        db.session.add_all([installation, layout_docs, components])
        db.session.flush()

        # Components submenu
        main_header = Menu(title='Main Header', icon='bi-circle', url='/docs/components/main-header',
                           parent_id=components.id, order_position=1)
        main_sidebar = Menu(title='Main Sidebar', icon='bi-circle', url='/docs/components/main-sidebar',
                            parent_id=components.id, order_position=2)

        db.session.add_all([main_header, main_sidebar])

        # Menu Management
        menu_mgmt = Menu(title='Menu Management', icon='bi-list-ul', url='/menu', order_position=13)
        db.session.add(menu_mgmt)

        db.session.commit()