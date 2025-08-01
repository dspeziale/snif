from flask import Blueprint, jsonify, request


def create_menu_blueprint(db, MenuItem):
    menu_bp = Blueprint('menu', __name__)

    @menu_bp.route('/', methods=['GET'])
    def get_menu():
        """Get all menu items in hierarchical structure"""
        try:
            # Get root level items (parent_id is None)
            root_items = MenuItem.query.filter_by(parent_id=None).order_by(MenuItem.order_index).all()

            menu_data = []
            for item in root_items:
                menu_data.append(item.to_dict())

            return jsonify({
                'success': True,
                'data': menu_data
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @menu_bp.route('/item/<int:item_id>', methods=['GET'])
    def get_menu_item(item_id):
        """Get specific menu item"""
        try:
            item = MenuItem.query.get_or_404(item_id)
            return jsonify({
                'success': True,
                'data': item.to_dict()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @menu_bp.route('/item', methods=['POST'])
    def create_menu_item():
        """Create new menu item"""
        try:
            data = request.json

            item = MenuItem(
                name=data.get('name'),
                icon=data.get('icon'),
                url=data.get('url'),
                parent_id=data.get('parent_id'),
                order_index=data.get('order_index', 0),
                is_active=data.get('is_active', False),
                has_children=data.get('has_children', False),
                badge=data.get('badge'),
                badge_class=data.get('badge_class'),
                is_header=data.get('is_header', False)
            )

            db.session.add(item)
            db.session.commit()

            return jsonify({
                'success': True,
                'data': item.to_dict(),
                'message': 'Menu item created successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @menu_bp.route('/item/<int:item_id>', methods=['PUT'])
    def update_menu_item(item_id):
        """Update menu item"""
        try:
            item = MenuItem.query.get_or_404(item_id)
            data = request.json

            item.name = data.get('name', item.name)
            item.icon = data.get('icon', item.icon)
            item.url = data.get('url', item.url)
            item.parent_id = data.get('parent_id', item.parent_id)
            item.order_index = data.get('order_index', item.order_index)
            item.is_active = data.get('is_active', item.is_active)
            item.has_children = data.get('has_children', item.has_children)
            item.badge = data.get('badge', item.badge)
            item.badge_class = data.get('badge_class', item.badge_class)
            item.is_header = data.get('is_header', item.is_header)

            db.session.commit()

            return jsonify({
                'success': True,
                'data': item.to_dict(),
                'message': 'Menu item updated successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @menu_bp.route('/item/<int:item_id>', methods=['DELETE'])
    def delete_menu_item(item_id):
        """Delete menu item"""
        try:
            item = MenuItem.query.get_or_404(item_id)

            # Check if item has children
            if item.children.count() > 0:
                return jsonify({
                    'success': False,
                    'error': 'Cannot delete menu item with children'
                }), 400

            db.session.delete(item)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Menu item deleted successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @menu_bp.route('/set-active/<int:item_id>', methods=['POST'])
    def set_active_menu(item_id):
        """Set active menu item"""
        try:
            # Deactivate all menu items
            MenuItem.query.update({MenuItem.is_active: False})

            # Activate selected item
            item = MenuItem.query.get_or_404(item_id)
            item.is_active = True

            # Also activate parent items if this is a child
            current_item = item
            while current_item.parent_id:
                parent = MenuItem.query.get(current_item.parent_id)
                if parent:
                    parent.is_active = True
                    current_item = parent
                else:
                    break

            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Menu item activated successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return menu_bp