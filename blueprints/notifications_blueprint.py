from flask import Blueprint, jsonify, request


def create_notifications_blueprint(db, Notification):
    notifications_bp = Blueprint('notifications', __name__)

    @notifications_bp.route('/', methods=['GET'])
    def get_notifications():
        """Get all notifications"""
        try:
            limit = request.args.get('limit', 10, type=int)
            unread_only = request.args.get('unread_only', False, type=bool)

            query = Notification.query
            if unread_only:
                query = query.filter_by(is_read=False)

            notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()

            return jsonify({
                'success': True,
                'data': [notification.to_dict() for notification in notifications],
                'total': Notification.query.count(),
                'unread_count': Notification.query.filter_by(is_read=False).count()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/<int:notification_id>', methods=['GET'])
    def get_notification(notification_id):
        """Get specific notification"""
        try:
            notification = Notification.query.get_or_404(notification_id)
            return jsonify({
                'success': True,
                'data': notification.to_dict()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/', methods=['POST'])
    def create_notification():
        """Create new notification"""
        try:
            data = request.json

            notification = Notification(
                icon=data.get('icon'),
                title=data.get('title'),
                message=data.get('message'),
                time_ago=data.get('time_ago'),
                url=data.get('url')
            )

            db.session.add(notification)
            db.session.commit()

            return jsonify({
                'success': True,
                'data': notification.to_dict(),
                'message': 'Notification created successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/<int:notification_id>/read', methods=['POST'])
    def mark_notification_read(notification_id):
        """Mark notification as read"""
        try:
            notification = Notification.query.get_or_404(notification_id)
            notification.is_read = True
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Notification marked as read'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/mark-all-read', methods=['POST'])
    def mark_all_notifications_read():
        """Mark all notifications as read"""
        try:
            Notification.query.filter_by(is_read=False).update({Notification.is_read: True})
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'All notifications marked as read'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/<int:notification_id>', methods=['DELETE'])
    def delete_notification(notification_id):
        """Delete notification"""
        try:
            notification = Notification.query.get_or_404(notification_id)
            db.session.delete(notification)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Notification deleted successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @notifications_bp.route('/count', methods=['GET'])
    def get_notification_count():
        """Get notification counts"""
        try:
            total = Notification.query.count()
            unread = Notification.query.filter_by(is_read=False).count()

            return jsonify({
                'success': True,
                'data': {
                    'total': total,
                    'unread': unread
                }
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return notifications_bp