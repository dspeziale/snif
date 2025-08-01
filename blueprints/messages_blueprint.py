from flask import Blueprint, jsonify, request
from datetime import datetime


def create_messages_blueprint(db, Message):
    messages_bp = Blueprint('messages', __name__)

    @messages_bp.route('/', methods=['GET'])
    def get_messages():
        """Get all messages"""
        try:
            limit = request.args.get('limit', 10, type=int)
            unread_only = request.args.get('unread_only', False, type=bool)

            query = Message.query
            if unread_only:
                query = query.filter_by(is_read=False)

            messages = query.order_by(Message.timestamp.desc()).limit(limit).all()

            return jsonify({
                'success': True,
                'data': [message.to_dict() for message in messages],
                'total': Message.query.count(),
                'unread_count': Message.query.filter_by(is_read=False).count()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/<int:message_id>', methods=['GET'])
    def get_message(message_id):
        """Get specific message"""
        try:
            message = Message.query.get_or_404(message_id)
            return jsonify({
                'success': True,
                'data': message.to_dict()
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/', methods=['POST'])
    def create_message():
        """Create new message"""
        try:
            data = request.json

            message = Message(
                sender_name=data.get('sender_name'),
                sender_avatar=data.get('sender_avatar'),
                message=data.get('message'),
                is_important=data.get('is_important', False)
            )

            db.session.add(message)
            db.session.commit()

            return jsonify({
                'success': True,
                'data': message.to_dict(),
                'message': 'Message created successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/<int:message_id>/read', methods=['POST'])
    def mark_message_read(message_id):
        """Mark message as read"""
        try:
            message = Message.query.get_or_404(message_id)
            message.is_read = True
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Message marked as read'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/mark-all-read', methods=['POST'])
    def mark_all_messages_read():
        """Mark all messages as read"""
        try:
            Message.query.filter_by(is_read=False).update({Message.is_read: True})
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'All messages marked as read'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/<int:message_id>', methods=['DELETE'])
    def delete_message(message_id):
        """Delete message"""
        try:
            message = Message.query.get_or_404(message_id)
            db.session.delete(message)
            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Message deleted successfully'
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @messages_bp.route('/count', methods=['GET'])
    def get_message_count():
        """Get message counts"""
        try:
            total = Message.query.count()
            unread = Message.query.filter_by(is_read=False).count()

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

    return messages_bp