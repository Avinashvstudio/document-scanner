from functools import wraps
from flask import session, jsonify

class SessionManager:
    USER_SESSION = 'user_session'
    ADMIN_SESSION = 'admin_session'
    
    @staticmethod
    def create_user_session(user_id, username):
        """Create a user session"""
        session[SessionManager.USER_SESSION] = {
            'user_id': user_id,
            'username': username,
            'is_admin': False
        }

    @staticmethod
    def create_admin_session(admin_id, username):
        """Create an admin session"""
        session[SessionManager.ADMIN_SESSION] = {
            'user_id': admin_id,
            'username': username,
            'is_admin': True
        }

    @staticmethod
    def clear_user_session():
        """Clear user session"""
        if SessionManager.USER_SESSION in session:
            session.pop(SessionManager.USER_SESSION)

    @staticmethod
    def clear_admin_session():
        """Clear admin session"""
        if SessionManager.ADMIN_SESSION in session:
            session.pop(SessionManager.ADMIN_SESSION)

    @staticmethod
    def get_current_user():
        """Get current user session data"""
        return session.get(SessionManager.USER_SESSION)

    @staticmethod
    def get_current_admin():
        """Get current admin session data"""
        return session.get(SessionManager.ADMIN_SESSION)

    @staticmethod
    def user_required(f):
        """Decorator for user-only routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not SessionManager.get_current_user():
                return jsonify({"error": "User login required"}), 403
            return f(*args, **kwargs)
        return decorated_function

    @staticmethod
    def admin_required(f):
        """Decorator for admin-only routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not SessionManager.get_current_admin():
                return jsonify({"error": "Admin login required"}), 403
            return f(*args, **kwargs)
        return decorated_function 