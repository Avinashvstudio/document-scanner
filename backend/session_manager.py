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
    def is_user_logged_in():
        """Check if a user is logged in"""
        return SessionManager.USER_SESSION in session

    @staticmethod
    def is_admin_logged_in():
        """Check if an admin is logged in"""
        return SessionManager.ADMIN_SESSION in session

    @staticmethod
    def user_required(f):
        """Decorator for user-only routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not SessionManager.is_user_logged_in():
                return jsonify({"error": "User login required"}), 403
            return f(*args, **kwargs)
        return decorated_function

    @staticmethod
    def admin_required(f):
        """Decorator for admin-only routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not SessionManager.is_admin_logged_in():
                return jsonify({"error": "Admin login required"}), 403
            return f(*args, **kwargs)
        return decorated_function 