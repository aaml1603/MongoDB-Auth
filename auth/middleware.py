from functools import wraps

from flask_jwt_extended import jwt_required


def auth_required(f):
    """Decorator for routes that require authentication."""
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function