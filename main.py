import logging
import sys

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter

from config import Config
from models import DatabaseManager
from auth import Authentication, RefreshTokenManager
from routes.auth_routes import init_auth_routes
from routes.user_routes import init_user_routes
from utils.rate_limits import get_remote_address
from utils.error_handlers import setup_error_handlers
from utils.scheduler import TokenCleanupScheduler


def create_app():
    """Application factory function."""
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize CORS with credentials support
    CORS(app, 
         origins=["http://localhost:3000"],
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization"])
    
    # Initialize JWT
    jwt = JWTManager(app)
    
    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per hour"],
        storage_uri="memory://"
    )
    
    # Setup comprehensive error handlers
    setup_error_handlers(app)
    
    # Initialize database manager
    db_manager = DatabaseManager()
    
    if not db_manager.connect():
        logging.error("Failed to establish database connection. Exiting.")
        sys.exit(1)
    
    # Initialize authentication and token management
    auth_manager = Authentication(db_manager)
    token_manager = RefreshTokenManager(db_manager)
    
    # Initialize and register blueprints
    auth_bp = init_auth_routes(auth_manager, token_manager, limiter)
    user_bp = init_user_routes(db_manager, limiter)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    
    # Start token cleanup scheduler
    cleanup_scheduler = TokenCleanupScheduler(token_manager, interval_hours=24)
    cleanup_scheduler.start()
    
    # Store scheduler in app context for graceful shutdown
    app.cleanup_scheduler = cleanup_scheduler
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=6969)