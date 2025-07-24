import logging
import sys

from flask import Flask
from flask_jwt_extended import JWTManager

from config import Config
from models import DatabaseManager
from auth import Authentication
from routes.auth_routes import init_auth_routes
from routes.user_routes import init_user_routes


def create_app():
    """Application factory function."""
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize JWT
    jwt = JWTManager(app)
    
    # Initialize database manager
    db_manager = DatabaseManager()
    
    if not db_manager.connect():
        logging.error("Failed to establish database connection. Exiting.")
        sys.exit(1)
    
    # Initialize authentication
    auth_manager = Authentication(db_manager)
    
    # Initialize and register blueprints
    auth_bp = init_auth_routes(auth_manager)
    user_bp = init_user_routes(db_manager)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=6969)