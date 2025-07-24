import logging

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity

auth_bp = Blueprint('auth', __name__)


def init_auth_routes(auth_manager):
    """Initialize auth routes with authentication manager."""
    
    @auth_bp.route('/register', methods=['POST'])
    def register():
        """User registration endpoint."""
        try:
            data = request.get_json()
            
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({"success": False, "message": "Email and password are required"}), 400
            
            email = data['email'].lower().strip()
            password = data['password']
            
            # Basic email validation
            if '@' not in email or '.' not in email:
                return jsonify({"success": False, "message": "Invalid email format"}), 400
            
            # Password strength validation
            if len(password) < 6:
                return jsonify({"success": False, "message": "Password must be at least 6 characters long"}), 400
            
            result = auth_manager.register_user(email, password)
            
            if result['success']:
                return jsonify(result), 201
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logging.error(f"Registration endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/login', methods=['POST'])
    def login():
        """User login endpoint."""
        try:
            data = request.get_json()
            
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({"success": False, "message": "Email and password are required"}), 400
            
            email = data['email'].lower().strip()
            password = data['password']
            
            result = auth_manager.authenticate_user(email, password)
            
            if result['success']:
                # Create access and refresh tokens
                access_token = create_access_token(identity=result['user']['id'])
                refresh_token = create_refresh_token(identity=result['user']['id'])
                return jsonify({
                    "success": True,
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": result['user']
                }), 200
            else:
                return jsonify(result), 401
                
        except Exception as e:
            logging.error(f"Login endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        """Refresh access token using refresh token."""
        try:
            user_id = get_jwt_identity()
            new_access_token = create_access_token(identity=user_id)
            
            return jsonify({
                "success": True,
                "access_token": new_access_token
            }), 200
            
        except Exception as e:
            logging.error(f"Refresh endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500
    
    return auth_bp