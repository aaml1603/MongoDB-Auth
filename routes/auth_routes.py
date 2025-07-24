import logging

from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from utils.rate_limits import RATE_LIMITS
from utils.cookie_auth import get_request_info, create_cookie_response, clear_auth_cookies, get_token_from_cookie

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


def init_auth_routes(auth_manager, token_manager, limiter):
    """Initialize auth routes with authentication manager."""
    
    @auth_bp.route('/register', methods=['POST'])
    @limiter.limit(RATE_LIMITS['auth_strict'])
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
    @limiter.limit(RATE_LIMITS['auth_strict'])
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
                # Create access token (JWT)
                access_token = create_access_token(identity=result['user']['id'])
                
                # Create stateful refresh token
                request_info = get_request_info()
                refresh_token = token_manager.create_refresh_token(result['user']['id'], request_info)
                
                # Create response with httpOnly cookies
                response_data = {
                    "success": True,
                    "message": "Login successful",
                    "user": result['user']
                }
                
                return create_cookie_response(response_data, access_token, refresh_token), 200
            else:
                return jsonify(result), 401
                
        except Exception as e:
            logging.error(f"Login endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/refresh', methods=['POST'])
    @limiter.limit(RATE_LIMITS['auth_moderate'])
    def refresh():
        """Refresh access token using stateful refresh token with rotation."""
        try:
            # Get refresh token from httpOnly cookie
            refresh_token = get_token_from_cookie('refresh_token')
            
            if not refresh_token:
                return jsonify({"success": False, "message": "No refresh token provided"}), 401
            
            # Validate and rotate token
            request_info = get_request_info()
            result = token_manager.validate_and_rotate_token(refresh_token, request_info)
            
            if not result.get('valid'):
                return jsonify({
                    "success": False, 
                    "message": result.get('error', 'Invalid refresh token')
                }), 401
            
            # Create new access token
            new_access_token = create_access_token(identity=result['user_id'])
            
            # Create response with new tokens in cookies
            response_data = {
                "success": True,
                "message": "Token refreshed successfully"
            }
            
            return create_cookie_response(response_data, new_access_token, result['new_token']), 200
            
        except Exception as e:
            logging.error(f"Refresh endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/request-password-reset', methods=['POST'])
    @limiter.limit(RATE_LIMITS['password_reset_request'])
    def request_password_reset():
        """Request password reset token."""
        try:
            data = request.get_json()
            
            if not data or not data.get('email'):
                return jsonify({"success": False, "message": "Email is required"}), 400
            
            email = data['email'].lower().strip()
            
            # Basic email validation
            if '@' not in email or '.' not in email:
                return jsonify({"success": False, "message": "Invalid email format"}), 400
            
            result = auth_manager.request_password_reset(email)
            
            # Always return 200 for security (don't reveal if email exists)
            return jsonify(result), 200
                
        except Exception as e:
            logging.error(f"Password reset request endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/reset-password', methods=['POST'])
    @limiter.limit(RATE_LIMITS['password_reset_confirm'])
    def reset_password():
        """Reset password using token."""
        try:
            data = request.get_json()
            
            if not data or not data.get('token') or not data.get('password'):
                return jsonify({"success": False, "message": "Token and password are required"}), 400
            
            token = data['token']
            password = data['password']
            
            # Password strength validation
            if len(password) < 6:
                return jsonify({"success": False, "message": "Password must be at least 6 characters long"}), 400
            
            result = auth_manager.reset_password(token, password, token_manager)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logging.error(f"Password reset endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/logout', methods=['POST'])
    @limiter.limit(RATE_LIMITS['auth_moderate'])
    def logout():
        """Logout user and revoke refresh token."""
        try:
            # Get refresh token from cookie
            refresh_token = get_token_from_cookie('refresh_token')
            
            # Revoke the refresh token if it exists
            if refresh_token:
                token_manager.revoke_token(refresh_token, "user_logout")
            
            # Create response and clear cookies
            response = make_response(jsonify({
                "success": True,
                "message": "Logged out successfully"
            }))
            
            clear_auth_cookies(response)
            return response, 200
            
        except Exception as e:
            logging.error(f"Logout endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/sessions', methods=['GET'])
    @limiter.limit(RATE_LIMITS['protected_moderate'])
    @jwt_required()
    def get_user_sessions():
        """Get all active sessions for the current user."""
        try:
            user_id = get_jwt_identity()
            sessions = token_manager.get_user_sessions(user_id)
            
            return jsonify({
                "success": True,
                "sessions": sessions
            }), 200
            
        except Exception as e:
            logging.error(f"Get sessions endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/sessions/<session_id>', methods=['DELETE'])
    @limiter.limit(RATE_LIMITS['auth_moderate'])
    @jwt_required()
    def revoke_session(session_id):
        """Revoke a specific session."""
        try:
            user_id = get_jwt_identity()
            
            # Find the session and verify it belongs to the user
            from bson import ObjectId
            session = token_manager.db_manager.database["refresh_tokens"].find_one({
                "_id": ObjectId(session_id),
                "user_id": user_id,
                "is_active": True
            })
            
            if not session:
                return jsonify({"success": False, "message": "Session not found"}), 404
            
            # Revoke the token
            success = token_manager.revoke_token(session["token"], "manual_revocation")
            
            if success:
                return jsonify({"success": True, "message": "Session revoked"}), 200
            else:
                return jsonify({"success": False, "message": "Failed to revoke session"}), 500
                
        except Exception as e:
            logging.error(f"Revoke session endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @auth_bp.route('/sessions/revoke-all', methods=['POST'])
    @limiter.limit(RATE_LIMITS['auth_strict'])
    @jwt_required()
    def revoke_all_sessions():
        """Revoke all sessions for the current user except the current one."""
        try:
            user_id = get_jwt_identity()
            current_refresh_token = get_token_from_cookie('refresh_token')
            
            # Get all user sessions
            sessions = token_manager.get_user_sessions(user_id)
            revoked_count = 0
            
            for session in sessions:
                # Don't revoke the current session
                if current_refresh_token and session.get('token') == current_refresh_token:
                    continue
                    
                # Revoke other sessions
                if token_manager.revoke_token(session['token'], "revoke_all_others"):
                    revoked_count += 1
            
            return jsonify({
                "success": True,
                "message": f"Revoked {revoked_count} sessions",
                "revoked_count": revoked_count
            }), 200
            
        except Exception as e:
            logging.error(f"Revoke all sessions endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500
    
    return auth_bp