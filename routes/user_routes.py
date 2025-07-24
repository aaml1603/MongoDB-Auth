import logging

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId

from auth import auth_required
from utils.rate_limits import RATE_LIMITS

user_bp = Blueprint('user', __name__, url_prefix='/api')


def init_user_routes(db_manager, limiter):
    """Initialize user routes with database manager."""
    
    @user_bp.route('/profile', methods=['GET'])
    @limiter.limit(RATE_LIMITS['protected_moderate'])
    @auth_required
    def get_profile():
        """Get user profile (protected route example)."""
        try:
            user_id = get_jwt_identity()
            user = db_manager.usuarios.find_one({"_id": ObjectId(user_id)})
            
            if not user:
                return jsonify({"success": False, "message": "User not found"}), 404
            
            return jsonify({
                "success": True,
                "user": {
                    "id": str(user["_id"]),
                    "email": user["email"],
                    "created_at": user.get("created_at"),
                    "is_active": user.get("is_active", True)
                }
            }), 200
            
        except Exception as e:
            logging.error(f"Profile endpoint error: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @user_bp.route('/health', methods=['GET'])
    @limiter.limit(RATE_LIMITS['public'])
    def health_check():
        """Health check endpoint."""
        return jsonify({"status": "healthy", "message": "API is running"}), 200
    
    return user_bp