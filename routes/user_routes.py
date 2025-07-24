import logging

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId

from auth import auth_required

user_bp = Blueprint('user', __name__)


def init_user_routes(db_manager):
    """Initialize user routes with database manager."""
    
    @user_bp.route('/profile', methods=['GET'])
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
    def health_check():
        """Health check endpoint."""
        return jsonify({"status": "healthy", "message": "API is running"}), 200
    
    return user_bp