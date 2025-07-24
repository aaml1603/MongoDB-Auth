# Example: How to implement stateful refresh tokens (not currently implemented)

import secrets
from datetime import datetime, timedelta
from models import DatabaseManager

class StatefulRefreshTokenManager:
    """Example implementation of database-stored refresh tokens."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create and store a refresh token in the database."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        token_data = {
            "token": token,
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": datetime.utcnow(),
            "is_active": True,
            "last_used": datetime.utcnow()
        }
        
        # Store in refresh_tokens collection
        self.db_manager.database["refresh_tokens"].insert_one(token_data)
        return token
    
    def validate_refresh_token(self, token: str) -> dict:
        """Validate and get user from refresh token."""
        token_data = self.db_manager.database["refresh_tokens"].find_one({
            "token": token,
            "is_active": True,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if not token_data:
            return {"valid": False}
        
        # Update last used
        self.db_manager.database["refresh_tokens"].update_one(
            {"_id": token_data["_id"]},
            {"$set": {"last_used": datetime.utcnow()}}
        )
        
        return {"valid": True, "user_id": token_data["user_id"]}
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a specific refresh token."""
        result = self.db_manager.database["refresh_tokens"].update_one(
            {"token": token},
            {"$set": {"is_active": False, "revoked_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke all refresh tokens for a user (e.g., on password change)."""
        result = self.db_manager.database["refresh_tokens"].update_many(
            {"user_id": user_id, "is_active": True},
            {"$set": {"is_active": False, "revoked_at": datetime.utcnow()}}
        )
        return result.modified_count
    
    def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from database."""
        result = self.db_manager.database["refresh_tokens"].delete_many({
            "expires_at": {"$lt": datetime.utcnow()}
        })
        return result.deleted_count

# Benefits of stateful approach:
# ✅ Can revoke tokens immediately
# ✅ Track active sessions
# ✅ Invalidate on password change
# ✅ Better security audit trail
# 
# Drawbacks:
# ❌ Database lookup on every refresh
# ❌ More complex implementation
# ❌ Requires token cleanup jobs