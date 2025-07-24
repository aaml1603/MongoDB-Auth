import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from user_agents import parse

from models import DatabaseManager


class RefreshTokenManager:
    """Manages stateful refresh tokens with database storage."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
        
        # Ensure collection has proper indexes
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Create database indexes for optimal performance."""
        try:
            # Index on token for fast lookups
            self.db_manager.database["refresh_tokens"].create_index("token", unique=True)
            
            # Index on user_id for user session management
            self.db_manager.database["refresh_tokens"].create_index("user_id")
            
            # Index on expires_at for cleanup operations
            self.db_manager.database["refresh_tokens"].create_index("expires_at")
            
            # Compound index for active token lookups
            self.db_manager.database["refresh_tokens"].create_index([
                ("token", 1),
                ("is_active", 1),
                ("expires_at", 1)
            ])
            
        except Exception as e:
            self.logger.warning(f"Failed to create indexes: {e}")
    
    def create_refresh_token(self, user_id: str, request_info: Dict) -> str:
        """Create and store a refresh token with session information."""
        token = secrets.token_urlsafe(48)  # 64 characters, URL-safe
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        # Parse user agent for session tracking
        user_agent = request_info.get('user_agent', '')
        parsed_ua = parse(user_agent)
        
        token_data = {
            "token": token,
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": datetime.utcnow(),
            "last_used": datetime.utcnow(),
            "is_active": True,
            
            # Session tracking information
            "session_info": {
                "ip_address": request_info.get('ip_address'),
                "user_agent": user_agent,
                "browser": f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}",
                "os": f"{parsed_ua.os.family} {parsed_ua.os.version_string}",
                "device": parsed_ua.device.family,
                "location": request_info.get('location', 'Unknown'),
            },
            
            # Usage tracking
            "usage_count": 0,
            "last_ip": request_info.get('ip_address')
        }
        
        try:
            # Store in refresh_tokens collection
            result = self.db_manager.database["refresh_tokens"].insert_one(token_data)
            self.logger.info(f"Refresh token created for user {user_id}")
            return token
            
        except Exception as e:
            self.logger.error(f"Failed to create refresh token: {e}")
            raise Exception("Failed to create refresh token")
    
    def validate_and_rotate_token(self, token: str, request_info: Dict) -> Dict:
        """Validate token and create a new one (token rotation)."""
        try:
            # Find and validate current token
            token_data = self.db_manager.database["refresh_tokens"].find_one({
                "token": token,
                "is_active": True,
                "expires_at": {"$gt": datetime.utcnow()}
            })
            
            if not token_data:
                self.logger.warning(f"Invalid refresh token attempt from {request_info.get('ip_address')}")
                return {"valid": False, "error": "Invalid or expired token"}
            
            user_id = token_data["user_id"]
            
            # Check for suspicious activity (IP change)
            if token_data["session_info"]["ip_address"] != request_info.get('ip_address'):
                self.logger.warning(f"IP change detected for token. Old: {token_data['session_info']['ip_address']}, New: {request_info.get('ip_address')}")
                # You could choose to invalidate token here for high security
            
            # Invalidate old token
            self.db_manager.database["refresh_tokens"].update_one(
                {"_id": token_data["_id"]},
                {
                    "$set": {
                        "is_active": False,
                        "rotated_at": datetime.utcnow(),
                        "rotation_reason": "normal_rotation"
                    }
                }
            )
            
            # Create new token
            new_token = self.create_refresh_token(user_id, request_info)
            
            self.logger.info(f"Token rotated for user {user_id}")
            return {
                "valid": True,
                "user_id": user_id,
                "new_token": new_token,
                "session_info": token_data["session_info"]
            }
            
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return {"valid": False, "error": "Token validation failed"}
    
    def revoke_token(self, token: str, reason: str = "manual_revocation") -> bool:
        """Revoke a specific refresh token."""
        try:
            result = self.db_manager.database["refresh_tokens"].update_one(
                {"token": token, "is_active": True},
                {
                    "$set": {
                        "is_active": False,
                        "revoked_at": datetime.utcnow(),
                        "revocation_reason": reason
                    }
                }
            )
            
            if result.modified_count > 0:
                self.logger.info(f"Token revoked: {reason}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Token revocation error: {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id: str, reason: str = "security_action") -> int:
        """Revoke all active refresh tokens for a user."""
        try:
            result = self.db_manager.database["refresh_tokens"].update_many(
                {"user_id": user_id, "is_active": True},
                {
                    "$set": {
                        "is_active": False,
                        "revoked_at": datetime.utcnow(),
                        "revocation_reason": reason
                    }
                }
            )
            
            count = result.modified_count
            if count > 0:
                self.logger.info(f"Revoked {count} tokens for user {user_id}: {reason}")
            
            return count
            
        except Exception as e:
            self.logger.error(f"Bulk token revocation error: {e}")
            return 0
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for a user."""
        try:
            sessions = list(self.db_manager.database["refresh_tokens"].find(
                {"user_id": user_id, "is_active": True},
                {
                    "token": 0,  # Don't return the actual token
                    "session_info": 1,
                    "created_at": 1,
                    "last_used": 1,
                    "usage_count": 1,
                    "_id": 1
                }
            ).sort("last_used", -1))
            
            return sessions
            
        except Exception as e:
            self.logger.error(f"Failed to get user sessions: {e}")
            return []
    
    def cleanup_expired_tokens(self) -> int:
        """Remove expired and old revoked tokens."""
        try:
            # Remove expired tokens
            expired_result = self.db_manager.database["refresh_tokens"].delete_many({
                "expires_at": {"$lt": datetime.utcnow()}
            })
            
            # Remove old revoked tokens (older than 7 days)
            old_revoked_cutoff = datetime.utcnow() - timedelta(days=7)
            revoked_result = self.db_manager.database["refresh_tokens"].delete_many({
                "is_active": False,
                "revoked_at": {"$lt": old_revoked_cutoff}
            })
            
            total_cleaned = expired_result.deleted_count + revoked_result.deleted_count
            
            if total_cleaned > 0:
                self.logger.info(f"Cleaned up {total_cleaned} old tokens")
            
            return total_cleaned
            
        except Exception as e:
            self.logger.error(f"Token cleanup error: {e}")
            return 0
    
    def get_token_stats(self) -> Dict:
        """Get statistics about refresh tokens."""
        try:
            pipeline = [
                {
                    "$group": {
                        "_id": "$is_active",
                        "count": {"$sum": 1}
                    }
                }
            ]
            
            stats = list(self.db_manager.database["refresh_tokens"].aggregate(pipeline))
            
            result = {"active": 0, "inactive": 0, "total": 0}
            for stat in stats:
                if stat["_id"]:
                    result["active"] = stat["count"]
                else:
                    result["inactive"] = stat["count"]
            
            result["total"] = result["active"] + result["inactive"]
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get token stats: {e}")
            return {"active": 0, "inactive": 0, "total": 0}