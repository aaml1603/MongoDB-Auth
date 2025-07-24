import logging
import secrets
from datetime import datetime, timedelta

import bcrypt

from models import DatabaseManager


class Authentication:
    """Handles user authentication operations."""
    
    def __init__(self, db_manager: DatabaseManager):
        """Initialize authentication with database manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__)
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash.
        
        Args:
            password: Plain text password
            hashed: Hashed password
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def register_user(self, email: str, password: str) -> dict:
        """Register a new user.
        
        Args:
            email: User's email address
            password: User's plain text password
            
        Returns:
            dict: Registration result
        """
        try:
            # Check if user already exists
            existing_user = self.db_manager.usuarios.find_one({"email": email})
            if existing_user:
                return {"success": False, "message": "User already exists"}
            
            # Hash password and create user
            hashed_password = self.hash_password(password)
            user_data = {
                "email": email,
                "password": hashed_password,
                "created_at": datetime.utcnow(),
                "is_active": True
            }
            
            result = self.db_manager.usuarios.insert_one(user_data)
            
            if result.inserted_id:
                self.logger.info(f"User registered successfully: {email}")
                return {"success": True, "message": "User registered successfully", "user_id": str(result.inserted_id)}
            else:
                return {"success": False, "message": "Failed to register user"}
                
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            return {"success": False, "message": "Registration failed"}
    
    def authenticate_user(self, email: str, password: str) -> dict:
        """Authenticate a user.
        
        Args:
            email: User's email address
            password: User's plain text password
            
        Returns:
            dict: Authentication result
        """
        try:
            # Find user by email
            user = self.db_manager.usuarios.find_one({"email": email})
            if not user:
                return {"success": False, "message": "Invalid credentials"}
            
            # Verify password
            if not self.verify_password(password, user["password"]):
                return {"success": False, "message": "Invalid credentials"}
            
            # Check if user is active
            if not user.get("is_active", True):
                return {"success": False, "message": "Account is deactivated"}
            
            self.logger.info(f"User authenticated successfully: {email}")
            return {"success": True, "user": {"id": str(user["_id"]), "email": user["email"]}}
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return {"success": False, "message": "Authentication failed"}
    
    def request_password_reset(self, email: str) -> dict:
        """Request a password reset token.
        
        Args:
            email: User's email address
            
        Returns:
            dict: Password reset request result
        """
        try:
            # Check if user exists
            user = self.db_manager.usuarios.find_one({"email": email})
            if not user:
                # Don't reveal if user exists or not for security
                return {"success": True, "message": "If an account with that email exists, a reset link has been sent"}
            
            # Generate secure reset token
            reset_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
            
            # Store reset token in database
            token_data = {
                "user_id": user["_id"],
                "email": email,
                "token": reset_token,
                "expires_at": expires_at,
                "used": False,
                "created_at": datetime.utcnow()
            }
            
            # Remove any existing tokens for this user
            self.db_manager.reset_tokens.delete_many({"user_id": user["_id"]})
            
            # Insert new token
            result = self.db_manager.reset_tokens.insert_one(token_data)
            
            if result.inserted_id:
                self.logger.info(f"Password reset token generated for user: {email}")
                return {
                    "success": True, 
                    "message": "If an account with that email exists, a reset link has been sent",
                    "reset_token": reset_token  # In production, this would be sent via email
                }
            else:
                return {"success": False, "message": "Failed to generate reset token"}
                
        except Exception as e:
            self.logger.error(f"Password reset request error: {e}")
            return {"success": False, "message": "Password reset request failed"}
    
    def reset_password(self, token: str, new_password: str, token_manager=None) -> dict:
        """Reset password using a valid token.
        
        Args:
            token: Password reset token
            new_password: New password
            
        Returns:
            dict: Password reset result
        """
        try:
            # Find valid token
            reset_data = self.db_manager.reset_tokens.find_one({
                "token": token,
                "used": False,
                "expires_at": {"$gt": datetime.utcnow()}
            })
            
            if not reset_data:
                return {"success": False, "message": "Invalid or expired reset token"}
            
            # Hash new password
            hashed_password = self.hash_password(new_password)
            
            # Update user password
            update_result = self.db_manager.usuarios.update_one(
                {"_id": reset_data["user_id"]},
                {"$set": {"password": hashed_password, "updated_at": datetime.utcnow()}}
            )
            
            if update_result.modified_count > 0:
                # Mark token as used
                self.db_manager.reset_tokens.update_one(
                    {"_id": reset_data["_id"]},
                    {"$set": {"used": True, "used_at": datetime.utcnow()}}
                )
                
                # Revoke all refresh tokens on password change for security
                if token_manager:
                    revoked_count = token_manager.revoke_all_user_tokens(
                        str(reset_data["user_id"]), 
                        "password_reset"
                    )
                    self.logger.info(f"Revoked {revoked_count} tokens after password reset")
                
                self.logger.info(f"Password reset successful for user: {reset_data['email']}")
                return {"success": True, "message": "Password reset successful"}
            else:
                return {"success": False, "message": "Failed to update password"}
                
        except Exception as e:
            self.logger.error(f"Password reset error: {e}")
            return {"success": False, "message": "Password reset failed"}
    
    def cleanup_expired_tokens(self) -> int:
        """Clean up expired reset tokens.
        
        Returns:
            int: Number of tokens cleaned up
        """
        try:
            result = self.db_manager.reset_tokens.delete_many({
                "expires_at": {"$lt": datetime.utcnow()}
            })
            
            if result.deleted_count > 0:
                self.logger.info(f"Cleaned up {result.deleted_count} expired reset tokens")
            
            return result.deleted_count
            
        except Exception as e:
            self.logger.error(f"Token cleanup error: {e}")
            return 0