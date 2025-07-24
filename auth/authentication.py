import logging
from datetime import datetime

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