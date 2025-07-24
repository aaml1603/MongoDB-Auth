import logging
from os import getenv
from typing import Optional

import pymongo
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

load_dotenv()


class DatabaseManager:
    """Manages MongoDB database connections and operations."""
    
    def __init__(self, db_name: str = None, collection_name: str = "Usuarios"):
        """Initialize database manager with configuration.
        
        Args:
            db_name: Name of the MongoDB database (defaults to env var MONGODB_DATABASE)
            collection_name: Name of the collection to use
        """
        self.db_name = db_name or getenv("MONGODB_DATABASE", "mascarga")
        self.collection_name = collection_name
        self.client: Optional[MongoClient] = None
        self.database: Optional[Database] = None
        self.usuarios: Optional[Collection] = None
        self.reset_tokens: Optional[Collection] = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def connect(self) -> bool:
        """Establish connection to MongoDB.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Validate environment variable
            db_url = getenv("MONGODB_STRING")
            if not db_url:
                self.logger.error("MONGODB_STRING environment variable not set")
                return False
                
            # Establish connection
            self.client = MongoClient(db_url)
            
            # Test connection
            self.client.admin.command('ping')
            self.logger.info("Successfully connected to MongoDB")
            
            # Setup database and collections
            self.database = self.client[self.db_name]
            self.usuarios = self.database[self.collection_name]
            self.reset_tokens = self.database["PasswordResetTokens"]
            
            return True
            
        except pymongo.errors.ConnectionFailure as e:
            self.logger.error(f"Failed to connect to MongoDB: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during connection: {e}")
            return False
    
    def close(self) -> None:
        """Close the database connection."""
        if self.client:
            self.client.close()
            self.logger.info("Database connection closed")