from datetime import timedelta
from os import getenv

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Flask application configuration."""
    
    JWT_SECRET_KEY = getenv('JWT_SECRET_KEY', 'your-secret-key-change-this')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)